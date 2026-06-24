/*
 * driver.c — SENTINEL-X Windows Kernel Driver
 *
 * FIX (v13 — work item API):
 *   ExInitializeWorkItem / ExQueueWorkItem are deprecated since WDK 10 and
 *   removed from the kernel on some Windows 11 builds. They caused
 *   "was declared deprecated" compiler warnings and potential load failures.
 *   Replaced with IoAllocateWorkItem / IoQueueWorkItem / IoFreeWorkItem.
 *   The callback signature changes to IO_WORKITEM_ROUTINE:
 *     VOID ScanWorkItemRoutine(PDEVICE_OBJECT, PVOID)
 *
 * FIX (v13 — unload race):
 *   DriverUnload used a blind 15-second KeDelayExecutionThread hoping the
 *   work item would finish. A work item that races past the sleep could
 *   call KeSetTimer AFTER KeCancelTimer (re-arming a cancelled timer) or
 *   dereference already-freed state. Fixed with a KEVENT (g_workItemDone)
 *   that the work item signals on exit — DriverUnload waits on it.
 *
 * FIX (v9 — IRQL):
 *   DPCs run at DISPATCH_LEVEL; ZwQuerySystemInformation requires
 *   PASSIVE_LEVEL. The DPC only queues the work item; scanning happens
 *   in the work item (PASSIVE_LEVEL in a system worker thread).
 */

#include "sentinelx.h"

DRIVER_CONTEXT g_ctx = { 0 };

/* Timer + DPC */
static KTIMER        g_scanTimer;
static KDPC          g_scanDpc;
static LARGE_INTEGER g_scanInterval;

/* Work item state */
static PIO_WORKITEM  g_scanWorkItem    = NULL;   /* FIX: IoAllocateWorkItem */
static BOOLEAN       g_workItemPending = FALSE;
static KSPIN_LOCK    g_workItemLock;
static KEVENT        g_workItemDone;             /* FIX: proper unload sync  */

/* ═══════════════════════════════════════════════════════════════════════
 *  Queue
 * ═══════════════════════════════════════════════════════════════════════ */
VOID QueueInit(PEVENT_QUEUE q) {
    RtlZeroMemory(q, sizeof(EVENT_QUEUE));
    KeInitializeSpinLock(&q->lock);
}

BOOLEAN QueuePush(PEVENT_QUEUE q, PSENTINEL_EVENT evt) {
    KIRQL   irql;
    BOOLEAN ok = FALSE;
    KeAcquireSpinLock(&q->lock, &irql);
    if (q->count < EVENT_QUEUE_MAX) {
        q->entries[q->tail] = *evt;
        q->tail  = (q->tail + 1) % EVENT_QUEUE_MAX;
        q->count++;
        ok = TRUE;
    }
    KeReleaseSpinLock(&q->lock, irql);
    return ok;
}

BOOLEAN QueuePop(PEVENT_QUEUE q, PSENTINEL_EVENT out) {
    KIRQL   irql;
    BOOLEAN ok = FALSE;
    KeAcquireSpinLock(&q->lock, &irql);
    if (q->count > 0) {
        *out    = q->entries[q->head];
        q->head = (q->head + 1) % EVENT_QUEUE_MAX;
        q->count--;
        ok = TRUE;
    }
    KeReleaseSpinLock(&q->lock, irql);
    return ok;
}

VOID QueueFlush(PEVENT_QUEUE q) {
    KIRQL irql;
    KeAcquireSpinLock(&q->lock, &irql);
    q->head = q->tail = q->count = 0;
    KeReleaseSpinLock(&q->lock, irql);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  SentinelAlert — safe to call at any IRQL
 * ═══════════════════════════════════════════════════════════════════════ */
VOID SentinelAlert(KS_EVENT_TYPE type, KS_SEVERITY sev, PCWSTR fmt, ...) {
    SENTINEL_EVENT evt = { 0 };
    va_list args;

    evt.type     = type;
    evt.severity = sev;
    KeQuerySystemTime(&evt.timestamp);

    va_start(args, fmt);
    RtlStringCchVPrintfW(evt.message, EVENT_MSG_LEN, fmt, args);
    va_end(args);

    if (!QueuePush(&g_ctx.queue, &evt))
        DbgPrint("[sentinelx] WARN: queue full\n");
    else
        KeSetEvent(&g_ctx.newEventSignal, IO_NO_INCREMENT, FALSE);

    DbgPrint("[sentinelx] ALERT sev=%d type=%d msg=%ws\n",
             (int)sev, (int)type, evt.message);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Scan work item — runs at PASSIVE_LEVEL (safe for Zw* calls)
 *
 *  Signature is IO_WORKITEM_ROUTINE: (PDEVICE_OBJECT, PVOID)
 *  FIX: replaced ExInitializeWorkItem / ExQueueWorkItem pattern.
 * ═══════════════════════════════════════════════════════════════════════ */
static VOID ScanWorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);
    KIRQL irql;

    /* IRQL is PASSIVE_LEVEL — safe to call ZwQuerySystemInformation */
    if (g_ctx.monitoring) {
        SsdtScan();
        DkomScan();
    }

    /* Clear pending flag so the DPC can queue a new work item next tick */
    KeAcquireSpinLock(&g_workItemLock, &irql);
    g_workItemPending = FALSE;
    KeReleaseSpinLock(&g_workItemLock, irql);

    /* Re-arm timer for next interval (only if still monitoring) */
    if (g_ctx.monitoring)
        KeSetTimer(&g_scanTimer, g_scanInterval, &g_scanDpc);

    /*
     * FIX: signal that this work item has completed.
     * DriverUnload waits on this event instead of sleeping blindly.
     */
    KeSetEvent(&g_workItemDone, IO_NO_INCREMENT, FALSE);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  DPC routine — DISPATCH_LEVEL, only queues work item
 * ═══════════════════════════════════════════════════════════════════════ */
static VOID ScanDpcRoutine(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1);
    UNREFERENCED_PARAMETER(A2);
    KIRQL irql;

    if (!g_ctx.monitoring || !g_scanWorkItem) return;

    KeAcquireSpinLock(&g_workItemLock, &irql);
    if (!g_workItemPending) {
        g_workItemPending = TRUE;
        KeClearEvent(&g_workItemDone);   /* mark as busy before queuing */
        KeReleaseSpinLock(&g_workItemLock, irql);
        /* FIX: IoQueueWorkItem instead of ExQueueWorkItem */
        IoQueueWorkItem(g_scanWorkItem, ScanWorkItemRoutine,
                        DelayedWorkQueue, NULL);
    } else {
        KeReleaseSpinLock(&g_workItemLock, irql);
        /* Previous scan still running — re-arm timer, skip this cycle */
        KeSetTimer(&g_scanTimer, g_scanInterval, &g_scanDpc);
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  IRP handlers
 * ═══════════════════════════════════════════════════════════════════════ */
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[sentinelx] Handle opened\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[sentinelx] Handle closed\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack  = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code   = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR          info   = 0;

    switch (code) {
    case IOCTL_READ_EVENT: {
        PVOID outBuf  = Irp->AssociatedIrp.SystemBuffer;
        ULONG outSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (!outBuf || outSize < sizeof(SENTINEL_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        SENTINEL_EVENT evt = { 0 };
        if (QueuePop(&g_ctx.queue, &evt)) {
            RtlCopyMemory(outBuf, &evt, sizeof(SENTINEL_EVENT));
            info   = sizeof(SENTINEL_EVENT);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_NO_MORE_ENTRIES;
        }
        break;
    }
    case IOCTL_FLUSH_QUEUE:
        QueueFlush(&g_ctx.queue);
        status = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  DriverUnload
 * ═══════════════════════════════════════════════════════════════════════ */
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symlink;
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[sentinelx] Unloading...\n");
    g_ctx.monitoring = FALSE;

    /* Cancel timer — no new DPCs after this returns */
    KeCancelTimer(&g_scanTimer);

    /*
     * FIX: wait for any in-progress work item to complete (up to 5 s).
     * Old code used KeDelayExecutionThread(15s) — a blind sleep that could
     * still race if the work item ran past the 15s window, and wasted 15s
     * on every clean unload.  The KEVENT gives us an exact notification.
     */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50LL * 10000000LL;  /* 5 seconds */
    KeWaitForSingleObject(&g_workItemDone, Executive, KernelMode,
                          FALSE, &timeout);

    SsdtCleanup();
    DkomCleanup();

    /* FIX: free the work item object */
    if (g_scanWorkItem) {
        IoFreeWorkItem(g_scanWorkItem);
        g_scanWorkItem = NULL;
    }

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (g_ctx.deviceObj)
        IoDeleteDevice(g_ctx.deviceObj);

    DbgPrint("[sentinelx] Unloaded.\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 *  DriverEntry
 * ═══════════════════════════════════════════════════════════════════════ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS      status;
    UNICODE_STRING devName, symlink;

    DbgPrint("[sentinelx] DriverEntry — SENTINEL-X v13\n");

    /* Init queue, signal, and spin locks */
    QueueInit(&g_ctx.queue);
    KeInitializeEvent(&g_ctx.newEventSignal, NotificationEvent, FALSE);
    KeInitializeSpinLock(&g_workItemLock);
    g_workItemPending = FALSE;
    g_ctx.monitoring  = TRUE;

    /*
     * FIX: initialise g_workItemDone as SIGNALED so DriverUnload won't
     * block if unloaded before the first work item ever runs.
     */
    KeInitializeEvent(&g_workItemDone, NotificationEvent, TRUE);

    /* IRP dispatch */
    DriverObject->DriverUnload                         = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    /* Create device */
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_ctx.deviceObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[sentinelx] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* Create symbolic link */
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[sentinelx] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_ctx.deviceObj);
        return status;
    }

    g_ctx.deviceObj->Flags |= DO_BUFFERED_IO;
    g_ctx.deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("[sentinelx] Device ready: %ws\n", DEVICE_NAME);

    /* Init detection modules */
    status = SsdtInit();
    if (!NT_SUCCESS(status))
        DbgPrint("[sentinelx] WARN: SsdtInit failed: 0x%08X\n", status);

    status = DkomInit();
    if (!NT_SUCCESS(status))
        DbgPrint("[sentinelx] WARN: DkomInit failed: 0x%08X\n", status);

    /*
     * FIX: allocate work item via IoAllocateWorkItem (not deprecated).
     * Must be done after IoCreateDevice because IoAllocateWorkItem
     * needs a valid PDEVICE_OBJECT.
     */
    g_scanWorkItem = IoAllocateWorkItem(g_ctx.deviceObj);
    if (!g_scanWorkItem) {
        DbgPrint("[sentinelx] IoAllocateWorkItem failed\n");
        SsdtCleanup();
        DkomCleanup();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_ctx.deviceObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Set up the scan timer: DPC → work item → PASSIVE_LEVEL scan */
    KeInitializeTimer(&g_scanTimer);
    KeInitializeDpc(&g_scanDpc, ScanDpcRoutine, NULL);
    g_scanInterval.QuadPart = -10LL * 10000000LL;  /* 10 s in 100-ns units */
    KeSetTimer(&g_scanTimer, g_scanInterval, &g_scanDpc);

    DbgPrint("[sentinelx] DriverEntry complete — monitoring active.\n");
    return STATUS_SUCCESS;
}
