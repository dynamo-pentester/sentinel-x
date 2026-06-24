/*
 * sentinelx.h — SENTINEL-X shared header
 *
 * FIX (warnings pass):
 *   - ZwQuerySystemInformation and RtlPcToFileHeader declared here with
 *     NTSYSAPI / NTKERNELAPI so PREfast treats them as externally satisfied.
 *   - _Success_(return != FALSE) on QueuePop declaration
 *   - _Printf_format_string_ added to SentinelAlert fmt parameter.
 */

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <aux_klib.h>
#include <ntstrsafe.h>

/* ── Build-identity ────────────────────────────────────────────────────── */
#define DRIVER_TAG        'XNTS'
#define DEVICE_NAME       L"\\Device\\SentinelX"
#define SYMLINK_NAME      L"\\DosDevices\\SentinelX"

/* ── IOCTL codes ───────────────────────────────────────────────────────── */
#define SENTINEL_DEVICE_TYPE  0x8000u
#define IOCTL_READ_EVENT  CTL_CODE(SENTINEL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_FLUSH_QUEUE CTL_CODE(SENTINEL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

/* ── Event definitions ─────────────────────────────────────────────────── */
#define EVENT_QUEUE_MAX  256u
#define EVENT_MSG_LEN    256u

typedef enum _KS_EVENT_TYPE {
    EVT_SSDT_HOOK = 1,
    EVT_SSDT_RESTORED,
    EVT_DKOM_ALERT,
    EVT_DRIVER_HIDDEN,
    EVT_DRIVER_RESTORED,
} KS_EVENT_TYPE;

typedef enum _KS_SEVERITY {
    SEV_INFO = 0,
    SEV_WARNING,
    SEV_CRITICAL,
} KS_SEVERITY;

typedef struct _SENTINEL_EVENT {
    KS_EVENT_TYPE type;
    KS_SEVERITY   severity;
    LARGE_INTEGER timestamp;
    WCHAR         message[EVENT_MSG_LEN];
} SENTINEL_EVENT, * PSENTINEL_EVENT;

/* ── Ring-buffer event queue ───────────────────────────────────────────── */
typedef struct _EVENT_QUEUE {
    KSPIN_LOCK     lock;
    ULONG          head;
    ULONG          tail;
    ULONG          count;
    SENTINEL_EVENT entries[EVENT_QUEUE_MAX];
} EVENT_QUEUE, * PEVENT_QUEUE;

/* ── Per-driver context ────────────────────────────────────────────────── */
typedef struct _DRIVER_CONTEXT {
    PDEVICE_OBJECT deviceObj;
    EVENT_QUEUE    queue;
    KEVENT         newEventSignal;
    BOOLEAN        monitoring;
} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

extern DRIVER_CONTEXT g_ctx;

/* ═══════════════════════════════════════════════════════════════════════
 *  Kernel API imports
 * ═══════════════════════════════════════════════════════════════════════ */
typedef enum _KS_SYSTEM_INFO_CLASS {
    KsSystemProcessInformation = 5,
    KsSystemModuleInformation = 11,
} KS_SYSTEM_INFO_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_                                            ULONG  SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID  SystemInformation,
    _In_                                            ULONG  SystemInformationLength,
    _Out_opt_                                       PULONG ReturnLength
);

NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(
    _In_  PVOID  PcValue,
    _Out_ PVOID* BaseOfImage
);

/* ═══════════════════════════════════════════════════════════════════════
 *  Queue API
 * ═══════════════════════════════════════════════════════════════════════ */
VOID    QueueInit(_Inout_ PEVENT_QUEUE q);
BOOLEAN QueuePush(_Inout_ PEVENT_QUEUE q, _In_  PSENTINEL_EVENT evt);
_Success_(return != FALSE)
BOOLEAN QueuePop(_Inout_ PEVENT_QUEUE q, _Out_ PSENTINEL_EVENT out);
VOID    QueueFlush(_Inout_ PEVENT_QUEUE q);

/* ── Alert helper ─────────────────────────────────────────────────────── */
VOID SentinelAlert(
    _In_                        KS_EVENT_TYPE type,
    _In_                        KS_SEVERITY   severity,
    _In_ _Printf_format_string_ PCWSTR        fmt,
    ...);

/* ── Detection modules ────────────────────────────────────────────────── */
NTSTATUS SsdtInit(VOID);
VOID     SsdtCleanup(VOID);
NTSTATUS SsdtScan(VOID);

NTSTATUS DkomInit(VOID);
VOID     DkomCleanup(VOID);
NTSTATUS DkomScan(VOID);

/* ── IRP dispatch ─────────────────────────────────────────────────────── */
NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchClose (_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchIoctl (_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
