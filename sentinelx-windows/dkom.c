/*
 * dkom.c — DKOM Detection + Driver Hiding  SENTINEL-X Windows (Final)
 *
 * DKOM: Cross-references EPROCESS walk vs ZwQuerySystemInformation.
 * Driver hiding: PE header scan of kernel VA space vs module list.
 * Dynamic EPROCESS offset discovery — no hardcoded build table.
 */
#include "sentinelx.h"

typedef struct _KS_PROCESS_ENTRY {
    ULONG  NextEntryOffset; ULONG NumberOfThreads;
    UCHAR  Reserved1[48];   UCHAR Reserved2[24];
    HANDLE UniqueProcessId; PVOID InheritedFromUniqueProcessId;
    ULONG  HandleCount;     ULONG Reserved3;
} KS_PROCESS_ENTRY, *PKS_PROCESS_ENTRY;

typedef struct _KS_MODULE_ENTRY {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase;
    ULONG  ImageSize; ULONG Flags;
    USHORT LoadOrderIndex; USHORT InitOrderIndex;
    USHORT LoadCount; USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} KS_MODULE_ENTRY, *PKS_MODULE_ENTRY;

typedef struct _KS_MODULE_LIST {
    ULONG NumberOfModules; KS_MODULE_ENTRY Modules[1];
} KS_MODULE_LIST, *PKS_MODULE_LIST;

#define MAX_TRACKED_PIDS        512
#define EPROCESS_SCAN_MIN       0x180u
#define EPROCESS_SCAN_MAX       0x600u
#define EPROCESS_WALK_VERIFY_MIN 10
#define MAX_WALK_GUARD          2048
#define MAX_HIDDEN_DRIVERS      64
#define PE_SCAN_MARGIN          (64ULL  * 1024 * 1024)
#define PE_MAX_IMAGE_SIZE       (256ULL * 1024 * 1024)
#define PE_MAX_LFANEW           4096u

static ULONG      g_pidOffset   = 0;
static ULONG      g_aplOffset   = 0;
static ULONG_PTR  g_alertedPids[MAX_TRACKED_PIDS] = { 0 };
static ULONG      g_alertedCount = 0;
static KSPIN_LOCK g_dkomLock;

static ULONG64    g_hiddenBases[MAX_HIDDEN_DRIVERS] = { 0 };
static ULONG      g_hiddenCount  = 0;
static KSPIN_LOCK g_hiddenLock;
static BOOLEAN    g_dkomReady    = FALSE;

static BOOLEAN IsAlerted(ULONG_PTR pid) {
    for (ULONG i = 0; i < g_alertedCount; i++) if (g_alertedPids[i] == pid) return TRUE;
    return FALSE;
}
static VOID AddAlerted(ULONG_PTR pid) {
    if (g_alertedCount < MAX_TRACKED_PIDS) g_alertedPids[g_alertedCount++] = pid;
}
static VOID RemoveAlerted(ULONG_PTR pid) {
    for (ULONG i = 0; i < g_alertedCount; i++) {
        if (g_alertedPids[i] != pid) continue;
        g_alertedPids[i] = g_alertedPids[--g_alertedCount]; return;
    }
}
static BOOLEAN IsHiddenBase(ULONG64 base) {
    for (ULONG i = 0; i < g_hiddenCount; i++) if (g_hiddenBases[i] == base) return TRUE;
    return FALSE;
}
static VOID AddHiddenBase(ULONG64 base) {
    if (g_hiddenCount < MAX_HIDDEN_DRIVERS) g_hiddenBases[g_hiddenCount++] = base;
}
static VOID RemoveHiddenBase(ULONG64 base) {
    for (ULONG i = 0; i < g_hiddenCount; i++) {
        if (g_hiddenBases[i] != base) continue;
        g_hiddenBases[i] = g_hiddenBases[--g_hiddenCount]; return;
    }
}
static BOOLEAN IsKernelPtr(ULONG_PTR a) {
    return (a >= 0xFFFF800000000000ULL) && (a != (ULONG_PTR)-1);
}

static BOOLEAN DiscoverEprocessOffsets(VOID) {
    ULONG_PTR eprocBase = (ULONG_PTR)PsInitialSystemProcess;
    if (!eprocBase) return FALSE;
    for (ULONG off = EPROCESS_SCAN_MIN; off <= EPROCESS_SCAN_MAX; off += sizeof(ULONG_PTR)) {
        ULONG_PTR val = 0;
        __try { val = *(PULONG_PTR)(eprocBase + off); }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (val != 4) continue;
        ULONG aplCand = off + (ULONG)sizeof(ULONG_PTR);
        PLIST_ENTRY startApl = (PLIST_ENTRY)(eprocBase + aplCand);
        PLIST_ENTRY cur = NULL; ULONG verified = 0; ULONG guard = 0;
        __try { cur = startApl->Flink; } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        while (guard++ < MAX_WALK_GUARD) {
            if (!IsKernelPtr((ULONG_PTR)cur) || !MmIsAddressValid(cur)) break;
            ULONG_PTR entryBase = (ULONG_PTR)cur - aplCand;
            if (!IsKernelPtr(entryBase) || !MmIsAddressValid((PVOID)entryBase)) break;
            ULONG_PTR pid = 0;
            __try { pid = *(PULONG_PTR)(entryBase + off); } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
            if (pid == 0 || (pid & 3) != 0 || pid >= 1000000ULL) break;
            verified++;
            PLIST_ENTRY nxt = NULL;
            __try { nxt = cur->Flink; } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
            if (nxt == startApl) break;
            cur = nxt;
        }
        if (verified < EPROCESS_WALK_VERIFY_MIN) continue;
        g_pidOffset = off; g_aplOffset = aplCand;
        DbgPrint("[sentinelx] DkomInit: EPROCESS pidOff=0x%X aplOff=0x%X (verified %u)\n",
            g_pidOffset, g_aplOffset, verified);
        return TRUE;
    }
    DbgPrint("[sentinelx] DkomInit: EPROCESS offset discovery failed\n");
    return FALSE;
}

static NTSTATUS CollectKernelPids(
    _Out_writes_to_(maxPids,*outCount) ULONG_PTR *pids,
    _In_ ULONG maxPids, _Out_ PULONG outCount)
{
    *outCount = 0;
    if (!g_aplOffset || !PsInitialSystemProcess) return STATUS_UNSUCCESSFUL;
    ULONG_PTR eprocBase = (ULONG_PTR)PsInitialSystemProcess;
    PLIST_ENTRY start = (PLIST_ENTRY)(eprocBase + g_aplOffset);
    PLIST_ENTRY cur = NULL; ULONG guard = 0;
    __try { cur = start->Flink; } __except(EXCEPTION_EXECUTE_HANDLER) { return STATUS_UNSUCCESSFUL; }
    while (cur != start && guard++ < MAX_WALK_GUARD) {
        if (!IsKernelPtr((ULONG_PTR)cur) || !MmIsAddressValid(cur)) break;
        ULONG_PTR entryBase = (ULONG_PTR)cur - g_aplOffset;
        ULONG_PTR pid = 0;
        __try { pid = *(PULONG_PTR)(entryBase + g_pidOffset); } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
        if (pid > 0 && (pid & 3) == 0 && pid < 1000000ULL)
            if (*outCount < maxPids) pids[(*outCount)++] = pid;
        PLIST_ENTRY nxt = NULL;
        __try { nxt = cur->Flink; } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
        cur = nxt;
    }
    return (*outCount > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static NTSTATUS CollectApiPids(
    _Out_writes_to_(maxPids,*outCount) ULONG_PTR *pids,
    _In_ ULONG maxPids, _Out_ PULONG outCount)
{
    NTSTATUS status; ULONG size = 0; PVOID buffer = NULL; *outCount = 0;
    status = ZwQuerySystemInformation(KsSystemProcessInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH || !size) return STATUS_UNSUCCESSFUL;
    size += 4096;
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
    status = ZwQuerySystemInformation(KsSystemProcessInformation, buffer, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buffer, DRIVER_TAG); return status; }
    PKS_PROCESS_ENTRY entry = (PKS_PROCESS_ENTRY)buffer;
    for (;;) {
        ULONG_PTR pid = (ULONG_PTR)entry->UniqueProcessId;
        if (*outCount < maxPids) pids[(*outCount)++] = pid;
        if (!entry->NextEntryOffset) break;
        entry = (PKS_PROCESS_ENTRY)((PUCHAR)entry + entry->NextEntryOffset);
    }
    ExFreePoolWithTag(buffer, DRIVER_TAG);
    return STATUS_SUCCESS;
}

static BOOLEAN PidInArray(ULONG_PTR pid, _In_reads_(n) ULONG_PTR *arr, ULONG n) {
    for (ULONG i = 0; i < n; i++) if (arr[i] == pid) return TRUE;
    return FALSE;
}

static PKS_MODULE_LIST GetModuleList(VOID) {
    NTSTATUS status; ULONG size = 0;
    status = ZwQuerySystemInformation(KsSystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH || !size) return NULL;
    size += 4096;
    PKS_MODULE_LIST list = (PKS_MODULE_LIST)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
    if (!list) return NULL;
    status = ZwQuerySystemInformation(KsSystemModuleInformation, list, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(list, DRIVER_TAG); return NULL; }
    return list;
}

static BOOLEAN BaseInModuleList(ULONG64 base, PKS_MODULE_LIST list) {
    for (ULONG i = 0; i < list->NumberOfModules; i++)
        if ((ULONG64)list->Modules[i].ImageBase == base) return TRUE;
    return FALSE;
}

static VOID PeScanForHiddenDrivers(PKS_MODULE_LIST knownList) {
    if (!knownList || !knownList->NumberOfModules) return;
    ULONG64 scanMin = (ULONG64)MAXULONG_PTR, scanMax = 0;
    for (ULONG i = 0; i < knownList->NumberOfModules; i++) {
        ULONG64 base = (ULONG64)knownList->Modules[i].ImageBase;
        ULONG   sz   = knownList->Modules[i].ImageSize;
        if (!base) continue;
        if (base < scanMin)      scanMin = base;
        if (base + sz > scanMax) scanMax = base + sz;
    }
    if (scanMin == (ULONG64)MAXULONG_PTR || !scanMax) return;
    scanMin = (scanMin > PE_SCAN_MARGIN) ? scanMin - PE_SCAN_MARGIN : (ULONG64)PAGE_SIZE;
    scanMax = scanMax + PE_SCAN_MARGIN;
    scanMin &= ~(ULONG64)(PAGE_SIZE - 1);
    scanMax  = (scanMax + PAGE_SIZE - 1) & ~(ULONG64)(PAGE_SIZE - 1);
    DbgPrint("[sentinelx] PeScan: %016llX - %016llX (%llu MB, %llu modules known)\n",
        scanMin, scanMax, (scanMax - scanMin)/(1024*1024),
        (ULONG64)knownList->NumberOfModules);

    KIRQL irql = 0;
    KeAcquireSpinLock(&g_hiddenLock, &irql);
    for (ULONG i = 0; i < g_hiddenCount; ) {
        ULONG64 base = g_hiddenBases[i];

        if (BaseInModuleList(base, knownList)) {
            /* Driver reappeared in module list - properly restored */
            RemoveHiddenBase(base);
            KeReleaseSpinLock(&g_hiddenLock, irql);
            SentinelAlert(EVT_DRIVER_RESTORED, SEV_INFO,
                L"[MODULE RESTORED] PE image @ %016llX back in module list", base);
            KeAcquireSpinLock(&g_hiddenLock, &irql);

        } else if (!MmIsAddressValid((PVOID)(ULONG_PTR)base)) {
            /*
             * CRITICAL FIX for multi-run evaluation:
             *
             * The base is no longer in the module list AND the pages are
             * no longer mapped. This means the driver was completely unloaded
             * (e.g., rmmod / sc stop) — NOT just hidden.
             *
             * Without this check, g_hiddenBases[] retains the entry forever.
             * On the next run, the rootkit reloads at the same base address,
             * PE scan finds it, IsHiddenBase() returns TRUE, and no alert
             * fires. Every run after the first silently misses.
             *
             * Fix: treat "gone from VA space" as implicitly restored.
             * Fire DRIVER_RESTORED so the eval script's WaitForRestored()
             * can synchronise, then clear the entry from g_hiddenBases[].
             */
            RemoveHiddenBase(base);
            KeReleaseSpinLock(&g_hiddenLock, irql);
            DbgPrint("[sentinelx] PeScan: base %016llX unloaded (pages gone) - clearing state\n", base);
            SentinelAlert(EVT_DRIVER_RESTORED, SEV_INFO,
                L"[MODULE RESTORED] PE image @ %016llX unloaded (pages freed)", base);
            KeAcquireSpinLock(&g_hiddenLock, &irql);

        } else {
            i++;
        }
    }
    KeReleaseSpinLock(&g_hiddenLock, irql);

    ULONG hiddenFound = 0;
    for (ULONG64 addr = scanMin; addr < scanMax; addr += PAGE_SIZE) {
        if (addr == 0 || !MmIsAddressValid((PVOID)addr)) continue;
        ULONG imageSize = 0;
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            LONG lfanew = dos->e_lfanew;
            if (lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || lfanew > (LONG)PE_MAX_LFANEW) continue;
            PVOID ntHdrAddr = (PVOID)(addr + (ULONG64)lfanew);
            if (!MmIsAddressValid(ntHdrAddr)) continue;
            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)ntHdrAddr;
            if (nt->Signature != IMAGE_NT_SIGNATURE)                 continue;
            if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)  continue;
            if (!nt->OptionalHeader.SizeOfImage)                     continue;
            if (nt->OptionalHeader.SizeOfImage > PE_MAX_IMAGE_SIZE)  continue;
            imageSize = nt->OptionalHeader.SizeOfImage;
        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }

        if (BaseInModuleList(addr, knownList)) {
            if (imageSize > PAGE_SIZE)
                addr += (ULONG64)(imageSize - PAGE_SIZE) & ~(ULONG64)(PAGE_SIZE - 1);
            continue;
        }
        KIRQL hiddenIrql = 0;
        KeAcquireSpinLock(&g_hiddenLock, &hiddenIrql);
        BOOLEAN already = IsHiddenBase(addr);
        if (!already) AddHiddenBase(addr);
        KeReleaseSpinLock(&g_hiddenLock, hiddenIrql);
        if (!already) {
            DbgPrint("[sentinelx] PeScan: hidden PE @ %016llX size=0x%X\n", addr, imageSize);
            SentinelAlert(EVT_DRIVER_HIDDEN, SEV_CRITICAL,
                L"[MODULE HIDDEN] PE image @ %016llX not in module list (size=0x%X)",
                addr, imageSize);
            hiddenFound++;
        }
        if (imageSize > PAGE_SIZE)
            addr += (ULONG64)(imageSize - PAGE_SIZE) & ~(ULONG64)(PAGE_SIZE - 1);
    }
    DbgPrint("[sentinelx] PeScan: complete - %u new hidden images found\n", hiddenFound);
}

NTSTATUS DkomInit(VOID) {
    DbgPrint("[sentinelx] DkomInit: enter\n");
    KeInitializeSpinLock(&g_dkomLock);
    KeInitializeSpinLock(&g_hiddenLock);
    if (DiscoverEprocessOffsets())
        DbgPrint("[sentinelx] DkomInit: EPROCESS walk ready (pidOff=0x%X aplOff=0x%X)\n",
            g_pidOffset, g_aplOffset);
    else
        DbgPrint("[sentinelx] DkomInit: EPROCESS walk disabled - driver hiding still active\n");
    g_dkomReady = TRUE;
    DbgPrint("[sentinelx] DkomInit: done\n");
    return STATUS_SUCCESS;
}

VOID DkomCleanup(VOID) {
    g_dkomReady = FALSE; g_aplOffset = 0; g_pidOffset = 0;
    g_hiddenCount = 0; g_alertedCount = 0;
    DbgPrint("[sentinelx] DkomCleanup done\n");
}

NTSTATUS DkomScan(VOID) {
    if (!g_dkomReady) return STATUS_SUCCESS;
    if (g_aplOffset) {
        ULONG_PTR *kernPids = (ULONG_PTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            MAX_TRACKED_PIDS * sizeof(ULONG_PTR), DRIVER_TAG);
        ULONG_PTR *apiPids  = (ULONG_PTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            MAX_TRACKED_PIDS * sizeof(ULONG_PTR), DRIVER_TAG);
        if (kernPids && apiPids) {
            ULONG kernCount = 0, apiCount = 0;
            CollectKernelPids(kernPids, MAX_TRACKED_PIDS, &kernCount);
            if (NT_SUCCESS(CollectApiPids(apiPids, MAX_TRACKED_PIDS, &apiCount))) {
                for (ULONG i = 0; i < kernCount; i++) {
                    ULONG_PTR pid = kernPids[i];
                    BOOLEAN inApi = PidInArray(pid, apiPids, apiCount);
                    KIRQL irql = 0;
                    KeAcquireSpinLock(&g_dkomLock, &irql);
                    if (!inApi && !IsAlerted(pid)) {
                        AddAlerted(pid); KeReleaseSpinLock(&g_dkomLock, irql);
                        SentinelAlert(EVT_DKOM_ALERT, SEV_CRITICAL,
                            L"[DKOM ALERT] pid=%llu hidden from API", (ULONG64)pid);
                    } else if (inApi && IsAlerted(pid)) {
                        RemoveAlerted(pid); KeReleaseSpinLock(&g_dkomLock, irql);
                    } else { KeReleaseSpinLock(&g_dkomLock, irql); }
                }
            }
        }
        if (kernPids) ExFreePoolWithTag(kernPids, DRIVER_TAG);
        if (apiPids)  ExFreePoolWithTag(apiPids,  DRIVER_TAG);
    }
    PKS_MODULE_LIST modList = GetModuleList();
    if (modList) { PeScanForHiddenDrivers(modList); ExFreePoolWithTag(modList, DRIVER_TAG); }
    return STATUS_SUCCESS;
}
