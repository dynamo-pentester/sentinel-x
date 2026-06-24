/*
 * ssdt.c — SSDT Hook Detection  SENTINEL-X Windows Driver
 */
#include "sentinelx.h"

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG  ServiceTableBase;
    PULONG  ServiceCounterTableBase;
    ULONG   NumberOfServices;
    PUCHAR  ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

static PKSERVICE_TABLE_DESCRIPTOR g_ssdt    = NULL;
static ULONG64                    g_ntBase  = 0;
static ULONG64                    g_ntEnd   = 0;

#define MAX_SYSCALLS 512
static ULONG64 g_baseline[MAX_SYSCALLS] = { 0 };
static ULONG   g_syscallCount           = 0;
static BOOLEAN g_baselineReady          = FALSE;
static BOOLEAN g_hooked[MAX_SYSCALLS]   = { FALSE };

static ULONG64 ResolveSsdtEntry(ULONG index) {
    PULONG base; ULONG count; LONG offset;
    if (!g_ssdt) return 0;
    base  = g_ssdt->ServiceTableBase;
    count = g_ssdt->NumberOfServices;
    if (index >= count || !base) return 0;
    offset = (LONG)(base[index]);
    return (ULONG64)base + (offset >> 4);
}

static PKSERVICE_TABLE_DESCRIPTOR FindSsdt(VOID) {
#ifdef _AMD64_
    ULONG64 lstar = __readmsr(0xC0000082UL);
    if (!lstar) { DbgPrint("[sentinelx] FindSsdt: LSTAR=0\n"); return NULL; }
    DbgPrint("[sentinelx] FindSsdt: LSTAR=%016llX\n", lstar);
    PUCHAR p = (PUCHAR)lstar;
    for (ULONG i = 0; i < 4096 - 6; i++) {
        if (p[i] != 0x4C || p[i+1] != 0x8D || p[i+2] != 0x15) continue;
        LONG relOffset = *(PLONG)(p + i + 3);
        PKSERVICE_TABLE_DESCRIPTOR candidate =
            (PKSERVICE_TABLE_DESCRIPTOR)((PUCHAR)(p + i + 7) + relOffset);
        __try {
            if (candidate->ServiceTableBase &&
                candidate->NumberOfServices >= 100 &&
                candidate->NumberOfServices <= MAX_SYSCALLS) {
                DbgPrint("[sentinelx] FindSsdt: SSDT @ %p (off=%u services=%u)\n",
                    candidate, i, candidate->NumberOfServices);
                return candidate;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    DbgPrint("[sentinelx] FindSsdt: pattern not found\n");
    return NULL;
#else
    return NULL;
#endif
}

static NTSTATUS FindNtoskrnlRange(VOID) {
    PVOID ntBase = NULL;
    RtlPcToFileHeader((PVOID)(ULONG_PTR)g_ssdt->ServiceTableBase, &ntBase);
    if (!ntBase) {
        DbgPrint("[sentinelx] FindNtoskrnlRange: RtlPcToFileHeader failed\n");
        return STATUS_NOT_FOUND;
    }
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    g_ntBase = (ULONG64)ntBase;
    g_ntEnd  = g_ntBase + nt->OptionalHeader.SizeOfImage;
    DbgPrint("[sentinelx] ntoskrnl: %016llX - %016llX\n", g_ntBase, g_ntEnd);
    return STATUS_SUCCESS;
}

NTSTATUS SsdtInit(VOID) {
    NTSTATUS status;
    DbgPrint("[sentinelx] SsdtInit\n");
    AuxKlibInitialize();
    g_ssdt = FindSsdt();
    if (!g_ssdt) {
        DbgPrint("[sentinelx] SsdtInit: SSDT not found\n");
        return STATUS_NOT_FOUND;
    }
    status = FindNtoskrnlRange();
    if (!NT_SUCCESS(status)) return status;
    g_syscallCount = g_ssdt->NumberOfServices;
    if (g_syscallCount > MAX_SYSCALLS) g_syscallCount = MAX_SYSCALLS;
    for (ULONG i = 0; i < g_syscallCount; i++) {
        g_baseline[i] = ResolveSsdtEntry(i);
        g_hooked[i]   = FALSE;
    }
    g_baselineReady = TRUE;
    DbgPrint("[sentinelx] SsdtInit: baseline %u syscalls\n", g_syscallCount);
    return STATUS_SUCCESS;
}

VOID SsdtCleanup(VOID) {
    g_baselineReady = FALSE;
    g_ssdt = NULL;
    DbgPrint("[sentinelx] SsdtCleanup done\n");
}

NTSTATUS SsdtScan(VOID) {
    if (!g_baselineReady || !g_ssdt || !g_ntBase) return STATUS_SUCCESS;
    ULONG count = g_ssdt->NumberOfServices;
    if (count > MAX_SYSCALLS) count = MAX_SYSCALLS;
    for (ULONG i = 0; i < count; i++) {
        ULONG64 cur  = ResolveSsdtEntry(i);
        BOOLEAN hook = (cur < g_ntBase || cur >= g_ntEnd);
        if (hook && !g_hooked[i]) {
            g_hooked[i] = TRUE;
            SentinelAlert(EVT_SSDT_HOOK, SEV_CRITICAL,
                L"[SCT HOOK] syscall[%u] expected=%016llX got=%016llX",
                i, g_baseline[i], cur);
        } else if (!hook && g_hooked[i]) {
            g_hooked[i] = FALSE;
            SentinelAlert(EVT_SSDT_RESTORED, SEV_INFO,
                L"[SCT RESTORED] syscall[%u] addr=%016llX", i, cur);
        }
    }
    return STATUS_SUCCESS;
}
