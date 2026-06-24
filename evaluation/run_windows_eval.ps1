# ============================================================
# SENTINEL-X Windows Evaluation Script v3
# Reads directly from \\.\SentinelX via DeviceIoControl.
#
# v3 fixes:
#   BUG 1: g_hooked[] in ssdt.c persists between runs.
#     FIX: WaitForRestored() polls for [SCT RESTORED] after each
#     rootkit unload — proves sentinelx reset g_hooked[]=FALSE.
#
#   BUG 2: Same for Stage 3 with g_hiddenBases[].
#     FIX: WaitForRestored() polls for [MODULE RESTORED].
#
#   BUG 3: On MISSED, g_hooked[] stays stale.
#     FIX: On MISSED, wait 12s so a scan fires and resets state.
#
# Usage (run as Administrator):
#   powershell -ExecutionPolicy Bypass -File run_windows_eval.ps1
#   powershell -ExecutionPolicy Bypass -File run_windows_eval.ps1 -Runs 100 -Stage "1,3"
# ============================================================

param(
    [int]    $Runs           = 100,
    [int]    $ScanTimeout    = 25,
    [int]    $RestoreTimeout = 15,
    [string] $Stage          = "1,3"
)

$ErrorActionPreference = "Continue"

# ── EDIT THESE PATHS IF NEEDED ────────────────────────────────────────────
$SENTINELX_SYS = "C:\Users\vboxuser\source\repos\sentinel-x\x64\Debug\sentinel-x.sys"
$TEST_SYS      = "C:\Users\vboxuser\source\repos\sentinel-x\x64\Debug\sentinel_test.sys"
# ─────────────────────────────────────────────────────────────────────────

$RESULTS_DIR  = ".\results"
$TIMESTAMP    = Get-Date -Format "yyyyMMdd_HHmmss"
$RESULTS_CSV  = "$RESULTS_DIR\eval_$TIMESTAMP.csv"

New-Item -ItemType Directory -Force -Path $RESULTS_DIR | Out-Null

function Log($msg)  { Write-Host "[+] $msg" -ForegroundColor Cyan }
function Good($msg) { Write-Host "    $msg"  -ForegroundColor Green }
function Bad($msg)  { Write-Host "    $msg"  -ForegroundColor Red }
function Warn($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }

# ── P/Invoke: DeviceIoControl ─────────────────────────────────────────────
$code = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class SentinelX {
    public const uint IOCTL_READ_EVENT  = 0x80006000u;
    public const uint IOCTL_FLUSH_QUEUE = 0x80006404u;
    public const int  EVENT_SIZE        = 528;

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static IntPtr Open() {
        return CreateFile(@"\\.\SentinelX", 0x80000000u, 0,
            IntPtr.Zero, 3, 0, IntPtr.Zero);
    }

    public static string ReadEvent(IntPtr handle) {
        byte[]   buf = new byte[EVENT_SIZE];
        uint     br  = 0;
        GCHandle pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
        try {
            bool ok = DeviceIoControl(handle, IOCTL_READ_EVENT,
                IntPtr.Zero, 0, pin.AddrOfPinnedObject(),
                (uint)buf.Length, out br, IntPtr.Zero);
            if (!ok || br < 16) return null;
            string msg = Encoding.Unicode.GetString(buf, 16, 512).TrimEnd('\0');
            return (msg.Length > 0) ? msg : null;
        } finally { pin.Free(); }
    }

    public static void Flush(IntPtr handle) {
        uint br = 0;
        DeviceIoControl(handle, IOCTL_FLUSH_QUEUE,
            IntPtr.Zero, 0, IntPtr.Zero, 0, out br, IntPtr.Zero);
    }
}
'@
Add-Type -TypeDefinition $code -Language CSharp 2>$null

# ── Driver management ─────────────────────────────────────────────────────
function Load-SentinelX {
    sc.exe stop   sentinelx 2>$null | Out-Null
    sc.exe delete sentinelx 2>$null | Out-Null
    Start-Sleep -Milliseconds 1500
    $binPath = (Resolve-Path $SENTINELX_SYS).Path
    sc.exe create sentinelx type= kernel binPath= $binPath | Out-Null
    sc.exe start sentinelx | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    Start-Sleep -Milliseconds 2000
    Log "sentinelx loaded"
    return $true
}
function Unload-SentinelX {
    sc.exe stop   sentinelx 2>$null | Out-Null
    sc.exe delete sentinelx 2>$null | Out-Null
}
function Load-Rootkit($stage) {
    sc.exe stop   sentinel_test 2>$null | Out-Null
    sc.exe delete sentinel_test 2>$null | Out-Null
    Start-Sleep -Milliseconds 600
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\sentinel_test\Parameters" `
        /v Stage /t REG_DWORD /d $stage /f 2>$null | Out-Null
    $binPath = (Resolve-Path $TEST_SYS).Path
    sc.exe create sentinel_test type= kernel binPath= $binPath | Out-Null
    sc.exe start sentinel_test 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function Unload-Rootkit {
    sc.exe stop   sentinel_test 2>$null | Out-Null
    sc.exe delete sentinel_test 2>$null | Out-Null
    Start-Sleep -Milliseconds 600
}

# ── Event matching ─────────────────────────────────────────────────────────
function IsAttackEvent($msg, $stage) {
    if ($null -eq $msg) { return $false }
    switch ($stage) {
        1       { return ($msg -match "SCT HOOK|SSDT HOOK") }
        3       { return ($msg -match "MODULE HIDDEN|PE image") }
        default { return ($msg -match "SCT HOOK|DKOM ALERT|MODULE HIDDEN") }
    }
}
function IsRestoredEvent($msg, $stage) {
    if ($null -eq $msg) { return $false }
    switch ($stage) {
        1       { return ($msg -match "SCT RESTORED") }
        3       { return ($msg -match "MODULE RESTORED") }
        default { return ($msg -match "RESTORED") }
    }
}

# ── WaitForRestored ────────────────────────────────────────────────────────
function WaitForRestored($stage, $handle, $timeoutSec) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($timeoutSec)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $msg = [SentinelX]::ReadEvent($handle)
            if (IsRestoredEvent $msg $stage) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 200
    }
    return $false
}

# ── Single trial ───────────────────────────────────────────────────────────
function Run-Trial($stage, $run, $handle) {
    [SentinelX]::Flush($handle)
    Start-Sleep -Milliseconds 200

    $attackMs  = [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    $detected  = $false
    $detectMs  = 0L
    $latencyMs = 0L

    $loaded = Load-Rootkit $stage
    if (-not $loaded) {
        Bad ("Stage $stage Run {0:D3}: rootkit load FAILED" -f $run)
        "$stage,$run,$attackMs,0,0,0" | Out-File $RESULTS_CSV -Append -Encoding utf8
        return
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ScanTimeout)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $msg = [SentinelX]::ReadEvent($handle)
            if (IsAttackEvent $msg $stage) {
                $detectMs  = [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
                $latencyMs = $detectMs - $attackMs
                $detected  = $true
                $preview   = $msg.Substring(0, [Math]::Min(70, $msg.Length))
                Good ("Stage $stage Run {0:D3}: DETECTED  {1}ms  [{2}]" -f $run, $latencyMs, $preview)
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 200
    }

    if (-not $detected) {
        Bad ("Stage $stage Run {0:D3}: MISSED (timeout={1}s)" -f $run, $ScanTimeout)
    }

    Unload-Rootkit

    # CRITICAL: wait for RESTORED event to reset g_hooked[]/g_hiddenBases[]
    $restored = WaitForRestored $stage $handle $RestoreTimeout
    if (-not $restored) {
        Warn ("Run {0:D3}: no RESTORED event in {1}s - waiting 12s for scan cycle" -f $run, $RestoreTimeout)
        Start-Sleep -Seconds 12
    }

    "$stage,$run,$attackMs,$detectMs,$latencyMs,$([int]$detected)" |
        Out-File $RESULTS_CSV -Append -Encoding utf8
}

# ── Summary ────────────────────────────────────────────────────────────────
function Compute-Summary {
    $data   = Import-Csv $RESULTS_CSV
    $groups = $data | Group-Object stage

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "   SENTINEL-X EVALUATION SUMMARY"        -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    foreach ($g in ($groups | Sort-Object Name)) {
        $rows  = $g.Group | Where-Object { $_.detected -ne "LOAD_FAILED" }
        $total = $rows.Count
        $det   = @($rows | Where-Object { $_.detected -eq '1' })
        $miss  = $total - $det.Count
        $rate  = if ($total -gt 0) { [math]::Round($det.Count/$total*100,1) } else { 0 }
        $lats  = @($det | ForEach-Object { [long]$_.latency_ms } | Where-Object { $_ -gt 0 })

        $mean=0.0; $stdev=0.0; $p50=0L; $p95=0L; $pmin=0L; $pmax=0L
        if ($lats.Count -gt 0) {
            $sorted = $lats | Sort-Object
            $mean   = [math]::Round(($lats | Measure-Object -Average).Average, 1)
            $p50    = $sorted[[int]($sorted.Count*0.50)]
            $p95    = $sorted[[int]($sorted.Count*0.95)]
            $pmin   = $sorted[0]; $pmax = $sorted[-1]
            if ($lats.Count -gt 1) {
                $sq   = $lats | ForEach-Object { [math]::Pow($_-$mean,2) }
                $var  = ($sq|Measure-Object -Sum).Sum/($lats.Count-1)
                $stdev= [math]::Round([math]::Sqrt($var),1)
            }
        }

        $label = switch ($g.Name) {
            "1" { "Stage 1 — SSDT hook (NtYieldExecution)" }
            "2" { "Stage 2 — DKOM (process hiding via ZwQSI hook)" }
            "3" { "Stage 3 — PsLoadedModuleList unlink (PE scan)" }
            default { "Stage $($g.Name)" }
        }

        Write-Host ""
        Write-Host "  $label" -ForegroundColor White
        Write-Host ("  Detection rate : {0}%  ({1}/{2} runs)" -f $rate, $det.Count, $total)
        Write-Host ("  Missed         : {0}" -f $miss)
        if ($lats.Count -gt 0) {
            Write-Host ("  Latency mean   : {0} ms  (sigma = {1} ms)" -f $mean, $stdev)
            Write-Host ("  Latency p50    : {0} ms" -f $p50)
            Write-Host ("  Latency p95    : {0} ms" -f $p95)
            Write-Host ("  Latency range  : {0} to {1} ms" -f $pmin, $pmax)
        } else {
            Write-Host "  Latency        : N/A (no detections)"
        }
    }
    Write-Host ""
    Write-Host ("  Results CSV : $RESULTS_CSV") -ForegroundColor Gray
}

# ── Main ───────────────────────────────────────────────────────────────────
Log "SENTINEL-X Windows Evaluation v3"
Log "Stages: $Stage | Runs: $Runs | ScanTimeout: ${ScanTimeout}s | RestoreTimeout: ${RestoreTimeout}s"

"stage,run,attack_time_ms,detect_time_ms,latency_ms,detected" | Out-File $RESULTS_CSV -Encoding utf8

if (-not (Load-SentinelX)) {
    Write-Host "[!] Failed to load sentinelx" -ForegroundColor Red; exit 1
}

$handle  = [SentinelX]::Open()
$INVALID = [IntPtr]::new(-1)
if ($handle -eq $INVALID -or $handle -eq [IntPtr]::Zero) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "[!] Cannot open \\.\SentinelX (Win32 error $err)" -ForegroundColor Red
    Write-Host "    Is sentinelx running? Is test-signing on?" -ForegroundColor Yellow
    Unload-SentinelX; exit 1
}
Log "Device handle open OK"

Log "Waiting 12s for first scan cycle (catalogues baseline PE images)..."
Start-Sleep -Seconds 12

try {
    $stageList = $Stage -split ',' | ForEach-Object { [int]$_.Trim() }
    foreach ($stage in $stageList) {
        Log "=== Stage $stage — $Runs runs ==="
        [SentinelX]::Flush($handle)
        for ($i = 1; $i -le $Runs; $i++) { Run-Trial $stage $i $handle }
    }
} finally {
    [SentinelX]::CloseHandle($handle) | Out-Null
    Unload-SentinelX
    Unload-Rootkit
}

Compute-Summary
Log "DONE — results in $RESULTS_CSV"
