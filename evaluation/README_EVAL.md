# SENTINEL-X Evaluation Scripts

## Linux (100 runs per stage)

```bash
cd evaluation/
sudo bash run_linux_eval.sh
```

Results saved to `results/eval_TIMESTAMP.csv`

## Windows (100 runs per stage)

Open PowerShell as Administrator:

```powershell
cd evaluation\
powershell -ExecutionPolicy Bypass -File run_windows_eval.ps1 -Runs 100 -Stage "1,3"
```

For stage 2 you need TargetPid set (notepad.exe PID):
```powershell
# First open notepad, find PID in Task Manager, then:
powershell -ExecutionPolicy Bypass -File run_windows_eval.ps1 -Runs 100 -Stage "2"
# Script will prompt; or pre-set in registry:
# reg add "HKLM\...\sentinel_test\Parameters" /v TargetPid /t REG_DWORD /d <PID> /f
```

## Analyze Results

```bash
# Auto-load latest CSV:
python3 analyze_results.py

# Specific file:
python3 analyze_results.py results/eval_20240101_120000.csv

# Demo mode (synthetic data):
python3 analyze_results.py --demo

# Save LaTeX table + summary:
python3 analyze_results.py --output results/paper_table
```

## Output Format (CSV)
```
stage, run, attack_time_ms, detect_time_ms, latency_ms, detected
1, 1, 1711234567890, 1711234575123, 7233, 1
```

## What Gets Measured
- **True Positive Rate** — % of attacks detected
- **Detection Latency** — mean ± std, min/max (ms and seconds)
- **False Negative Rate** — missed detections
- **LaTeX table** — ready to paste into IEEE paper

## Expected Results (Linux, 10s scan interval)
| Stage | Technique | Expected TPR | Expected Latency |
|-------|-----------|-------------|-----------------|
| 1 | SCT hooks | ~100% | 5-10s |
| 2 | DKOM | ~100% | 5-10s |
| 3 | Module hiding | ~100% | 5-10s |
| 6 | LKM hiding | ~100% | 5-10s |

Latency is bounded by the scan interval (10s worst-case, ~5s average).
