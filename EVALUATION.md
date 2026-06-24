# Running the SENTINEL-X Evaluation

## Linux (Kali VM)
```bash
cd evaluation/
sudo bash run_linux_eval.sh
python3 analyze_results.py
```

## Windows VM
```powershell
# As Administrator:
powershell -ExecutionPolicy Bypass -File evaluation\run_windows_eval.ps1
```

## University requirement: 100 runs
Both scripts default to 100 runs per stage. Results auto-saved with timestamps.
LaTeX table generated automatically for paper insertion.
