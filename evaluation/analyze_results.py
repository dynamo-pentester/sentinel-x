#!/usr/bin/env python3
"""
SENTINEL-X Results Analyzer
Reads CSV from Linux or Windows eval scripts and produces:
  - Per-stage statistics table (IEEE paper ready)
  - Detection latency distribution
  - Overall accuracy summary
  - LaTeX table output

Usage:
    python3 analyze_results.py results/eval_TIMESTAMP.csv
    python3 analyze_results.py --demo   # generates synthetic demo data
"""

import sys, csv, os, math, argparse
from collections import defaultdict

# ── Event type labels ─────────────────────────────────────────────────────
STAGE_LABELS = {
    1: "SCT Hook (NtYieldExecution)",
    2: "DKOM (Process Hiding)",
    3: "Driver Hiding (PE Unlink)",
    4: "CR0 Tamper",
    5: "LSTAR Tamper",
    6: "LKM Hiding",
    7: "Prologue Hook",
    8: "Netfilter Hook",
    9: "Ftrace Hook",
}

def mean(vals): return sum(vals) / len(vals) if vals else 0
def std(vals):
    if len(vals) < 2: return 0
    m = mean(vals)
    return math.sqrt(sum((x-m)**2 for x in vals) / len(vals))

def load_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))

def generate_demo_data():
    """Generate synthetic demo data for testing the analyzer."""
    import random, time
    rows = []
    random.seed(42)
    for stage in [1,2,3]:
        for run in range(1, 101):
            # Simulate realistic detection latencies (5-12s for 10s scan interval)
            if random.random() < 0.98:  # 98% detection rate
                latency = random.gauss(7500, 1200)  # ~7.5s mean
                latency = max(500, min(12000, latency))
                detected = 1
            else:
                latency = 0
                detected = 0
            rows.append({
                'stage': str(stage), 'run': str(run),
                'attack_time_ms': '0', 'detect_time_ms': '0',
                'latency_ms': str(round(latency, 1)), 'detected': str(detected)
            })
    return rows

def analyze(rows, output_prefix=None):
    stages = defaultdict(list)
    for r in rows:
        stages[r['stage']].append(r)

    print("=" * 70)
    print("SENTINEL-X EVALUATION RESULTS")
    print("=" * 70)

    all_stats = []
    for stage_key in sorted(stages.keys(), key=lambda x: int(x)):
        data  = stages[stage_key]
        total = len(data)
        stage_int = int(stage_key)
        label = STAGE_LABELS.get(stage_int, f"Stage {stage_key}")

        detected  = [r for r in data if r['detected'] == '1']
        latencies = [float(r['latency_ms']) for r in detected
                     if float(r['latency_ms']) > 0]

        tp = len(detected)
        fn = total - tp
        tp_rate = tp / total * 100 if total > 0 else 0
        m   = mean(latencies)
        s   = std(latencies)
        mn  = min(latencies) if latencies else 0
        mx  = max(latencies) if latencies else 0

        all_stats.append({
            'stage': stage_key, 'label': label, 'total': total,
            'tp': tp, 'fn': fn, 'tp_rate': tp_rate,
            'mean': m, 'std': s, 'min': mn, 'max': mx
        })

        print(f"\nStage {stage_key} — {label}")
        print(f"  Runs            : {total}")
        print(f"  Detected (TP)   : {tp} ({tp_rate:.1f}%)")
        print(f"  Missed   (FN)   : {fn}")
        print(f"  Latency mean    : {m/1000:.2f}s ± {s/1000:.2f}s")
        print(f"  Latency range   : {mn/1000:.2f}s – {mx/1000:.2f}s")

    # Overall
    total_runs  = sum(s['total'] for s in all_stats)
    total_tp    = sum(s['tp']    for s in all_stats)
    overall_tpr = total_tp / total_runs * 100 if total_runs > 0 else 0
    all_lat     = []
    for stage_key in stages:
        data = stages[stage_key]
        all_lat += [float(r['latency_ms']) for r in data
                    if r['detected']=='1' and float(r['latency_ms'])>0]

    print("\n" + "=" * 70)
    print("OVERALL")
    print(f"  Total runs      : {total_runs}")
    print(f"  True positives  : {total_tp} ({overall_tpr:.1f}%)")
    print(f"  Overall latency : {mean(all_lat)/1000:.2f}s ± {std(all_lat)/1000:.2f}s")
    print("=" * 70)

    # LaTeX table
    latex = generate_latex(all_stats)
    print("\n--- LaTeX Table (paste into paper) ---")
    print(latex)

    if output_prefix:
        with open(f"{output_prefix}_summary.txt", "w") as f:
            f.write(f"Overall TPR: {overall_tpr:.1f}%\n")
            f.write(f"Overall latency: {mean(all_lat)/1000:.2f}s ± {std(all_lat)/1000:.2f}s\n")
        with open(f"{output_prefix}_latex.tex", "w") as f:
            f.write(latex)
        print(f"\nSaved: {output_prefix}_summary.txt, {output_prefix}_latex.tex")

def generate_latex(stats):
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{SENTINEL-X Detection Performance (100 runs per stage)}",
        r"\label{tab:eval}",
        r"\begin{tabular}{llccc}",
        r"\hline",
        r"\textbf{Stage} & \textbf{Technique} & \textbf{TPR (\%)} & "
        r"\textbf{Mean Latency (s)} & \textbf{Std (s)} \\",
        r"\hline",
    ]
    for s in stats:
        label = s['label'].replace('&', r'\&')
        lines.append(
            f"{s['stage']} & {label} & {s['tp_rate']:.1f} & "
            f"{s['mean']/1000:.2f} & {s['std']/1000:.2f} \\\\"
        )
    lines += [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", nargs="?", help="Path to eval CSV")
    parser.add_argument("--demo", action="store_true", help="Run with synthetic demo data")
    parser.add_argument("--output", default=None, help="Output file prefix")
    args = parser.parse_args()

    if args.demo:
        print("[DEMO MODE] Using synthetic data")
        rows = generate_demo_data()
    elif args.csv_file:
        if not os.path.exists(args.csv_file):
            print(f"File not found: {args.csv_file}"); sys.exit(1)
        rows = load_csv(args.csv_file)
    else:
        # Auto-find latest CSV in results/
        results_dir = "./results"
        if os.path.exists(results_dir):
            csvs = sorted([f for f in os.listdir(results_dir) if f.endswith('.csv')])
            if csvs:
                path = os.path.join(results_dir, csvs[-1])
                print(f"Auto-loading: {path}")
                rows = load_csv(path)
            else:
                print("No CSV files found. Run eval first or use --demo")
                sys.exit(1)
        else:
            print("No results directory. Run eval first or use --demo")
            sys.exit(1)

    analyze(rows, args.output)

if __name__ == "__main__":
    main()
