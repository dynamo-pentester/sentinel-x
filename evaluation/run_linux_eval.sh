#!/usr/bin/env bash
# ============================================================
# SENTINEL-X Linux Evaluation  v15
# ============================================================
# Uses timestamp-based dmesg polling — immune to ring buffer wrap.
#
# Usage:
#   sudo bash run_linux_eval.sh [OPTIONS]
#
# Options:
#   --stages  1,3,9   Comma-separated stages 1-9 (default: all)
#   --runs    100     Runs per stage (default: 100)
#   --timeout 15      Seconds per detection window (default: 15)
#   --help
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SENTINELX_KO="$ROOT/sentinelx/sentinelx.ko"
ROOTKIT_KO="$ROOT/rootkit-test/sentinel_test_rootkit.ko"
RESULTS_BASE="$SCRIPT_DIR/results"

RUNS=100
DETECT_TIMEOUT=15
RESTORE_TIMEOUT=10
SELECTED_STAGES=(1 2 3 4 5 6 7 8 9)
SCAN_PERIOD_S=3

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'
BLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --stages|-s) IFS=',' read -ra SELECTED_STAGES <<< "$2"; shift 2 ;;
        --runs|-n)   RUNS="$2"; shift 2 ;;
        --timeout|-t) DETECT_TIMEOUT="$2"; shift 2 ;;
        --help|-h) sed -n '4,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "Unknown: $1" ;;
    esac
done

[[ $EUID -ne 0 ]]      && die "Run as root"
[[ -f "$SENTINELX_KO" ]] || die "Not found: $SENTINELX_KO"
[[ -f "$ROOTKIT_KO"   ]] || die "Not found: $ROOTKIT_KO"

mkdir -p "$RESULTS_BASE"
TS=$(date +%Y%m%d_%H%M%S)
OUT="$RESULTS_BASE/eval_${TS}"
mkdir -p "$OUT"
CSV="$OUT/eval.csv"
echo "stage,run,attack_ns,detect_ns,latency_ms,detected" > "$CSV"

# ── dmesg polling helpers (timestamp-based, survives ring buffer wrap) ────────
dmesg_mark() {
    # Returns the kernel timestamp of the latest dmesg line, e.g. "12345.678901"
    dmesg 2>/dev/null \
        | grep -oP '(?<=\[)\s*[\d.]+(?=\])' \
        | tail -1 \
        | tr -d ' ' \
        || echo "0"
}

dmesg_since() {
    local since_ts=$1 pattern=$2
    dmesg 2>/dev/null | awk -v ts="$since_ts" '
        match($0, /^\[\s*([0-9]+\.[0-9]+)\]/, a) { if (a[1]+0 > ts+0) print }
    ' | grep -qE "$pattern"
}

# ── Per-stage patterns ────────────────────────────────────────────────────────
alert_for() {
    case $1 in
        1) echo '\[SCT HOOK\]' ;;
        2) echo '\[CR0 ALERT\]' ;;
        3) echo '\[LSTAR' ;;
        4) echo '\[CHANGE.*HOOK PATTERN\]' ;;
        5) echo '\[MODULE HIDDEN\]' ;;
        6) echo '\[PRIVESC\]' ;;
        7) echo '\[NF HOOK\]' ;;
        8) echo '\[FTRACE HOOK\]' ;;
        9) echo '\[DKOM ALERT\]' ;;
    esac
}

has_restore() { case $1 in 1|2|3|4|5) return 0 ;; *) return 1 ;; esac; }

restore_for() {
    case $1 in
        1) echo '\[SCT RESTORED\]' ;;
        2) echo '\[CR0 RESTORED\]' ;;
        3) echo '\[LSTAR RESTORED\]' ;;
        4) echo '\[RESTORED\]' ;;
        5) echo '\[MODULE RESTORED\]' ;;
    esac
}

declare -A S_NAME=([1]="SCT Hook" [2]="CR0 Tamper" [3]="LSTAR Tamper"
                   [4]="Prologue Hook" [5]="Module Hide" [6]="Privesc"
                   [7]="Netfilter Hook" [8]="Ftrace Hook" [9]="DKOM")

# ── Module helpers ────────────────────────────────────────────────────────────
ks_loaded()  { lsmod 2>/dev/null | grep -q '^sentinelx '; }
rkt_loaded() { lsmod 2>/dev/null | grep -q '^sentinel_test_rootkit '; }

load_sentinelx() {
    rkt_loaded && rmmod sentinel_test_rootkit 2>/dev/null || true
    ks_loaded  && rmmod sentinelx             2>/dev/null || true
    sleep 1
    insmod "$SENTINELX_KO" anti_unload=0 || die "insmod sentinelx failed"

    local period_ms=2000
    [[ -f /sys/module/sentinelx/parameters/period_ms ]] \
        && period_ms=$(cat /sys/module/sentinelx/parameters/period_ms)
    SCAN_PERIOD_S=$(( (period_ms + 999) / 1000 ))

    local settle=$(( SCAN_PERIOD_S + 3 ))
    log "sentinelx loaded (period=${period_ms}ms) — settling ${settle}s"
    sleep "$settle"
}

unload_sentinelx() {
    ks_loaded && { rmmod sentinelx 2>/dev/null || true; sleep 1; }
}

# ── Single trial ─────────────────────────────────────────────────────────────
run_trial() {
    local stage=$1 run=$2
    local detected=0 detect_ns=0 latency="0.00"
    local alert_re; alert_re=$(alert_for "$stage")

    # Snapshot latest dmesg timestamp BEFORE insmod
    local pre_ts; pre_ts=$(dmesg_mark)

    local extra_pre=0
    [[ $stage -eq 9 ]] && extra_pre=$(( SCAN_PERIOD_S + 3 ))
    [[ $stage -eq 3 ]] && extra_pre=$SCAN_PERIOD_S

    # Load rootkit
    rkt_loaded && rmmod sentinel_test_rootkit 2>/dev/null || true
    sleep 0.2
    if ! insmod "$ROOTKIT_KO" stage="$stage" 2>/dev/null; then
        warn "S$stage R$run: insmod failed"
        echo "$stage,$run,0,0,0,0" >> "$CSV"
        printf "  S%s R%03d/%d: ${RED}MISS${NC} (insmod)\n" "$stage" "$run" "$RUNS"
        return
    fi
    local attack_ns; attack_ns=$(date +%s%N)

    [[ $extra_pre -gt 0 ]] && sleep "$extra_pre"

    # Poll for detection using timestamp comparison — never affected by wrap
    local deadline=$(( attack_ns + DETECT_TIMEOUT * 1000000000 ))
    while true; do
        local now; now=$(date +%s%N)
        if dmesg_since "$pre_ts" "$alert_re"; then
            detect_ns=$now; detected=1; break
        fi
        [[ $now -ge $deadline ]] && break
        sleep 0.1
    done

    if [[ $detected -eq 1 ]]; then
        local diff=$(( detect_ns - attack_ns ))
        latency=$(echo "scale=2; $diff / 1000000" | bc)
    fi

    # Snapshot timestamp after detection, before rmmod
    local post_ts; post_ts=$(dmesg_mark)

    # Unload rootkit
    if ! rmmod sentinel_test_rootkit 2>/dev/null; then
        warn "S$stage R$run: rmmod failed — reloading sentinelx"
        unload_sentinelx; sleep 1
        rmmod sentinel_test_rootkit 2>/dev/null || true
        load_sentinelx
    fi

    # Wait for RESTORED or fixed settle
    if has_restore "$stage"; then
        local restore_re; restore_re=$(restore_for "$stage")
        local rdeadline=$(( $(date +%s%N) + RESTORE_TIMEOUT * 1000000000 ))
        local restored=0
        while true; do
            dmesg_since "$post_ts" "$restore_re" && { restored=1; break; }
            [[ $(date +%s%N) -ge $rdeadline ]] && break
            sleep 0.2
        done
        [[ $restored -eq 0 ]] && sleep "$SCAN_PERIOD_S"
    else
        sleep $(( SCAN_PERIOD_S + 1 ))
    fi

    echo "$stage,$run,$attack_ns,$detect_ns,$latency,$detected" >> "$CSV"

    if [[ $detected -eq 1 ]]; then
        printf "  S%s R%03d/%d: ${GRN}DETECTED${NC} (%sms)\n" "$stage" "$run" "$RUNS" "$latency"
    else
        printf "  S%s R%03d/%d: ${RED}MISSED${NC}\n" "$stage" "$run" "$RUNS"
        ks_loaded || { warn "sentinelx gone — reloading"; load_sentinelx; }
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────
generate_summary() {
    log "Summary..."
    python3 -u - "$CSV" "$OUT" << 'PYEOF'
import csv, sys, math, json, os
from collections import defaultdict

csv_path, out_dir = sys.argv[1], sys.argv[2]
with open(csv_path) as f:
    rows = list(csv.DictReader(f))

stages = defaultdict(list)
for r in rows:
    stages[r['stage']].append(r)

NAMES = {'1':'SCT Hook','2':'CR0 Tamper','3':'LSTAR Tamper',
         '4':'Prologue Hook','5':'Module Hide','6':'Privesc',
         '7':'Netfilter Hook','8':'Ftrace Hook','9':'DKOM'}

def pct(d,p):
    if not d: return 0.0
    s=sorted(d); k=(len(s)-1)*p/100; lo,hi=int(k),min(int(k)+1,len(s)-1)
    return s[lo]+(s[hi]-s[lo])*(k-lo)

lines=['='*64,'SENTINEL-X LINUX EVALUATION RESULTS','='*64]
jout=[]; all_tp=[]

for s in sorted(stages,key=int):
    data=stages[s]; det=[r for r in data if r['detected']=='1']
    lats=[float(r['latency_ms']) for r in det if float(r['latency_ms'])>0]
    tp=len(det)/len(data)*100 if data else 0; all_tp.append(tp)
    mean=sum(lats)/len(lats) if lats else 0
    std=math.sqrt(sum((x-mean)**2 for x in lats)/len(lats)) if len(lats)>1 else 0
    lines+=[f'\nStage {s} — {NAMES.get(s,s)}',
            f'  Runs           : {len(data)}',
            f'  True Positives : {len(det)} / {len(data)}  ({tp:.1f}%)',
            f'  Misses         : {len(data)-len(det)}']
    if lats:
        lines+=[f'  Mean latency   : {mean:.1f} ms',
                f'  Std (σ)        : {std:.1f} ms',
                f'  Median (p50)   : {pct(lats,50):.1f} ms',
                f'  p95            : {pct(lats,95):.1f} ms',
                f'  Min / Max      : {min(lats):.1f} / {max(lats):.1f} ms']
    else:
        lines.append('  Latency        : N/A (no detections)')
    jout.append({'stage':int(s),'name':NAMES.get(s,s),'total':len(data),
                 'detected':len(det),'tp_pct':round(tp,2),
                 'mean_ms':round(mean,2),'std_ms':round(std,2),
                 'p50_ms':round(pct(lats,50),2),'p95_ms':round(pct(lats,95),2)})

ov=sum(all_tp)/len(all_tp) if all_tp else 0
lines+=['','='*64,f'Overall detection rate : {ov:.1f}%','='*64]
report='\n'.join(lines); print(report)
with open(os.path.join(out_dir,'summary.txt'),'w') as f: f.write(report+'\n')
with open(os.path.join(out_dir,'summary.json'),'w') as f:
    json.dump({'stages':jout,'overall_tp_pct':round(ov,2)},f,indent=2)
print(f'\nSaved: {out_dir}/')
PYEOF
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    rkt_loaded && rmmod sentinel_test_rootkit 2>/dev/null || true
    ks_loaded  && rmmod sentinelx             2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Main ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}SENTINEL-X Linux Evaluation v15${NC}"
printf "  Stages : %s\n  Runs   : %s\n  Timeout: %ss\n  Output : %s\n\n" \
    "${SELECTED_STAGES[*]}" "$RUNS" "$DETECT_TIMEOUT" "$OUT"

# Clear ring buffer at start so timestamps are fresh
dmesg --clear 2>/dev/null || true

load_sentinelx

total_s=${#SELECTED_STAGES[@]}; done_s=0

for stage in "${SELECTED_STAGES[@]}"; do
    done_s=$(( done_s + 1 ))
    log "=== Stage $stage — ${S_NAME[$stage]} [$done_s/$total_s] — $RUNS runs ==="
    for run in $(seq 1 "$RUNS"); do
        run_trial "$stage" "$run"
    done
    if [[ $done_s -lt $total_s ]]; then
        log "Reloading sentinelx between stages..."
        unload_sentinelx; sleep 1; load_sentinelx
    fi
done

unload_sentinelx
echo ""; generate_summary
log "Done."
