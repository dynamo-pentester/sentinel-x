# SENTINEL-X

**Cross-Platform Kernel Integrity Monitor with Blockchain-Anchored Forensic Evidence**

> Research prototype — Ramco Institute of Technology, Dept. of CSE  
> Paper: *SENTINEL-X: A Cross-Platform Kernel Integrity Monitor with Verifiable Blockchain-Anchored Forensic Evidence* (under review)

---

## What it does

Kernel rootkits operating at Ring-0 defeat conventional scanners through a simple race: install, operate, and remove artefacts within one scan interval. SENTINEL-X closes this race with a **dual-layer architecture**:

- **Synchronous layer** — kprobe/kretprobe handlers fire on the first offending kernel function invocation, independent of any timer. Detection latency: **< 5 ms** (p95) for four attack classes.
- **Periodic layer** — `guard_tick()` enforces nine structural kernel invariants on a 2-second cycle, covering attacks that require observation over time.
- **Evidence pipeline** — every detection is ECDSA-P256 signed, AES-256-GCM encrypted, Merkle-batched, and anchored to an Ethereum Sepolia smart contract for tamper-evident third-party audit.

**Evaluation results (n=100 trials per stage):** 100% true-positive rate across all 9 Linux attack stages and 2 Windows stages. False-positive rate: 2.0%, confined to a documented `do_task_dead()` kernel-thread exit path.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL SPACE (Ring 0)                                          │
│                                                                 │
│  sentinelx.ko (Linux, kernel 6.18)                             │
│    Periodic layer:  guard_tick() every 2s                       │
│      SCT baseline diff, CR0 read, LSTAR rdmsr,                 │
│      FNV-1a prologue hash, task-list walk (DKOM)               │
│    Synchronous layer: kprobe / kretprobe                        │
│      commit_creds, nf_register_*, register_ftrace_*,           │
│      do_init_module, wake_up_new_task, do_exit                 │
│                                                                 │
│  ksentinel.sys (Windows 10 x64, KMDF)                          │
│    SSDT scanner: 489 entries vs ntoskrnl bounds                │
│    PE image scanner: MZ/PE walk across 1,927 MB                │
└──────────────┬──────────────────────────────────────────────────┘
               │ /dev/kmsg  (Linux)
               │ IOCTL_READ_EVENT  (Windows)
┌──────────────▼──────────────────────────────────────────────────┐
│  USER SPACE                                                     │
│  sentinel_daemon.py                                             │
│    LinuxBridge / WindowsBridge → event_parser.py               │
│    → evidence_manager.py                                        │
│         ECDSA-P256 sign → AES-256-GCM encrypt                  │
│         → SHA-256 Merkle tree (batch=32)                       │
│         → Ethereum Sepolia smart contract anchor               │
│    → SQLite (sentinel.db)                                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Coverage

### Linux (kernel 6.18)

| Stage | Attack | Method | Layer | Mean latency |
|-------|--------|--------|-------|-------------|
| S1 | SCT Hook | Baseline diff | Periodic | 1,651 ms |
| S2 | CR0 WP Tamper | Per-CPU `read_cr0()` | Periodic | 1,699 ms |
| S3 | LSTAR Tamper | `rdmsr(MSR_LSTAR)` | Periodic | 2,035 ms |
| S4 | Prologue Hook | FNV-1a hash | Periodic | 1,675 ms |
| S5 | Module Hide | kretprobe on `do_init_module` | Sync | 137 ms |
| S6 | Priv. Escalation | kprobe on `commit_creds` | Sync | 2.5 ms |
| S7 | Netfilter Hook | kprobe on `nf_register_*` | Sync | 3.0 ms |
| S8 | ftrace Hook | kprobe on `register_ftrace_*` | Sync | 3.7 ms |
| S9 | DKOM | kprobe + periodic poll | Hybrid | 5,096 ms |

### Windows (10 x64, 22H2)

| Stage | Attack | Method | Mean latency |
|-------|--------|--------|-------------|
| W1 | SSDT Hook (NtYieldExecution) | SSDT entry bounds check | 9,811 ms |
| W2 | DKOM via ZwQSI hook | SSDT scanner | Verified† |
| W3 | Driver Hide (PsLoadedModuleList unlink) | PE image scan | 5,836 ms |

† W2 triggers a PatchGuard bugcheck (0x109) before the eval harness can record latency. Detection confirmed via post-reboot WAL recovery from `sentinel.db`.

---

## Repository Structure

```
sentinel-x/
├── sentinelx/               # Linux LKM source (sentinelx.c, Makefile)
├── sentinelx-windows/       # Windows KMDF driver (driver.c, dkom.c, ssdt.c)
├── rootkit-test/            # Linux test rootkit (sentinel_test_rootkit.c)
├── sentinel-test-windows/   # Windows test driver (sentinel_test_win.c)
├── bridge/                  # OS bridge layer
│   ├── linux_bridge.py      # /dev/kmsg reader
│   ├── windows_bridge.py    # IOCTL_READ_EVENT poller
│   ├── event_parser.py      # KernelEvent schema parser
│   └── os_detector.py
├── src/                     # Evidence pipeline
│   ├── evidence_manager.py  # Sign + encrypt + Merkle + anchor
│   ├── crypto_utils.py      # ECDSA-P256, AES-256-GCM, HKDF
│   ├── db_utils.py          # SQLite schema and queries
│   ├── merkle_utils.py      # SHA-256 Merkle tree
│   └── web3_utils.py        # Sepolia Web3 + contract interaction
├── evaluation/              # Eval scripts and results
│   ├── run_linux_eval.sh
│   ├── run_windows_eval.ps1
│   ├── analyze_results.py
│   └── results/             # CSV + summary files per stage
├── sentinel_daemon.py       # Unified daemon (Linux + Windows)
├── deploy_contract.py       # MILBASTERLog Solidity contract deploy
├── check.py                 # Blockchain verification tool
├── setup.sh                 # Automated setup (Ubuntu/Kali)
├── MILBASTERLog_abi.json    # Smart contract ABI
├── .env.example             # Config template
└── requirements.txt
```

---

## Quick Start

### Prerequisites

- **Linux:** Kali 2025 / Ubuntu 24.04, kernel 6.17–6.18, kernel headers, Python 3.10+
- **Windows:** Windows 10 x64 (22H2), WDK, test-signing enabled, VirtualBox recommended

### Linux Setup

```bash
# 1. Clone and install Python dependencies
git clone https://github.com/dynamo-pentester/sentinel-x.git
cd sentinel-x
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — add your Infura/Alchemy RPC URL and Ethereum key

# 3. Build the LKM
cd sentinelx
make
cd ..

# 4. Load the monitor
sudo insmod sentinelx/sentinelx.ko

# 5. Start the daemon
sudo python3 sentinel_daemon.py

# Watch alerts in real time (separate terminal)
sudo dmesg -w | grep sentinelx
```

### Windows Setup

See [`sentinelx-windows/README_BUILD.txt`](sentinelx-windows/README_BUILD.txt) for driver build instructions.

Run the daemon as Administrator:
```powershell
python sentinel_daemon.py
```

### Verify blockchain anchoring

```bash
python3 check.py
```

---

## Running the Evaluation

### Linux (100 runs per stage, all stages)

```bash
cd evaluation/
sudo bash run_linux_eval.sh
python3 analyze_results.py          # generates LaTeX table + summary
```

### Windows (stages 1 and 3 — automated)

```powershell
# As Administrator:
powershell -ExecutionPolicy Bypass -File evaluation\run_windows_eval.ps1 -Runs 100 -Stage "1,3"
```

### Windows Stage W2 (manual)

W2 hooks `ZwQuerySystemInformation` to hide a target PID. PatchGuard detects the SSDT corruption and issues bugcheck 0x109, terminating the VM before the eval harness can record latency. Run it manually:

```powershell
# Open notepad, note its PID, then:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sentinel_test\Parameters" /v TargetPid /t REG_DWORD /d <PID> /f
powershell -ExecutionPolicy Bypass -File evaluation\run_windows_eval.ps1 -Runs 1 -Stage "2"
# Detection recoverable from sentinel.db WAL after reboot
```

---

## Evidence Pipeline

Each detected event follows Algorithm 1 from the paper:

```
event_json  →  ECDSA-P256 sign  →  AES-256-GCM encrypt
            →  SHA-256 leaf hash  →  Merkle tree (batch 32)
            →  Sepolia smart contract anchor (root hash)
            →  SQLite persist (encrypted blob + proof)
```

Any third party can verify a record without accessing raw data by recomputing the Merkle inclusion path from the stored leaf hash and checking the root against the on-chain anchor.

---

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `SENTINEL_NODE_ID` | Node identifier for evidence signing |
| `INFURA_SEPOLIA_URL` | Alchemy/Infura Sepolia RPC endpoint |
| `PRIVATE_KEY` | Ethereum wallet private key (hex, no 0x) |
| `ACCOUNT` | Ethereum wallet address |
| `CONTRACT_ADDR` | Deployed MILBASTERLog contract address |
| `ANCHOR_BATCH_SIZE` | Events per Merkle batch (default: 32) |
| `ANCHOR_INTERVAL` | Anchor worker interval in seconds (default: 60) |

**Never commit `.env` or `keystore/*_priv.pem` to version control.**

---

## Limitations

- **DKOM false positives (2.0%):** `do_task_dead()` bypasses the `do_exit` kprobe. Fix (kprobe on `do_task_dead` with PID-namespace cross-referencing) is in progress.
- **Scan-cycle inflation under load:** `guard_tick()` iterates 595 symbols; under VirtualBox CPU contention the effective cycle can reach 22–27 s. Splitting the watchlist into smaller scheduled work items is planned.
- **Data-only sub-interval attacks:** An attack that modifies kernel data structures without invoking any kprobe-instrumented function and completes before the next periodic tick evades both layers. This is a fundamental constraint shared by all software-only kernel monitors.
- **Self-targeting adversary:** A Ring-0 adversary who patches SENTINEL-X's own kprobe handler memory can disable detection. Outside the stated threat model.

---

## Security Notice

The test rootkits (`rootkit-test/`, `sentinel-test-windows/`) are included **solely for evaluation purposes**. They run exclusively in isolated VMs with test signing enabled and are not intended for deployment on production systems. The Linux test rootkit is fully reversible via `rmmod`.

---

## Acknowledgements

Thanks to [MatheuZSecurity](https://github.com/MatheuZSecurity), founder of the Rootkit Researchers community and developer of the original Kernel Sentinel prototype, whose public work on kernel instrumentation techniques provided the architectural foundation for this system.

---

## License

Research prototype. See LICENSE for terms.

---

## Citation

```bibtex
@article{rishikesh2026sentinelx,
  title   = {{SENTINEL-X}: A Cross-Platform Kernel Integrity Monitor
             with Verifiable Blockchain-Anchored Forensic Evidence},
  author  = {Rishikesh, R},
  journal = {(under review)},
  year    = {2026}
}
```
