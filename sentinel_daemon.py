#!/usr/bin/env python3
"""
sentinel_daemon.py — SENTINEL-X Unified Daemon (Linux + Windows)

Linux:   reads /dev/kmsg for sentinelx LKM alerts
Windows: reads \\.\\sentinelx device for sentinelx.sys alerts

Both feed into the same MIL-BASTER evidence pipeline:
    sign + encrypt → SQLite → Merkle proof → Sepolia blockchain

Usage:
    Linux:   sudo python3 sentinel_daemon.py [--dry-run]
    Windows: python sentinel_daemon.py [--dry-run]  (run as Administrator)
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(ROOT / "sentinel_daemon.log")),
    ]
)
log = logging.getLogger("sentinel.daemon")

from bridge.os_detector import get_os
from bridge.linux_bridge import LinuxBridge

try:
    from bridge.windows_bridge import WindowsBridge
except ImportError:
    WindowsBridge = None

EVIDENCE_AVAILABLE = False
try:
    from src.db_utils import init_db
    from src.evidence_manager import persist_and_maybe_anchor, anchor_worker_once
    from src.crypto_utils import gen_node_keypair
    EVIDENCE_AVAILABLE = True
    log.info("Evidence pipeline loaded OK")
except ImportError as e:
    log.warning(f"Evidence pipeline not available: {e}")
    log.warning("Running in LOG-ONLY mode")

SEVERITY_TRUST_DELTA = {
    "CRITICAL": -25, "HIGH": -10, "MEDIUM": -5, "INFO": 0,
}

ANOMALY_TYPE_MAP = {
    # Linux
    "SCT_HOOK": 1, "CR0_TAMPER": 2, "LSTAR_TAMPER": 3,
    "PROLOGUE_HOOK": 4, "MODULE_HIDDEN": 5, "DKOM_ALERT": 6,
    "PRIVESC": 7, "NF_HOOK": 8, "FTRACE_HOOK": 9, "WATCHLIST_CHANGE": 10,
    # Windows
    "SSDT_HOOK": 1, "DRIVER_HIDDEN": 5,
    "PATCHGUARD": 11, "IRP_HOOK": 12,
}

cfg = {
    "node_id":         os.environ.get("SENTINEL_NODE_ID", "sentinel_node_1"),
    "dry_run":         os.environ.get("SENTINEL_DRY_RUN", "0") == "1",
    "anchor_interval": int(os.environ.get("ANCHOR_INTERVAL", "60")),
}

stats = {
    "received": 0, "persisted": 0, "skipped": 0,
    "anchors": 0, "errors": 0, "start": time.time(),
}

stop_event = threading.Event()


def _handle_signal(sig, frame):
    log.info(f"Signal {sig} received — shutting down...")
    stop_event.set()

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def _log_event(event):
    sev   = event.get("severity", "INFO")
    etype = event.get("event_type", "UNKNOWN")
    os_s  = event.get("os", "?")
    det   = event.get("details", {})
    icons = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔶", "INFO": "ℹ️ "}
    detail_str = " | ".join(f"{k}={v}" for k, v in det.items()) if det else ""
    log.warning(f"{icons.get(sev,'•')} [{os_s.upper()}][{sev}] {etype} {detail_str}")


def process_event(event):
    stats["received"] += 1
    severity   = event.get("severity", "INFO")
    event_type = event.get("event_type", "UNKNOWN")

    _log_event(event)

    if severity == "INFO":
        stats["skipped"] += 1
        return

    if cfg["dry_run"]:
        log.info(f"[DRY-RUN] Would persist: {event_type}")
        stats["skipped"] += 1
        return

    if not EVIDENCE_AVAILABLE:
        stats["skipped"] += 1
        return

    try:
        evidence_obj = {
            "event_type":   event_type,
            "severity":     severity,
            "os":           event.get("os", "unknown"),
            "details":      event.get("details", {}),
            "raw":          event.get("body", ""),
            "dmesg_ts":     event.get("dmesg_ts", 0),
            "anomaly_type": ANOMALY_TYPE_MAP.get(event_type, 99),
            "trust_delta":  SEVERITY_TRUST_DELTA.get(severity, 0),
        }
        rowid, event_hash = persist_and_maybe_anchor(cfg["node_id"], evidence_obj)
        stats["persisted"] += 1
        log.info(f"✅ Persisted [{event_type}] rowid={rowid} hash={event_hash[:16]}...")
    except Exception as e:
        stats["errors"] += 1
        log.error(f"Failed to persist {event_type}: {e}")


def anchor_loop():
    log.info(f"Anchor worker started (interval={cfg['anchor_interval']}s)")
    while not stop_event.is_set():
        stop_event.wait(timeout=cfg["anchor_interval"])
        if stop_event.is_set():
            break
        if cfg["dry_run"] or not EVIDENCE_AVAILABLE:
            continue
        try:
            result = anchor_worker_once()
            if result:
                stats["anchors"] += 1
                log.info(
                    f"⛓️  Anchored {result['count']} events | "
                    f"root={result['root'][:16]}... | "
                    f"tx={result.get('tx_hash', 'local')}"
                )
        except Exception as e:
            stats["errors"] += 1
            log.error(f"Anchor worker error: {e}")


def print_stats():
    uptime = int(time.time() - stats["start"])
    log.info(
        f"📊 Stats | uptime={uptime}s | received={stats['received']} | "
        f"persisted={stats['persisted']} | anchors={stats['anchors']} | "
        f"errors={stats['errors']}"
    )


def main():
    parser = argparse.ArgumentParser(description="SENTINEL-X Unified Daemon")
    parser.add_argument("--os",      choices=["linux", "windows"],
                        help="Override OS detection")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log only — no DB/blockchain writes")
    parser.add_argument("--node-id", default=None,
                        help="Node ID for evidence signing")
    args = parser.parse_args()

    if args.dry_run:
        cfg["dry_run"] = True
        log.info("DRY-RUN mode — no DB writes or blockchain")

    if args.node_id:
        cfg["node_id"] = args.node_id

    os_type = args.os if args.os else get_os()
    log.info(f"OS detected: {os_type.upper()}")

    if EVIDENCE_AVAILABLE and not cfg["dry_run"]:
        init_db()
        gen_node_keypair(cfg["node_id"])
        log.info(f"Node: {cfg['node_id']} | DB initialized")

    # Start the right bridge for this OS
    if os_type == "linux":
        bridge = LinuxBridge()
    elif os_type == "windows":
        if WindowsBridge is None:
            log.error("WindowsBridge not available — install pywin32: pip install pywin32")
            sys.exit(1)
        bridge = WindowsBridge()
    else:
        log.error(f"Unknown OS: {os_type}")
        sys.exit(1)

    bridge.start()

    log.info("=" * 60)
    log.info("  SENTINEL-X DAEMON RUNNING")
    log.info(f"  Node:     {cfg['node_id']}")
    log.info(f"  OS:       {os_type.upper()}")
    log.info(f"  Dry-run:  {cfg['dry_run']}")
    log.info(f"  Evidence: {EVIDENCE_AVAILABLE}")
    log.info("=" * 60)

    threading.Thread(target=anchor_loop, name="anchor_worker", daemon=True).start()

    last_stats = time.time()
    while not stop_event.is_set():
        event = bridge.get_event(timeout=1.0)
        if event:
            process_event(event)
        if time.time() - last_stats > 30:
            print_stats()
            last_stats = time.time()

    log.info("Shutting down...")
    bridge.stop()

    if EVIDENCE_AVAILABLE and not cfg["dry_run"]:
        try:
            result = anchor_worker_once()
            if result:
                log.info(f"Final anchor: {result}")
        except Exception as e:
            log.error(f"Final anchor failed: {e}")

    print_stats()
    log.info("SENTINEL-X daemon stopped.")


if __name__ == "__main__":
    main()
