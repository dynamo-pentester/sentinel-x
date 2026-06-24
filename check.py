"""
check.py — SENTINEL-X blockchain verification tool

Shows:
  1. Total events logged via contract.addLog()     → contract.count()
  2. Recent addLog entries                          → contract.getLog(i)
  3. Merkle root anchors (raw self-transfer txs)   → anchors table in DB
"""
import os
import json
import sqlite3
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

infura_url    = os.getenv("INFURA_SEPOLIA_URL")
contract_addr = os.getenv("CONTRACT_ADDR", "").strip().strip("'\"")
db_path       = os.getenv("MILBASTER_DB", "sentinel.db")

if not infura_url or not contract_addr:
    raise ValueError("Missing INFURA_SEPOLIA_URL or CONTRACT_ADDR in .env")

# ── Connect ───────────────────────────────────────────────────────────────────
FALLBACK_RPCS = [
    infura_url,
    "https://rpc.sepolia.org",
    "https://sepolia.gateway.tenderly.co",
]

w3 = None
for rpc in FALLBACK_RPCS:
    try:
        _w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
        if _w3.is_connected():
            w3 = _w3
            print(f"✅ Connected: {rpc[:60]}")
            break
    except Exception as e:
        print(f"⚠️  {rpc[:40]}… failed: {e}")

if not w3:
    raise RuntimeError("Could not connect to any RPC")

# ── Load ABI ──────────────────────────────────────────────────────────────────
abi_path = os.path.join(os.path.dirname(__file__), "MILBASTERLog_abi.json")
with open(abi_path) as f:
    abi = json.load(f)

contract = w3.eth.contract(address=contract_addr, abi=abi)

# ── 1. addLog count ───────────────────────────────────────────────────────────
try:
    log_count = contract.functions.count().call()
    print(f"\n{'='*55}")
    print(f"  Total events on-chain (addLog calls): {log_count}")
    print(f"{'='*55}")
except Exception as e:
    print(f"❌ contract.count() failed: {e}")
    log_count = 0

# ── 2. Print last 5 addLog entries ────────────────────────────────────────────
if log_count > 0:
    print("\nRecent on-chain events:")
    start = max(0, log_count - 5)
    for i in range(start, log_count):
        try:
            entry = contract.functions.getLog(i).call()
            print(f"  [{i}] {entry}")
        except Exception as e:
            print(f"  [{i}] error: {e}")

# ── 3. Merkle root anchors from local DB ─────────────────────────────────────
print(f"\n{'='*55}")
print("  Merkle root anchors (DB):")
print(f"{'='*55}")
try:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT root_hash, tx_hash, block_number, created_at "
        "FROM anchors ORDER BY created_at DESC LIMIT 10"
    )
    rows = cur.fetchall()
    con.close()
    if rows:
        for root_hash, tx_hash, block_num, ts in rows:
            from datetime import datetime
            dt = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  Root : {root_hash[:20]}…")
            print(f"  TxHash: {(tx_hash or 'pending')[:66]}")
            print(f"  Block : {block_num}   Time: {dt} UTC")
            print()
    else:
        print("  No anchors in DB yet (run daemon to generate events)")
except Exception as e:
    print(f"  DB error: {e}")

# ── 4. Evidence count ─────────────────────────────────────────────────────────
print(f"{'='*55}")
try:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM evidence")
    ev_total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM evidence WHERE tx_hash IS NOT NULL")
    ev_anchored = cur.fetchone()[0]
    con.close()
    print(f"  Evidence total    : {ev_total}")
    print(f"  Evidence anchored : {ev_anchored}")
except Exception as e:
    print(f"  DB evidence count error: {e}")
print(f"{'='*55}\n")
