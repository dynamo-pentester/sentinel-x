# src/web3_utils.py
"""
Robust Web3 helper for MIL-BASTER.

Features:
- Web3 connection with primary + fallback RPCs
- Contract loading from ABI (fallback to minimal ABI)
- push_event_to_chain() to call contract.addLog(...) (with local fallback cache)
- push_root_to_chain() to publish merkle root as a small tx (demo mode)
- helpers: verify_transaction, get_logs_from_chain, get_blockchain_status

Environment variables expected (demo / config):
- INFURA_SEPOLIA_URL (optional primary RPC)
- PRIVATE_KEY (hex, required for on-chain writes)
- ACCOUNT (optional; derived from PRIVATE_KEY if missing)
- CONTRACT_ADDR (contract address for addLog)
- CHAIN_ID (optional; defaults to Sepolia 11155111)
"""

import os
import json
import time
from typing import Optional, Dict, List
from dotenv import load_dotenv
from web3 import Web3, HTTPProvider
from web3.exceptions import TransactionNotFound
from eth_account import Account
from .db_utils import get_conn  # small helper to query anchors table (if you kept db_utils.get_conn)
load_dotenv()

# Config from env
INFURA_URL = os.getenv("INFURA_SEPOLIA_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT = os.getenv("ACCOUNT")
CONTRACT_ADDR = os.getenv("CONTRACT_ADDR")
ABI_PATH = os.path.join(os.path.dirname(__file__), "..", "MILBASTERLog_abi.json")
CHAIN_ID = int(os.environ.get("CHAIN_ID", "11155111"))

# Fallback RPCs for Sepolia (useful if primary is missing/unreliable)
_infura_fallback = os.getenv("INFURA_SEPOLIA_URL")  # reuse primary if set
FALLBACK_RPCS = [
    rpc for rpc in [
        "https://rpc.sepolia.org",
        "https://sepolia.gateway.tenderly.co",
        "https://ethereum-sepolia.blockpi.network/v1/rpc/public",
        _infura_fallback,  # only included if env var is set
    ]
    if rpc
]

# Local cache for events if chain push fails or disabled
local_log_cache: List[Dict] = []


class Web3Manager:
    def __init__(self):
        self.w3: Optional[Web3] = None
        self.contract = None
        self.is_connected: bool = False
        self.current_rpc: Optional[str] = None
        self._initialize_connection()

    def _initialize_connection(self):
        # Try primary INFURA_URL first
        tried = []
        if INFURA_URL:
            tried.append(INFURA_URL)
            try:
                w3 = Web3(HTTPProvider(INFURA_URL, request_kwargs={"timeout": 10}))
                if w3.is_connected():
                    self.w3 = w3
                    self.current_rpc = INFURA_URL
                    self.is_connected = True
                    print(f"✅ Connected to primary RPC: {INFURA_URL[:50]}...")
                    self._load_contract()
                    return
                else:
                    print(f"⚠️ Primary RPC not responding: {INFURA_URL[:50]}...")
            except Exception as e:
                print(f"❌ Primary RPC failed: {e}")

        # Try fallback RPCs
        for rpc_url in FALLBACK_RPCS:
            if rpc_url in tried:
                continue
            try:
                print(f"🔄 Trying fallback RPC: {rpc_url[:60]}...")
                w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
                if w3.is_connected():
                    self.w3 = w3
                    self.current_rpc = rpc_url
                    self.is_connected = True
                    print(f"✅ Connected to fallback RPC: {rpc_url[:60]}...")
                    self._load_contract()
                    return
            except Exception as e:
                print(f"❌ Fallback RPC failed {rpc_url[:40]}...: {e}")
                continue

        # No connection established
        self.w3 = None
        self.is_connected = False
        print("❌ No RPC connection established. Blockchain logging will be disabled.")

    def _load_contract(self):
        if not CONTRACT_ADDR:
            print("⚠️ CONTRACT_ADDR not set. Smart contract calls will fail.")
            return

        # load ABI if available
        abi = None
        try:
            if os.path.exists(ABI_PATH):
                with open(ABI_PATH, "r") as f:
                    abi = json.load(f)
                print(f"✅ Loaded contract ABI from {ABI_PATH}")
        except Exception as e:
            print(f"❌ Failed to load ABI: {e}")
            abi = None

        if abi is None:
            # minimal fallback ABI (must match deployed contract events/functions you use)
            abi = [
                {
                    "inputs": [
                        {"internalType": "string", "name": "eventHash", "type": "string"},
                        {"internalType": "string", "name": "anomalyType", "type": "string"},
                        {"internalType": "int256", "name": "trustDelta", "type": "int256"}
                    ],
                    "name": "addLog",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"internalType": "string", "name": "eventHash", "type": "string"}
                    ],
                    "name": "storeEvent",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]
            print("⚠️ Using minimal fallback ABI (ensure it matches your deployed contract).")

        try:
            if self.w3:
                self.contract = self.w3.eth.contract(address=CONTRACT_ADDR, abi=abi)
                print(f"✅ Contract initialized at {CONTRACT_ADDR}")
        except Exception as e:
            print(f"❌ Contract initialization failed: {e}")
            self.contract = None

    def check_connection(self) -> bool:
        if not self.w3:
            return False
        try:
            # quick check
            _ = self.w3.eth.block_number
            return True
        except Exception:
            print("❌ Connection lost, attempting reconnection...")
            self.is_connected = False
            self._initialize_connection()
            return self.is_connected

    def get_gas_price(self) -> int:
        """Return legacy gas price fallback (used only if EIP-1559 params unavailable)."""
        try:
            if self.check_connection():
                return self.w3.eth.gas_price
            else:
                return self.w3.to_wei(20, "gwei") if self.w3 else 20 * (10 ** 9)
        except Exception:
            return 20 * (10 ** 9)

    def get_eip1559_gas_params(self) -> dict:
        """Return EIP-1559 maxFeePerGas and maxPriorityFeePerGas for Sepolia.
        Uses 2 Gwei priority fee (validator tip) + 2x base fee cap.
        Falls back to legacy gasPrice if block doesn't expose baseFeePerGas."""
        try:
            if self.check_connection() and self.w3:
                latest = self.w3.eth.get_block("latest")
                base_fee = latest.get("baseFeePerGas")
                if base_fee:
                    priority = self.w3.to_wei(2, "gwei")
                    return {
                        "maxPriorityFeePerGas": priority,
                        "maxFeePerGas": base_fee * 2 + priority,
                        "type": "0x2",
                    }
        except Exception:
            pass
        # fallback: legacy gasPrice
        return {"gasPrice": self.get_gas_price()}

    def estimate_gas(self, transaction) -> int:
        try:
            if self.check_connection():
                return self.w3.eth.estimate_gas(transaction)
            else:
                return 200000
        except Exception:
            return 200000


# single global manager instance
web3_manager = Web3Manager()


def _anchor_exists_in_db(root_hex: str):
    """Return stored anchor row if exists (tx_hash, block_number) or None"""
    try:
        from .db_utils import get_conn  # safe import
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT tx_hash, block_number FROM anchors WHERE root_hash = ?", (root_hex,))
            r = cur.fetchone()
            if r:
                return {"tx_hash": r[0], "block_number": r[1]}
    except Exception:
        # if DB unavailable for some reason, act as if anchor not present
        pass
    # Also check local_log_cache for a local root entry
    for e in local_log_cache:
        if e.get("anomalyType") == "MERKLE_ROOT" and e.get("eventHash") == root_hex:
            return {"tx_hash": e.get("transactionHash"), "block_number": e.get("blockNumber")}
    return None

def _derive_account_address() -> Optional[str]:
    global ACCOUNT
    if ACCOUNT:
        return ACCOUNT
    if not PRIVATE_KEY:
        return None
    acct = Account.from_key(PRIVATE_KEY)
    ACCOUNT = acct.address
    return ACCOUNT


def get_blockchain_status() -> Dict:
    return {
        "connected": web3_manager.is_connected,
        "current_rpc": web3_manager.current_rpc,
        "contract_address": CONTRACT_ADDR,
        "account": _derive_account_address(),
        "block_number": web3_manager.w3.eth.block_number if (web3_manager.w3 and web3_manager.is_connected) else None
    }


def verify_transaction(tx_hash: str, timeout: int = 60) -> Dict:
    """
    Wait for tx receipt and return basic status info.
    """
    if not web3_manager.check_connection():
        return {"error": "No blockchain connection"}

    try:
        w3 = web3_manager.w3
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        return {
            "success": True,
            "block_number": receipt.blockNumber,
            "gas_used": getattr(receipt, "gasUsed", None),
            "status": getattr(receipt, "status", None)
        }
    except TransactionNotFound:
        return {"error": "Transaction not found"}
    except Exception as e:
        return {"error": str(e)}


# --- paste below into src/web3_utils.py (replace existing push_event_to_chain & push_root_to_chain) ---

def _get_raw_signed_bytes(signed_obj):
    """
    SignedTransaction objects vary across library versions.
    Try common attribute names and return raw bytes or None.
    """
    candidates = ["rawTransaction", "raw_transaction", "rawTxn", "raw_tx"]
    for attr in candidates:
        raw = getattr(signed_obj, attr, None)
        if raw:
            return raw
    # fallback: try dict-like access
    try:
        return signed_obj.raw  # unlikely but safe-guard
    except Exception:
        return None


def push_event_to_chain(event_hash_hex: str, anomaly_type: int = 1, trust_delta: int = 0) -> Optional[str]:
    """
    Call contract.addLog(eventHash, anomalyType, trustDelta).
    Always append an entry to local_log_cache as a fallback.
    Returns tx_hash_hex if submitted, else None.
    """
    tx_hash_hex = None
    acct_address = _derive_account_address()

    if web3_manager.is_connected and PRIVATE_KEY and acct_address and web3_manager.contract:
        try:
            w3 = web3_manager.w3
            contract = web3_manager.contract
            # build transaction
            nonce = w3.eth.get_transaction_count(acct_address)
            gas_params = web3_manager.get_eip1559_gas_params()
            txn = contract.functions.addLog(
                event_hash_hex,
                int(anomaly_type),   # uint8 — must be int not str
                int(trust_delta)     # int16
            ).build_transaction({
                "chainId": CHAIN_ID,
                "gas": 250000,
                "nonce": nonce,
                "from": acct_address,
                **gas_params,
            })

            # sign using eth-account Account
            signed_txn = Account.sign_transaction(txn, PRIVATE_KEY)
            raw_signed = _get_raw_signed_bytes(signed_txn)
            if raw_signed is None:
                # best-effort: try creating raw from signed_txn if it provides .raw or .raw_transaction
                raise RuntimeError("Could not extract raw signed bytes from sign object")

            tx_hash = w3.eth.send_raw_transaction(raw_signed)
            tx_hash_hex = Web3.to_hex(tx_hash)

            print(f"✅ TX sent successfully: {tx_hash_hex}")
            # optional: wait for receipt (demo-friendly)
            try:
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                if receipt and getattr(receipt, "status", 0) == 1:
                    print(f"📦 Confirmed in block {receipt.blockNumber}")
            except Exception as e:
                print(f"⏳ TX confirmation wait failed or timed out: {e}")

        except Exception as e:
            print(f"❌ Blockchain push failed: {e}")

    else:
        print("⚠️ Blockchain not connected/credentials missing; storing locally.")

    # always store locally as backup
    entry = {
        "blockNumber": 0 if not tx_hash_hex else None,
        "transactionHash": tx_hash_hex if tx_hash_hex else "LOCAL_" + event_hash_hex[:12],
        "eventHash": event_hash_hex,
        "anomalyType": anomaly_type,
        "trustDelta": trust_delta,
        "timestamp": int(time.time())
    }
    local_log_cache.append(entry)
    print(f"🧩 Event stored locally: {entry['transactionHash']}")
    return tx_hash_hex


def push_root_to_chain(root_hex: str) -> dict:
    """
    Robust push_root_to_chain:
    - If root already anchored in DB, return stored record (no send).
    - Use pending nonce to avoid nonce reuse.
    - If RPC returns 'already known' treat as non-fatal (store local fallback).
    - Always append local_log_cache entry as fallback.
    Returns {'tx_hash': <hex>|None, 'block_number': <int>|None}
    """
    # 1) if already anchored -> return existing
    existing = _anchor_exists_in_db(root_hex)
    if existing:
        print(f"ℹ️ Root already anchored (db/local): {existing}")
        return {"tx_hash": existing.get("tx_hash"), "block_number": existing.get("block_number")}

    acct_address = _derive_account_address()
    w3 = web3_manager.w3

    if not (web3_manager.is_connected and PRIVATE_KEY and acct_address and w3):
        # not configured: record local and return
        print("⚠️ push_root_to_chain: no chain/keys; recording locally.")
        local_log_cache.append({
            "blockNumber": 0,
            "transactionHash": "LOCAL_ROOT_" + root_hex[:12],
            "eventHash": root_hex,
            "anomalyType": "MERKLE_ROOT",
            "trustDelta": 0,
            "timestamp": int(time.time())
        })
        return {"tx_hash": None, "block_number": None}

    try:
        # use pending nonce to avoid reuse with mempool txs
        nonce = w3.eth.get_transaction_count(acct_address, "pending")
        gas_params = web3_manager.get_eip1559_gas_params()
        tx = {
            "nonce": nonce,
            "to": acct_address,
            "value": 0,
            "gas": 200000,
            "data": Web3.to_hex(text=root_hex),
            "chainId": CHAIN_ID,
            **gas_params,
        }
        signed = Account.sign_transaction(tx, PRIVATE_KEY)
        raw_signed = _get_raw_signed_bytes(signed)
        if raw_signed is None:
            raise RuntimeError("No raw signed bytes available")

        tx_hash = w3.eth.send_raw_transaction(raw_signed)
        tx_hash_hex = Web3.to_hex(tx_hash)

        # store a local entry immediately so repeated calls see it
        local_log_cache.append({
            "blockNumber": 0,
            "transactionHash": tx_hash_hex,
            "eventHash": root_hex,
            "anomalyType": "MERKLE_ROOT",
            "trustDelta": 0,
            "timestamp": int(time.time())
        })

        # attempt to get receipt (demo-friendly). If it times out, we still have local entry.
        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            blk = getattr(receipt, "blockNumber", None)
            # NOTE: do NOT write to the anchors table here.
            # attach_merkle_info() in db_utils is the single, canonical anchor writer.
            # Writing here would duplicate that work and split DB responsibility across modules.
            print(f"✅ Root tx submitted & mined: {tx_hash_hex} (block {blk})")
            return {"tx_hash": tx_hash_hex, "block_number": blk}
        except Exception as e:
            # receipt not available now; return tx_hash but keep local record
            print(f"⏳ Root tx submitted (no receipt yet): {tx_hash_hex} — {e}")
            return {"tx_hash": tx_hash_hex, "block_number": None}

    except Exception as e:
        # Handle JSON-RPC 'already known' and similar mempool duplicates gracefully
        msg = str(e)
        if "already known" in msg or "known" in msg:
            print(f"⚠️ RPC reports already-known tx for this root: {msg[:200]}")
            # try to find existing tx in local cache and return it if present
            for e_local in local_log_cache:
                if e_local.get("anomalyType") == "MERKLE_ROOT" and e_local.get("eventHash") == root_hex:
                    print("ℹ️ Found existing local record for root, returning that.")
                    return {"tx_hash": e_local.get("transactionHash"), "block_number": e_local.get("blockNumber")}
            # fall back to local-record with placeholder id
            local_log_cache.append({
                "blockNumber": 0,
                "transactionHash": "LOCAL_ROOT_" + root_hex[:12],
                "eventHash": root_hex,
                "anomalyType": "MERKLE_ROOT",
                "trustDelta": 0,
                "timestamp": int(time.time())
            })
            return {"tx_hash": None, "block_number": None}

        # Other errors: record locally and return None
        print(f"❌ push_root_to_chain failed: {msg}")
        local_log_cache.append({
            "blockNumber": 0,
            "transactionHash": "LOCAL_ROOT_" + root_hex[:12],
            "eventHash": root_hex,
            "anomalyType": "MERKLE_ROOT",
            "trustDelta": 0,
            "timestamp": int(time.time())
        })
        return {"tx_hash": None, "block_number": None}

def get_logs_from_chain(from_block: int = 0, to_block: str = "latest") -> List[Dict]:
    """
    Return logs from contract (if connected) combined with local cache.
    Note: event names/arg names depend on your contract ABI - adapt if necessary.
    """
    chain_logs: List[Dict] = []
    if web3_manager.is_connected and web3_manager.contract:
        try:
            contract = web3_manager.contract
            # if the contract has an event named `LogAdded` or similar, adapt here
            # We don't assume an exact event name; try 'LogAdded' then fallback silently.
            try:
                event_filter = contract.events.LogAdded.create_filter(fromBlock=from_block, toBlock=to_block)
                entries = event_filter.get_all_entries()
                for log in entries:
                    chain_logs.append({
                        "blockNumber": getattr(log, "blockNumber", None),
                        "transactionHash": getattr(log, "transactionHash", b"").hex() if getattr(log, "transactionHash", None) else None,
                        "eventHash": log.args.get("eventHash") if hasattr(log, "args") else None,
                        "anomalyType": log.args.get("anomalyType") if hasattr(log, "args") else None,
                        "trustDelta": log.args.get("trustDelta") if hasattr(log, "args") else None
                    })
            except Exception:
                # event may have different name; ignore and continue
                pass
        except Exception as e:
            print(f"⚠️ get_logs_from_chain failed: {e}")

    # merge chain logs + local fallback (local logs appended last for visibility)
    return chain_logs + list(local_log_cache)
