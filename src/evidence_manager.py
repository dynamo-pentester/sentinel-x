# src/evidence_manager.py
import time
import json
from typing import List, Tuple
from .db_utils import save_evidence, get_unanchored_evidence, attach_merkle_info, get_evidence_by_id
from .crypto_utils import sign_message, aes_gcm_encrypt, sha256_hex, load_node_private_key, derive_node_symmetric_key
from .merkle_utils import build_merkle, get_proof_for_leaf
from .web3_utils import push_root_to_chain, push_event_to_chain

# Config
BATCH_SIZE = int(__import__("os").environ.get("ANCHOR_BATCH_SIZE", "32"))
ANCHOR_INTERVAL = int(__import__("os").environ.get("ANCHOR_INTERVAL", "60"))  # seconds

def create_signed_encrypted_evidence(node_id: str, evidence_obj: dict, peer_pubkey_bytes: bytes=None):
    ts = int(time.time())
    evidence_obj["_evidence_ts"] = ts
    evidence_obj["_node_id"] = node_id
    evidence_bytes = json.dumps(evidence_obj, separators=(",", ":"), sort_keys=True).encode()

    priv = load_node_private_key(node_id)
    signature = sign_message(priv, evidence_bytes)

    package = {
        "evidence": evidence_obj,
        "signature": signature.hex(),
        "signer_id": node_id
    }
    package_bytes = json.dumps(package, separators=(",", ":"), sort_keys=True).encode()

    aes_key = derive_node_symmetric_key(node_id, peer_pubkey_bytes=peer_pubkey_bytes)
    ciphertext, nonce, tag = aes_gcm_encrypt(aes_key, package_bytes)
    stored_blob = nonce + tag + ciphertext
    event_hash = sha256_hex(stored_blob)
    return event_hash, stored_blob, signature

def persist_and_maybe_anchor(node_id: str, evidence_obj: dict, peer_pubkey_bytes: bytes=None):
    created_at = int(time.time())
    event_hash, stored_blob, signature = create_signed_encrypted_evidence(node_id, evidence_obj, peer_pubkey_bytes)
    rowid = save_evidence(event_hash, stored_blob, node_id, signature, created_at)
    return rowid, event_hash

def anchor_worker_once():
    items = get_unanchored_evidence(limit=BATCH_SIZE)
    if not items:
        return None
    row_ids = [r[0] for r in items]
    leaves = []
    rows = []
    for rid in row_ids:
        r = get_evidence_by_id(rid)
        leaves.append(r["encrypted_blob"])
        rows.append(r)
    root, levels = build_merkle(leaves)
    proofs = []
    for i, r in enumerate(rows):
        proof = get_proof_for_leaf(levels, i)
        proofs.append((r["id"], i, proof))

    # ── Step 1: push each event to the contract via addLog() ─────────────────
    # This is the call that increments contract.count().
    # We derive a numeric anomaly_type from the event_type field if present,
    # otherwise default to 1 (CRITICAL).  trust_delta from evidence metadata.
    for r in rows:
        ev = r.get("evidence") or {}
        if isinstance(ev, str):
            import json as _json
            try:
                ev = _json.loads(ev)
            except Exception:
                ev = {}
        # map string severity → numeric for the contract (uint8)
        sev_map = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        sev_str = (ev.get("severity") or "CRITICAL").upper()
        anomaly_type = sev_map.get(sev_str, 1)
        trust_delta  = int(ev.get("trust_delta", 0))
        push_event_to_chain(r["event_hash"], anomaly_type, trust_delta)

    # ── Step 2: push Merkle root as a timestamped on-chain anchor ────────────
    # This is a raw self-transfer tx embedding the root in tx.data —
    # it is a proof-of-existence timestamp, separate from addLog calls above.
    tx_info  = push_root_to_chain(root)
    tx_hash  = tx_info.get("tx_hash")
    blk      = tx_info.get("block_number")
    attach_merkle_info(proofs, root, tx_hash, blk)
    return {"root": root, "tx_hash": tx_hash, "block_number": blk, "count": len(rows)}

def start_anchor_loop(loop_forever=True):
    import time
    while True:
        try:
            res = anchor_worker_once()
            if res:
                print("Anchored root:", res)
        except Exception as e:
            print("[anchor_worker] exception:", e)
        if not loop_forever:
            break
        time.sleep(ANCHOR_INTERVAL)
