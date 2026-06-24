# src/merkle_utils.py
"""Simple pure-Python Merkle tree utilities (no external deps).
Functions:
- hash_leaf(bytes) -> hex
- build_merkle(list_of_bytes) -> (root_hex, levels)
- get_proof_for_leaf(levels, leaf_index) -> proof_list
Proof format: list of dicts { "position": "left"|"right", "hash": "<hex>" }
"""
import hashlib
from typing import List, Tuple, Any, Dict

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_leaf(data: bytes) -> str:
    return _sha256_hex(data)

def build_merkle(leaves: List[bytes]) -> Tuple[str, List[List[str]]]:
    """
    Build a Merkle tree from a list of *raw leaf bytes*.
    Returns (root_hex, levels), where levels[0] is the list of leaf hashes (hex),
    and levels[-1][0] is the root hex string.
    """
    if not leaves:
        return ("", [])
    # level 0: leaf hashes
    level = [_sha256_hex(b) for b in leaves]
    levels = [level]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            if i + 1 < len(level):
                right = level[i + 1]
            else:
                # duplicate last if odd count
                right = left
            # combine left||right as binary
            left_bytes = bytes.fromhex(left)
            right_bytes = bytes.fromhex(right)
            combined = _sha256_hex(left_bytes + right_bytes)
            next_level.append(combined)
        level = next_level
        levels.append(level)
    root = levels[-1][0]
    return root, levels

def get_proof_for_leaf(levels: List[List[str]], leaf_index: int) -> List[Dict[str, str]]:
    """
    Given levels produced by build_merkle, produce the Merkle proof for leaf_index.
    Returns a list of {'position': 'left'|'right', 'hash': '<hex>'}, in bottom-up order.
    """
    proof = []
    if not levels or leaf_index < 0 or leaf_index >= len(levels[0]):
        return proof
    idx = leaf_index
    for level in levels[:-1]:  # skip the root level
        # sibling index
        if idx % 2 == 0:
            sibling_index = idx + 1
            position = "right"
        else:
            sibling_index = idx - 1
            position = "left"
        if sibling_index >= len(level):
            # sibling is the same as current (duplicate)
            sibling_hash = level[idx]
        else:
            sibling_hash = level[sibling_index]
        proof.append({"position": position, "hash": sibling_hash})
        # move up
        idx = idx // 2
    return proof

def verify_proof(leaf_hash_hex: str, proof: List[Dict[str, str]], root_hex: str) -> bool:
    """
    Verify a Merkle proof (helper) — returns True if proof leads to root_hex.
    Proof format: [{'position':'left'|'right', 'hash':'...'}, ...]
    """
    cur = leaf_hash_hex
    for step in proof:
        sibling = step["hash"]
        if step["position"] == "left":
            combined = bytes.fromhex(sibling) + bytes.fromhex(cur)
        else:
            combined = bytes.fromhex(cur) + bytes.fromhex(sibling)
        cur = _sha256_hex(combined)
    return cur == root_hex
