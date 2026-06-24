# src/db_utils.py
import sqlite3
import json
import os
from contextlib import contextmanager
from typing import Optional, Dict, Any

DB_PATH = os.environ.get("MILBASTER_DB", "milbaster.db")

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER UNIQUE,
    event_hash TEXT UNIQUE,
    encrypted_blob BLOB,
    signer_id TEXT,
    signature BLOB,
    created_at INTEGER,
    merkle_index INTEGER,
    merkle_proof TEXT,
    tx_hash TEXT,
    block_number INTEGER
);

CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_hash TEXT UNIQUE,
    tx_hash TEXT,
    block_number INTEGER,
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS trust (
    node_id TEXT PRIMARY KEY,
    trust_score INTEGER,
    last_updated INTEGER
);
"""

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA_SQL)

def next_seq(conn) -> int:
    cur = conn.cursor()
    cur.execute("SELECT MAX(seq) FROM evidence;")
    r = cur.fetchone()
    if r is None or r[0] is None:
        return 1
    return int(r[0]) + 1

def save_evidence(event_hash: str, encrypted_blob: bytes, signer_id: str, signature: bytes, created_at: int) -> int:
    """
    Save an evidence blob and return the new row id.
    Merkle/anchor fields are filled by the anchor worker.
    """
    with get_conn() as conn:
        seq = next_seq(conn)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO evidence (seq, event_hash, encrypted_blob, signer_id, signature, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (seq, event_hash, encrypted_blob, signer_id, signature, created_at)
        )
        rowid = cur.lastrowid
        return rowid

def attach_merkle_info(row_ids_and_proofs, root_hash: str, tx_hash: str=None, block_number: int=None):
    """
    row_ids_and_proofs: list of tuples (rowid, merkle_index, proof_json)
    atomically attach the proof and anchor info for each evidence row.
    """
    with get_conn() as conn:
        cur = conn.cursor()
        for rowid, merkle_index, proof in row_ids_and_proofs:
            cur.execute(
                "UPDATE evidence SET merkle_index = ?, merkle_proof = ? WHERE id = ?",
                (merkle_index, json.dumps(proof), rowid)
            )
        if tx_hash:
            # create anchors table entry
            import time
            cur.execute(
                "INSERT OR IGNORE INTO anchors (root_hash, tx_hash, block_number, created_at) VALUES (?, ?, ?, ?)",
                (root_hash, tx_hash, block_number, int(time.time()))
            )
            # also persist tx_hash/block_number into evidence rows with this root (optional)
            cur.executemany(
                "UPDATE evidence SET tx_hash = ?, block_number = ? WHERE id = ?",
                [(tx_hash, block_number, rowid) for rowid, _, _ in row_ids_and_proofs]
            )

def get_unanchored_evidence(limit: int=256):
    """
    Returns list of tuples (id, event_hash, created_at).
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, event_hash, created_at FROM evidence WHERE merkle_index IS NULL ORDER BY seq LIMIT ?", (limit,))
        return cur.fetchall()

def get_evidence_by_id(rowid: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, seq, event_hash, encrypted_blob, signer_id, signature, created_at, merkle_index, merkle_proof, tx_hash, block_number FROM evidence WHERE id = ?", (rowid,))
        r = cur.fetchone()
        if not r:
            return None
        keys = ["id","seq","event_hash","encrypted_blob","signer_id","signature","created_at","merkle_index","merkle_proof","tx_hash","block_number"]
        res = dict(zip(keys, r))
        if res.get("merkle_proof"):
            res["merkle_proof"] = json.loads(res["merkle_proof"])
        return res

def save_trust(node_id: str, trust_score: int, ts: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO trust (node_id, trust_score, last_updated) VALUES (?, ?, ?)", (node_id, trust_score, ts))
