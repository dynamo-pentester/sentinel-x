# src/trust.py
import time
from .db_utils import save_trust

def update_trust(node_id: str, delta: int, prev_score: int=None) -> int:
    """
    Update trust by delta (positive or negative). Returns new trust score.
    prev_score is optional; if not provided we treat base 100.
    Guaranteed to be side-effect safe (no invalid list ops).
    """
    base = prev_score if prev_score is not None else 100
    new_score = base + delta
    # clamp
    if new_score < 0:
        new_score = 0
    if new_score > 100:
        new_score = 100
    save_trust(node_id, new_score, int(time.time()))
    return new_score
