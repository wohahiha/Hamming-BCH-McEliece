from __future__ import annotations
import argparse
import json
import random
from typing import Dict, Any, List
import os

from .hamming_code import (
    HAMMING_N, HAMMING_K, HAMMING_T,
    build_block_diag_G_rows,
    random_invertible_matrix,
    mat_left_mul,
    apply_perm,
    invert_perm,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEYS_DIR = os.path.join(SCRIPT_DIR, "keys_and_text")

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _rows_to_hex(rows: List[int]) -> List[str]:
    return [hex(r) for r in rows]

def keygen(L: int, seed: int | None = None) -> tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(L, int) or L <= 0:
        raise ValueError("L must be a positive integer.")

    k = HAMMING_K * L
    n = HAMMING_N * L

    rng = random.Random(seed) if seed is not None else None

    G_blk_rows = build_block_diag_G_rows(L)

    S_rows, S_inv_rows = random_invertible_matrix(k, rng=rng)

    perm = list(range(n))
    (rng if rng is not None else random).shuffle(perm)
    perm_inv = invert_perm(perm)

    SG_rows = mat_left_mul(S_rows, G_blk_rows, k)
    G_pub_rows = [apply_perm(row, perm) for row in SG_rows]

    pub = {
        "scheme": "block_hamming_mceliece_toy",
        "n": n,
        "k": k,
        "L": L,
        "n_block": HAMMING_N,
        "k_block": HAMMING_K,
        "t_block": HAMMING_T,
        "G_pub_hex_rows": _rows_to_hex(G_pub_rows),
    }
    priv = {
        "scheme": "block_hamming_mceliece_toy",
        "n": n,
        "k": k,
        "L": L,
        "n_block": HAMMING_N,
        "k_block": HAMMING_K,
        "t_block": HAMMING_T,
        "S_inv_hex_rows": _rows_to_hex(S_inv_rows),
        "perm_inv": perm_inv,
    }
    return pub, priv

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--L", type=int, default=20)
    ap.add_argument("--pub", type=str, default=os.path.join(DEFAULT_KEYS_DIR, "public_key.json"))
    ap.add_argument("--priv", type=str, default=os.path.join(DEFAULT_KEYS_DIR, "private_key.json"))
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    pub, priv = keygen(args.L, seed=args.seed)

    ensure_dir(os.path.dirname(args.pub))
    with open(args.pub, "w", encoding="utf-8") as f:
        json.dump(pub, f, ensure_ascii=False, indent=2)
    ensure_dir(os.path.dirname(args.priv))
    with open(args.priv, "w", encoding="utf-8") as f:
        json.dump(priv, f, ensure_ascii=False, indent=2)

    print(f"[keygen] L={args.L} => (n,k)=({pub['n']},{pub['k']})")

if __name__ == "__main__":
    main()
