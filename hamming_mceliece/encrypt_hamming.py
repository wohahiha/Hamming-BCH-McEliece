from __future__ import annotations
import argparse
import json
import random
from typing import Dict, Any, List

from .hamming_code import (
    bits_str_to_int,
    vec_mul_mat,
    random_error_vector,
)

def _hex_to_rows(hex_rows: List[str]) -> List[int]:
    return [int(x, 16) for x in hex_rows]

def encrypt(pub: Dict[str, Any], msg_bits: str, t_err: int, seed: int | None = None) -> Dict[str, Any]:
    k = int(pub["k"])
    n = int(pub["n"])

    if len(msg_bits) != k:
        raise ValueError(f"message bitstring length must be exactly k={k}")
    if not isinstance(t_err, int) or t_err < 0 or t_err > n:
        raise ValueError("t_err must be an int in [0, n].")

    G_pub_rows = _hex_to_rows(pub["G_pub_hex_rows"])
    m = bits_str_to_int(msg_bits)

    c0 = vec_mul_mat(m, G_pub_rows)

    rng = random.Random(seed) if seed is not None else None
    e = random_error_vector(n, t_err, rng=rng)

    ct = c0 ^ e

    return {
        "scheme": pub.get("scheme", "block_hamming_mceliece_toy"),
        "n": n,
        "k": k,
        "L": int(pub["L"]),
        "t_err": t_err,
        "ct_hex": hex(ct),
    }

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pub", type=str, default="public_key.json")
    ap.add_argument("--msg", type=str, required=True)
    ap.add_argument("--t", type=int, default=1)
    ap.add_argument("--out", type=str, default="ciphertext.json")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    with open(args.pub, "r", encoding="utf-8") as f:
        pub = json.load(f)

    ct_obj = encrypt(pub, args.msg.strip(), args.t, seed=args.seed)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(ct_obj, f, ensure_ascii=False, indent=2)

    print(f"[encrypt] wrote ciphertext to {args.out}")

if __name__ == "__main__":
    main()
