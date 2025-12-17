from __future__ import annotations
import argparse
import json
from typing import Dict, Any, List

from .hamming_code import (
    apply_perm,
    block_decode,
    vec_mul_mat,
)

def _hex_to_rows(hex_rows: List[str]) -> List[int]:
    return [int(x, 16) for x in hex_rows]

def decrypt(priv: Dict[str, Any], ct_obj: Dict[str, Any]) -> Dict[str, Any]:
    k = int(priv["k"])
    L = int(priv["L"])

    ct = int(ct_obj["ct_hex"], 16)
    perm_inv = list(priv["perm_inv"])
    S_inv_rows = _hex_to_rows(priv["S_inv_hex_rows"])

    # Step 1: unpermute: y = c * P^{-1}
    y = apply_perm(ct, perm_inv)

    # Step 2: block Hamming decode => get mS (k bits)
    mS, corrected_y, syndromes = block_decode(y, L)

    # Step 3: m = (mS) * S^{-1}
    m = vec_mul_mat(mS, S_inv_rows)

    # convert to bitstring (same convention as encrypt)
    msg_bits = "".join("1" if ((m >> i) & 1) else "0" for i in range(k))

    return {
        "scheme": priv.get("scheme", "block_hamming_mceliece_toy"),
        "n": int(priv["n"]),
        "k": k,
        "L": L,
        "msg_bits": msg_bits,
        "syndromes_per_block": syndromes,
    }

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--priv", type=str, default="private_key.json")
    ap.add_argument("--ct", type=str, default="ciphertext.json")
    ap.add_argument("--out", type=str, default="plaintext.json")
    args = ap.parse_args()

    with open(args.priv, "r", encoding="utf-8") as f:
        priv = json.load(f)
    with open(args.ct, "r", encoding="utf-8") as f:
        ct_obj = json.load(f)

    pt_obj = decrypt(priv, ct_obj)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(pt_obj, f, ensure_ascii=False, indent=2)

    print(f"[decrypt] wrote plaintext to {args.out}")

if __name__ == "__main__":
    main()
