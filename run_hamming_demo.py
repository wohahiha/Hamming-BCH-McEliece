# run_hamming_demo.py
# Quick end-to-end demo: keygen -> encrypt -> decrypt

from __future__ import annotations
import argparse
import os
import sys
import json
from typing import List

# === add Code/code directory into Python path ===
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(ROOT_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from .hamming_mceliece.keygen_hamming import keygen
from .hamming_mceliece.encrypt_hamming import encrypt
from .hamming_mceliece.decrypt_hamming import decrypt

# ---------- helpers ----------
def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--L", type=int, default=20, help="L value (default: 20)")
    ap.add_argument("--t", type=int, default=1, help="error weight t_err (default 1)")
    ap.add_argument("--seed", type=int, default=20251213, help="base seed for reproducibility")
    ap.add_argument("--output-dir", type=str, default="None", help="Output directory for keys_and_text (default: ./hamming_mceliece/keys_and_text)")
    args = ap.parse_args()

    L = args.L # Get single L value
    t_err = args.t
    base_seed = args.seed

    # Base output directory
    if args.output_dir:
        base_output_dir = args.output_dir
    else:
        base_output_dir = os.path.join(ROOT_DIR, "hamming_mceliece", "keys_and_text")
    ensure_dir(base_output_dir)
    print(f"[demo] Ensuring base output directory: {base_output_dir}")

    current_seed = base_seed + L # Adjust seed for L
    
    # Create L-specific subdirectory
    l_output_dir = os.path.join(base_output_dir, f"L_{L}")
    ensure_dir(l_output_dir)
    print(f"[demo] Processing L={L}. Output to: {l_output_dir}")

    pub, priv = keygen(L, seed=current_seed)

    k = int(pub["k"])
    # deterministic message from seed (no extra deps)
    m_int = ((current_seed + 777) * 0x9E3779B97F4A7C15) & ((1 << k) - 1)
    msg_bits = "".join("1" if ((m_int >> i) & 1) else "0" for i in range(k))

    ct_obj = encrypt(pub, msg_bits, t_err=t_err, seed=current_seed + 1)
    pt_obj = decrypt(priv, ct_obj)

    ok = (pt_obj["msg_bits"] == msg_bits)

    print("=== Block-Hamming McEliece Demo (TOY) ===")
    print(f"L={L}, (n,k)=({pub['n']},{pub['k']}), t_err={t_err}")
    print(f"message first 64 bits : {msg_bits[:64]}")
    print(f"decrypt first 64 bits : {pt_obj['msg_bits'][:64]}")
    print(f"SUCCESS? {ok}")

    # write artifacts to L-specific directory
    with open(os.path.join(l_output_dir, "public_key.json"), "w", encoding="utf-8") as f:
        json.dump(pub, f, ensure_ascii=False, indent=2)
    with open(os.path.join(l_output_dir, "private_key.json"), "w", encoding="utf-8") as f:
        json.dump(priv, f, ensure_ascii=False, indent=2)
    with open(os.path.join(l_output_dir, "ciphertext.json"), "w", encoding="utf-8") as f:
        json.dump(ct_obj, f, ensure_ascii=False, indent=2)
    with open(os.path.join(l_output_dir, "plaintext.json"), "w", encoding="utf-8") as f:
        json.dump(pt_obj, f, ensure_ascii=False, indent=2)

    print(f"[demo] wrote artifacts for L={L} to {l_output_dir}")



if __name__ == "__main__":
    main()
