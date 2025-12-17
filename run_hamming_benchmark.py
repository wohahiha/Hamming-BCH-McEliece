# run_benchmark.py
# Benchmark script for Block-Hamming McEliece (educational toy)
# Output: CSV + JSON with mean/std, success rate, key sizes, timings.

from __future__ import annotations
import argparse
import csv
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple

# === add Code/code directory into Python path ===
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(ROOT_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from .hamming_mceliece.keygen_hamming import keygen 
from .hamming_mceliece.encrypt_hamming import encrypt 
from .hamming_mceliece.decrypt_hamming import decrypt  


# ---------- helpers ----------

def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def parse_int_list(s: str) -> List[int]:
    parts = [p.strip() for p in s.split(",") if p.strip() != ""]
    out: List[int] = []
    for p in parts:
        # allow "0" as well
        if not (p.isdigit() and len(p) > 0):
            raise argparse.ArgumentTypeError(f"Expected comma-separated ints, got: {s}")
        out.append(int(p))
    if not out:
        raise argparse.ArgumentTypeError("List cannot be empty.")
    return out

def mean_std(values: List[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)

def bits_to_bytes(nbits: int) -> int:
    return (nbits + 7) // 8

def json_size_bytes(obj: Any) -> int:
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return len(s.encode("utf-8"))

def _hex_rows_to_bytes(hex_rows: List[str], bit_len: int) -> int:
    total_bits = len(hex_rows) * bit_len    # 计算所有行的比特数
    return bits_to_bytes(total_bits)    # 将总比特数转换为字节数

def _perm_inv_to_bytes(perm_inv: List[int], n: int) -> int:
    # Each element in perm_inv is an integer from 0 to n-1.
    # We need ceil(log2(n)) bits to represent each integer.
    if n <= 1:
        bits_per_element = 1
    else:
        bits_per_element = (n - 1).bit_length()
    total_bits = len(perm_inv) * bits_per_element
    return bits_to_bytes(total_bits)

# 测试时间·单位：毫秒
def perf_ms(func, *args, **kwargs):
    t0 = time.perf_counter_ns()
    out = func(*args, **kwargs)
    t1 = time.perf_counter_ns()
    return out, (t1 - t0) / 1e6

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------- benchmark core ----------

def bench_one_setting(
    L: int,
    t_err: int,
    repeat_keygen: int,
    repeat_encdec: int,
    seed: int | None,
) -> Dict[str, Any]:
    """
    For fixed (L, t_err):
      - time keygen repeat_keygen times (fresh keys)
      - use the last generated keypair to time encrypt/decrypt repeat_encdec times
      - measure success rate, sizes, expansion
    """
    # 1) keygen timings + size stats
    pub_last = None
    priv_last = None
    keygen_ms_list: List[float] = []
    pub_bytes_list: List[int] = []
    priv_bytes_list: List[int] = []

    for i in range(repeat_keygen):
        kg_seed = None if seed is None else (seed + 100000 + i)
        (pub, priv), kg_ms = perf_ms(keygen, L, kg_seed)
        n = int(pub["n"])
        k = int(pub["k"])
        keygen_ms_list.append(kg_ms)
        pub_bytes_list.append(_hex_rows_to_bytes(pub["G_pub_hex_rows"], n))
        priv_bytes_list.append(_hex_rows_to_bytes(priv["S_inv_hex_rows"], k) + _perm_inv_to_bytes(priv["perm_inv"], n))
        pub_last, priv_last = pub, priv

    assert pub_last is not None and priv_last is not None
    n = int(pub_last["n"])
    k = int(pub_last["k"])

    keygen_mean, keygen_std = mean_std(keygen_ms_list)
    pub_bytes_mean, pub_bytes_std = mean_std([float(x) for x in pub_bytes_list])
    priv_bytes_mean, priv_bytes_std = mean_std([float(x) for x in priv_bytes_list])

    # 2) encrypt/decrypt timings + success rate (fixed key)
    enc_ms_list: List[float] = []
    dec_ms_list: List[float] = []
    success = 0

    for j in range(repeat_encdec):
        msg_seed = None if seed is None else (seed + 200000 + j)

        # 生成随机消息
        if msg_seed is None:
            m_int = int.from_bytes(os.urandom(bits_to_bytes(k)), "little") & ((1 << k) - 1)
        else:
            m_int = (msg_seed * 0x9E3779B97F4A7C15) & ((1 << k) - 1)

        # 将整数明文转换为二进制字符串
        msg_bits = "".join("1" if ((m_int >> i) & 1) else "0" for i in range(k))    # 从k比特整数转换为k长度的二进制字符串

        enc_seed = None if seed is None else (seed + 300000 + j)
        ct_obj, enc_ms = perf_ms(encrypt, pub_last, msg_bits, t_err, enc_seed)
        enc_ms_list.append(enc_ms)

        pt_obj, dec_ms = perf_ms(decrypt, priv_last, ct_obj)
        dec_ms_list.append(dec_ms)

        if pt_obj["msg_bits"] == msg_bits:
            success += 1

    enc_mean, enc_std = mean_std(enc_ms_list)
    dec_mean, dec_std = mean_std(dec_ms_list)
    success_rate = success / repeat_encdec if repeat_encdec > 0 else 0.0

    # 3) ciphertext expansion & size
    # 转换成向上取整的字节数
    # ct_raw_bytes = bits_to_bytes(n)  # actual ciphertext bits => bytes
    # pt_raw_bytes = bits_to_bytes(k)  # plaintext bits => 
    # 直接转换成小数形式
    ct_raw_bytes = n / 8.0  # actual ciphertext bits => bytes (float)
    pt_raw_bytes = k / 8.0  # plaintext bits => bytes (float)

    # 输出检查
    print(f"Current setting: n={n}, k={k}, ct_raw_bytes={ct_raw_bytes}, pt_raw_bytes={pt_raw_bytes}")
    
    expansion_ratio = n / k

    # measure our stored ciphertext JSON object size (not the "raw ciphertext" size)
    ct_json_bytes = json_size_bytes(ct_obj)

    return {
        "L": L,
        "n": n,
        "k": k,
        "t_err": t_err,
        "repeat_keygen": repeat_keygen,
        "repeat_encdec": repeat_encdec,
        "success_rate": success_rate,

        "keygen_ms_mean": keygen_mean,
        "keygen_ms_std": keygen_std,
        "encrypt_ms_mean": enc_mean,
        "encrypt_ms_std": enc_std,
        "decrypt_ms_mean": dec_mean,
        "decrypt_ms_std": dec_std,

        "pubkey_bytes_mean": pub_bytes_mean,
        "pubkey_bytes_std": pub_bytes_std,
        "privkey_bytes_mean": priv_bytes_mean,
        "privkey_bytes_std": priv_bytes_std,

        "plaintext_bytes_raw": pt_raw_bytes,
        "ciphertext_bytes_raw": ct_raw_bytes,
        "expansion_ratio_n_over_k": expansion_ratio,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--Ls", type=parse_int_list, default=[20],
                    help="comma-separated L list, e.g. 10,20 (default: 20)")
    ap.add_argument("--ts", type=parse_int_list, default=[1, 2, 3],
                    help="comma-separated t_err list, e.g. 1,2,3 (default: 1,2,3)")
    ap.add_argument("--repeat-keygen", type=int, default=10,
                    help="repeat times for key generation (default 10)")
    ap.add_argument("--repeat", type=int, default=10,
                    help="repeat times for encrypt/decrypt per (L,t_err) (default 10)")
    ap.add_argument("--seed", type=int, default=20251213,
                    help="base seed for reproducibility. Use --seed -1 for nondeterministic.")
    ap.add_argument("--out-prefix", type=str,
                    default="hamming_mceliece/results/benchmark_hamming",
                    help="output prefix without extension (default results/benchmark_hamming_YYYYmmdd_HHMMSS)")
    args = ap.parse_args()

    seed = None if args.seed == -1 else int(args.seed)

    env = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }

    results: List[Dict[str, Any]] = []
    # 从命令行获取到L值列表，在此处可调整分块数量
    for L in args.Ls:
        if L <= 0:
            raise ValueError("L must be positive.")
            # 从命令行中获取到t_err值列表，在此处可调整错误权重
        for t_err in args.ts:
            if t_err < 0:
                raise ValueError("t_err must be >= 0.")
            print(f"[benchmark] running L={L}, t_err={t_err} ...")
            row = bench_one_setting(
                L=L,
                t_err=t_err,
                repeat_keygen=args.repeat_keygen,
                repeat_encdec=args.repeat,
                seed=seed,
            )
            # results积累当前L和t_err情况下的结果
            results.append(row)
            print(f"  success_rate={row['success_rate']:.3f} | "
                  f"keygen={row['keygen_ms_mean']:.2f}ms | "
                  f"enc={row['encrypt_ms_mean']:.2f}ms | dec={row['decrypt_ms_mean']:.2f}ms | "
                  f"pub~{int(row['pubkey_bytes_mean'])}B priv~{int(row['privkey_bytes_mean'])}B")

    out_json = args.out_prefix + ".json"
    out_csv = args.out_prefix + ".csv"

    ensure_dir(os.path.dirname(out_json))

    payload = {
        "env": env,
        "params": {
            "Ls": args.Ls,
            "ts": args.ts,
            "repeat_keygen": args.repeat_keygen,
            "repeat_encdec": args.repeat,
            "seed": seed,
        },
        "results": results,
    }

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    fieldnames = [
        "L", "n", "k", "t_err",
        "repeat_keygen", "repeat_encdec", "success_rate",   # 成功率
        "keygen_ms_mean", "keygen_ms_std",  # 密钥生成时间
        "encrypt_ms_mean", "encrypt_ms_std",  # 加密时间
        "decrypt_ms_mean", "decrypt_ms_std",  # 解密时间
        "pubkey_bytes_mean", "pubkey_bytes_std",  # 公钥尺寸
        "privkey_bytes_mean", "privkey_bytes_std",  # 私钥尺寸
        "plaintext_bytes_raw", "ciphertext_bytes_raw",  # 明文密文尺寸（以字节为单位）
        "expansion_ratio_n_over_k", # 理论密文比特扩张率（明文长度n/密文长度k）
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(r)

    print(f"[benchmark] wrote: {out_json}")
    print(f"[benchmark] wrote: {out_csv}")


if __name__ == "__main__":
    main()
