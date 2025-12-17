# run_bch_benchmark.py
# ============================================================
#  分块 BCH McEliece 变体 —— 基准实验（Benchmark）脚本
# ============================================================
#
# 【本文件在整个项目中的角色】
# ------------------------------------------------------------
# 1. run_bch_demo.py：
#    - 只跑 1 次 KeyGen / Encrypt / Decrypt
#    - 用于“系统是否能正常工作”的快速验证
#
# 2. run_benchmark.py（本文件）：
#    - 批量重复实验（repetitions 次）
#    - 统计平均时间、标准差、成功率、错误分布
#    - 生成 CSV / JSON，作为【报告与画图】的唯一数据来源
#
# 3. MATLAB main.m：
#    - 只负责读 results/ 里的 CSV
#    - 不做任何实验，只画图
#
# ============================================================
# 运行方式（在 code/ 目录下）：
# ------------------------------------------------------------
#   python run_benchmark.py
#
# 输出文件：
#   code/bch_mceliece/results/benchmark_bch_raw.csv
#   code/bch_mceliece/results/benchmark_bch_summary.json
# ============================================================


# ===================== 标准库导入 ============================
import os
import time
import json
import csv
import random
import statistics
from typing import Dict, Any, List


# ===================== 项目内部模块导入 ======================
# 注意：
# - run_benchmark.py 位于 code/ 根目录
# - bch_mceliece/ 与其同级
# - 只要 bch_mceliece/__init__.py 存在，下面的导入就是稳定的

from .bch_mceliece.keygen_bch import keygen
from .bch_mceliece.encrypt_bch import encrypt
from .bch_mceliece.decrypt_bch import decrypt
from .bch_mceliece.security_bch import estimate_security_bits


# ============================================================
# 路径与输出文件配置
# ============================================================

# 当前文件所在目录（即 code/）
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# 分块 BCH 模块目录：code/bch_mceliece/
BCH_DIR = os.path.join(ROOT_DIR, "bch_mceliece")

# 结果统一输出到：code/bch_mceliece/results/
RESULTS_DIR = os.path.join(BCH_DIR, "results")

# 原始逐轮数据（每一行 = 一次实验）
CSV_PATH = os.path.join(RESULTS_DIR, "benchmark_bch_raw.csv")

# 汇总统计（每个参数配置一条记录）
JSON_PATH = os.path.join(RESULTS_DIR, "benchmark_bch_summary.json")


# ============================================================
# 工具函数：目录与 CSV 初始化
# ============================================================

def _ensure_dir(path: str):
    """
    确保目录存在。
    若目录不存在则创建；若已存在则不做任何事。
    """
    os.makedirs(path, exist_ok=True)


def _ensure_csv_header(csv_path: str):
    """
    确保 CSV 文件存在且包含表头。

    这样做的目的：
    - MATLAB 画图时可以通过列名索引字段
    - 避免多次追加写入时表头重复
    """

    header = [
        # 方案标识（为未来 BCH / Hamming 共用留接口）
        "scheme",

        # 系统参数
        "L",                # 分块数
        "t0",               # 每块最大错误数
        "n", "k",            # 码长 / 信息位长度

        # 单次实验统计
        "t_total",          # 实际注入错误总数
        "keygen_s",         # KeyGen 时间（秒）
        "enc_s",            # Encrypt 时间（秒）
        "dec_s",            # Decrypt 时间（秒）
        "success",          # 是否解密成功（1/0）

        # 系统规模指标
        "pk_bits",          # 公钥大小（bit）
        "priv_bits",        # 私钥大小（bit）
        "rate_n_over_k",    # 密文扩张率 n/k

        # 安全性估算（bit，粗略 ISD 指标）
        "sec_bits_est"      # 估算的安全位（bit）
    ]

    # 若文件不存在，或存在但为空，则写入表头
    if (not os.path.exists(csv_path)) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)


# ============================================================
# 工具函数：生成随机明文
# ============================================================

def _rand_bits(length: int):
    """
    生成长度为 length 的随机二进制明文向量。
    每一位均为 0 或 1。
    """
    return [random.randint(0, 1) for _ in range(length)]


# ============================================================
# 单次实验（最重要的原子操作）
# ============================================================

def run_single(L: int, t0: int) -> Dict[str, Any]:
    """
    执行“一次完整的 McEliece 流程”：
        KeyGen -> Encrypt -> Decrypt

    并返回：
        - 时间消耗
        - 是否解密成功
        - 实际注入错误数
        - 系统规模与安全性指标

    这是 benchmark 的“最小实验单元”。
    """

    # ---------------- 1) KeyGen ----------------
    t_start = time.time()
    kp = keygen(L=L, t_errors=t0)
    keygen_s = time.time() - t_start

    # 码参数
    n = kp.code.n
    k = kp.code.k

    # 公钥 / 私钥大小估算（与前面分析保持一致）
    pk_bits = k * n
    priv_bits = (k ** 2) * 2 + n

    # 扩张率
    rate = n / k

    # ---------------- 2) Encrypt ----------------
    msg = _rand_bits(k)

    t_start = time.time()
    cipher, t_total = encrypt(kp, msg)  # encrypt 返回 (cipher, t_total)
    enc_s = time.time() - t_start

    # ---------------- 3) Decrypt ----------------
    t_start = time.time()
    msg_hat = decrypt(kp, cipher)
    dec_s = time.time() - t_start

    success = int(msg_hat == msg)

    # ---------------- 4) 安全性估算 ----------------
    # 计算的是在每次实验中，基于 实际注入错误数 t_total 和 码长 n 的一个 通用信息论安全性估算
    # 这个值可以作为对通用攻击（如 ISD）复杂度的 一个参考或基础指标 ，但 estimate_stern_cascade_bch 提供了更针对性的 ISD 攻击复杂度估算，所以这里不直接使用
    sec_bits = estimate_security_bits(n, t_total)

    return {
        "scheme": "bch",
        "L": L,
        "t0": t0,
        "n": n,
        "k": k,
        "t_total": t_total,
        "keygen_s": keygen_s,
        "enc_s": enc_s,
        "dec_s": dec_s,
        "success": success,
        "pk_bits": pk_bits,
        "priv_bits": priv_bits,
        "rate_n_over_k": rate,
        "sec_bits_est": sec_bits
    }


# ============================================================
# Benchmark 主逻辑
# ============================================================

def benchmark(configs: List[Dict[str, int]], repetitions: int = 50):
    """
    对多个参数配置 (L, t0) 执行 benchmark。

    参数：
        configs      : [{'L':10,'t0':2}, ...]
        repetitions  : 每个配置重复实验次数

    输出：
        - CSV：逐轮原始数据（画图用）
        - JSON：按配置汇总的均值/标准差（报告查表用）
    """

    _ensure_dir(RESULTS_DIR)
    _ensure_csv_header(CSV_PATH)

    summary_rows = []

    # 遍历每一组参数配置
    for cfg in configs:
        L = cfg["L"]
        t0 = cfg["t0"]

        print(f"\n========== Benchmark: L={L}, t0={t0}, reps={repetitions} ==========\n")

        rows = []

        # ---------- 重复实验 ----------
        for i in range(repetitions):
            r = run_single(L=L, t0=t0)
            rows.append(r)

            # 逐轮打印，便于发现异常
            print(
                f"[{i+1:>4}/{repetitions}] "
                f"succ={r['success']}  "
                f"t_total={r['t_total']:>3}  "
                f"keygen={r['keygen_s']:.4f}s "
                f"enc={r['enc_s']:.4f}s "
                f"dec={r['dec_s']:.4f}s"
            )

            # 立即写入 CSV，避免中途异常导致数据丢失
            with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    r["scheme"],
                    r["L"], r["t0"],
                    r["n"], r["k"],
                    r["t_total"],
                    r["keygen_s"], r["enc_s"], r["dec_s"],
                    r["success"],
                    r["pk_bits"], r["priv_bits"],
                    r["rate_n_over_k"],
                    r["sec_bits_est"]
                ])

        # ---------- 汇总统计 ----------
        def _mean_std(arr):
            if len(arr) == 1:
                return {"mean": arr[0], "std": 0.0}
            return {
                "mean": statistics.mean(arr),
                "std": statistics.stdev(arr)
            }

        summary = {
            "scheme": "bch",
            "L": L,
            "t0": t0,
            "repetitions": repetitions,
            "keygen_s": _mean_std([x["keygen_s"] for x in rows]),
            "enc_s": _mean_std([x["enc_s"] for x in rows]),
            "dec_s": _mean_std([x["dec_s"] for x in rows]),
            "success_rate": _mean_std([x["success"] for x in rows]),
            "t_total": _mean_std([x["t_total"] for x in rows]),
            "sec_bits_est": _mean_std([x["sec_bits_est"] for x in rows]),
        }

        summary_rows.append(summary)

        # 每个配置跑完就写 JSON
        with open(JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(summary_rows, f, indent=2, ensure_ascii=False)

        print("\n---- 汇总 ----")
        print(f"成功率均值 = {summary['success_rate']['mean']:.4f}")
        print(f"t_total 均值 = {summary['t_total']['mean']:.2f}")
        print(f"安全性估算均值 = {summary['sec_bits_est']['mean']:.2f} bit")


# ============================================================
# 程序入口
# ============================================================

def main():
    """
    在这里定义“实验计划”。
    改参数，只需改这里。
    """

    configs = [
        {"L": 5,  "t0": 2},
        {"L": 10, "t0": 2},
        {"L": 15, "t0": 2},
        {"L": 20, "t0": 2},
    ]

    repetitions = 200   # 报告级别建议 >= 50；你现在用 200 很合适

    benchmark(configs, repetitions)


if __name__ == "__main__":
    main()
