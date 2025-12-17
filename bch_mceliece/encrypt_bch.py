# encrypt_bch.py
# ============================================================
#  分块 BCH(15,7) 级联码上的 McEliece —— Encrypt（加密/编码）
# ------------------------------------------------------------
#  本文件实现 McEliece 加密流程（对应 keygen_bch.py 的密钥结构）：
#
#    1) 使用公钥矩阵 G_pub 对明文进行编码：c0 = m * G_pub
#    2) 按“每个 15-bit 子块最多 t0 个错误”的模型注入错误 e
#    3) 输出密文：c = c0 + e（逐位 XOR）
#
# ============================================================

from __future__ import annotations

import random
from typing import List, Tuple

# 从 keygen_bch 导入：
# - 密钥对类型 McElieceKeyPair（携带 G_pub、t_errors、code 参数等）
# - mat_vec_mul_mod2：用于实现 m * G_pub
from .keygen_bch import McElieceKeyPair, mat_vec_mul_mod2


# ============================================================
# 辅助函数：受限注错（每块≤t0）
# ============================================================

def inject_block_limited_errors(n: int, L: int, n0: int, t0: int) -> Tuple[List[int], int]:
    """
    构造错误向量 e，满足“每块最多 t0 个错误”。

    输入：
      n: 总长度（应为 15L）
      L: 分块数
      n0: 每块长度（BCH 固定 15）
      t0: 每块最大错误数

    输出：
      (e, t_total)
      e: 长度 n 的 0/1 向量
      t_total: 本次注入的错误总数（整数）
    """
    e = [0] * n
    t_total = 0

    for blk in range(L):
        # 每块注入 0..t0 个错误
        t_blk = random.randint(0, t0)
        t_total += t_blk

        if t_blk == 0:
            continue

        start = blk * n0
        end = (blk + 1) * n0

        # 在该块的 n0 个位置中不放回抽样 t_blk 个错误位置
        positions = random.sample(range(start, end), t_blk)
        for pos in positions:
            e[pos] = 1

    return e, t_total


# ============================================================
# Encrypt：加密（编码 + 注错）
# ============================================================

def encrypt(kp: McElieceKeyPair, msg_bits: List[int]) -> Tuple[List[int], int]:
    """
    McEliece 加密。

    输入：
      kp:
        由 keygen_bch.keygen() 生成的 McElieceKeyPair，内含：
          - 公钥生成矩阵 G_pub（k×n）
          - 分块码参数 code.n / code.k
          - 每块最大错误数 t_errors (=t0)
      msg_bits:
        明文比特向量（长度 k）

    输出：
      (cipher_bits, t_total)
      cipher_bits: 密文向量（长度 n）
      t_total: 本轮实际注入的错误总数

    加密步骤：
      1) 编码（无错码字）：c0 = m * G_pub
      2) 构造错误向量 e（每块≤t0）
      3) 密文：c = c0 XOR e
    """
    # -------------------- 0) 输入检查 --------------------
    if kp is None:
        raise ValueError("kp 不能为空（需要由 keygen() 生成的密钥对）")

    n = kp.code.n
    k = kp.code.k

    if msg_bits is None or len(msg_bits) != k:
        raise ValueError(f"明文长度必须为 k={k}，但收到 len(msg_bits)={0 if msg_bits is None else len(msg_bits)}")

    t0 = int(kp.t_errors)
    if t0 < 0:
        raise ValueError("t0（每块最大错误数）必须为非负整数")

    # -------------------- 1) 编码：c0 = m * G_pub --------------------
    # 这里的 mat_vec_mul_mod2 是 GF(2) 行向量乘矩阵
    c0 = mat_vec_mul_mod2(msg_bits, kp.G_pub)

    # -------------------- 2) 注错：每块≤t0 --------------------
    # 分块参数：BCH(15,7) 固定 n0=15，分块数 L = n / 15
    n0 = 15
    if n % n0 != 0:
        raise ValueError(f"当前实现假设 n 可被 15 整除，但 n={n}")

    L = n // n0

    e, t_total = inject_block_limited_errors(n=n, L=L, n0=n0, t0=t0)

    # -------------------- 3) 密文：c = c0 XOR e --------------------
    cipher = [a ^ b for a, b in zip(c0, e)]
    return cipher, t_total

