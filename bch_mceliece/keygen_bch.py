# keygen_bch.py
# ============================================================
#  分块 BCH(15,7) 级联码上的 McEliece —— KeyGen（密钥生成）
# ------------------------------------------------------------
#  本文件负责 “密钥生成” 和 必需的 GF(2) 矩阵工具函数。
#
#  - KeyGen 实现：
#      1) 构造原始分块 BCH 码对象 code（提供 encode 等）
#      2) 通过对标准基向量编码，得到原始生成矩阵 G0（k×n）
#      3) 生成随机可逆矩阵 S（k×k）及其逆 S^{-1}
#      4) 生成列置换 P（以 perm 表示）及其逆 perm_inv
#      5) 计算公钥矩阵：G_pub = S * G0 * P
#      6) 封装成 McElieceKeyPair 返回
#
# ============================================================

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import List, Tuple

# 注意：相对导入，保证在 code/ 根目录运行 demo/benchmark 时也能正常导入
from .bch_code import BlockBCH15172


# ============================================================
# GF(2) 线性代数工具：秩 / 逆 / 乘法 / 列置换
# ============================================================

def matrix_rank_mod2(A: List[List[int]]) -> int:
    """
    计算二进制矩阵 A 在 GF(2) 上的秩（rank）。

    输入：
      A: m×n 二进制矩阵（元素只应为 0/1）

    输出：
      rank: GF(2) 上的秩
    """
    # 使用高斯消元法（模 2）
    M = [row[:] for row in A]
    m = len(M)
    n = len(M[0]) if m > 0 else 0

    r = 0  # 当前找到的主元行数
    for c in range(n):
        # 在第 c 列寻找一个主元（值为 1 的行）
        pivot = None
        for i in range(r, m):
            if M[i][c] == 1:
                pivot = i
                break
        if pivot is None:
            continue

        # 将主元行交换到第 r 行
        M[r], M[pivot] = M[pivot], M[r]

        # 用主元行消去其他行的该列（模2：异或）
        for i in range(m):
            if i != r and M[i][c] == 1:
                # 行消元：row_i = row_i XOR row_r
                M[i] = [x ^ y for x, y in zip(M[i], M[r])]

        r += 1
        if r == m:
            break

    return r


def matrix_inverse_mod2(A: List[List[int]]) -> List[List[int]]:
    """
    计算 GF(2) 上方阵 A 的逆矩阵 A^{-1}。

    注意：
    - KeyGen 使用此函数得到 S^{-1}，以便解密时恢复明文

    输入：
      A: k×k 二进制矩阵（可逆）

    输出：
      A_inv: k×k 二进制矩阵，满足 A * A_inv = I（模2）
    """
    k = len(A)
    # 构造增广矩阵 [A | I]
    M = [row[:] + [1 if i == j else 0 for j in range(k)] for i, row in enumerate(A)]

    # 高斯-约旦消元（模2）
    r = 0
    for c in range(k):
        pivot = None
        for i in range(r, k):
            if M[i][c] == 1:
                pivot = i
                break
        if pivot is None:
            raise ValueError("矩阵不可逆（找不到主元）")

        M[r], M[pivot] = M[pivot], M[r]

        # 消去其它行
        for i in range(k):
            if i != r and M[i][c] == 1:
                M[i] = [x ^ y for x, y in zip(M[i], M[r])]

        r += 1

    # 右半部分即为逆矩阵
    A_inv = [row[k:] for row in M]
    return A_inv


def random_invertible_matrix(k: int) -> Tuple[List[List[int]], List[List[int]]]:
    """
    生成 GF(2) 上随机可逆的 k×k 矩阵 S 及其逆 S^{-1}。

    输入：
      k: 方阵维度

    输出：
      (S, S_inv)
    """
    while True:
        S = [[random.randint(0, 1) for _ in range(k)] for _ in range(k)]
        if matrix_rank_mod2(S) == k:
            return S, matrix_inverse_mod2(S)


def mat_mul_mod2(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    """
    GF(2) 上矩阵乘法：C = A * B（模2）。

    输入：
      A: m×k
      B: k×n

    输出：
      C: m×n
    """
    m = len(A)
    k = len(A[0])
    n = len(B[0])

    # 预取 B 的列向量以加速
    B_cols = [[B[i][j] for i in range(k)] for j in range(n)]

    C = [[0] * n for _ in range(m)]
    for i in range(m):
        row = A[i]
        for j in range(n):
            col = B_cols[j]
            # 点积（模2）：sum(row[t]*col[t]) mod 2
            s = 0
            for t in range(k):
                s ^= (row[t] & col[t])
            C[i][j] = s
    return C


def mat_vec_mul_mod2(vec: List[int], M: List[List[int]]) -> List[int]:
    """
    GF(2) 上“行向量 vec × 矩阵 M”的乘法：out = vec * M（模2）。

    约定：
    - 明文 m 是行向量（1×k）
    - 生成矩阵 G 是 k×n
    - 编码为 c = m * G（模2）

    输入：
      vec: 1×k
      M:   k×n

    输出：
      out: 1×n
    """
    k = len(vec)
    n = len(M[0])
    out = [0] * n

    for j in range(n):
        s = 0
        for i in range(k):
            s ^= (vec[i] & M[i][j])
        out[j] = s
    return out


def apply_perm_to_vector(v: List[int], perm_old_to_new: List[int]) -> List[int]:
    """
    对向量 v 应用列置换（old -> new 语义）。

    统一约定：
      perm[old] = new
    即：
      原来在 old 位置的比特，移动到 new 位置

    因此：
      out[new] = v[old]

    输入：
      v: 长度 n 的向量
      perm_old_to_new: 长度 n 的置换数组，perm[old]=new

    输出：
      out: 置换后的向量
    """
    n = len(v)
    out = [0] * n
    for old, new in enumerate(perm_old_to_new):
        out[new] = v[old]
    return out


def apply_perm_to_matrix_cols(G: List[List[int]], perm_old_to_new: List[int]) -> List[List[int]]:
    """
    对矩阵 G 的列执行置换（old -> new）。

    输入：
      G: k×n 二进制矩阵
      perm_old_to_new: 长度 n 的置换

    输出：
      G_perm: k×n
    """
    k = len(G)
    n = len(G[0])
    out = [[0] * n for _ in range(k)]
    for old, new in enumerate(perm_old_to_new):
        for i in range(k):
            out[i][new] = G[i][old]
    return out


def make_intrablock_perm(L: int, n0: int = 15) -> List[int]:
    """
    生成“块内置换”（仅在每个 15-bit 子块内洗牌，不跨块）。

    输入：
      L: 分块数
      n0: 每块长度，BCH(15,7) 固定为 15

    输出：
      perm_old_to_new: 长度 n=L*n0 的置换数组
    """
    n = L * n0
    perm = [0] * n

    for blk in range(L):
        base = blk * n0
        local_old = list(range(base, base + n0))
        local_new = local_old[:]
        random.shuffle(local_new)  # 仅在块内洗牌

        # 构造 old -> new 映射
        for old, new in zip(local_old, local_new):
            perm[old] = new

    return perm


# ============================================================
# 密钥对数据结构
# ============================================================

@dataclass
class McElieceKeyPair:
    """
    McEliece 密钥对对象（分块 BCH 版本）。

    字段含义：
      code:
        分块 BCH 编码对象，包含：
          - n: 总码长（15L）
          - k: 总信息位长度（7L）
          - encode(msg_bits) 等
      S / S_inv:
        GF(2) 上随机可逆矩阵及其逆（k×k）
      perm / perm_inv:
        列置换及其逆（长度 n），满足 perm[old]=new
      G_pub:
        公钥生成矩阵 G_pub = S * G0 * P（k×n）
      t_errors:
        设计参数 t0：每个 15-bit 子块最大注入错误数（用于 Encrypt）
        注意：Encrypt 已迁移到 encrypt_bch.py，但该参数仍属于 keypair 的公共配置
    """
    code: BlockBCH15172
    S: List[List[int]]
    S_inv: List[List[int]]
    perm: List[int]
    perm_inv: List[int]
    G_pub: List[List[int]]
    t_errors: int


# ============================================================
# KeyGen：生成密钥对
# ============================================================

def keygen(L: int, t_errors: int = 2) -> McElieceKeyPair:
    """
    生成分块 BCH(15,7) McEliece 密钥对。

    输入：
      L:
        分块数量。总码长 n = 15L，总信息位长度 k = 7L。
      t_errors:
        每个 15-bit 子块的最大注入错误数 t0。对 BCH(15,7) 通常取 2。

    输出：
      McElieceKeyPair

    公钥构造流程：
      1) 构造分块 BCH 编码器 code
      2) 通过编码标准基向量得到原始生成矩阵 G0（k×n）
      3) 生成随机可逆矩阵 S（k×k）
      4) 生成块内置换 perm（长度 n）
      5) 计算 G_pub = S * G0 * P（P 用列置换实现）
    """
    # 1) 构造分块 BCH 级联码对象
    code = BlockBCH15172(L=L)
    n = code.n
    k = code.k

    # 2) 构造原始生成矩阵 G0（k×n）
    G0 = []
    for i in range(k):
        e_i = [0] * k
        e_i[i] = 1
        cw = code.encode(e_i)
        G0.append(cw)

    # 3) 随机可逆矩阵 S 及其逆
    S, S_inv = random_invertible_matrix(k)

    # 4) 块内置换 perm（old->new）及逆 perm_inv（new->old）
    perm = make_intrablock_perm(L=L, n0=15)
    perm_inv = [0] * n
    for old, new in enumerate(perm):
        perm_inv[new] = old

    # 5) 计算公钥矩阵：G_pub = S * G0，然后对列执行置换
    G_tmp = mat_mul_mod2(S, G0)                 # k×n
    G_pub = apply_perm_to_matrix_cols(G_tmp, perm)

    return McElieceKeyPair(
        code=code,
        S=S,
        S_inv=S_inv,
        perm=perm,
        perm_inv=perm_inv,
        G_pub=G_pub,
        t_errors=t_errors
    )
