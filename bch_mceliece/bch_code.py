# bch_code.py
# ============================================================
#  分块 BCH(15,7) 级联码（Block-BCH）编码/译码实现
#  ------------------------------------------------------------
#  本文件实现：
#   1) GF(2)[x] 多项式的基本运算（乘法、模多项式）
#   2) BCH(15,7) 的系统编码（systematic encoding）
#   3) 单块译码（此处采用“穷举最近邻/最小汉明距离”解码）
#   4) 分块级联：把 L 个 BCH(15,7) 串联成总码 (15L, 7L)
#   5) BlockBCH15172 类封装，以及生成矩阵构造
#
#  说明：
#   - 严格的 BCH 代数译码（例如 Berlekamp–Massey / Chien search）
#     可以实现 O(n^2) 左右复杂度的纠错。
#   - 但这里每块 k0=7，码字数仅 2^7=128，穷举最近邻译码成本极低，
#     便于实现与验证正确性，且对小规模的 L（如 10,20,30）完全可行。
# ============================================================

import math
from dataclasses import dataclass

# ============================================================
# 一、GF(2)[x] 多项式运算（用整数比特表示多项式）
# ============================================================
# 表示约定：
#   用一个非负整数 p_bits 表示多项式 p(x)：
#     p_bits 的第 i 位（从低到高）表示 x^i 的系数（0/1）。
#   例如：p(x) = x^3 + x + 1  -> bits: 1 + 2 + 8 = 11 (0b1011)
# ============================================================

def poly_deg(p_bits: int) -> int:
    """
    返回多项式 p(x) 的次数 deg(p)。
    输入：
      p_bits: 整数比特表示的多项式
    输出：
      deg: 最高非零项次数；若 p=0 则返回 -1
    """
    if p_bits == 0:
        return -1
    # bit_length()-1 正好是最高位索引
    return p_bits.bit_length() - 1


def poly_mul(a: int, b: int) -> int:
    """
    GF(2)[x] 上多项式乘法：res(x) = a(x) * b(x)
    输入：
      a, b: 整数比特表示
    输出：
      res: 整数比特表示
    """
    res = 0
    x = a
    y = b
    while y:
        if y & 1:
            # 若当前位为 1，则累加（GF(2)加法为 XOR）
            res ^= x
        y >>= 1
        x <<= 1
    return res


def poly_mod(a: int, mod_poly: int) -> int:
    """
    计算 a(x) mod mod_poly(x) 的余数。
    输入：
      a: 被除多项式
      mod_poly: 模多项式（除式）
    输出：
      r: 余数，次数 < deg(mod_poly)
    """
    r = a
    dm = poly_deg(mod_poly)
    while poly_deg(r) >= dm:
        shift = poly_deg(r) - dm
        r ^= (mod_poly << shift)
    return r


# ============================================================
# 二、BCH(15,7) 参数与系统编码
# ============================================================
# BCH(15,7) 的基础参数：
#   n0 = 15：单块码长
#   k0 = 7 ：单块信息位
#   R0 = 8 ：单块校验位
#
# 系统编码（systematic encoding）：
#   目标码字 c(x) 满足：
#     c(x) = m(x)*x^R0 + r(x)
#   其中 r(x) = (m(x)*x^R0) mod g(x)
#   因而 c(x) 可被 g(x) 整除，即为循环码码字。
# ============================================================

# 生成多项式 g(x)=x^8 + x^7 + x^6 + x^4 + 1 的比特表示：
#  - x^8 对应 (1<<8)
#  - x^7 对应 (1<<7)
#  - x^6 对应 (1<<6)
#  - x^4 对应 (1<<4)
#  - 常数项 1
G_POLY_15_7 = (1 << 8) | (1 << 7) | (1 << 6) | (1 << 4) | 1

# 单块参数
N0 = 15
K0 = 7
R0 = N0 - K0  # 8 parity bits


def bits_to_int(bits):
    """
    将低位在前（little-endian）的比特列表转换为整数。
    约定：
      bits[i] 对应 x^i 的系数（或向量的第 i 位）
    示例：
      bits=[1,0,1] -> 1 + 4 = 5
    """
    val = 0
    for i, b in enumerate(bits):
        if b:
            val |= (1 << i)
    return val


def int_to_bits(x, length):
    """
    将整数 x 转为长度为 length 的比特列表（低位在前）。
    """
    return [(x >> i) & 1 for i in range(length)]


def bch15_7_encode_block(msg_bits):
    """
    对单个 BCH(15,7) 分块进行系统编码。
    输入：
      msg_bits: 长度 K0=7 的消息比特
    输出：
      code_bits: 长度 N0=15 的码字比特（系统形式：前/后位取决于你的位序约定）
    """
    assert len(msg_bits) == K0

    # 1) 消息多项式 m(x)
    m_poly = bits_to_int(msg_bits)

    # 2) 乘 x^R0：相当于左移 R0 位
    shifted = m_poly << R0

    # 3) 求余数 rem(x)
    rem = poly_mod(shifted, G_POLY_15_7)

    # 4) 系统码字 c(x) = shifted + rem
    c_poly = shifted ^ rem

    # 输出 N0 位码字
    return int_to_bits(c_poly, N0)


# ============================================================
# 三、单块译码：穷举最近邻（最小汉明距离）
# ============================================================
# 译码策略：
#   - 预先枚举所有 2^K0=128 个合法码字
#   - 对接收向量 r，计算与每个码字的汉明距离 d
#   - 选择距离最小者
# ============================================================

_SINGLE_BLOCK_CODEWORDS = []
_SINGLE_BLOCK_MESSAGES = []

# 预计算所有消息及对应码字（整数形式）
for m_int in range(1 << K0):
    msg = int_to_bits(m_int, K0)
    cw = bch15_7_encode_block(msg)
    _SINGLE_BLOCK_MESSAGES.append(m_int)
    _SINGLE_BLOCK_CODEWORDS.append(bits_to_int(cw))


def bch15_7_decode_block(recv_bits):
    """
    单块译码（穷举最近邻）。
    输入：
      recv_bits: 长度 N0=15 的接收比特
    输出：
      m_hat_bits: 估计的消息比特（长度 7）
      c_hat_bits: 估计的码字比特（长度 15）
      best_d: recv 与 c_hat 的最小汉明距离
    """
    r_int = bits_to_int(recv_bits)

    best_d = N0 + 1
    best_m = 0
    best_c = 0

    # 枚举所有码字，选距离最小者
    for m_int, c_int in zip(_SINGLE_BLOCK_MESSAGES, _SINGLE_BLOCK_CODEWORDS):
        # XOR 后的 1 的个数就是汉明距离
        d = (r_int ^ c_int).bit_count()
        if d < best_d:
            best_d = d
            best_m = m_int
            best_c = c_int
            # 如果距离=0，完全匹配，可提前停止
            if d == 0:
                break

    return int_to_bits(best_m, K0), int_to_bits(best_c, N0), best_d


# ============================================================
# 四、分块级联编码/译码（L 个 BCH(15,7) 串联）
# ============================================================
# 将总消息长度 k = 7L 分成 L 个长度 7 的块；
# 每块独立编码为 15 位；
# 最终码字长度 n = 15L。
# ============================================================

def block_encode(msg_bits, L):
    """
    分块编码：输入长度 K0*L 的消息，输出长度 N0*L 的码字。
    """
    assert len(msg_bits) == K0 * L
    out = []
    for i in range(L):
        block = msg_bits[i * K0:(i + 1) * K0]
        out.extend(bch15_7_encode_block(block))
    return out


def block_decode(code_bits, L):
    """
    分块译码：逐块最近邻译码，并累加每块最小距离。
    输入：
      code_bits: 长度 N0*L
    输出：
      msg_hat_bits: 长度 K0*L
      total_dist: 所有块 best_d 之和
    """
    assert len(code_bits) == N0 * L
    msg = []
    total_dist = 0
    for i in range(L):
        block = code_bits[i * N0:(i + 1) * N0]
        m_hat, _, d = bch15_7_decode_block(block)
        msg.extend(m_hat)
        total_dist += d
    return msg, total_dist


# ============================================================
# 五、BlockBCH15172：分块码封装
# ============================================================
# 该类对外提供：
#   - n, k：总码长/总信息长度
#   - encode/decode：整体编码/译码接口
#   - generator_matrix_block：构造原始生成矩阵 G0（k×n）
# ============================================================

@dataclass
class BlockBCH15172:
    L: int
    n0: int = N0
    k0: int = K0

    @property
    def n(self) -> int:
        """总码长 n = 15 * L"""
        return self.n0 * self.L

    @property
    def k(self) -> int:
        """总信息长度 k = 7 * L"""
        return self.k0 * self.L

    def encode(self, msg_bits):
        """
        总体编码接口：输入长度 k 的比特向量，输出长度 n 的码字。
        """
        return block_encode(msg_bits, self.L)

    def decode(self, code_bits):
        """
        总体译码接口：输入长度 n 的比特向量，输出长度 k 的消息估计。
        """
        return block_decode(code_bits, self.L)[0]

    def generator_matrix_block(self):
        """
        构造原始生成矩阵 G0（k×n），用于 McEliece 公钥生成：
          G_pub = S * G0 * P
        """
        G = []
        for i in range(self.k):
            basis = [0] * self.k
            basis[i] = 1
            cw = self.encode(basis)
            G.append(cw)
        return G
