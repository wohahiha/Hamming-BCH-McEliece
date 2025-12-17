from __future__ import annotations
from typing import List, Tuple, Optional
import secrets
import random

HAMMING_N = 15
HAMMING_K = 11
HAMMING_T = 1

PARITY_POS = [1, 2, 4, 8]  # 1-indexed
DATA_POS = [3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15]

def _parity(x: int) -> int:
    return x.bit_count() & 1

# Precompute parity masks
_PARITY_MASKS = {}
for p in PARITY_POS:
    mask = 0
    for i in range(1, HAMMING_N + 1):
        if i != p and (i & p):
            mask |= 1 << (i - 1)
    _PARITY_MASKS[p] = mask

def bits_str_to_int(s: str) -> int:
    s = s.strip()
    x = 0
    for i, ch in enumerate(s):
        if ch == "1":
            x |= 1 << i
        elif ch == "0":
            pass
        else:
            raise ValueError("Bitstring must contain only '0'/'1'.")
    return x

def int_to_bits_str(x: int, nbits: int) -> str:
    return "".join("1" if ((x >> i) & 1) else "0" for i in range(nbits))

def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for j, src in enumerate(perm):
        inv[src] = j
    return inv

def apply_perm(row_vec: int, perm: List[int]) -> int:
    out = 0
    for j, src in enumerate(perm):
        if (row_vec >> src) & 1:
            out |= 1 << j
    return out

def hamming15_encode(msg11: int) -> int:
    cw = 0
    for j, pos in enumerate(DATA_POS):
        if (msg11 >> j) & 1:
            cw |= 1 << (pos - 1)
    for p in PARITY_POS:
        bit = _parity(cw & _PARITY_MASKS[p])
        if bit:
            cw |= 1 << (p - 1)
    return cw

def hamming15_syndrome(r15: int) -> int:
    s = 0
    for j in range(4):
        val = 0
        for i in range(1, HAMMING_N + 1):
            if i & (1 << j):
                val ^= (r15 >> (i - 1)) & 1
        s |= val << j
    return s

def hamming15_decode(r15: int) -> Tuple[int, int, int]:
    s = hamming15_syndrome(r15)
    corrected = r15
    if s != 0:
        pos = s
        if 1 <= pos <= HAMMING_N:
            corrected ^= 1 << (pos - 1)
    msg = 0
    for j, pos in enumerate(DATA_POS):
        if (corrected >> (pos - 1)) & 1:
            msg |= 1 << j
    return msg, corrected, s

def build_base_G_rows() -> List[int]:
    return [hamming15_encode(1 << i) for i in range(HAMMING_K)]

def build_block_diag_G_rows(L: int) -> List[int]:
    if not isinstance(L, int) or L <= 0:
        raise ValueError("L must be a positive integer.")
    base = build_base_G_rows()
    rows: List[int] = []
    for b in range(L):
        shift = b * HAMMING_N
        for i in range(HAMMING_K):
            rows.append(base[i] << shift)
    return rows

def block_decode(r: int, L: int) -> Tuple[int, int, List[int]]:
    if not isinstance(L, int) or L <= 0:
        raise ValueError("L must be a positive integer.")
    msg = 0
    corrected = 0
    syndromes: List[int] = []
    for b in range(L):
        r_block = (r >> (b * HAMMING_N)) & ((1 << HAMMING_N) - 1)
        m_block, c_block, s = hamming15_decode(r_block)
        msg |= m_block << (b * HAMMING_K)
        corrected |= c_block << (b * HAMMING_N)
        syndromes.append(s)
    return msg, corrected, syndromes

def vec_mul_mat(v: int, M_rows: List[int]) -> int:
    acc = 0
    x = v
    while x:
        lsb = x & -x
        i = lsb.bit_length() - 1
        acc ^= M_rows[i]
        x ^= lsb
    return acc

def mat_left_mul(A_rows: List[int], B_rows: List[int], k: int) -> List[int]:
    out: List[int] = []
    for arow in A_rows:
        acc = 0
        x = arow
        while x:
            lsb = x & -x
            i = lsb.bit_length() - 1
            acc ^= B_rows[i]
            x ^= lsb
        out.append(acc)
    return out

def invert_matrix(rows: List[int], size: int) -> List[int]:
    if len(rows) != size:
        raise ValueError("rows length must equal size.")
    mask = (1 << size) - 1
    aug = [(rows[i] & mask) | (1 << (size + i)) for i in range(size)]
    for col in range(size):
        pivot = None
        for r in range(col, size):
            if (aug[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            raise ValueError("matrix is singular")
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(size):
            if r != col and ((aug[r] >> col) & 1):
                aug[r] ^= aug[col]
    inv = [(aug[i] >> size) & mask for i in range(size)]
    return inv

def random_invertible_matrix(size: int, rng: Optional[random.Random] = None):
    if not isinstance(size, int) or size <= 0:
        raise ValueError("size must be a positive integer.")
    rr = rng if rng is not None else secrets.SystemRandom()
    while True:
        rows = [rr.getrandbits(size) for _ in range(size)]
        try:
            inv = invert_matrix(rows, size)
            return rows, inv
        except ValueError:
            continue

def random_error_vector(nbits: int, weight: int, rng: Optional[random.Random] = None) -> int:
    if not isinstance(nbits, int) or nbits <= 0:
        raise ValueError("nbits must be positive.")
    if not isinstance(weight, int) or weight < 0 or weight > nbits:
        raise ValueError("weight must be int in [0, nbits].")
    rr = rng if rng is not None else secrets.SystemRandom()
    positions = rr.sample(range(nbits), weight)
    e = 0
    for p in positions:
        e |= 1 << p
    return e
