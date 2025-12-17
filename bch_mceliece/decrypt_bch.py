# decrypt_bch.py
# ============================================================
#  分块 BCH McEliece 的解密模块（Decrypt）
#  ------------------------------------------------------------
#  本文件实现 McEliece 解密流程（对应 keygen_bch.py 的密钥结构）：
#
#    公钥：G_pub = S * G0 * P
#    密文：c = m * G_pub + e
#         = m * (S*G0*P) + e
#
#  解密目标：从 c 恢复明文 m
#
#  私钥信息：
#    - P^{-1}（以 perm_inv 数组形式存储）
#    - 原始码结构：G0 对应的分块 BCH(15,7) 级联码（code 对象可译码）
#    - S^{-1}（GF(2) 上 k×k）
#
#  解密步骤：
#    1) 去置换：c' = c * P^{-1}
#       由于 c = (m*S*G0*P) + e，
#       则 c' = (m*S*G0) + (e * P^{-1})
#
#    2) 用私钥码译码（纠错）：
#       对 c' 进行分块 BCH 译码，得到 mS（即“被 S 混淆后的消息”）
#
#    3) 去线性混淆：m = (mS) * S^{-1}
#
#  注意：
#    - 这里仍使用 GF(2) 行向量乘法约定：
#        m 是 1×k 行向量
#        S^{-1} 是 k×k
#        m = mS * S^{-1}
#
# ============================================================


from .keygen_bch import apply_perm_to_vector, mat_vec_mul_mod2


def decrypt(kp, ciphertext):
    """
    McEliece 解密函数（对应分块 BCH 变体）。

    输入：
      kp: McElieceKeyPair（私钥持有者的 keypair）
          需要包含：
            - kp.perm_inv : 列置换的逆（长度 n）
            - kp.code     : 原始分块 BCH 码对象（可译码）
            - kp.S_inv    : GF(2) 上 k×k 可逆矩阵 S 的逆
      ciphertext: 密文向量（长度 n 的 0/1 列表）

    输出：
      msg: 解密得到的明文向量（长度 k 的 0/1 列表）
    """

    # 去掉列置换 P：把密文向量恢复到“未置换的码字坐标系”
    c_unperm = apply_perm_to_vector(ciphertext, kp.perm_inv)

    # 使用 BCH 译码纠错：恢复“被 S 混淆后的消息” mS
    msg_scrambled = kp.code.decode(c_unperm)

    # 乘以 S^{-1} 得到明文 m
    msg = mat_vec_mul_mod2(msg_scrambled, kp.S_inv)

    return msg
