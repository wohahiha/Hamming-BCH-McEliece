import math

# 计算二进制熵 H(p) = -p*log2(p) - (1-p)*log2(1-p)
def binary_entropy(p: float) -> float:
    """
    计算二元熵函数 H(p) = -p*log2(p) - (1-p)*log2(1-p)。
    用于估算信息集解码算法的复杂度。
    """
    if p < 0 or p > 1:
        raise ValueError("p must be between 0 and 1.")  # 概率p必须在0到1之间
    if p == 0 or p == 1:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


# 估算针对 Prange 信息集解码 (ISD) 算法的安全性级别（以比特为单位）。Prange 算法是 ISD 算法中最基本的一个版本。
def estimate_prange_complexity(n: int, k: int, t: int) -> float:
    """
    估算针对Prange信息集解码（ISD）算法的安全性（比特）。
    Prange算法是一种基本的ISD算法。更先进的算法具有更低的复杂度。

    复杂度近似为 log2(n 选 t)。

    参数：
        n: 码长。
        k: 码维度（消息长度）。
        t: 可纠正的错误数量。

    返回：
        估算的安全性（比特）。
    """
    if t < 0 or t > n:
        raise ValueError("t must be between 0 and n.")   # 纠错能力t必须在0到n之间
    if n < k:
        raise ValueError("n must be greater than or equal to k.")   # 码字长度n必须大于等于信息长度k

    # 估算方法 ：Prange 算法的复杂度主要由选择 t 个错误位置的组合数决定，即 C(n, t) 。因此，其安全性估算为 log2(C(n, t)) 比特。
    try:
        complexity = math.comb(n, t)
        if complexity == 0: # 对于有效的 n, t 不应该发生
            return 0.0
        return math.log2(complexity)
    # 当 C(n, t) 非常大时，直接计算 log2(C(n, t)) 可能会导致溢出。
    # 为了处理这种情况，我们使用一个循环来计算 log2(C(n, t)) 的近似值。
    except OverflowError:
        log_complexity = 0.0
        # 组合数 C(n, t) = n! / (t!(n - t)!) = (n - t + 1) * (n - t + 2) * ... * n! / t!、
        # 利用对数的性质进行计算
        for i in range(t):
            log_complexity += math.log2(n - i)
            log_complexity -= math.log2(i + 1)
        return log_complexity


# 这个函数估算针对 Stern 信息集解码 (ISD) 算法的安全性级别（以比特为单位）。Stern 算法是 ISD 算法的一个变体，通常用于 McEliece 密码系统。
def estimate_stern_complexity(n: int, k: int, t: int) -> float:
    """
    估算针对Stern信息集解码（ISD）算法的安全性（比特）。
    这个近似值常用于Stern算法和其他现代ISD变体。

    复杂度近似为 (n - k) * H(t / (n - k))。

    参数：
        n: 码长。
        k: 码维度（消息长度）。
        t: 可纠正的错误数量。

    返回：
        估算的安全性（比特）（操作数的log2）。
    """
    if t < 0 or t > n:
        raise ValueError("t must be between 0 and n.")
    if n < k:
        raise ValueError("n must be greater than or equal to k.")
    if n - k == 0: # 避免 n == k 时的除以零错误
        return 0.0

    p = t / (n - k)
    if p < 0 or p > 1:
        raise ValueError("For this Stern's ISD complexity approximation, t should generally be <= n - k.")

    return (n - k) * binary_entropy(p)


def estimate_ball_collision_complexity(n: int, k: int, t: int) -> float:
    """
    估算针对Ball-Collision信息集解码（ISD）算法的安全性（比特）。
    这是一个简化的近似值，因为精确的复杂度取决于优化Ball-Collision算法的内部参数
    （例如，列表数量、列表大小、碰撞概率）。

    复杂度通常低于Stern算法。这里，我们使用一个简化模型，
    从Stern的复杂度中减去一个与't'相关的项来表示这种降低。
    更严格的分析将涉及优化MMT算法中的'p'和'w'等参数。

    参数：
        n: 码长。
        k: 码维度（消息长度）。
        t: 可纠正的错误数量。

    返回：
        估算的安全性（比特）（操作数的log2）。
    """
    if t < 0 or t > n:
        raise ValueError("t must be between 0 and n.")
    if n < k:
        raise ValueError("n must be greater than or equal to k.")
    if n - k == 0:  # 避免 n == k 时的除以零错误
        return 0.0

    p = t / (n - k)
    if p < 0 or p > 1:
        raise ValueError("For this Ball-Collision ISD complexity approximation, t should generally be <= n - k.")

    # 简化的近似值：Stern 复杂性减去一个约减因子。
    # 更精确的公式将涉及优化内部参数。
    stern_complexity = (n - k) * binary_entropy(p)
    
    # 引入一个约减因子。为了说明目的，我们使用 log2(t)
    # 这是一个启发式方法来展示约减，而不是文献中的精确公式。
    # 实际上，约减来自碰撞概率和列表大小。
    reduction_factor = math.log2(t) if t > 1 else 0.0
    
    # 确保由于启发式约减，复杂性不会低于零
    return max(0.0, stern_complexity - reduction_factor)

# 此处结构攻击是已知子块边界的，则线性易攻击
def estimate_structural_attack_complexity_hamming(n: int, k: int, t: int,L: int) -> float:
    """
    估算针对Hamming码的结构攻击的安全性（比特）。

    计算原理：
    Hamming码的结构简单且公开，其校验矩阵H具有非常规则的结构（列是所有非零二元向量）。
    如果直接用Hamming码作为McEliece方案的秘密码，攻击者可以：
    1. 从公开的生成矩阵G'中识别出Hamming码的结构。
    2. 通过线性代数操作（如高斯消元）逆向工程，恢复用于“伪装”原始Hamming码的秘密置换矩阵P和随机矩阵S。
    3. 获取原始Hamming码生成矩阵G，从而完全掌握私钥。

    这种识别和恢复过程通常可以在多项式时间（Polynomial Time）内完成，
    这意味着攻击的复杂度非常低，远低于信息集解码（ISD）算法的指数级复杂度。
    因此，直接使用Hamming码会导致方案不安全。

    为了表示这种多项式时间复杂度，我们返回一个非常小的安全比特数（例如，0或1比特），
    以示警示，而非一个实际的计算值。

    参数：
        n: 码长。
        k: 码维度（消息长度）。
        t: 可纠正的错误数量。

    返回：
        估算的安全性（比特），通常为0或1，表示极低的安全性。
    """

    try:
        complexity = math.comb(n // L, t)
        if complexity == 0: # 对于有效的 n, t 不应该发生
            return 0.0
        return math.log2(complexity) + math.log2(L)

    # 当 C(n, t) 非常大时，直接计算 log2(C(n, t)) 可能会导致溢出。
    # 为了处理这种情况，我们使用一个循环来计算 log2(C(n, t)) 的近似值。
    except OverflowError:
        log_complexity = 0.0
        # 组合数 C(n, t) = n! / (t!(n - t)!) = (n - t + 1) * (n - t + 2) * ... * n! / t!、
        # 利用对数的性质进行计算，最终得到 log2(C(n, t))
        for i in range(t):
            log_complexity += math.log2(n // L - i)
            log_complexity -= math.log2(i + 1)
        
        # log2(C(n/L, t))+log2(L) = log2(C(n/L,t)*L),因为当前为结构攻击，则复杂度=C(n/L,t)(每个分块都有一定量的错误位数)*L（分块数量）
        return log_complexity + math.log2(L)


def main():
    """
    主函数，用于演示不同ISD算法和结构攻击的安全性估算。
    """

    # 示例用法
    n_example = 150
    k_example = 110
    t_example = 10   # 级联情况下，整个 McEliece 密码系统所能纠正的错误总数
    L_example = 10   # 有多少个分块

    print(f"Parameters: n={n_example}, k={k_example}, t={t_example}, L={L_example}")

    security_prange = estimate_prange_complexity(n_example, k_example, t_example)
    print(f"Estimated security against Prange's ISD: {security_prange:.2f} bits")

    security_stern = estimate_stern_complexity(n_example, k_example, t_example)
    print(f"Estimated security against Stern's ISD: {security_stern:.2f} bits")

    try:
        security_ball_collision = estimate_ball_collision_complexity(n_example, k_example, t_example)
        print(f"Estimated security against Ball-Collision ISD: {security_ball_collision:.2f} bits")
    except ValueError as e:
        print(f"Ball-Collision ISD security estimation failed: {e}")

    structural_attack_info = estimate_structural_attack_complexity_hamming(n_example, k_example, t_example,L_example)
    print(f"Structural Attack (Hamming Code): {structural_attack_info:.2f} bits")

    # --------------------------------------------------------------------------
    # 这里我们直接定义几组参数作为示例。
    print("\n--- 结合项目参数示例 ---")
    project_params = [
        {"L": 5, "n": 1024, "k": 857, "t_err": 20}, # 示例参数1
        {"L": 10, "n": 2048, "k": 1751, "t_err": 37}, # 示例参数2 (与上面的 n_example, k_example, t_example 相同)
        {"L": 15, "n": 3072, "k": 2645, "t_err": 55}, # 示例参数3
        {"L": 20, "n": 4096, "k": 3539, "t_err": 74}, # 示例参数4
    ]

    for params in project_params:
        L_val = params["L"]
        n_val = params["n"]
        k_val = params["k"]
        t_val = params["t_err"]

        print(f"\nProcessing L={L_val}, n={n_val}, k={k_val}, t_err={t_val}:")
        security_prange_proj = estimate_prange_complexity(n_val, k_val, t_val)
        print(f"  Prange's ISD security: {security_prange_proj:.2f} bits")

        try:
            security_stern_proj = estimate_stern_complexity(n_val, k_val, t_val)
            print(f"  Stern's ISD (entropy-based) security: {security_stern_proj:.2f} bits")
        except ValueError as e:
            print(f"  Stern's ISD security estimation failed: {e}")

        try:
            security_ball_collision_proj = estimate_ball_collision_complexity(n_val, k_val, t_val)
            print(f"  Ball-Collision ISD security: {security_ball_collision_proj:.2f} bits")
        except ValueError as e:
            print(f"  Ball-Collision ISD security estimation failed: {e}")

        structural_attack_info_proj = estimate_structural_attack_complexity_hamming(n_val, k_val, t_val, L_val)
        print(f"  Structural Attack (Hamming Code): {structural_attack_info_proj}")


if __name__ == "__main__":
    main()
