import math
import pandas as pd

# 已有的二进制熵函数（复用）
def binary_entropy(p: float) -> float:
    if p < 0 or p > 1:
        raise ValueError("p must be between 0 and 1.")
    if p == 0 or p == 1:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


# 针对级联 (15,7)BCH 码的结构攻击复杂度估算，设当前为在公开矩阵 G' 中找不到子块边界的情况，此时结构攻击为指数级
def estimate_structural_attack_complexity_bch_cascade(n: int, k: int, t: int, L: int) -> float:
    """
    估算针对级联 (15,7)BCH 码的 McEliece 变体的结构攻击安全性（比特）。
    每个子码为 (15,7)BCH码，生成多项式 g(x)=x^8 + x^7 + x^6 + x^4 + 1，纠错能力 t=2。

    计算原理：
    级联 BCH 码虽比汉明码结构复杂，但子码的代数特性（明确的生成多项式和纠错能力）仍可能被利用。
    攻击者可通过识别子码结构、分析分块间关联性来降低攻击难度，其复杂度显著低于通用 ISD 算法。

    复杂度估算基于：
    1. 单个 (15,7)BCH 码的结构攻击复杂度（与纠错能力 t=2 相关）
    2. 级联分块数量L带来的组合影响
    最终近似为 log2(C(15,2)^L * L)，其中 C(15,2) 为单个分块的攻击复杂度基数

    参数：
        n: 总码长（必须为 15*L，因每个子码长 15）
        k: 总维度（必须为 7*L，因每个子码维度 7）
        t: 总纠错数（必须为 2*L，因每个子码纠 2 个错误）
        L: 级联的 BCH 码分块数量

    返回：
        估算的安全性（比特）
    """
    # 参数合法性检查
    if L <= 0:
        raise ValueError("L must be a positive integer (number of BCH blocks).")
    if n != 15 * L:
        raise ValueError(f"n must be 15*L for (15,7) BCH cascade, got {n} with L={L}.")
    if k != 7 * L:
        raise ValueError(f"k must be 7*L for (15,7) BCH cascade, got {k} with L={L}.")
    if t != 2 * L:
        raise ValueError(f"t must be 2*L (2 errors per block), got {t} with L={L}.")
    if t < 0 or t > n:
        raise ValueError("t must be between 0 and n.")

    # 单个(15,7)BCH码的参数
    block_n = 15
    block_t = 2

    try:
        # 单个分块的攻击复杂度基数：C(15,2)
        per_block = math.comb(block_n, block_t)
        # 级联后总复杂度近似为 (单块复杂度)^L * L（分块协同因子）
        total_complexity = (per_block ** L) * L
        return math.log2(total_complexity) if total_complexity > 0 else 0.0
    except OverflowError:
        # 处理大数值溢出，用对数累加计算
        log_per_block = 0.0
        # 计算 log2(C(block_n, block_t))
        # 组合数 C(n, k) = n! / (k! * (n-k)!) = (n * (n-1) * ... * (n-k+1)) / (k * (k-1) * ... * 1) 。
        # log2(C(n, k)) = log2(n) + log2(n-1) + ... + log2(n-k+1) - (log2(k) + log2(k-1) + ... + log2(1))
        for i in range(block_t):
            log_per_block += math.log2(block_n - i)
            log_per_block -= math.log2(i + 1)
        # 总对数复杂度 = L*单块对数复杂度 + log2(L)
        log_total = L * log_per_block + math.log2(L)
        return log_total


# 针对级联 BCH 码的 ISD 算法安全性估算（复用并适配级联场景），采用了对 Stern 算法攻击的安全性衡量方式
def estimate_stern_cascade_bch(n: int, k: int, t: int, L: int) -> float:
    """
    估算级联 (15,7)BCH 码对抗 Stern ISD 算法的安全性。
    考虑级联结构对信息集解码复杂度的影响。
    """
    if n < k:
        raise ValueError("n must be greater than or equal to k.")
    if n - k == 0:
        return 0.0
    if t < 0 or t > n:
        raise ValueError("t must be between 0 and n.")

    # 级联码的校验位长度为 n-k = (15-7)*L = 8L
    p = t / (n - k)  # 错误率 = 总错误数 / 总校验位长度
    if p < 0 or p > 1:
        raise ValueError("t should be <= n - k for Stern's complexity estimation.")

    return (n - k) * binary_entropy(p)


def estimate_security_bits(n: int, t: int) -> float:
    """
    安全性估算主函数。

    输入：
      n: 码长（分块 BCH 级联中 n = 15 * L）
      t: 错误数（必须取真实注入错误总数 t_total）

    输出：
      lambda: 安全性估算值（bit）
        解释为：攻击复杂度数量级约为 2^lambda

    使用的粗略模型：
      lambda = n * H2(t/n)

    注意：
      - 若 t=0 或 t=n，则 H2=0，返回 0（极端情况）
    """
    # ------------------------
    # 1) 输入合法性检查
    # ------------------------
    # 显式限制类型与范围：
    #  - 避免 n,t 被误传为 float 或 None
    #  - 避免 t 超出 [0, n] 导致 p 不在 [0,1]
    if not isinstance(n, int) or not isinstance(t, int):
        raise ValueError("n 和 t 必须为整数")
    if n <= 0:
        raise ValueError("n 必须为正整数")
    if t < 0 or t > n:
        raise ValueError("t 必须在 [0, n] 范围内")

    # ------------------------
    # 2) 极端边界处理
    # ------------------------
    # t=0：无错误，组合不确定性为 0
    # t=n：全错，形式上也为极端情况；本模型返回 0
    if t == 0 or t == n:
        return 0.0

    # ------------------------
    # 3) 计算 p 与二元熵 H2(p)
    # ------------------------
    p = t / n  # p ∈ (0,1)

    #   H2(p) = -p log2 p - (1-p) log2(1-p)
    h2 = -p * math.log2(p) - (1 - p) * math.log2(1 - p)

    # ------------------------
    # 4) 返回估算 bit 数
    # ------------------------
    return n * h2


# 新增函数：从 CSV 文件中分析 t_total
def analyze_t_total_for_L(csv_file_path: str, target_L: int) -> dict[str, float]:
    """
    从 CSV 文件中提取指定 L 值对应的 t_total 数据，并计算其平均值和最大值。

    Args:
        csv_file_path: 包含 benchmark 结果的 CSV 文件路径。
        target_L: 目标 L 值。

    Returns:
        一个字典，包含指定 L 值对应的 t_total 的平均值和最大值。
        例如: {"t_total_mean": 10.5, "t_total_max": 12.0}
    """
    try:
        df = pd.read_csv(csv_file_path)
    except FileNotFoundError:
        print(f"错误：未找到文件 {csv_file_path}")
        return {}
    except Exception as e:
        print(f"读取 CSV 文件时发生错误：{e}")
        return {}

    # 过滤出指定 L 值的数据
    filtered_df = df[df['L'] == target_L]

    if filtered_df.empty:
        print(f"未找到 L={target_L} 的数据。")
        return {"t_total_mean": float('nan'), "t_total_max": float('nan')}

    # 提取 t_total 列
    t_total_data = filtered_df['t_total']

    # 计算平均值和最大值
    mean_t_total = t_total_data.mean()
    max_t_total = t_total_data.max()

    return {"t_total_mean": mean_t_total, "t_total_max": max_t_total}


def main():
    """演示级联(15,7)BCH码的安全性估算"""
    print("=== 级联(15,7)BCH码的McEliece变体安全性估计 ===")

    # 当前目录下的.csv文件
    csv_file_path = "./results/benchmark_bch_raw.csv"
    
    # 示例参数：不同数量的分块L
    bch_cascade_params = [
        {"L": 5},   # 总码长75，总维度35，总纠错10
        {"L": 10},   # 总码长150，总维度70，总纠错20
        {"L": 15},  # 总码长225，总维度105，总纠错30
        {"L": 20},  # 总码长200，总维度100，总纠错40
    ]

    for params in bch_cascade_params:
        L = params["L"]
        n = 15 * L
        k = 7 * L
        t_design = 2 * L # 这是码的设计纠错能力，用于结构攻击估算

        print(f"\n参数: L={L}, n={n}, k={k}, t_design={t_design}")

        # 从 CSV 获取 t_total 的平均值
        t_total_stats = analyze_t_total_for_L(csv_file_path, L)
        t_total_mean = t_total_stats.get("t_total_mean", float('nan'))
        t_total_max = t_total_stats.get("t_total_max", float('nan'))

        if math.isnan(t_total_mean):
            print(f"警告：未找到 L={L} 的 t_total 平均值，跳过 Stern ISD 估算。")
            continue

        print(f"  从 CSV 获取的 t_total 平均值: {t_total_mean:.2f}，最大值: {t_total_max:.2f}")

        # 结构攻击安全性
        try:
            struct_security = estimate_structural_attack_complexity_bch_cascade(n, k, t_design, L)
            print(f"结构攻击安全性: {struct_security:.2f} bits")
        except ValueError as e:
            print(f"结构攻击估算失败: {e}")

        # Stern ISD算法安全性 (使用 t_total_mean)
        try:
            stern_security_mean = estimate_stern_cascade_bch(n, k, int(round(t_total_mean)), L) # t 必须是整数
            print(f"平均情况下Stern ISD安全性: {stern_security_mean:.2f} bits")
        except ValueError as e:
            print(f"平均情况下Stern ISD估算失败: {e}")

         # 最坏情况下Stern ISD算法安全性(使用 t_total_max)
        try:
            stern_security_max = estimate_stern_cascade_bch(n, k, int(round(t_total_max)), L) # t 必须是整数
            print(f"最坏情况下Stern ISD安全性: {stern_security_max:.2f} bits")
        except ValueError as e:
            print(f"最坏情况下Stern ISD估算失败: {e}")

    # 简单自测：n=150, t=20
    # 输出值含义：粗略攻击复杂度数量级约为 2^{该值}
    print("\n--- 粗略安全性估算示例 ---")
    print("Example (n=150, t=20):", estimate_security_bits(150, 20))


if __name__ == "__main__":
    main()
