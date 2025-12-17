import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib.font_manager as fm

# 配置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei']  # 或者其他支持中文的字体，如 'WenQuanYi Micro Hei'
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
plt.rcParams.update({'font.size': 30}) # 全局字体大小

def plot_runtime_results(csv_file_path, output_dir):
    # 读取CSV文件
    df = pd.read_csv(csv_file_path)

    # 过滤 t0 = 2 的数据 (根据 run_bch_benchmark.py 中的配置)
    # 注意：这里假设 t0 始终为 2，如果 run_bch_benchmark.py 中的 t0 配置有变化，这里也需要相应调整
    df_filtered = df[df['t0'] == 2]

    # 按 L 分组并计算各运行时间的均值和标准差
    grouped = df_filtered.groupby('L').agg(
        keygen_s_mean=('keygen_s', 'mean'),
        keygen_s_std=('keygen_s', 'std'),
        enc_s_mean=('enc_s', 'mean'),
        enc_s_std=('enc_s', 'std'),
        dec_s_mean=('dec_s', 'mean'),
        dec_s_std=('dec_s', 'std')
    ).reset_index()

    # 将时间从秒转换为毫秒
    grouped['keygen_ms_mean'] = grouped['keygen_s_mean'] * 1000
    grouped['keygen_ms_std'] = grouped['keygen_s_std'] * 1000
    grouped['enc_ms_mean'] = grouped['enc_s_mean'] * 1000
    grouped['enc_ms_std'] = grouped['enc_s_std'] * 1000
    grouped['dec_ms_mean'] = grouped['dec_s_mean'] * 1000
    grouped['dec_ms_std'] = grouped['dec_s_std'] * 1000

    # 提取所需数据
    L_values = grouped['L']
    keygen_mean = grouped['keygen_ms_mean']
    keygen_std = grouped['keygen_ms_std']
    encrypt_mean = grouped['enc_ms_mean']
    encrypt_std = grouped['enc_ms_std']
    decrypt_mean = grouped['dec_ms_mean']
    decrypt_std = grouped['dec_ms_std']

    # 绘制图表
    plt.figure(figsize=(12, 10))

    plt.errorbar(L_values, keygen_mean, yerr=keygen_std, fmt='-o', capsize=5, label='密钥生成', color='blue', linewidth=2)
    plt.errorbar(L_values, encrypt_mean, yerr=encrypt_std, fmt='-s', capsize=5, label='加密', color='red', linewidth=2)
    plt.errorbar(L_values, decrypt_mean, yerr=decrypt_std, fmt='-^', capsize=5, label='解密', color='gold', linewidth=2)

    # 设置图表标题和标签
    plt.title('运行时间随分块数变化 (每块最大错误数 t0=2, 均值±标准差)', fontsize=30)
    plt.xlabel('分块数 L', fontsize=30)
    plt.ylabel('时间 (毫秒)', fontsize=30)
    plt.xticks([5, 10, 15, 20], fontsize=30)
    plt.yticks(fontsize=30)
    plt.legend(fontsize=30)
    plt.grid(True)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    output_image_path = os.path.join(output_dir, '图1_运行时间_vs_L.pdf')

    # 保存图表为PDF
    plt.tight_layout() # 调整布局以适应标签
    plt.savefig(output_image_path, bbox_inches='tight')

def plot_key_size_results(csv_file_path, output_dir):
    # 读取CSV文件
    df = pd.read_csv(csv_file_path)

    # 过滤 t0 = 2 的数据
    df_filtered = df[df['t0'] == 2]

    # 按 L 分组并计算公钥和私钥尺寸的均值和标准差
    grouped = df_filtered.groupby('L').agg(
        pk_bits_mean=('pk_bits', 'mean'),
        pk_bits_std=('pk_bits', 'std'),
        priv_bits_mean=('priv_bits', 'mean'),
        priv_bits_std=('priv_bits', 'std')
    ).reset_index()

    # 提取所需数据，以字节为单位 (CSV中是bit，这里转换为字节)
    L_values = grouped['L']
    public_key_mean = grouped['pk_bits_mean'] / 8
    public_key_std = grouped['pk_bits_std'] / 8
    private_key_mean = grouped['priv_bits_mean'] / 8
    private_key_std = grouped['priv_bits_std'] / 8

    # 绘制图表
    plt.figure(figsize=(12, 10))

    plt.errorbar(L_values, public_key_mean, yerr=public_key_std, fmt='-o', capsize=5, label='公钥', color='blue', linewidth=2)
    plt.errorbar(L_values, private_key_mean, yerr=private_key_std, fmt='-s', capsize=5, label='私钥', color='orangered', linewidth=2)

    # 设置图表标题和标签
    plt.title('密钥大小随分块数变化 (t0=2, 均值±标准差)', fontsize=30)
    plt.xlabel('分块数 L', fontsize=30)
    plt.ylabel('密钥大小 (字节)', fontsize=30)
    plt.xticks([5, 10, 15, 20], fontsize=30)
    plt.yticks(fontsize=30)
    plt.legend(fontsize=30)
    plt.grid(True)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    output_image_path = os.path.join(output_dir, '图2_密钥大小_vs_L.pdf')

    # 保存图表为PDF
    plt.tight_layout() # 调整布局以适应标签
    plt.savefig(output_image_path, bbox_inches='tight')

def plot_expansion_ratio_results(csv_file_path, output_dir):
    # 读取CSV文件
    df = pd.read_csv(csv_file_path)

    # 过滤 t0 = 2 的数据
    df_filtered = df[df['t0'] == 2]

    # 按 L 分组并计算 rate_n_over_k 的均值和标准差
    grouped = df_filtered.groupby('L').agg(
        rate_n_over_k_mean=('rate_n_over_k', 'mean'),
        rate_n_over_k_std=('rate_n_over_k', 'std')
    ).reset_index()

    # 提取所需数据
    L_values = grouped['L']
    expansion_ratio_mean = grouped['rate_n_over_k_mean']
    expansion_ratio_std = grouped['rate_n_over_k_std']

    # 绘制图表
    plt.figure(figsize=(12, 10))

    # 绘制折线图 (带误差棒)
    plt.errorbar(L_values, expansion_ratio_mean, yerr=expansion_ratio_std, fmt='-o', color='blue', linewidth=2, markersize=8, capsize=5)

    # 设置图表标题和标签
    plt.title('密文扩张率随分块数变化 (t0=2)', fontsize=30)
    plt.xlabel('分块数 L', fontsize=30)
    plt.ylabel('实际密文字节扩张率 (密文长度/明文长度)', fontsize=30)

    # 设置横坐标刻度
    plt.xticks([5, 10, 15, 20], fontsize=30)
    plt.yticks(fontsize=30)

    # 添加网格
    plt.grid(True, linestyle='--', alpha=0.7)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    output_image_path = os.path.join(output_dir, '图3_密文扩张率_vs_L.pdf')

    # 调整布局并保存图表
    plt.tight_layout()
    plt.savefig(output_image_path, bbox_inches='tight')

def plot_success_rate_results(csv_file_path, output_dir):
    # 读取CSV文件
    df = pd.read_csv(csv_file_path)

    # 过滤 t0 = 2 的数据
    df_filtered = df[df['t0'] == 2]

    # 按 L 分组并计算 success 的均值和标准差
    grouped = df_filtered.groupby('L').agg(
        success_mean=('success', 'mean'),
        success_std=('success', 'std')
    ).reset_index()

    # 提取所需数据
    L_values = grouped['L']
    success_mean = grouped['success_mean']
    success_std = grouped['success_std']

    # 绘制图表
    plt.figure(figsize=(12, 10))

    # 绘制折线图 (带误差棒)
    plt.errorbar(L_values, success_mean, yerr=success_std, fmt='-o', color='blue', linewidth=2, markersize=8, capsize=5)

    # 设置图表标题和标签
    plt.title('解密成功率随分块数变化 (t0=2)', fontsize=30)
    plt.xlabel('分块数 L', fontsize=30)
    plt.ylabel('解密成功率', fontsize=30)

    # 设置横坐标刻度
    plt.xticks([5, 10, 15, 20], fontsize=30)
    plt.yticks(fontsize=30)

    # 添加网格
    plt.grid(True, linestyle='--', alpha=0.7)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    output_image_path = os.path.join(output_dir, '图4_解密成功率_vs_L.pdf')

    # 调整布局并保存图表
    plt.tight_layout()
    plt.savefig(output_image_path, bbox_inches='tight')

if __name__ == '__main__':
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(SCRIPT_DIR, 'results', 'benchmark_bch_raw.csv')
    output_figures_dir = os.path.join(SCRIPT_DIR, 'figures')

    # 检查CSV文件是否存在
    if not os.path.exists(csv_file):
        print(f"错误：未找到文件 {csv_file}。请确保该文件存在于当前目录或 'results' 目录中。")
    else:
        plot_runtime_results(csv_file, output_figures_dir)
        print(f"图表已保存到 {os.path.join(output_figures_dir, '图1_运行时间_vs_L.pdf')}")
        plot_key_size_results(csv_file, output_figures_dir)
        print(f"图表已保存到 {os.path.join(output_figures_dir, '图2_密钥大小_vs_L.pdf')}")
        plot_expansion_ratio_results(csv_file, output_figures_dir)
        print(f"图表已保存到 {os.path.join(output_figures_dir, '图3_密文扩张率_vs_L.pdf')}")
        plot_success_rate_results(csv_file, output_figures_dir)
        print(f"图表已保存到 {os.path.join(output_figures_dir, '图4_解密成功率_vs_L.pdf')}")
