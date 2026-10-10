# Hamming-BCH-McEliece

本仓库是一个实验性质的 McEliece 公钥加密系统实现，用于对比分块级联 Hamming 码与 BCH 码在 McEliece 体制中的密钥规模、运行时间、密文扩张率、解密成功率和安全性估计表现。

项目包含两条实现路线：

- `hamming_mceliece/`：基于分块 Hamming 码的 McEliece toy implementation。
- `bch_mceliece/`：基于分块 BCH 码的 McEliece toy implementation。


## 功能特性

- Hamming 版本和 BCH 版本的密钥生成、加密、解密流程。
- 快速 demo 脚本，用于验证 KeyGen -> Encrypt -> Decrypt 的完整链路。
- benchmark 脚本，用于重复实验并输出 CSV/JSON 结果。
- 绘图脚本，用于从实验结果生成运行时间、密钥大小、密文扩张率和解密成功率图表。
- 安全性估计脚本，用于给出课程实验的粗略安全位估算。

## 技术栈

- Python
- matplotlib
- pandas

依赖列表见 `requirements.txt`。

## 安装

```powershell
git clone https://github.com/wohahiha/Hamming-BCH-McEliece.git
cd Hamming-BCH-McEliece
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS 可使用：

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 快速演示

在父目录下存在 `code/` 包目录、且本仓库内容位于 `code/` 内时，运行：

### Hamming 版本

```bash
python -m code.run_hamming_demo --L 20 --t 1 --seed 20251213 --output-dir code/hamming_mceliece/keys_and_text
```

常用参数：

- `--L`：分块长度，默认值为 `20`。
- `--t`：注入错误数，默认值为 `1`。
- `--seed`：随机数种子，用于复现实验。
- `--output-dir`：密钥、明文、密文和解密结果的输出目录。

### BCH 版本

```bash
python -m code.run_bch_demo
```

BCH demo 使用脚本内置参数，主要用于快速验证 BCH 版本的 KeyGen、Encrypt 和 Decrypt 是否能跑通。

## 实验评测

### Hamming benchmark

```bash
python -m code.run_hamming_benchmark --Ls 5,10,15,20 --ts 1 --repeat-keygen 10 --repeat 10 --seed 98765 --out-prefix code/hamming_mceliece/results/benchmark_hamming
```

参数说明：

- `--Ls`：不同分块长度，逗号分隔，例如 `5,10,15,20`。
- `--ts`：不同错误修正能力/错误注入参数，逗号分隔。
- `--repeat-keygen`：每组参数下密钥生成重复次数。
- `--repeat`：每组参数下加密/解密重复次数。
- `--seed`：随机数种子。
- `--out-prefix`：输出文件路径和文件名前缀。

### BCH benchmark

```bash
python -m code.run_bch_benchmark
```

BCH benchmark 会输出逐轮实验结果和汇总统计，供后续绘图和报告分析使用。

## 绘图与安全性估计

### 根据实验结果生成图像

```bash
python -m code.hamming_mceliece.plot_hamming
python -m code.bch_mceliece.plot_bch
```

### 运行安全性估计脚本

```bash
python -m code.hamming_mceliece.security_hamming
python -m code.bch_mceliece.security_bch
```

## 输出文件

运行 demo、benchmark 和绘图脚本后，主要输出位于：

- `hamming_mceliece/keys_and_text/`：Hamming demo 生成的公钥、私钥、明文、密文和解密结果示例。
- `hamming_mceliece/results/`：Hamming benchmark 的 CSV/JSON 结果。
- `hamming_mceliece/figures/`：Hamming 版本实验图表。
- `bch_mceliece/results/`：BCH benchmark 的原始 CSV 和汇总 JSON。
- `bch_mceliece/figures/`：BCH 版本实验图表。

## 项目结构

```text
Hamming-BCH-McEliece/
├── hamming_mceliece/
│   ├── decrypt_hamming.py
│   ├── encrypt_hamming.py
│   ├── hamming_code.py
│   ├── keygen_hamming.py
│   ├── plot_hamming.py
│   ├── security_hamming.py
│   ├── figures/
│   ├── keys_and_text/
│   └── results/
├── bch_mceliece/
│   ├── bch_code.py
│   ├── decrypt_bch.py
│   ├── encrypt_bch.py
│   ├── keygen_bch.py
│   ├── plot_bch.py
│   ├── security_bch.py
│   ├── figures/
│   └── results/
├── run_hamming_demo.py
├── run_bch_demo.py
├── run_hamming_benchmark.py
├── run_bch_benchmark.py
├── requirements.txt
└── README.md
```

## 贡献者与版权

Copyright (c) 2026 wohahiha, edss, Henry Soh, wanlahahaha

## 许可证

本项目基于 MIT License 开源，详见 [LICENSE](./LICENSE)。
