# McEliece PKE Course Project — Block-Hamming Variant

## 项目介绍：
本项目实现了基于汉明码和BCH码的McEliece公钥加密系统，包含密钥生成、加密、解密和性能评测等功能。项目结构清晰，代码注释详细，适合用于课程实验和研究。

---

## 目录结构
/code/                          # 根目录（顶层）
├── hamming_mceliece/           # 汉明版McEliece核心模块目录
│   ├── figures/                # 存储生成的图表（按照下面命令行运行之后生成）
│   │   ├── 图1_运行时间_vs_L.pdf
│   │   ├── 图2_密钥大小_vs_L.pdf
│   │   ├── 图3_密文扩张率_vs_L.pdf
│   │   └── 图4_解密成功率_vs_L.pdf
│   ├── keys_and_text/          # 存储密钥和明密文示例（按照下面命令行运行之后生成）
│   │   └── L_20/
│   │       ├── ciphertext.json
│   │       ├── plaintext.json
│   │       ├── private_key.json
│   │       └── public_key.json
│   ├── results/                # 存储性能测试结果（按照下面命令行运行之后生成）
│   │   ├── benchmark_hamming.csv
│   │   └── benchmark_hamming.json
│   ├── decrypt_hamming.py      # 汉明版解密模块
│   ├── encrypt_hamming.py      # 汉明版加密模块
│   ├── hamming_code.py         # 汉明编码/译码模块
│   ├── keygen_hamming.py       # 汉明版密钥生成模块
│   ├── plot_hamming.py         # 汉明版绘图脚本
│   └── security_hamming.py     # 汉明版安全性估计模块
├── bch_mceliece/               # BCH版McEliece核心模块目录
│   ├── figures/                # 存储生成的图表（按照下面命令行运行之后生成）
│   │   ├── 图1_运行时间_vs_L.pdf
│   │   ├── 图2_密钥大小_vs_L.pdf
│   │   ├── 图3_密文扩张率_vs_L.pdf
│   │   └── 图4_解密成功率_vs_L.pdf
│   ├── results/                # 存储性能测试结果（按照下面命令行运行之后生成）
│   │   ├── benchmark_bch_raw.csv
│   │   └── benchmark_bch_summary.json
│   ├── __init__.py             # Python包初始化文件
│   ├── bch_code.py             # BCH编码/译码模块
│   ├── decrypt_bch.py          # BCH版解密模块
│   ├── encrypt_bch.py          # BCH版加密模块
│   ├── keygen_bch.py           # BCH版密钥生成模块
│   ├── plot_bch.py             # BCH版绘图脚本
│   └── security_bch.py         # BCH版安全性估计模块
├── run_hamming_demo.py         # 汉明版快速演示脚本
├── run_bch_demo.py             # BCH版快速演示脚本
├── run_hamming_benchmark.py    # 汉明版性能对比测试脚本
├── run_bch_benchmark.py        # BCH版性能对比测试脚本
├── README.md                   # 环境配置+运行说明
└── requirements.txt            # 依赖包列表


## 依赖安装

```bash
pip install -r requirements.txt
```


## 快速演示（对于单种情况）
在根目录之前的一层目录下运行：
汉明码：
```bash
python -m code.run_hamming_demo --L 20 --t 1 --seed 20251213 --output-dir hamming_mceliece/keys_and_text
```

各参数解析：
- `--L`：指定分块长度L，默认值为`20`。
- `--t`：指定错误修正能力t，默认值为`1`。
- `--seed`：指定随机数种子，默认值为`20251213`。
- `--output-dir`：指定keys_and_text文件夹输出目录，默认值为`hamming_mceliece/keys_and_text`。

BCH码：
```bash
python -m code.run_bch_demo
```


## 实验评测（用于对比不同分块数量下的性能）
在根目录之前的一层目录下运行：
汉明码：
```bash
python -m code.run_hamming_benchmark --Ls 5,10,15,20 --ts 1 --repeat-keygen 10 --repeat 10 --seed 98765 --out-prefix code/hamming_mceliece/results/benchmark_hamming
```

各参数解析：
- `--Ls`：指定不同的分块长度L（逗号分隔），默认值为`5,10,15,20`。
- `--ts`：指定不同的错误修正能力t（逗号分隔），默认值为`1`。
- `--repeat-keygen`：指定每个参数组合下密钥生成的重复次数，默认值为`10`。
- `--repeat`：指定每个参数组合下加密/解密的重复次数，默认值为`10`。
- `--seed`：指定随机数种子，默认值为`98765`。
- `--out-prefix`：指定输出结果路径和命名前缀，默认值为`code/hamming_mceliece/results/benchmark_hamming`，即存储于`code/hamming_mceliece/results`文件夹中，该文件夹里面的文件以`benchmark_hamming`来命名。

BCH码：
```bash
python -m code.run_bch_benchmark
```


## 根据实验结果生成图像
在根目录之前的一层目录下运行：
汉明码：
```bash
python -m code.hamming_mceliece.plot_hamming
```

BCH码：
```bash
python -m code.bch_mceliece.plot_bch
```

## 安全性估计（代码辅助）
在根目录之前的一层目录下运行：
汉明码：
```bash
python -m code.hamming_mceliece.security_hamming
```

BCH码：
```bash
python -m code.bch_mceliece.security_bch
```