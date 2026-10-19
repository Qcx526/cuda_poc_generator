# P4-B 复现所需版本清单

报告语言：`zh-CN`。本文件回答一个问题：**要把哪些东西换成哪个版本，才能在真实目标上
复现这些 CVE**。版本约束全部来自本地七维输入中记录的公告值；未安装、未下载、
未执行任何样本。"目标版本"是待验证的安装目标，安装后必须以 `--version` 实测并把
观测值写入档案，不得把本文件当作已观测事实。

## 1. 一句话结论

- **16 个工具链 CVE 现在就能复现**：本机 `CUDA Toolkit 11.2`（`cuobjdump`/`nvdisasm`
  均为 11.2）落在全部 16 个的受影响区间内，不需要改任何东西。
- **想让证据更贴近厂商实测**：再并行安装 `CUDA Toolkit 12.8.x`，用于
  `12.8.55 / 12.8.90` 这一批（Talos 实测版本）。两个 Toolkit 可以共存，不需要卸载 11.2。
- **3 个驱动 CVE 需要降级驱动到 550 分支**（`< 550.90.07`），有蓝屏风险，建议在第二台机器上做。
- **1 个驱动 CVE 在本机硬件上不可能复现**：`CVE-2026-24191` 只影响 Maxwell / Volta / Pascal，
  而 GTX 1660 是 Turing（sm_75）。

## 2. 已可复现：16 个用户态工具链 CVE

本机观测：`cuobjdump` / `nvdisasm` / `nvcc` 均来自 `CUDA Toolkit v11.2`（2020-11-30 构建）。

| CVE | 工具 | 受影响区间 | 修复版本 | 与 11.2 的关系 |
|---|---|---|---|---|
| 2022-21821 | cuobjdump | < 11.6 Update 2 | 11.6U2 | 受影响 |
| 2023-0196 | cuobjdump | < 12.1 | 12.1 | 受影响 |
| 2024-0076 | cuobjdump + nvdisasm | < 12.4 | 12.4 | 受影响 |
| 2024-0109 | cuobjdump | ≤ 12.6 | 12.6 Update 1 | 受影响 |
| 2024-0110 | cuobjdump | ≤ 12.6 | 12.6 Update 1 | 受影响 |
| 2024-0111 | cuobjdump | ≤ 12.6 | 12.6 Update 1 | 受影响 |
| 2024-0124 | nvdisasm | 输入未给出区间，需按公告补录 | 未记录 | **未知，需补公告** |
| 2024-0125 | nvdisasm | ≤ 12.6 Update 1 | 12.6 Update 2 | 受影响 |
| 2024-53877 | nvdisasm | ≤ 12.8 | 12.8（另有 12.9 口径） | 受影响 |
| 2025-23247 | cuobjdump | < 12.9 | 12.9 | 受影响（Talos 实测 12.8.55） |
| 2025-23308 | nvdisasm | ≤ 12.9.88 | 13.0 | 受影响 |
| 2025-23338 | nvdisasm | < 13.0 | 13.0 | 受影响（Talos 实测 12.8.90） |
| 2025-23339 | cuobjdump | < 13.0 | 13.0 | 受影响（Talos 实测 12.8.55） |
| 2025-23340 | nvdisasm | < 13.0 | 13.0 | 受影响（Talos 实测 12.8.90） |
| 2025-23346 | cuobjdump | < 13.0 | 13.0 | 受影响 |
| 2025-33231 | Nsight Systems（Windows） | < 13.1 | 13.1 | 需单独安装 Nsight Systems，与 Toolkit 版本独立 |

**建议动作**：先不要动 11.2。在 11.2 上先把 **14 个受影响区间已确认**的工具链 CVE 跑通，
拿到第一批真实证据（`0124` 待补公告值，`33231` 需单独安装 Nsight Systems）；
之后再装 12.8 做版本对照。对照本身就是论文里"版本相关性"的证据。

### 2.1 可选：并行安装 CUDA Toolkit 12.8.x

- 目的：匹配 Talos 实测的 `cuobjdump 12.8.55`。
- 方式：官方 Toolkit 安装器，选择"自定义 → 只装 Toolkit，不装驱动"。
  两个版本共存于 `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2` 与 `v12.8`。
- **安装后必须实测**：`cuobjdump --version`、`nvdisasm --version`，把输出、文件路径和
  SHA-256 写进档案。公告里的版本号是厂商实测值，不代表任意安装包都等于它。
- 注意：CUDA 12.8 的 GPU 运行需要 570 分支以上驱动，但 `cuobjdump`/`nvdisasm` 是
  纯 CPU 工具，编译与解析都不需要驱动参与。所以 550 驱动 + 12.8 Toolkit 的组合可用于
  这两个工具，不能用于运行 GPU 代码。

### 2.2 版本口径核对（重要）

NVIDIA 官方组件版本表与本项目输入资料存在一处不一致，必须先澄清再对照：

| 工具包 | 官方发布版本 | 官方组件表 |
|---|---|---|
| CUDA 12.8.0 | 2025-01 | `cuobjdump 12.8.55`、`nvdisasm 12.8.55` |
| CUDA 12.9.0 | 2025-05 | `cuobjdump 12.9.26`、`nvdisasm 12.9.19` |
| CUDA 12.9 Update 2 | 2025-08 | `cuobjdump 12.9.82`、`nvdisasm 12.9.88` |

- 输入资料为 `CVE-2025-23338` / `23340` 记录的是 **`nvdisasm 12.8.90`**，但 12.8 与 12.9
  的官方组件表里都没有这个构建号。它可能来自某个未公开的内部构建或厂商测试镜像。
- 因此复现 `23338` / `23340` 时，只能先用公开可得的最接近版本（12.8.55 或 12.9.88），
  并在报告里明确写"工具构建号与 Talos 实测不一致"。**不得**把 12.8.55 的结果当作
  "与 Talos 同版本复现"。
- `CVE-2025-23308` 输入写"≤ 12.9.88"，与 12.9 Update 2 的 `nvdisasm 12.9.88` 一致，
  这一条可以用公开版本精确对齐。
- 结论：**版本号必须逐个用 `--version` 实测**，不能从公告反推。这也是本项目要求把
  工具 SHA-256 写进证据清单的原因。

## 3. 需要降级驱动：3 个（有风险）

先澄清一个版本号陷阱：NVIDIA 的 `550.54.14` 是 **Linux** 构建，同一分支的 **Windows**
构建是 `551.61`（官方发布说明写作 "550.54.14(Linux)/551.61(Windows)"）。
Windows GeForce 的版本号不能直接套用 Linux 分支号。

| CVE | Windows GeForce 受影响区间 | 修复版本 | 建议目标 |
|---|---|---|---|
| 2024-0090 | R555 分支 `555.99` 之前的全部版本（含 R550/551.x） | 555.99 | **551.61** |
| 2024-0091 | 同上（R555 分支 `555.99` 之前） | 555.99 | **551.61** |
| 2024-0107 | R555 分支 `556.12` 之前；Talos 实测 551.61 | 556.12 | **551.61** |

三个 CVE 在 Windows 上的交集是 **551.61**：它低于 0090/0091 的 555.99 上界，也低于
0107 的 556.12 上界，并且就是 0107 的 Talos 实测版本。GTX 1660 在该驱动的支持列表内
（GeForce 16 系列）。

NVIDIA 公告中 0090/0091 的 Linux 修复号（550.90.07 / 535.183.01 / 470.256.02）
不适用于 Windows GeForce，不要拿它们判断本机是否受影响。

**风险与做法（必须遵守）**：

1. 这三个是显示驱动缺陷，触发成功通常表现为**蓝屏或显示驱动重置**，不是普通进程崩溃。
   **不要在唯一的工作机上做**；若只有一台机器，先建系统还原点并准备安全模式卸载步骤。
2. 卸载用 DDU 在安全模式下清理，再装 551.61。不要直接覆盖安装，残留会导致版本判定错误。
3. 安装后断开网络并关闭 NVIDIA App / GeForce Experience 的自动更新，否则驱动会被悄悄升级回去。
4. 降级后先跑一次 `nvidia-smi` 记录驱动版本，再开始实验。
5. 回滚：DDU 清理后重装当前的 `617.42`。
6. 551.61 对应 CUDA 12.4 运行时上限。CUDA 12.8 的 GPU 运行能力会失效，
   但 `cuobjdump`/`nvdisasm` 是纯 CPU 工具，不受影响。
   因此驱动实验与 GPU 库实验**不能在同一时间窗口做**。

## 4. 不可能在本机复现：1 个

`CVE-2026-24191` 的输入明确记录 **仅 Maxwell / Volta / Pascal 架构的 GPU 受影响**。
GTX 1660 是 Turing（`sm_75`），即使把驱动降到受影响区间也不满足架构条件。
需要一台 Pascal（GTX 10xx）或 Maxwell（GTX 9xx）机器；没有的话这个 CVE 保持
`UNSUPPORTED_ENVIRONMENT`，不占迭代预算。

## 5. GPU 库与服务：3 个

| CVE | 组件 | 受影响版本 | 靶场 |
|---|---|---|---|
| 2024-0115 | CV-CUDA | 0.1.0 – 0.6.0 | Linux + GPU 容器，`pip install cv-cuda==0.6.0` |
| 2025-23273 | nvJPEG | < 13.0 | `nvcr.io/nvidia/cuda:12.x-devel` + 对应 nvJPEG |
| 2025-23316 | Triton Inference Server | < 25.08 | `nvcr.io/nvidia/tritonserver:25.07-py3`（含漏洞的最后一个版本） |

这三个需要 GPU 设备与 `nvidia-container-toolkit`。在本机单卡上跑之前，必须先验证
"容器被杀死后设备仍健康"（`nvidia-smi` 前后对比），否则会拖垮宿主机。

## 6. 下一步执行顺序

1. 用现有 11.2 跑通 15 个工具链 CVE，产出第一批真实证据。
2. 补录 `CVE-2024-0124` 的受影响版本区间（输入缺公告值）。
3. 装 12.4 Toolkit（GPU 库需要）或 12.8 Toolkit（仅用于 CPU 工具的版本对照）。
4. 在第二台机器上做驱动类；本机只做架构匹配的排除登记。
5. 最后做 GPU 库/服务，需要先通过设备健康检查。

## 7. 推荐组合与官方下载

没有单一组合能覆盖全部 23 个，但下面两套都远高于"只装最新版"：

| 组合 | 驱动 | Toolkit | 覆盖 | 代价 |
|---|---|---|---|---|
| A 单机最大覆盖 | **551.61** | 11.2.2 + 12.4.0 | 21 / 23 | 有蓝屏风险；CUDA ≥12.8 的 GPU 运行失效；Triton 25.07 跑不了 |
| B 稳妥 | 617.42（不改） | 11.2.2 + 12.8.0 | 19 / 23 | 三个驱动 CVE 需第二台机器 |

A 组排除 `CVE-2026-24191`（Turing 架构不符）与 `CVE-2025-23316`（Triton 25.07 需要 ≥575 驱动）。
B 组排除 4 个驱动类。

### 7.1 下载地址

| 组件 | 版本 | 链接 |
|---|---|---|
| GeForce 驱动 | 551.61（Win10 64-bit，634 MB） | https://www.nvidia.com/download/driverResults.aspx/221745/en-us |
| 驱动历史归档 | — | https://www.nvidia.com/en-us/drivers/ |
| CUDA Toolkit | 11.2 Update 2（`cuda_11.2.2_461.33_win10.exe`，2.8 GB） | https://developer.nvidia.com/cuda-11.2.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exelocal |
| CUDA Toolkit | 12.4.0（Windows / x86_64 / 10 / exe local） | https://developer.nvidia.com/cuda-12-4-0-download-archive |
| CUDA Toolkit | 12.8.0（可选，仅用 CPU 工具） | https://developer.nvidia.com/cuda-12-8-0-download-archive |
| Toolkit 总归档 | — | https://developer.nvidia.com/cuda-toolkit-archive |
| DDU 卸载工具 | 最新 | https://www.wagnardsoft.com/display-driver-uninstaller-DDU- |

### 7.2 安装顺序与坑

1. 建系统还原点，断网，关闭 NVIDIA App / GeForce Experience 的自动更新。
2. 安全模式运行 DDU，选 GPU / NVIDIA，"Clean and restart"。
3. 装 **551.61**，自定义安装 + 勾选"执行清洁安装"，装完重启。
4. 装 CUDA 11.2.2，**自定义安装时取消勾选 `Display Driver`**（否则会把驱动写回 461.33）。
5. 装 CUDA 12.4.0，同样取消勾选 `Display Driver`。
6. 验证：
   ```text
   nvidia-smi                                  # 应为 551.61
   "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\cuobjdump.exe" --version
   "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin\cuobjdump.exe" --version
   ```
   把两条 `--version` 的完整输出与文件 SHA-256 写进证据档案；不要只记版本号。

### 7.3 回滚

DDU 清理后重装 617.42。CUDA Toolkit 可以并存，不需要卸载。

## 8. 本轮未做的事

- 未安装 CUDA 12.4 / 12.8，未安装 Nsight Systems。
- 未运行任何真实漏洞样本。

## 9. 本机当前实测状态（2026-10-19）

驱动已降级、CUDA 已重装，以下为**实测值**，替换此前的推导：

| 项 | 值 |
|---|---|
| GPU | NVIDIA GeForce GTX 1660（Turing，sm_75） |
| 驱动 | **551.61**（`nvidia-smi` 实测） |
| CUDA Toolkit | `v11.2`，`nvcc` / `cuobjdump` / `nvdisasm` 均为 **11.2.152**（build `compiler.29618528_0`） |
| 运行时库 | `cudart64_110.dll`、`cudart.lib`、`cudart_static.lib` 均在 |
| 头文件 / 库 | `include` 148 项、`lib/x64` 30 项 |
| 空 kernel 编译 | `nvcc -cubin -G -arch=sm_75` 成功，产物 40,616 字节 |
| `compute-sanitizer.exe` | **不存在**（11.2 Windows 侧只有旧的 `cuda-memcheck.exe`） |
| Nsight Systems | 未安装（仅 `CVE-2025-33231` 需要） |

注意：重装把 `cuobjdump` 从 11.2.0（2020-11-30 构建）换成了 11.2.152（U2）。
构建号变化意味着旧的工具哈希与任何基于旧构建的证据都需要重算；
U2 仍在所有相关 CVE 的受影响区间内（最早的修复点是 11.6 Update 2）。
`nvcc` 编译时会尝试读取注册表探测 Visual Studio，被沙箱拦截时不影响 `-cubin` 产物。
