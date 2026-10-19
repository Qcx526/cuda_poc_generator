# P4-A 目标环境档案与靶场分档

报告语言：`zh-CN`。本文件记录"每个 CVE 到底需要什么样的执行环境"的判定规则、
本地研究语料的实际分布，以及靶场选型结论。它是 P4 迭代闭环的前置条件，
不是执行授权。

## 1. 范围与边界

- 输入：七维归一化 JSON。输出：`TargetEnvironmentProfile`（`profile_schema_version: "1.0"`）。
- 实现：`src/target_profile.py`，纯函数、无 I/O 副作用、不启动进程、不探测宿主。
- 档案描述 **CVE 的环境需求**，不描述 **本机能否满足**。两者混在一起会让
  "这台机器恰好有 cuobjdump 11.2" 冒充"该 CVE 需要 11.2"。
- `automation_tier` 是该类目标允许的自动化**上限**，不是授权。真实执行仍需
  独立的准入判定与证据合同。

## 2. 三类隔离档位 + 一个排除类

| 档位 | 适用 | 复位方式 | 自动化上限 |
|---|---|---|---|
| `CONTAINER_CPU` | 一次性用户态工具，文件进、退出码出 | 销毁容器 | `FULL_AUTO` |
| `CONTAINER_GPU` | 触发需要 GPU 设备的库 | 销毁容器 + 设备健康检查 | `GPU_WATCHDOG` |
| `CONTAINER_SERVICE` | 长驻服务，HTTP/gRPC 入口 | 销毁容器 + 服务生命周期协议 | `SUPERVISED` |
| `DEDICATED_HOST` | 显示/编译器驱动栈 | 一次性宿主机或快照回滚 | `MANUAL_ONLY` |

`UNCLASSIFIED` 只用于输入未声明工具也未声明 GPU 的情形，其 `automation_tier`
为 `NOT_ALLOWED`，默认拒绝。

## 3. 判定规则与优先级

顺序固定，先命中先返回：

1. **DRIVER**：组件名/类型命中 `nvgpucomp`、`nvlddmkm`、`nvwgf2um`、
   `display driver`、`compiler driver`、`显示驱动`。容器共享宿主驱动，
   因此不能靠销毁容器回滚。
2. **NETWORK_SERVICE**：攻击面入口含 HTTP/gRPC/服务端。一次运行需要启动、
   健康检查、停止三段协议，不能当作"跑一条命令"。
3. **GPU_LIBRARY**：CUDA 维度声明了参与触发的 GPU 架构，或组件是
   `cudnn/cublas/tensorrt/cv-cuda/nvjpeg/nvdec/nvrtc/cutlass` 之一
   （后者用于架构字段写"N/A（缺陷在 API 层）"但实际仍需设备的库）。
4. **USERLAND_TOOL**：声明了可执行工具，且无 GPU 声明。
5. **UNKNOWN**：其余。

两个已修正的误判，作为规则回归用例保留在 `tests/test_target_profile.py`：

- 输入用"非驱动"排除驱动类时，不能被"驱动"二字命中（Triton）；
- 组件标签里的 `CUDA Toolkit` 不能当作 GPU 依赖（cuobjdump/nvdisasm）。

## 4. 本地研究语料的实际分布

只读盘点本地原工程输入目录的 23 个 CVE（本仓库当前只收录其中 6 个）：

| 类 | 数量 | CVE |
|---|---|---|
| `USERLAND_TOOL` | 16 | 2022-21821、2023-0196、2024-0076、2024-0109、2024-0110、2024-0111、2024-0124、2024-0125、2024-53877、2025-23247、2025-23308、2025-23338、2025-23339、2025-23340、2025-23346、2025-33231 |
| `DRIVER` | 4 | 2024-0090、2024-0091、2024-0107、2026-24191 |
| `GPU_LIBRARY` | 2 | 2024-0115（CV-CUDA）、2025-23273（nvJPEG） |
| `NETWORK_SERVICE` | 1 | 2025-23316（Triton Inference Server） |

**结论：23 个 CVE 只需要 3 类靶场，不是 23 种环境。** 真正的差异集中在
"哪个工具、哪个版本、哪种输入格式"，这三项用一个参数化镜像即可覆盖。

用户态工具的版本差异是实际存在的：`cuobjdump 11.2`（本机既有）、
`cuobjdump 12.8.55`、`nvdisasm 12.8.90`（Talos 实测版本）。同一镜像族
按版本打 tag 即可，不需要为每个 CVE 单独构建。

## 5. 本机不可复现的 4 个

`CVE-2024-0090`、`0091`、`0107`、`2026-24191` 属于驱动类，且输入资料明确记录：
本机驱动 `617.42` 高于全部修复分支上界（分别为 555.x、555.99、556.12、
595.71.05）。它们在本机**已修复**，无论靶场怎么搭都不可能复现，只能换一台
装旧驱动的独立主机。这四个不进入自动闭环，状态保持
`UNSUPPORTED_ENVIRONMENT`，不占用迭代预算。

## 6. 靶场选型：Docker 优先，WSL 降级

| 维度 | Docker | WSL2 |
|---|---|---|
| 工具版本钉死 | 镜像 tag + digest，逐字节可复现 | 共享发行版，改版本要动全局 |
| 复位成本 | 销毁容器 | 重装包/清缓存，可能污染其他实验 |
| 证据绑定 | 镜像 digest + 容器 ID + 工具 SHA | 只有当前发行版状态 |
| 隔离原语 | `--network none --read-only --cap-drop ALL --pids-limit` 现成 | 依赖发行版配置 |
| GPU | `--gpus` + nvidia-container-toolkit | 绑定宿主驱动 |
| 当前可用性 | 已安装 4.95（CLI 29.8.2），引擎需人工启动 | 存在，但本会话被安全策略禁止调用 |

因此：**执行平面用 Docker，平台指纹继续用现有的 Windows→WSL 探测链。**
两者不冲突——`platform_probe` 负责"目标是什么"，容器负责"在哪跑"。
Docker 未安装时，`CONTAINER_*` 档位返回 `BACKEND_UNAVAILABLE`，不得静默回退到
本机进程执行。

## 7. 自动化分级（对应用户目标）

| 档位 | 谁在跑 | 失败后果 | 建议 |
|---|---|---|---|
| `FULL_AUTO` | 容器内一次性进程 | 容器退出，宿主不受影响 | 可以做"生成→执行→判定→迭代"全自动 |
| `GPU_WATCHDOG` | GPU 容器 | 可能拖挂设备，需重启宿主 | 全自动但串行、硬超时、每轮前后健康检查 |
| `SUPERVISED` | 网络隔离开的服务容器 | 需要显式停止 | 自动，但必须带生命周期协议 |
| `MANUAL_ONLY` | 专用宿主机 | 可能蓝屏/需重启 | 不自动 |

用户要求"全自动"，在工程上可以满足，但**全自动的前提是故障域被限制在容器内**。
`FULL_AUTO` 覆盖 16 个用户态工具 CVE，这已经是语料的 70%，也是论文最容易
出数据的一档。

## 8. 与现有执行链的衔接

- `src/tools/process.py::run_tool`、`src/lifecycle_process.py`：进程组、超时、
  `RLIMIT`、输出上限、回收——容器内仍复用同一套观测语义。
- `src/probe_process.py`、`src/platform_probe.py`：目标环境指纹，保持不变。
- `src/cve_lab.py`：当前硬编码只接受 `CVE-2025-23339`，P4-B 应改为读取本档案，
  而不是继续按 CVE 名字分支。
- `src/candidate_adapter.py`：`execution_admission` 恒为 `UNSUPPORTED`。
  放开它需要新的准入合同，不在本文件范围。

## 9. 本轮未做的事

- Docker Desktop 4.95 已安装（CLI 29.8.2），但引擎未启动：其 WSL2 后端会调用
  `wsl.exe`，而本会话的安全策略禁止该程序。需要由操作者手动启动一次 Docker Desktop，
  或从"安全中心 → 命令安全 → 程序黑名单"移除 `wsl.exe`。
- 未构建任何镜像，未运行任何容器。
- 未执行任何真实漏洞样本或生成候选。
- 未把原工程的 17 个 CVE 输入迁入本仓库（属私有研究资料，需单独决定）。
- 未验证 `CONTAINER_GPU` 在本机单卡环境下的设备复位能力。
