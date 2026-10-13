# CUDA PoC Generator

**NVIDIA CUDA 漏洞专项 PoC 生成 Agent**

> **免责声明**: 本工具仅供经过合法授权的安全研究与渗透测试使用。使用者必须在获得目标系统所有者明确书面授权后方可使用本工具。未经授权对系统进行攻击属于违法行为，作者不承担任何由滥用导致的法律责任。

---

## 概述

CUDA PoC Generator 是一个专用于 **NVIDIA CUDA 生态系统漏洞** 的自动化 PoC（概念验证）生成 Agent。它基于通用的 `universal_poc_generator` 框架演进而来，通过最新版本的 **LangChain + RAG** 架构，经 **NIUBIAPI 中转站**（OpenAI 兼容接口）调用大模型，内建 **CUDA 专项 7 层漏洞分析模型**，覆盖市面上绝大部分 CUDA 程序或库的漏洞类型。

### 核心能力

| 能力 | 说明 |
|------|------|
| **7 层 CUDA 漏洞分析模型** | 攻击面映射 → 原语识别 → 可控性评估 → 目标定义 → 触发路径构造 → 缓解分析 → 可靠性工程 |
| **LangChain + ChromaDB RAG** | CUDA 专项知识增强检索，涵盖 CWE 分类、CUDA API 安全、已知 CVE 案例 |
| **NIUBIAPI 中转驱动** | 通过中转站 OpenAI 兼容接口调用，内建 CUDA 安全专家人格 |
| **人在回路反馈迭代** | 用户在 GPU 环境执行 PoC 后粘贴输出，Agent 自动解析 CUDA 错误码并优化 |
| **7 维度结构化输入** | 专为 CUDA 漏洞定制的 7 类 JSON 输入格式 |
| **CUDA 辅助函数库** | 预置 CUDA Driver/Runtime API 签名和攻击面知识 |

---

## CUDA PoC Agent 成体系的思考行为模式

本 Agent 内建了一套专为 CUDA 漏洞设计的 **7 层分析 × 5 阶段执行** 成体系思考框架。

### 一、7 层 CUDA 漏洞分析模型 (7-Layer CUDA Vulnerability Analysis Model)

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: 利用可靠性工程 (Reliability Engineering)           │
│  ├─ [CUDA_STEP:Sxx] 步骤标记、GPU 错误码解析、TDR 处理      │
│  ├─ GPU 资源清理、环境自适应检测                             │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: 缓解措施分析 (Mitigation Analysis)                 │
│  ├─ GPU ECC, MIG 分区, GPU MMU 隔离                         │
│  ├─ ASLR, SMEP/SMAP, IOMMU, VT-d                            │
│  ├─ nvidia-container-toolkit 容器隔离                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: 触发路径构造 (Trigger Path Construction)           │
│  ├─ 最小 CUDA 操作序列 (cuInit→cuCtxCreate→cuModuleLoad→…)  │
│  ├─ CUDA 上下文生命周期管理                                  │
│  ├─ 同步/异步错误处理路径                                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: 利用目标定义 (Exploitation Goal Definition)        │
│  ├─ RCE / LPE / Info Leak / DoS                             │
│  ├─ Container Escape / Persistent Implant                   │
│  ├─ Kernel→Userland GPU 内存逃逸                             │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: 可控性评估 (Controllability Assessment)            │
│  ├─ 数据可控: kernel args, buffer size, grid/block dims     │
│  ├─ 文件可控: .cu/.ptx/.cubin/.fatbin 构造                   │
│  ├─ 时序可控: CUDA Stream/Event 竞争窗口                     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: 漏洞原语识别 (Primitive Identification)            │
│  ├─ 整数溢出/回绕 (CWE-190) — CUDA 中最常见                 │
│  ├─ 堆缓冲区溢出 (CWE-122) — GPU 全局内存/主机端堆           │
│  ├─ UAF (CWE-416) — CUDA 内存/Stream/Event 生命周期          │
│  ├─ 竞争条件 (CWE-362) — 多 Stream/MPS 并发                  │
│  ├─ 空指针解引用 / OOB 读写 / 类型混淆 / 格式化字符串 …      │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: CUDA 攻击面映射 (Attack Surface Mapping)           │
│  ├─ Driver API (cuMemAlloc, cuLaunchKernel, cuModuleLoad…)  │
│  ├─ Runtime API (cudaMalloc, cudaMemcpy…)                   │
│  ├─ Toolchain (nvcc, cuobjdump, nvdisasm, ptxas…)           │
│  ├─ Libraries (cuBLAS, cuDNN, cuFFT…)                       │
│  ├─ Virtualization (MPS, MIG, GPU Passthrough)               │
│  └─ GPU Direct / RDMA / CUDA IPC                             │
└─────────────────────────────────────────────────────────────┘
```

#### Layer 1: CUDA 攻击面映射

识别漏洞所在的具体 CUDA 子系统。CUDA 生态系统可分为 6 大攻击面：

1. **CUDA Driver API** (`libcuda.so` / `nvcuda.dll`) — cuInit, cuCtxCreate, cuMemAlloc, cuMemFree, cuLaunchKernel, cuModuleLoad, cuStreamCreate, cuEventCreate 等
2. **CUDA Runtime API** (`libcudart.so`) — cudaMalloc, cudaMemcpy, cudaLaunchKernel, cudaMallocManaged 等
3. **CUDA Toolchain** — nvcc, cuobjdump, nvdisasm, ptxas, nvlink, fatbinary
4. **CUDA Libraries** — cuBLAS, cuDNN, cuFFT, cuSPARSE, cuSOLVER
5. **GPU Virtualization** — MPS, MIG, GPU Passthrough, nvidia-container-toolkit
6. **GPU Direct / RDMA / CUDA IPC** — 跨进程/跨主机 GPU 通信

#### Layer 2: 漏洞原语识别

精确识别漏洞提供的能力原语。CUDA 中最常见的漏洞类型：

| CWE | 原语 | CUDA 特定场景 |
|-----|------|--------------|
| CWE-190 | 整数溢出/回绕 | 16-bit/32-bit 字段在计算 buffer 大小时溢出（如 CVE-2025-23247） |
| CWE-122 | 堆缓冲区溢出 | GPU 全局内存越界、主机端 CUDA 工具堆溢出 |
| CWE-416 | UAF | cuMemFree 后 kernel 继续访问、CUDA Stream/Event 销毁后使用 |
| CWE-476 | 空指针解引用 | CUDA API 返回 NULL 未检查 |
| CWE-125 | 越界读取 | GPU 共享内存/全局内存信息泄露 |
| CWE-362 | 竞争条件 | 多 Stream 竞争、MPS 多进程竞争、Unified Memory 页面迁移 |
| CWE-787 | 越界写入 | Kernel 内数组越界、共享内存越界、cuMemcpy 参数越界 |
| CWE-78  | 命令注入 | nvcc 编译选项注入、cuobjdump 参数注入 |
| CWE-22  | 路径遍历 | CUDA 工具文件路径处理 |
| CWE-457 | 未初始化内存 | GPU 内存分配（cudaMalloc）后未清零 |

#### Layer 3: 可控性评估

精确评估攻击者对漏洞触发条件的控制程度：

- **数据可控**: kernel 参数、buffer 大小、grid/block 维度是否由攻击者控制
- **文件可控**: 攻击者能否构造恶意 .cu、.ptx、.cubin、.fatbin 文件
- **时序可控**: 能否精确控制 CUDA Stream 同步时机来触发竞争条件
- **环境依赖**: 漏洞是否依赖特定 GPU 架构 (sm_75/86/89)、CUDA 版本、驱动版本

#### Layer 4: 利用目标定义

明确漏洞的利用目标：

- **RCE**: 通过恶意输入触发 CUDA 工具/服务远程代码执行
- **LPE**: 通过 CUDA 驱动漏洞实现本地权限提升
- **Info Leak**: GPU 内存信息泄露（kernel 地址、驱动内存、相邻进程数据）
- **DoS**: GPU 挂起 (TDR)、驱动崩溃、MPS/MIG 服务不可用
- **Container Escape**: 通过 GPU 直通/MIG 配置缺陷/MPS 服务实现容器逃逸
- **Persistent Implant**: GPU 内存中隐藏恶意代码

#### Layer 5: 触发路径构造

设计最小的 CUDA 操作序列来触发漏洞：

```
典型 CUDA 利用链：
  cuInit(0)
  → cuDeviceGet(&dev, 0)
  → cuCtxCreate(&ctx, 0, dev)
  → [构造恶意数据]
  → cuModuleLoadData(&module, malicious_data)  ← 漏洞触发点
  → cuModuleGetFunction(&func, module, "vuln_kernel")
  → [观察崩溃/异常行为]
  → cuCtxDestroy(ctx)
```

#### Layer 6: 缓解措施分析

识别目标环境中可能阻碍利用的缓解措施：

- **GPU 侧**: GPU ECC、GPU MMU、MIG 分区隔离、GPU 可信执行环境
- **主机侧**: ASLR、SMEP/SMAP、KASLR、IOMMU/VT-d/AMD-Vi
- **驱动层**: nvidia.ko 参数验证增强、CUDA 驱动输入校验
- **容器层**: gVisor GPU passthrough、nvidia-container-toolkit 挂载隔离

#### Layer 7: 利用可靠性工程

确保 PoC 在不同 CUDA 环境下可靠执行：

- **[CUDA_STEP:Sxx] 步骤标记**: 每个步骤清晰标注执行状态
- **CUDA 错误码完整解析**: 0=SUCCESS, 1=INVALID_VALUE, 2=OUT_OF_MEMORY, 700=ILLEGAL_ADDRESS 等
- **GPU 状态恢复**: TDR 超时处理、设备丢失 (Device Lost) 重试
- **环境自适应**: 启动时检测 CUDA 版本、驱动版本、GPU 架构，自动适配

---

### 二、5 阶段 PoC 执行流水线

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CUDA PoC Agent 5-Phase Execution Pipeline                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: 情报收集                Phase 2: 漏洞分析                     │
│  ┌──────────────────┐            ┌──────────────────┐                   │
│  │ 加载 7 类 CUDA   │            │ 7 层 CUDA 分析   │                   │
│  │ 漏洞输入 JSON     │───────────→│ 模型深度分析     │                   │
│  │ (D1 到 D7)       │            │                  │                   │
│  │                  │            │ root_cause +     │                   │
│  │ CUDA RAG 知识库  │            │ exploit_strategy │                   │
│  │ 向量检索         │            └────────┬─────────┘                   │
│  └──────────────────┘                     │                             │
│                                           ↓                             │
│  Phase 5: 迭代优化                Phase 3: PoC 构造                     │
│  ┌──────────────────┐            ┌──────────────────┐                   │
│  │ 更新 CUDA 上下文 │            │ LLM 代码生成     │                   │
│  │ 注入用户补充信息 │←───────────│ + CUDA 辅助函数  │                   │
│  │                  │            │                  │                   │
│  │ 重新分析 + 生成  │            │ [CUDA_STEP:Sxx]  │                   │
│  └──────────────────┘            │ 标记 PoC 脚本    │                   │
│          ↑                       └────────┬─────────┘                   │
│          │                                ↓                             │
│  ┌──────┴───────────┐            ┌──────────────────┐                   │
│  │ CUDA 失败分析    │            │ 用户执行 (GPU)   │                   │
│  │ CUDA 错误码解析  │←───────────│ 粘贴终端输出     │                   │
│  │ 缺失信息收集     │            │                  │                   │
│  └──────────────────┘            └──────────────────┘                   │
│  Phase 5 (续)                    Phase 4: 验证反馈                      │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Phase 1: 情报收集 (Intelligence Gathering)

1. 加载 7 维度 CUDA 漏洞输入 JSON 文件
2. 构建/加载 CUDA 专项 RAG 知识库 (LangChain + ChromaDB)
3. 根据漏洞特征 (CVE/CWE/CUDA component/GPU arch) 查询 RAG 知识库
4. 为后续分析阶段注入 CUDA 领域知识

#### Phase 2: 漏洞分析 (Vulnerability Analysis)

1. CUDA 安全专家 LLM (内建 7 层分析模型) 执行根因分析
2. 输出 `root_cause_analysis` + `exploit_strategy`
3. 每步策略包含: pseudocode, success_condition, failure_condition, expected_cuda_behavior
4. 置信度评分 + 低置信度自动提示补充信息

#### Phase 3: PoC 构造 (PoC Construction)

1. LLM 根据攻击策略生成完整 Python PoC 脚本
2. 引用 CUDA 辅助函数库签名
3. 自动包含 CUDA 环境检测代码
4. 所有步骤使用 [CUDA_STEP:Sxx] 标记
5. 完整的 CUDA 错误码检查和解释

#### Phase 4: 验证反馈 (Validation & Feedback)

1. 用户在目标 GPU 环境执行 PoC
2. 粘贴终端输出回 Agent
3. 自动解析 [CUDA_STEP:Sxx] 标记和 CUDA 错误码
4. 支持 "SUCCESS" 快速确认和 "QUIT" 退出

#### Phase 5: 迭代优化 (Iteration & Optimization)

1. LLM 分析 CUDA PoC 失败原因（CUDA 错误码 + 日志）
2. 识别缺失的 CUDA 环境信息（驱动版本、GPU 型号、Toolkit 版本等）
3. 向用户提问并收集补充信息
4. 将补充信息注入漏洞上下文，返回 Phase 2 开始新一轮迭代
5. 最多 10 轮迭代（可配置）

---

## CUDA 漏洞覆盖范围

本 Agent 覆盖市面上绝大部分 CUDA 程序或库的漏洞类型：

### 按 CUDA 子系统分类

| 子系统 | 覆盖的漏洞类型 | 典型攻击入口 |
|--------|--------------|-------------|
| **CUDA Driver API** | 整数溢出、UAF、OOB 读写、类型混淆、竞争条件 | cuMemAlloc、cuLaunchKernel、cuModuleLoad 参数 |
| **CUDA Runtime API** | 缓冲区溢出、空指针、未初始化内存 | cudaMalloc、cudaMemcpy、cudaLaunchKernel |
| **CUDA Toolchain** | 整数溢出、命令注入、路径遍历、OOB 读写 | nvcc 编译、cuobjdump 解析、PTX 汇编 |
| **CUDA Libraries** | 参数验证缺陷、缓冲区溢出 | cuBLAS 矩阵维度、cuDNN 张量描述符 |
| **GPU Virtualization** | 隔离逃逸、权限提升、信息泄露 | MPS 服务、MIG 配置、GPU 直通 |
| **CUDA IPC/GPU Direct** | UAF、竞争条件、越界读写 | IPC 句柄、RDMA 缓冲区 |

### 按 CWE 分类

| CWE | 覆盖率说明 |
|-----|-----------|
| CWE-190 (整数溢出) | ✅ CUDA 中最常见，Agent 内建 16/32/64-bit 回绕检测逻辑 |
| CWE-122 (堆溢出) | ✅ 涵盖 GPU 全局内存和主机端 CUDA 工具堆 |
| CWE-416 (UAF) | ✅ 涵盖 CUDA 内存/Stream/Event/Graph 生命周期 |
| CWE-476 (空指针) | ✅ CUDA API 返回值检查 |
| CWE-125 (越界读) | ✅ GPU 共享内存/全局内存泄露 |
| CWE-362 (竞争条件) | ✅ CUDA 流/事件/MPS 多进程并发 |
| CWE-787 (越界写) | ✅ Kernel 数组边界、cuMemcpy 参数 |
| CWE-78 (命令注入) | ✅ CUDA 工具链命令参数 |
| CWE-22 (路径遍历) | ✅ CUDA 工具文件路径 |
| CWE-457 (未初始化) | ✅ GPU 内存分配 |

---

## 快速开始

### 环境要求

- Python 3.10+
- 对于运行生成的 PoC: NVIDIA GPU + CUDA Toolkit 环境

### 安装

```bash
cd cuda_poc_generator
pip install -r requirements.txt
```

### 准备 CUDA 漏洞输入

在 `data/inputs/<CVE-ID>/` 目录下创建 7 个 JSON 文件（每个 CVE 一个子目录）：

| 文件 | 维度 | 内容 |
|------|------|------|
| `1_os_environment.json` | D1 | 操作系统与环境依赖 (OS、kernel、驱动版本) |
| `2_cuda_environment.json` | D2 | CUDA 运行环境 (GPU 架构、CUDA/驱动版本、受影响工具) |
| `3_affected_component.json` | D3 | 受影响组件 (具体库/工具/API 及版本范围) |
| `4_attack_surface.json` | D4 | 攻击面与入口点 (API 调用、文件输入、网络端点) |
| `5_vulnerability_type.json` | D5 | 漏洞类型 (CWE 分类 + CVSS) |
| `6_impact_controllability.json` | D6 | 影响后果与可控性描述 |
| `7_root_cause.json` | D7 | 漏洞根源描述 (代码级技术细节) |

> 项目中已包含 CVE-2025-23247 (cuobjdump 整数回绕) 的完整示例输入。

### 配置 LLM

项目通过 **NIUBIAPI 中转站**的 OpenAI 兼容接口调用模型。
端点与中转站要求的请求头已在 `config/default.yaml` 中配置：

```yaml
llm:
  api_base: "https://www.niubiapi.com/v1"
  headers:
    User-Agent: "claude-cli/2.0.76 (external, cli)"   # 中转站要求，勿删
```

获取中转站 Key 后设置环境变量：

```bash
# Windows PowerShell
$env:NIUBIAPI_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"

# Linux/macOS
export NIUBIAPI_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"
```

也可以直接复制 `.env.example` 为 `.env` 并填入 Key（会被自动加载）。

如需切换模型，编辑 `config/default.yaml` 中的 `llm.model_name`，或设置环境变量 `CPG_LLM_MODEL_NAME`。

### 运行

```bash
# 使用默认配置和示例数据运行
python main.py --cve-id CVE-2024-0124

# 指定 CVE 编号（自动定位到 data/inputs/<cve-id>/）
python main.py --cve-id CVE-2025-23339

# 指定自定义 CUDA 漏洞输入目录
python main.py --input-dir ./my_cuda_vuln

# 限制最大迭代次数
python main.py --max-iter 5

# 使用自定义配置
python main.py --config ./my_cuda_config.yaml
```

---

## 项目结构

```
cuda_poc_generator/
├── config/
│   └── default.yaml                    # 默认配置文件
├── data/
│   ├── inputs/                         # CVE 输入数据，按 CVE 编号子目录组织
│   │   ├── CVE-2024-0124/              # 每个 CVE 一个子目录，含 7 个 JSON
│   │   │   ├── 1_os_environment.json
│   │   │   ├── 2_cuda_environment.json
│   │   │   ├── 3_affected_component.json
│   │   │   ├── 4_attack_surface.json
│   │   │   ├── 5_vulnerability_type.json
│   │   │   ├── 6_impact_controllability.json
│   │   │   └── 7_root_cause.json
│   │   └── CVE-2025-23339/           # 另一个 CVE 的数据
│   ├── knowledge_bases/
│   │   ├── .chromadb/                  # ChromaDB 向量持久化
│   │   └── cuda/
│   │       └── cuda_vulnerability_knowledge.md  # CUDA 知识库种子
│   ├── outputs/                        # 生成的 PoC 和报告，按 CVE 子目录
│   │   ├── CVE-2024-0124/              # cuda_poc_vN.py + cuda_analysis_vN.json + cuda_final_report.json
│   │   └── CVE-2025-23339/
│   └── templates/                      # 代码模板（可选）
├── src/
│   ├── __init__.py
│   ├── config_loader.py                # 配置加载
│   ├── llm_client.py                   # LangChain + LLM 封装（NIUBIAPI 中转 / OpenAI 兼容）
│   ├── data_loader.py                  # CUDA 数据加载 + LangChain RAG
│   ├── cuda_library.py                 # CUDA 辅助函数签名库
│   ├── core_expert.py                  # CUDA 安全专家 (7 层模型)
│   ├── code_generator.py               # CUDA PoC 代码生成
│   ├── feedback_loop.py                # 人在回路 CUDA 反馈
│   ├── pipeline.py                     # CUDA 主流水线
│   └── utils.py                        # 工具函数
├── main.py                             # 程序入口
├── requirements.txt
└── README.md
```

---

## 用户补充接口 (Human-in-the-Loop)

当 CUDA PoC 执行失败时，Agent 会主动请求以下类型的补充信息：

### 自动检测的失败类型

| 失败类型 | 自动分析 | 向用户请求的信息 |
|---------|---------|-----------------|
| CUDA_ERROR_INVALID_VALUE (1) | API 参数错误 | 请求提供 cuobjdump/nvcc 使用方式 |
| CUDA_ERROR_OUT_OF_MEMORY (2) | GPU 内存不足 | 请求提供 `nvidia-smi` 输出、GPU 显存大小 |
| CUDA_ERROR_NO_DEVICE (100) | 无 GPU 设备 | 确认是否有 GPU 硬件 |
| CUDA_ERROR_ILLEGAL_ADDRESS (700) | 越界访问触发 | 请求提供 dmesg 日志、崩溃信号 |
| CUDA_ERROR_LAUNCH_FAILED (719) | Kernel 启动失败 | 请求提供 nvcc 编译输出、GPU 架构 |
| Python Traceback | 代码异常 | 请求提供完整 traceback |
| SIGSEGV / SIGABRT | 崩溃 | 请求 dmesg/coredump 信息 |

### 交互示例

```
--- 为了改进 CUDA PoC，需要您补充以下信息：---

[Q01] 目标系统的 CUDA Toolkit 精确版本？
    （背景：cuobjdump 解析逻辑在 12.9 修复，需要确认是否受影响版本）
    您的回答：12.8

[Q02] cuobjdump 执行时的完整错误输出？
    （背景：需要确认是 malloc(0) 还是其他原因导致的崩溃）
    您的回答：Segmentation fault (core dumped)
```

---

## 与 universal_poc_generator 的对比

| 维度 | universal_poc_generator | cuda_poc_generator |
|------|------------------------|-------------------|
| 目标领域 | 通用（蓝牙/WiFi/IoT/Web...） | 专注 CUDA 生态系统 |
| 输入维度 | 7 个通用维度 | 7 个 CUDA 专项维度 (含 cuda_environment) |
| LLM 框架 | 原始 OpenAI SDK | LangChain (ChatOpenAI) |
| RAG 框架 | llama-index + ChromaDB | LangChain + ChromaDB |
| 分析模型 | 8 条通用利用原则 | 7 层 CUDA 专项分析模型 |
| 辅助函数库 | 领域可插拔协议库 | CUDA Driver/Runtime API + ELF 操作 |
| 错误码知识 | 通用 | CUDA 完整错误码映射表 |
| 攻击面知识 | 通用 | 6 大 CUDA 攻击面详细分类 |
| 迭代标记 | [STEP:Sxx] | [CUDA_STEP:Sxx] |

---

## 许可证

本项目仅供授权安全研究使用。
#   c u d a _ p o c _ g e n e r a t o r  
 