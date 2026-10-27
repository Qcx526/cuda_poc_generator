# CUDA PoC Generator

面向 **GPU 漏洞全品类**的 PoC 生成工程：从漏洞资料出发，让模型写出可执行的 PoC，
再由判分器**自己**跑一遍工具链给出差分判定，失败结果回流下一轮。

支持三层目标，同一套判定规则：

| 层 | 目标形态 | 执行位置 | 崩溃信号 |
|---|---|---|---|
| `userland_toolchain` | 畸形文件 → CLI 工具（cuobjdump / nvdisasm） | 隔离容器 | 信号 / 退出码 |
| `driver_userland` | 驱动附带的用户态组件（着色器编译器等） | 本机进程 | `0xC0000005` + 模块归因 |
| `driver_kernel` | 内核驱动（`nvlddmkm`），ioctl 序列 | 本机 + 跨重启取证 | bugcheck（事件 1001） |

当前测试规模：**1486 passed, 66 skipped**。

## 1. 当前状态（实测，不是计划）

| 能力 | 状态 | 证据 |
|---|---|---|
| 工具链层闭环 | ✅ 可用 | `CVE-2024-0076` 3/3、`CVE-2025-23339` 2/3，单次 163–317 秒 |
| 判分器自主执行 | ✅ 可用 | 候选交 `artifacts.json`，判分器按声明逐个跑工具 |
| 内核层取证 | ✅ 可用 | 跨重启布防/采集，读 bugcheck 事件，7 项宿主检查全绿 |
| D3DKMT 客户端 | ✅ 可达 | adapter / device / context 三句柄实测可用 |
| 内核 escape 触发 | ❌ 未打通 | 分发前被权限拒绝（`0xC0000022`），见 `docs/P4_Z` |
| 用户态编译触发 | ❌ 未打通 | 分派函数对像素着色器不进入，见 `docs/P4_V` |

**已知结论**：内核层的困难不是方法不足，而是接口被系统性硬化——
六条否证见 `docs/P5_A_GPU_POC_FEASIBILITY.md`。

## 2. 闭环流程

```
specs/<CVE>/spec.json        规格：入口、字段、oracle
        │
        ├─ [generate]  模型读规格 → 候选脚本（lint 不过则重写，最多两次）
        ├─ [execute]   候选跑出产物 → 判分器**自己**再跑一遍工具
        ├─ [grade]     三条件判定：baseline 干净 + crafted 崩 + control 干净
        └─ [feedback]  失败归类 → 具象指令 → 下一轮
```

三条设计约束，都是踩过坑之后定下的：

1. **判分器自己跑**：候选只交文件和角色，工具调用由判分器决定。
   否则候选可以靠"我跑了，崩了"蒙混过关。
2. **角色显式声明**：`artifacts.json`（或 `[CPG_LABEL]` 行）。
   按文件名猜角色曾把良性基线和攻击样本搞混。
3. **崩溃必须归因**：内核层要 bugcheck 事件，用户态要模块名。
   只看退出码曾把 d3d9 校验器的崩溃当成驱动漏洞（见 `docs/P5_A` §5.2）。

## 3. 快速开始

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c constraints/windows-py312.txt -e ".[dev]"
Copy-Item .env.example .env      # 填入 DEEPSEEK_API_KEY

# 跑一个 CVE（工具链层；需要 Docker Desktop 已启动）
.\.venv\Scripts\python.exe -u -m src.batch_loop --cve CVE-2025-23340 --iterations 2 --repeat 1 --workdir data/loop/first
```

第一次运行的逐阶段说明见 [首次运行指南](docs/P5_B_FIRST_RUN.md)。

结果位置：

| 路径 | 内容 |
|---|---|
| `data/loop/<run>/<CVE>/loop_report.zh-CN.md` | 人读报告：判定、理由、每轮记录 |
| `data/loop/<run>/<CVE>/iteration_N_observation.txt` | 原始执行输出（含 `[CPG_RUN]` 与清单信息） |
| `data/outputs/<CVE>/` | 候选脚本与它产出的文件 |

判定含义：`SUPPORTED` 三条件成立；`NOT_VERIFIED` 有崩溃但对照不干净或未崩；
`EXHAUSTED` 迭代用尽；`ERROR` 阶段失败。

## 4. 目录结构

```text
main.py                  单次生成入口（历史接口，仍可用）
src/batch_loop.py        批量闭环驱动
src/closed_loop.py       循环与终止条件
src/loop_stages.py       生成 / 执行 / 反馈三个阶段
src/reproduction.py      日志解析与差分判定
src/failure_taxonomy.py  失败归类与可重试判定
src/spec_model.py        规格模型（含 driver 层的 trigger 步骤）
src/driver_probe.py      内核探针：布防 → 启动 → 跨重启采集
src/driver_crash.py      bugcheck 解析与开机时间判定
specs/<CVE>/spec.json    每个目标一份规格
data/harness/            着色器测试器与字节码样本
data/knowledge_bases/    检索语料（会被 RAG 摄取）
tools/                   探测、取证、逆向工具
docs/                    合同、验收、可行性报告
```

## 5. 工具

**运行闭环**

| 工具 | 用途 |
|---|---|
| `src.batch_loop` | 批量跑 CVE，输出汇总 |
| `tools.diag_generation` | 单独诊断生成阶段 |
| `tools.compare_runs` | 多次运行对比 |

**内核层取证**

| 工具 | 用途 |
|---|---|
| `tools.check_driver_env` | 宿主自检：驱动版本、转储配置、自动重启 |
| `tools.harvest_probe` | 重启后采集：`--scan` 遍历所有已布防探针 |
| `tools.probe_d3dkmt` | D3DKMT 三段探测（adapter / device / escape） |
| `tools.probe_gpu_surface` | 枚举可达的设备对象与 NVAPI 面 |

**驱动逆向**

| 工具 | 用途 |
|---|---|
| `tools.extract_escape_codes` | 从 `nvlddmkm.sys` 提取 `0x1000xxxx` 候选（按版本选文件） |
| `tools.extract_ioctls` | 从 `nvapi64.dll` 提取 DeviceIoControl 码 |
| `tools.probe_ioctl_channel` | 验证 ioctl 通道是否可用（无效码探针） |
| `tools.sweep_escapes` | 逐码尝试 escape，命中即停 |
| `tools.hook_umd_escape` | 拦截 UMD 的 escape 调用 |

**着色器路径**

| 工具 | 用途 |
|---|---|
| `tools.driver.run_fuzz` | 按语法生成变体并跑（带崩溃归因） |
| `tools.driver.trace_run` | 在指定 RVA 下断，返回是否命中 |
| `tools.driver.byte_trace` | 字节级跟踪 |
| `tools.driver.sincos_token_fuzz` | 定向损坏指令令牌字段 |
| `data/harness/shader_runner.exe` | `compile` / `bytecode` / `assemble` 三种模式 |

## 6. 输入与配置

漏洞输入为七维 JSON（`data/inputs/CVE-*/`）：

```text
1_os_environment.json            OS/kernel/权限/环境
2_cuda_environment.json          GPU/CUDA/驱动/工具链
3_affected_component.json        组件与版本范围
4_attack_surface.json            入口与输入控制
5_vulnerability_type.json        CWE/类型
6_impact_controllability.json    影响与控制条件
7_root_cause.json                根因、来源与研究假设
```

配置优先级：进程环境 > 根目录 `.env` > `config/default.yaml`。
常用覆盖项：`CPG_LLM_MODEL_NAME`、`CPG_LLM_API_BASE`、`CPG_LLM_API_KEY_ENV`、
`CPG_RAG_ENABLED`、`CPG_MAX_ITERATIONS`。密钥只放 `.env`，不入库。

RAG 读取 `data/knowledge_bases/` 下的 UTF-8 `.md`/`.txt`，本地 CPU 嵌入
（`all-MiniLM-L6-v2`），索引存 `data/knowledge_bases/.chromadb/`（不提交）。
`--no-rag` 只关 RAG，不影响模型调用。

## 7. 已知边界

- **工具链层**：需要 Docker，镜像 `cpg/cuda112-py3:1.0`。
- **内核层**：需要 Windows + 真 GPU + 可回滚的崩溃恢复（`AutoReboot=1`、转储开启）。
- **用户态编译层**：版本敏感（`CVE-2024-0107` 只在 551.61 复现，535.98 已修复）。
- **生成阶段**：受模型服务稳定性影响，抖动表现为 `STAGE_ERROR`，重跑即可。
- 主流程不会自动编译 CUDA 源码或启动 kernel；工具链层的产物由候选脚本构造。

## 8. 文档索引

**可行性结论**

- [GPU 驱动 PoC 可行性：一天的实测与结论](docs/P5_A_GPU_POC_FEASIBILITY.md) — 11 组否证、三个静默错误、下一步路线
- [内核 escape 入口探测](docs/P4_Z_KERNEL_ESCAPE_PROBE.md) — 六条否证与判别方法
- [驱动逆向地图](docs/P4_V_DRIVER_RE_MAP.md) — CVE-2024-0107 的实测 RVA（含勘误）

**操作指南**

- [首次运行](docs/P5_B_FIRST_RUN.md)
- [环境迁移](docs/ENVIRONMENT_MIGRATION.md)
- [归档合同](docs/CVE_ARTIFACT_PACKAGING.md)

**历史阶段**：`docs/P0_*` 至 `docs/P4_*` 记录各阶段的合同与验收。

## 9. 环境与依赖

- Python `>=3.10,<3.13`（本轮 Windows 使用 3.12.13）
- 依赖入口 `pyproject.toml`；`constraints/windows-py312.txt` 为版本快照
- 运行闭环需要 Docker Desktop；内核层工具需要 Windows 与 NVIDIA 驱动
- 着色器逆向的调试器默认 `D:\Windows Kits\10\Debuggers\x64\cdb.exe`

## 10. 测试与提交

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check main.py src tests tools
```

约定见 `AGENTS.md`：默认在 `main` 开发，验收通过后提交推送，不 force push，
不提交 `.env`、虚拟环境、缓存与私有原始证据。

## 11. 生成物不代表漏洞已验证

候选能被生成、能被 lint 通过、甚至能让工具崩溃，都不等于复现成立。
判定只认三条件同时成立，且每条结论都带证据路径（`[CPG_RUN]` 行、崩溃归因、对照结果）。
