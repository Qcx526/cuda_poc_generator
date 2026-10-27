# CUDA / GPU PoC Generator

LLM 驱动的漏洞 PoC 生成与**迭代验证**系统。生成只是起点：候选必须在隔离环境里跑出
**差分证据**——基线干净、构造样本崩溃、单变量对照干净——才算复现。

**当前版本：Closed-Loop Iterative Generation。判定以差分证据为准，不以候选自述为准。**

## 1. 核心能力

- **闭环迭代**：规格 → 生成 → 执行 → 差分判分 → 失败归因 → 带反馈重试（`src/closed_loop.py`）
- **三层目标**：`userland_toolchain`（nvdisasm/cuobjdump，Docker 隔离）、`driver_userland`
  （nvgpucomp64 等）、`driver_kernel`（nvlddmkm，带崩溃取证）
- **差分判分**：判分器**自己**把产物逐个喂给目标工具，不听候选报告；三条件同时成立才判
  `SUPPORTED`（`src/reproduction.py`）
- **失败归因**：12 类失败分类（语法/lint/路径未达/前提/假阳性/无观察…），可归因的失败
  才重试，且反馈带具体指令（`src/failure_taxonomy.py`）
- **崩溃取证**：内核层执行前写标记、跨重启采集开机事件 6005 与 bugcheck 1001，
  结果归因到候选与变体（`src/driver_probe.py` / `src/driver_crash.py`）
- **质量 lint**：生成阶段的硬约束（版本分类、驱动探测上下文、手工 ELF 布局、项目内 import 等），
  违规候选被拒并重写
- **RAG 知识库**：`data/knowledge_bases/` 下的方法条目（含 GPU 驱动入口链与已否证路径），
  供生成阶段检索
- **七维资料加载**：七类 JSON 输入、字段来源与 SHA-256、严格合同校验（`src/data_loader.py`）
- **可复现报告**：每轮 `iteration_N_observation.txt` 原始输出 + 中文 `loop_report.zh-CN.md`

## 2. 快速开始（Windows）

```powershell
# 1) 环境：原生 CPython 3.12（uv 管理的解释器亦可，用绝对路径）
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c constraints/windows-py312.txt -e ".[dev]"

# 2) 密钥：本地 .env（不要提交）
Copy-Item .env.example .env
#   DEEPSEEK_API_KEY=...   CPG_LLM_MODEL_NAME / CPG_LLM_API_BASE 见 §8

# 3) Docker：工具链层在容器里执行
docker images cpg/cuda112-py3:1.0     # 缺失则 docker build -t cpg/cuda112-py3:1.0 -f docker/Dockerfile .

# 4) 跑一个 CVE（规格已就绪，oracle 明确）
.\.venv\Scripts\python.exe -u -m src.batch_loop --cve CVE-2025-23340 --iterations 2 --repeat 1 --workdir data/loop/first
```

首次运行的完整走查（每阶段输出含义、结果落点、常见两件事）见
**[docs/P5_B_FIRST_RUN.md](docs/P5_B_FIRST_RUN.md)**。

## 3. 三层目标与判定

| 层 | 目标 | 执行环境 | 判定 |
|---|---|---|---|
| `userland_toolchain` | nvdisasm / cuobjdump 等独立工具 | Docker（`cpg/cuda112-py3:1.0`，无网络、限内存） | 进程退出码 / SIGSEGV |
| `driver_userland` | `nvgpucomp64.dll` 等驱动用户态组件 | 本机（cdb 断点 + 退出码） | **退出码 + 出错模块归因** |
| `driver_kernel` | `nvlddmkm.sys`（escape / ioctl） | 本机，先布防再触发 | **bugcheck 1001 + 跨重启取证** |

**判定语义**：

```
SUPPORTED    基线干净 ∧ 构造样本崩溃 ∧ 单变量对照干净
NOT_VERIFIED 有崩溃但对照不干净，或无崩溃
EXHAUSTED    迭代用尽且每轮归因明确
ERROR        阶段失败（生成失败 / 超时 / 容器问题）
```

**用户态归因规则**（踩过坑后固化）：访问违例必须归因到模块才算命中——截断输入会让
`d3d9!CBaseShaderValidator` 先崩，与目标组件无关。

## 4. 闭环架构

```text
specs/<CVE>/spec.json          规格：入口、解析字段、oracle（触发条件）
        │
        ▼
[generate]   读规格 + RAG + 失败反馈 → 写 cuda_poc_vN.py（过 lint 才放行）
        │
        ▼
[execute]    容器/本机执行候选 → 候选产出 artifacts.json（benign/crafted/controls）
        │     判分器再自己把产物喂给目标工具，记录 [CPG_RUN] 行
        ▼
[grade]      差分判定 → SUPPORTED / NOT_VERIFIED / …
        │
        ▼
[diagnose]   失败归因（12 类）→ 可归因且可重试？
        │            ├─ 是 → [feedback] 带指令进入下一轮
        ▼            └─ 否 → 结束并写报告
loop_report.zh-CN.md + iteration_N_observation.txt
```

设计铁律（详见 [docs/P4_Z_KERNEL_ESCAPE_PROBE.md](docs/P4_Z_KERNEL_ESCAPE_PROBE.md)）：

1. **目标函数是差分判定**，不是"观察到崩溃"——否则会收敛到假阳性
2. **内核路径禁止无界重试**——每次触发都可能蓝屏；一次一个值，触发即停
3. **反馈必须可归因**（lint 罪名 / 对照结果 / 退出码），"没崩"不回流

## 5. 规格：添加一个目标

`specs/<CVE>/spec.json` 声明：入口调用、输入形态、解析字段及偏移、oracle（哪个字段、
什么条件、预期效果）、版本范围。oracle 明确时策略为 `MUTATE_DIRECTED`（定点变异），
否则降级为搜索。现有目标：

```
CVE-2024-0076   cuobjdump ELF 解析越界写
CVE-2024-0091   cuobjdump 空指针
CVE-2024-0107   nvgpucomp64 着色器编译越界读（driver_userland）
CVE-2025-23247 / 23339 / 23340   nvdisasm / cuobjdump 内存类
CVE-2026-24193  nvlddmkm 越界写（driver_kernel，入口可达性已实测）
```

## 6. 常用命令

```powershell
# 单个 CVE 闭环
.\.venv\Scripts\python.exe -u -m src.batch_loop --cve CVE-2025-23340 --iterations 2 --repeat 1 --workdir data/loop/run1

# 批量（工具链层）
.\.venv\Scripts\python.exe -u -m src.batch_loop --tier userland_toolchain --limit 3

# 内核层（带布防与取证）
.\.venv\Scripts\python.exe -u -m src.batch_loop --tier driver_kernel --cve CVE-2026-24193

# 静态入口：从 nvlddmkm.sys 提取 escape 码候选（按版本匹配）
.\.venv\Scripts\python.exe -m tools.extract_escape_codes

# 质量检查
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check main.py src tests tools
```

## 7. 目录结构

```text
src/                    闭环内核（closed_loop / loop_stages / reproduction /
                        failure_taxonomy / backends）与加载、配置、探测
specs/                  每个 CVE 的入口与 oracle 规格
tools/                  探测与提取工具（probe_* / extract_* / sweep_* / driver/）
data/inputs/CVE-*/      七维研究输入（受控）
data/knowledge_bases/   RAG 语料（CUDA 漏洞知识 + GPU 驱动方法与已否证路径）
data/outputs/<CVE>/     候选脚本与产物（artifacts.json 声明角色）
data/loop/<run>/        每轮观察与中文报告
constraints/            版本约束快照（Windows 3.12 / core）
tests/                  离线回归（83 个文件，约 1150 个测试函数）
docs/                   P0–P5 阶段合同与验收报告（64 篇）
```

## 8. 依赖与模型配置

| 组 | 用途 | 安装 |
|---|---|---|
| 核心 | YAML/dotenv/Pydantic/httpx/OpenAI/LangChain | `pip install -c constraints/core.txt -e .` |
| `dev` | pytest、ruff | `pip install -c constraints/core.txt -e '.[dev]'` |
| `rag` | Chroma、sentence-transformers | `pip install -c constraints/core.txt -e '.[rag]'` |
| `search` | Tavily 联网检索 | `pip install -c constraints/core.txt -e '.[search]'` |

`.env` 三项（密钥留在本地，不进仓库）：

```dotenv
DEEPSEEK_API_KEY=<本地密钥>
CPG_LLM_MODEL_NAME=deepseek-flash
CPG_LLM_API_BASE=https://api.deepseek.com
```

配置优先级：进程环境高于 `.env`，`CPG_*` 高于 YAML。支持覆盖项包括
`CPG_LLM_MODEL_NAME / API_BASE / API_KEY_ENV / TEMPERATURE / MAX_TOKENS / TIMEOUT /
MAX_RETRIES` 与 `CPG_RAG_ENABLED`。Tavily Key 未设置时跳过 Web 检索；`--no-rag`
只禁用 RAG，不禁用 LLM 或 Tavily 网络请求。LangSmith 外部追踪默认关闭。

RAG 加载 `data/knowledge_bases/` 下 UTF-8 `.md`/`.txt`，嵌入
`sentence-transformers/all-MiniLM-L6-v2`（CPU），索引存 `.chromadb/` 不提交。
更新语料后需 `force_rebuild` 重建。

工具链执行需要 Docker 与镜像 `cpg/cuda112-py3:1.0`（构建见 `docker/Dockerfile`）。

## 9. 边界与当前限制（如实）

- **生成成功不等于复现**：只有差分三条件同时成立才判 `SUPPORTED`；历史 run 的
  `NOT_VERIFIED` 保留原判，不改写
- **`driver_kernel` 层入口可达但未打通**：D3DKMT 链路已实测到 device/context，
  escape 在分发前被权限拒绝；六条否证与方法记录见
  [docs/P5_A_GPU_POC_FEASIBILITY.md](docs/P5_A_GPU_POC_FEASIBILITY.md)
- **`driver_userland`（CVE-2024-0107）**：版本对齐（551.61）、断点与归因工具就绪，
  但构造到达漏洞路径的输入仍在研究；已否证路径见
  [docs/P4_V_DRIVER_RE_MAP.md](docs/P4_V_DRIVER_RE_MAP.md)
- **执行隔离**：工具链层在无网络容器内；内核层执行前必须布防标记，触发后跨重启取证。
  不满足前置（Docker、镜像、cdb）时对应层直接报 `ERROR`，不静默跳过

## 10. 文档索引

| 主题 | 入口 |
|---|---|
| 首次运行走查 | `docs/P5_B_FIRST_RUN.md` |
| GPU 驱动 PoC 可行性（11 组否证与方法） | `docs/P5_A_GPU_POC_FEASIBILITY.md` |
| 内核 escape 探测记录 | `docs/P4_Z_KERNEL_ESCAPE_PROBE.md` |
| CVE-2024-0107 逆向地图与勘误 | `docs/P4_V_DRIVER_RE_MAP.md` |
| 七维输入 JSON 结构 | `docs/P1_A_CONTRACT.md` |
| 历史阶段合同（P0–P3：分析/平台/工具/Oracle/打包） | `docs/P*_*.md` 系列 |

## 11. 质量基线

```text
pytest:  1486 passed / 66 skipped（含编码回归、候选故障归因、判定链路）
ruff:    clean（main.py / src / tests / tools）
语言:    代码与合同英文，报告默认简体中文 UTF-8
```
