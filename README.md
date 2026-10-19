# CUDA PoC Generator

基于已有 CUDA 专项 PoC 生成系统的增量研究工程。保留七层分析 Prompt、七维漏洞输入、RAG、CUDA 知识映射和辅助工具，以候选代码生成为起点，逐步建设可复现实验和基于目标条件的验证系统。

**当前版本：Single-shot Generation。生成候选不代表漏洞已验证。**

## 1. 当前已实现能力

- 从七类 JSON 文件加载资料，兼容 flat/wrapped 归一化，校验目标 CVE、关键字段、类型和明确冲突，保留原字段来源与 SHA-256。
- LangChain `ChatOpenAI` 调用 OpenAI 兼容端点；默认使用官方 DeepSeek API。
- 七层 CUDA 根因分析与验证策略 Prompt；完整 JSON 解析与严格 Pydantic 分析合同，失败阻止生成。
- 生成 Python 候选 PoC，去除 Markdown 包装，进行 Python AST 和粗略名称检查；失败时最多请求两次静态纠正。
- 可选本地 CPU embedding + Chroma 持久化检索；可选 Tavily CVE Web 检索。
- 带字段状态、来源和内容哈希的只读平台探测；支持 Windows 经 `wsl.exe` 显式探测 WSL，并分别保存两套环境。
- 可导入的编译、ELF 操作、反汇编工具；主流程不自动执行这些工具。
- P1-C 底层工具使用严格 `ToolResult` 和私有原始日志；编译采用受控 argv、明确架构及参数白名单，ELF 操作严格支持 ELF64 little-endian。
- P2-C 独立入口支持明确授权的固定无害 CUDA 编译/检查、受控进程与跨环境原始证据核验；不启动 kernel 或生成候选。
- P3-A 独立离线 Oracle 提供六例公开资料审查、严格触发条件/证据引用、环境资格与确定性报告。仅合成测试域开放规则 `VERIFIED`；真实 CVE 仍为 `NOT_VERIFIED`，未实现生产根因验证器。见 [合同与命令](docs/P3_A_ORACLE_CONTRACT.md)、[六例资格](docs/P3_A_CVE_ELIGIBILITY.md)、[实际验收](docs/P3_A_VALIDATION.md)。
- P3-B 增加主机侧 Memcheck XML v4 证据解析、A～F 准备条件、固定 Windows→WSL 诊断能力探测；未认证导入和合成数据不能升级为真实 CVE 证据。见 [专项证据](docs/P3_B_HOST_PARSER_EVIDENCE.md)、[可行性矩阵](docs/P3_B_FEASIBILITY.md)。
- 新正式报告默认简体中文 UTF-8；main.py 默认按 `data/outputs/<CVE>/runs/<run_id>/` 保存独立研究归档，支持中文导航 ZIP、包外 SHA 和离线校验。旧 v1 API/英文完整性载体保留，历史原件不改。见 [语言合同](docs/REPORT_LOCALE_CONTRACT.md)、[归档合同](docs/CVE_ARTIFACT_PACKAGING.md)、[P3-B 验收](docs/P3_B_VALIDATION.md)。
- P3-C 支持显式 `--package`，将本轮生成、中文归档、ZIP 和独立校验串联，输出 ZIP 路径与包外 SHA；失败不引用旧 run。见 [交付合同](docs/P3_C_PACKAGING.md)、[诊断准备](docs/P3_C_REAL_DIAGNOSTIC.md)、[验收](docs/P3_C_VALIDATION.md)。
- P3-D-R1 增加独立授权的固定无害 CPU Memcheck 动作。Windows→WSL 实测已完成正常与受控异常两轮：保存原始 XML、进程身份、资源/回收结果，离线重读并生成中文报告。仅支持两份冻结 fixture，生成的 PoC 和真实 CVE 输入仍不执行。见 [固定诊断合同](docs/P3_D_R1_MEMCHECK_CONTRACT.md)和[实测验收](docs/P3_D_R1_VALIDATION.md)。

## 2. 尚未实现的功能与边界

主流程没有自动 CUDA 编译、PoC 执行、Compute Sanitizer 验证、运行反馈迭代、真实 CVE 成功 Oracle 或 benchmark。P3-A 只建立独立离线条件合同和合成规则判定。`iteration` 配置是保留的历史接口，当前不控制循环；静态纠正也不是运行反馈。

P1-A 已接入严格输入与分析合同：JSON/schema/CVE 不合格会失败，不再传入代码生成。结构合法仍不能证明模型根因、输入资料或拟定策略属实。AST 通过不代表依赖可导入、CUDA API 正确、可以运行或漏洞触发；静态纠正最终失败仍保存候选，并明确标为 `STATIC_INVALID`、`NOT_EXECUTED`、`NOT_VERIFIED`。

P1-B 已移除主探测流程的默认 GPU 架构和预设 nvcc 架构列表。不可访问、未检查或失败的字段保留明确状态；CUDA Driver API 当前为 `NOT_CHECKED`。平台快照与工具版本查询不能证明 CUDA kernel 可运行，详见 [平台合同](docs/P1_B_PLATFORM_CONTRACT.md)。

## 3. 系统架构与真实流程

```text
main.py → CLI 检查 → ConfigLoader（根目录 .env + YAML + CPG_*）
  → CudaPipeline
    → CudaDataLoader：七维原始文件 → 归一化 → 一致性/字段检查
      → input_manifest_v1.json（来源、哈希、状态与未验证声明）
    → 新鲜平台探测：默认 local；显式 wsl 时经 wsl.exe 返回 Linux 快照
      → 严格 PlatformSnapshot 校验 → 私有原始记录 + 确定性 Markdown 摘要
    → 模型客户端初始化 → 可选 RAG / Tavily 检索（平台失败时跳过）
    → CudaSecurityExpert：一次 LLM 分析 → 完整JSON解析 → 严格模型/CVE校验
      → cuda_analysis_v1.raw.txt（原文）与 cuda_analysis_v1.json（合格分析）
    → CudaCodeGenerator：一次 LLM 生成 + 最多两次静态纠正
      → cuda_poc_v1.py + cuda_poc_v1.status.json + cuda_run_v1.json
```

输入合格后才初始化模型客户端。专家使用归一化七维资料和 RAG；环境及 Web 文本只进入代码生成上下文。分析及生成器入口都校验目标 CVE。工具库的引用说明进入 Prompt，主流程不会自动调用这些工具。RAG 查询现在读取归一化字段，并保留组件短名/正式名称及两种根因摘要字段。

```text
config/default.yaml             默认配置
src/{pipeline,core_expert,code_generator,llm_client}.py
src/{data_loader,config_loader,env_probe,cuda_library,utils}.py
src/models/                     归一化/严格分析/候选状态；旧输入字段视图保留
src/tools/                      compile / env / inspect / elf_ops / search
data/inputs/CVE-*/               受控七维研究输入
data/knowledge_bases/cuda/       受控知识源 .md / .txt
tests/                          离线 CLI / 配置 / Mock 回归
docs/                           基线审计、迁移与验收报告
```

## 4. Windows 10 + VS Code + WSL2

Windows 管理 Git、编辑代码及运行离线测试；使用根目录 `.venv`，不使用 Conda base。WSL Ubuntu 22.04 使用自己的 Linux Python/venv，Linux CUDA 12.8、gcc/g++ 和 Compute Sanitizer。**两套 venv 不可互相复用**，Windows Python 不能直接加载 WSL 的 `libcuda.so`。

源码可位于 Windows 文件系统；从 WSL 进入对应 `/mnt/<盘符>/...`。Windows 现在可通过正式只读入口自动获取 WSL 快照，无需手动进入 WSL 终端。生成时只有显式 `--target-backend wsl` 才调用 WSL；默认仍探测当前 Python 宿主。后续 GPU 实验仍须在明确授权和隔离策略下执行，目前没有 PoC 自动执行后端。

支持范围暂限定 Python `>=3.10,<3.13`。本轮 Windows 使用 3.12.13；现有 WSL 使用 3.10.12（未额外安装 Python 3.12）。没有安装或更改 CUDA 驱动、Toolkit、WSL 网络。历史 Conda 环境保留，见 [迁移说明](docs/ENVIRONMENT_MIGRATION.md)。

## 5. Windows 安装：PowerShell

在项目根目录执行。先确保所选 Python 3.12 是原生 CPython，而非 Conda：

```powershell
py -0p
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c constraints/windows-py312.txt -e ".[dev]"
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check main.py src tests
```

如果 `py -3.12` 找不到解释器，但已有可信的 CPython 3.12（例如 uv 管理的解释器），直接使用其 **3.12 绝对路径**：`& "<Python 3.12 路径>" -m venv .venv`。本轮正是通过已有的 uv 管理 CPython 3.12.13 路径建立 `.venv`，未安装或覆盖其他 Python。

不必激活即可使用以上完整解释器路径；可选激活：`.\.venv\Scripts\Activate.ps1`。若 PowerShell 阻止激活，继续使用完整路径即可。VS Code 已配置 `.venv/Scripts/python.exe`；已有工作区解释器选择可能需手动执行 **Python: Select Interpreter**。不要复用历史 Conda 解释器。

## 6. WSL 安装与离线检查：Bash

从 VS Code 的 WSL 终端进入项目 Linux 挂载路径，例如 `/mnt/f/qcx/code/cuda_poc_generator`：

```bash
cd /mnt/f/qcx/code/cuda_poc_generator
python3 --version
python3 -m venv /home/pocdev/.venvs/cuda-poc-generator
source /home/pocdev/.venvs/cuda-poc-generator/bin/activate
python -m pip install -c constraints/wsl-py310.txt -e '.[dev]'
python main.py --help
python -m unittest discover -s tests -q
python -m pytest -q
python -m ruff check main.py src tests
```

这里的版本快照对应现有 Python 3.10.12；若使用已安装的其他支持版本，先用 `constraints/core.txt` 安装并重新验证，不宣称已有版本快照适用于所有 Python。缺少 `venv` 支持时先由环境维护者准备对应 `python3-venv`，不要删除或覆盖已有环境。

WSL Remote 工作区中通过 **Python: Select Interpreter** 指定 `/home/pocdev/.venvs/cuda-poc-generator/bin/python`；仓库共享设置默认服务 Windows，Remote 解释器由该环境单独选择。

## 7. 依赖与版本策略

`pyproject.toml` 是元数据和依赖入口；不需要 Python CUDA 包或本机 Toolkit 才能做离线开发。

| 组 | 用途 | 安装 |
|---|---|---|
| 核心 | YAML、dotenv、Pydantic、httpx、OpenAI SDK、LangChain core/OpenAI | `python -m pip install -c constraints/core.txt -e .` |
| `dev` | pytest、ruff；回归采用 unittest + Mock | `python -m pip install -c constraints/core.txt -e '.[dev]'` |
| `rag` | Chroma、HuggingFace、sentence-transformers | 见下一节 |
| `search` | Tavily 可选联网检索 | `python -m pip install -c constraints/core.txt -e '.[search]'` |

核心 LangChain/OpenAI 固定在原 requirements 的最低版本，避免本轮大升级。平台快照固定实际安装的核心和开发传递依赖，并删除本地 editable 路径；它们是版本约束快照，不是带 wheel 哈希的完整供应链锁。RAG/search 仅完成依赖解析检查，未完成真实安装、模型下载和联网功能验证。

原 requirements 中未直接使用的 `langchain` 聚合包、community、text-splitters、rich、click 不再强制安装；实际需要的 LangSmith/tiktoken 仍由 LangChain 引入。Tavily 补上单独 extra。`requirements.txt` 保留旧式完整安装入口（RAG + search），可能下载较多依赖；推荐按需安装。

## 8. API Key 与模型配置

`llm.model_name` 是模型名，`llm.api_base` 是 API 地址，`llm.api_key_env` 是保存密钥的环境变量名称。当前默认 YAML 的三项同名 `CPG_*` 写法采用有限兼容规则：有标准环境覆盖时使用覆盖值，缺失时采用已发布默认值并给出中文警告。其他普通字符串不会自动展开；推荐显式引用 `{env: MY_SETTING, default: "value"}`，实际密钥仍留在未跟踪的 `.env`。精确语义、优先级与七项旧失败的修复见 [配置兼容合同](docs/P3_C_CONFIG_COMPATIBILITY.md)。

仅在本地创建 `.env`，不要把真实密钥填进 `.env.example`：

```powershell
# 首次使用且 .env 不存在时执行；已有 .env 请直接编辑，勿覆盖。
Copy-Item .env.example .env
```

```dotenv
DEEPSEEK_API_KEY=<本地密钥>
CPG_LLM_MODEL_NAME=deepseek-flash
CPG_LLM_API_BASE=https://api.deepseek.com
```

截至 2026-10-14，默认模型名和端点依据 [DeepSeek 官方首次调用文档](https://api-docs.deepseek.com/zh-cn/)。本轮没有真实 API 请求，不能据此宣称账号/模型已联通。

配置优先级：现有进程环境高于项目根 `.env`；`CPG_*` 高于 YAML。默认密钥变量为 `DEEPSEEK_API_KEY`，兼容旧 `DEEPSEEK_KEY`。其他 OpenAI 兼容供应商须显式设置 `llm.api_key_env` 或 `CPG_LLM_API_KEY_ENV`，以及自己的 endpoint/model；原 NIUBIAPI 配置仍可使用，但不会从无关供应商的变量取密钥。不要在 YAML 中存明文密钥。

支持环境覆盖：`CPG_LLM_MODEL_NAME`、`CPG_LLM_API_BASE`、`CPG_LLM_API_KEY_ENV`、`CPG_LLM_TEMPERATURE`、`CPG_LLM_MAX_TOKENS`、`CPG_LLM_TIMEOUT`、`CPG_LLM_MAX_RETRIES`、`CPG_RAG_ENABLED`、`CPG_VULN_TYPE`。`CPG_MAX_ITERATIONS` 仅保留兼容，当前没有运行循环。`streaming` 也未实现实际流式返回。

Tavily Key 未设置时跳过 Web 检索；若设置 Key，生成主流程会尝试联网检索。`--no-rag` 只禁用 RAG，**不会禁用 LLM 或 Tavily 网络请求**。LangSmith 外部追踪默认关闭；开启前需考虑研究资料和 Prompt 的外发。

## 9. RAG 知识库准备

源码加载 `data/knowledge_bases/cuda/` 下 UTF-8 `.md`/`.txt`，自带知识源继续跟踪。嵌入为 `sentence-transformers/all-MiniLM-L6-v2`、`device=cpu`；首次使用需要联网下载模型。索引保存在 `data/knowledge_bases/.chromadb/`，不提交 Git。

```bash
# 可选功能；本轮没有执行以下安装/下载/构建。
# 如需明确 CPU-only torch，先从官方 CPU wheel 源安装。
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -c constraints/core.txt -e '.[rag]'
```

CPU wheel 选择依据 [PyTorch 官方安装说明](https://pytorch.org/get-started/locally/)。RAG 初始化缺依赖或部分模型加载错误时会记录降级说明；其他索引/模型异常仍可能中止生成。索引未记录源文档哈希和模型 revision；更新文档后需要人工管理重建，`force_rebuild` 的重复累积风险尚未修复。配置现在会拒绝 `chunk_overlap >= chunk_size`。

## 10. CVE 七维输入 JSON

```text
1_os_environment.json          OS/kernel/权限/环境
2_cuda_environment.json        GPU/CUDA/驱动/工具链
3_affected_component.json      组件与版本范围
4_attack_surface.json          入口与输入控制
5_vulnerability_type.json      CWE/类型等
6_impact_controllability.json   影响与控制条件
7_root_cause.json              根因、来源与研究假设
```

例如现有 D7 包装形式：

```json
{
  "cve_id": "CVE-2024-0124",
  "root_cause": {
    "summary": "研究资料中的根因描述；需核对官方来源和目标版本"
  }
}
```

仓库含 6 个 CVE、42 个 JSON，全部通过 P1-A 归一化回归，源文件不变。CLI 现在要求七个文件均为合法 JSON object、目标 CVE ID 合法且一致，并具备组件名、入口、CWE、根因摘要等最小关键内容；缺失/损坏/冲突不能继续。OS/GPU 等可显式未知，字段状态区分 `MISSING/UNKNOWN/CONFLICT/VALID/INVALID`，JSON 容器最多128层。旧 `load_inputs()` 仍原样返回字典；主流程使用新 `load_normalized_inputs()`。所有资料标为 `input_assertion/unverified`，不核验公告或认定 CVE 已复现。接口、例子及迁移说明见 [P1-A 合同](docs/P1_A_CONTRACT.md)。

## 11. 候选生成命令与输出

以下命令会调用模型，**本轮未执行真实生成**。先确认密钥、目标资料和输出目录，调用成本以供应商当时计费为准：

```bash
python main.py --cve-id CVE-2024-0124 --no-rag
python main.py --input-dir ./my_data --output-dir ./data/outputs/local --no-rag
python main.py --config config/default.yaml --cve-id CVE-2025-23339
# Windows 主程序使用 WSL 平台上下文；仍然只生成候选，会调用模型。
python main.py --cve-id CVE-2024-0124 --no-rag --target-backend wsl --wsl-distro Ubuntu-22.04
```

`--cve-id` 与 `--input-dir` 互斥。默认输出在 `data/outputs/<CVE>/`：

| 文件 | 意义 |
|---|---|
| `cuda_analysis_v1.json` | 模型分析与拟定策略；不是实验结论 |
| `cuda_poc_v1.py` | 未执行的候选代码；静态失败也可能保存 |
| `input_manifest_v1.json` | 原始/归一化字段、来源路径、输入哈希、诊断和生成调用 ID |
| `cuda_analysis_v1.raw.txt` | 成功或非法响应的完整原文，保留首尾空白和 CRLF；供应商失败未返回文本时不新建 |
| `cuda_poc_v1.status.json` | 生成、静态、执行、验证四组独立状态及候选哈希 |
| `cuda_run_v1.json` | 当前调用的完整/失败状态与有效产物引用；`COMPLETE` 不表示漏洞成功 |

同一 CVE 的重复生成仍会覆盖当前 `v1` 元数据；请用不同 `--output-dir` 保留完整版本。每次调用有新 `run_id`，失败会更新报告及候选状态，旧源码/旧合格分析保留，并标为 `preexisting_artifacts`，不引用为当前成功。输入无效时报告位于输出根目录。默认输出被 Git 忽略；自定义目录也必须保护原文及私有资料。该生成目录不含实际执行证据，此处 `run_id` 仅标识生成调用；固定无害动作的独立执行证据见下文 P2-B。任意输出目录的工具 import 固定回溯问题仍未修复。

## 12. 正式只读平台探测与后续实验

Windows PowerShell（不加载模型、不读取 `.env`、不调用付费 API）：

```powershell
.\.venv\Scripts\python.exe -m src.platform_probe --backend local
.\.venv\Scripts\python.exe -m src.platform_probe --backend wsl --distro Ubuntu-22.04
```

默认 Linux 解释器是 `/home/pocdev/.venvs/cuda-poc-generator/bin/python`，用户 `pocdev`；可用 `--linux-python`、`--wsl-user` 显式调整。生成流程对应配置在 `config/default.yaml` 的 `platform` 节。WSL 终端也可用自身 venv 执行 `python -m src.platform_probe --backend local`。

Windows 记录位于 `data/outputs/platform_probes/<probe_id>/`；Linux 默认使用 `~/.local/state/cuda-poc-generator/platform_probes/<probe_id>/`。包含快照、命令、原始双流和确定性报告。Windows 使用受保护 DACL，Linux 检查实际目录 `0700` / 文件 `0600`；`/mnt/*` 若不落实权限会明确失败。这些产物不进入 Git。`PARTIAL` 保留可用观测和未知项，`FAILED` 不提供替代快照；CLI 分别返回 0 / 1，不能仅凭退出码判断能力齐全。

底层工具接口和迁移见 [P1-C 合同](docs/P1_C_TOOL_CONTRACT.md)：`compile_cubin` 必须指定 `arch` 或提供合格 snapshot；Windows 先从 Visual Studio developer terminal 准备 MSVC，再使用项目 `.venv`。不再自动拼接 `vcvarsall` 与编译命令。`compile_kernel_source` 返回的两个文件均保留，成功后由调用者清理独立目录。原始工具记录默认在 Windows `data/outputs/tool_runs/` 或 Linux `~/.local/state/cuda-poc-generator/tool_runs/`。

版本检查也可在 WSL 手动执行：

```bash
# 仅查看已经安装的工具，不执行 PoC。
export PATH=/usr/local/cuda-12.8/bin:$PATH
nvcc --version
compute-sanitizer --version
gcc --version
g++ --version
```

P1-B 真实只读桥接观察到 WSL 的 nvcc `12.8.93`、Compute Sanitizer `2025.1.0.0`、GTX 1660 / CC `7.5`；`sm_75` 是由实测 CC 派生的 `INFERRED` 值。Windows 本机 Toolkit 为 `11.2`，不能替代 WSL 的 `12.8`。本机横幅的 `CUDA UMD Version: 13.4` 单独记录，不冒充 Driver API 或最大兼容版本。P1-B 阶段未执行编译 smoke、kernel 或 PoC，详见 [P1-B 验收](docs/P1_B_VALIDATION.md)。

后续实验必须在明确授权和隔离策略下，先审查候选、核对受影响版本与目标条件，再决定编译/执行范围。保留 argv、cwd、运行身份、超时、stdout/stderr、退出码、环境快照和哈希，目标 oracle 独立判定。CUDA 错误码、crash、sanitizer 的通用 OOB 报告都不能自动证明目标 CVE 被验证。本轮不提供默认自动运行样本的步骤。

P2-A 新增独立的受控请求、操作者授权、身份绑定和 Preflight。只开放固定无害 Python fixture，用于 Windows→WSL 通信与资源限制核对；不会执行生成候选。需要操作者明确授权时，可在 Windows PowerShell 运行下列独立入口（Linux checkout 路径必须按实际位置填写，授权引用应指向自己的批准记录）：

```powershell
.\.venv\Scripts\python.exe -m src.fixture_smoke --help
.\.venv\Scripts\python.exe -m src.fixture_smoke --authorize-fixed-fixture --authorization-reference "your-approval-record" --operator-id "your-operator-id" --linux-project-root "/mnt/f/qcx/code/cuda_poc_generator"
```

未给授权 flag 时不启动通信。该命令没有任意候选或 argv 参数，不编译 CUDA；资源不能落实、目标冲突、工具身份不符或快照过期都阻断 fixture。原始证据默认保存在 Git 忽略的私有 `data/outputs/execution_preflight/`，不要把这些目录上传。请求/授权/policy 摘要、原始字节、manifest 和确定性 Markdown 的合同见 [P2-A 执行前置合同](docs/P2_A_EXECUTION_CONTRACT.md)，真实联调见 [独立报告](docs/P2_A_REAL_INTEGRATION.md)。

P2-B 在此基础上增加固定无害动作的执行生命周期、超时/取消、进程组与后代回收、独立 WSL STATUS、ExecutionRecord 和可离线重建的证据报告。仅支持代码注册表中的正常/非零/超时/超量输出/子进程清理及 CPU 测试，生成候选继续 `NOT_EXECUTED`，漏洞状态继续 `NOT_VERIFIED`。操作者明确授权固定测试时使用：

```powershell
.\.venv\Scripts\python.exe -m src.lifecycle_cli --help
.\.venv\Scripts\python.exe -m src.lifecycle_cli --authorize-fixed-actions --action p2b-normal-v1 --authorization-reference "your-approval-record" --operator-id "your-operator-id" --linux-project-root "/mnt/f/qcx/code/cuda_poc_generator"
```

其他动作和取消方式见 [P2-B 生命周期合同](docs/P2_B_EXECUTION_LIFECYCLE.md)。退出 0 只代表固定任务有效完成，不能代表 CVE；非零、超时和资源限制会返回独立状态。Windows launcher 消失不能证明 Linux 已回收，未确认时保留 UNKNOWN/CLEANUP_FAILED。私有 `data/outputs/execution_lifecycle/` 保存原始证据及控制句柄，禁止提交其中的 control token/日志；[P2-B 验收](docs/P2_B_VALIDATION.md) 与 [真实联调摘要](docs/P2_B_REAL_INTEGRATION.md) 区分 Mock、无害真实运行和未执行的 CUDA 测试。

P2-C 新增固定空 kernel 的编译与二进制检查入口。只有操作者明确授权后才调用 WSL 的 nvcc/cuobjdump/nvdisasm；不运行编译产物、不接受候选源码或自由 flags。Windows 项目根目录执行，项目 WSL 路径及批准引用填写实际值：

```powershell
.\.venv\Scripts\python.exe -m src.cuda_smoke --help
.\.venv\Scripts\python.exe -m src.cuda_smoke --authorize-safe-cuda-smoke --backend wsl --authorization-reference "your-approval-record" --operator-id "your-operator-id" --linux-project-root "<项目的 WSL 路径>"
```

架构取新鲜 GPU/nvcc 观测，CUDA 工具使用单独的 4 GiB 每进程地址空间策略；这不是 VRAM 限额或 GPU 沙箱。原始 Linux 文件经独立 STATUS 重读，再与 Windows 保存字节核验；未确认回收或原件不可访问时不会宣称完整成功。正常 CLI 返回报告目录，只有执行完成且原件 VERIFIED 才退出 0。合同、真实工具版本/哈希、失败诊断及双环境结果见 [P2-C 集成合同](docs/P2_C_CUDA_INTEGRATION.md)、[验收](docs/P2_C_VALIDATION.md)、[真实联调](docs/P2_C_REAL_INTEGRATION.md)。候选仍 NOT_EXECUTED，CVE 仍 NOT_VERIFIED。

P3-D-R2 补充了独立的 `cuobjdump 12.8.55-1` 固定工具身份档案和只读候选预检。`python -m src.cve_lab preflight ...` 只校验已归档生成 run、源码 SHA-256 与 WSL 目标身份，不执行候选；任意 `cuda_poc_v1.py` 的执行仍为 UNSUPPORTED。另有 Windows→WSL 固定无害动作传输和真实 `cuobjdump` 工具链 smoke 记录，均不包含 CVE 输入或 GPU kernel。详见 [P3-D-R2 执行合同](docs/P3_D_R2_EXECUTION_CONTRACT.md)及[验收记录](docs/P3_D_R2_VALIDATION.md)。

P3-D-R3 增加独立的固定无害接收文件动作：`src.cve_lab execute --mode fixed-staged-normal` 仅在明确的固定 fixture 授权下，将 Windows 传输的 `p2b-normal-v1` 精确源码落盘，并由 WSL 子进程读取该文件描述符、核对文件身份和 SHA-256 后运行。`src.cve_lab evaluate` 可离线重读本轮证据并重建中文报告。两者都不执行已生成的 LLM PoC；生成候选继续 `NOT_EXECUTED`，指定 CVE 继续 `NOT_VERIFIED`。本轮目标 cuobjdump+Memcheck 自动诊断子任务受到安全审查阻断，尚无该链路的实测结果。接口和实际验收状态见 [P3-D-R3 合同](docs/P3_D_R3_EXECUTION.md)、[验收记录](docs/P3_D_R3_VALIDATION.md)。

P4-A 增加只读的目标环境档案：`src/target_profile.py` 从七维输入派生 `USERLAND_TOOL / GPU_LIBRARY / NETWORK_SERVICE / DRIVER` 四类，以及对应的隔离档位与自动化上限；它不启动进程、不探测宿主，也不授予执行权。本地 23 个 CVE 归为 16 / 2 / 1 / 4，其中 4 个驱动类在本机已修复、不可复现。见 [环境档案与靶场分档](docs/P4_A_TARGET_ENVIRONMENT.md)。

P4-B 给出复现所需的精确版本清单：本机 `CUDA 11.2` 已覆盖全部 16 个工具链 CVE 的受影响区间；3 个驱动 CVE 需要降到 550 分支（有蓝屏风险，建议第二台机器）；`CVE-2026-24191` 只影响 Maxwell/Volta/Pascal，GTX 1660（Turing）天然不匹配。文档同时指出 `nvdisasm 12.8.90` 在 NVIDIA 公开组件表中不存在，不得当作可获取版本。见 [版本清单](docs/P4_B_VERSION_MATRIX.md)。

## 13. 常见问题与测试状态

- `--help` 现在可在未安装第三方依赖时运行；真正生成仍须安装核心依赖。
- 密钥缺失：检查 `.env` 的变量名及 `llm.api_key_env`，不要输出密钥诊断。
- HTTP 401/403：检查账号权限和凭证；404：核对官方模型名和 endpoint；这些错误不会自动重试。
- RAG DLL/模型加载问题：检查 CPU torch 与 Python 的版本兼容性，或临时使用 `--no-rag`；不要盲目强制重装 GPU 软件。
- WSL 工具缺失：检查已安装工具的 Linux 路径和 PATH，Windows 路径不能替代 Linux 动态库。
- `WSL_UNAVAILABLE` / `WSL_DISTRO_NOT_FOUND`：检查已启用的 `wsl.exe` 和发行版名称；超时或无效响应查看本次私有 `probe_result.json`，不会复用历史快照。
- 历史临时诊断脚本 `_diag.py`、`_check_rel.py` 已按维护者要求移除；正式离线测试使用上述 pytest 命令。

逐项 PASS/FAILED/NOT_CHECKED、修改前后对比见 [P0 验收记录](docs/P0_VALIDATION.md)。离线 Mock 通过只能证明这些接线和静态行为；真实 LLM、RAG、Tavily 和漏洞触发不在本轮通过范围。P1-B 另行完成真实 GPU/工具只读查询和 Windows → WSL 通信，结果不等于 CUDA 执行成功。

P1-A 新增严格合同与阻断、原文保留及独立状态回归，双环境验收见 [P1-A 交付记录](docs/P1_A_VALIDATION.md)。非 JSON、截断、额外杂文、重复键、NaN/Infinity、字段缺失/类型错误、步骤 ID 或目标 CVE 冲突均会失败；没有结构纠正重试（0次），供应商请求沿用既有有界重试。

P1-B 见 [平台合同](docs/P1_B_PLATFORM_CONTRACT.md)、[验收记录](docs/P1_B_VALIDATION.md)；P1-C 工具修复、双环境测试和未检查项见 [工具合同](docs/P1_C_TOOL_CONTRACT.md)、[验收记录](docs/P1_C_VALIDATION.md)。P2-A 的双环境测试、身份负例与真实固定 fixture 结果见 [验收记录](docs/P2_A_VALIDATION.md)。P2-B/P2-C 已提供固定无害动作和真实工具证据；P3-A 已建立离线 Oracle 合同。经授权的候选执行准入、真实根因验证、受影响/修复差分仍待独立审查；P4 有界反馈、P5 benchmark 尚未实现。

## 14. 安全边界、来源与许可证说明

P3-B 的诊断、资料归档与离线验证可从 Windows venv 使用：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostics_probe --backend wsl
$p3bRunId = [guid]::NewGuid().ToString("N")
.\.venv\Scripts\python.exe -m src.artifact_cli import-review --cve CVE-2025-23308 --run-id $p3bRunId
.\.venv\Scripts\python.exe -m src.artifact_cli package --cve CVE-2025-23308 --run-id $p3bRunId
.\.venv\Scripts\python.exe -m src.artifact_cli verify --package <zip-path> --expected-sha256 <independently-checked-package-sha256>
.\.venv\Scripts\python.exe -m src.report_cli --help
```

尖括号参数是模板。版本探测只运行固定 `--version`；资料包有七维原始副本和中文审查报告，执行与 Oracle 部分明确未执行/未评估。`INTEGRITY_VERIFIED` 不是 CVE `VERIFIED`。两个目标的根因和修复差分未完成，真实实验隔离/准备仍为 `UNSUPPORTED`。Synthetic、通用探测和固定 smoke 不归入真实 CVE 实验包。包目录示例、实际 ZIP 哈希与重建结果见 [中文归档验收](docs/P3_B_PACKAGING_VALIDATION.md)。

需要生成后自动交付时，可使用 `python main.py --cve-id CVE-2025-23308 --no-rag --package`；该命令正常使用会调用配置的模型，本阶段只以 Mock 验收。候选仍不运行，原六份 v1 产物保留，并额外保存本轮 `runs/<run_id>/`、`packages/<CVE>_<run_id>.zip` 及包外中文交付回执。没有 `--package` 时不自动创建 ZIP。旧 Python API 默认布局不变。

固定无害 CPU 诊断需操作者明确授权、实测工具身份和可落实的资源/隔离门禁。Windows `.venv` 可使用以下固定入口；`verify-fixed` 只读取原始档案并按外部固定的清单 SHA-256 独立重建中文报告：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks run-fixed --task p3c-normal-v1 --authorize-fixed-memcheck --operator-id "your-operator-id" --authorization-reference "your-fixed-diagnostic-approval" --linux-project-root "<项目的 WSL 路径>"
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks verify-fixed --directory "data/outputs/fixed_memcheck/<run_id>" --manifest-sha256 "<independently-pinned-manifest-sha256>"
```

正常 fixture 的真实闭环通过后，才能在匹配授权下运行 `p3c-invalid-write-v1`。档案位于 `data/outputs/fixed_memcheck/`，与 CVE 实验归档分离。Memcheck 的错误类别仅是固定无害程序的诊断观察，真实 CVE 结论保持 `NOT_VERIFIED`。

仅用于经过授权的安全研究和防御验证。不得自动运行真实漏洞 PoC、提权或破坏性样本；不得把模型结论当客观证据；不得提交 API Key、私有日志、GPU UUID 或主机绝对路径。

本工程继承原有 CUDA 专项系统，并保留原 README 所述 `universal_poc_generator` 设计来源、七层分析、RAG、Prompt、辅助工具及生成能力。保留源码中的作者标识 `CUDA Security Research Framework` 和原免责声明；项目维护仓库为 [Qcx526/cuda_poc_generator](https://github.com/Qcx526/cuda_poc_generator)。主线选择、同源关系与外部数据的迁移规则见 [主线与数据迁移](docs/REPOSITORY_MAINLINE.md)。

原 README 的许可证说明为“本项目仅供授权安全研究使用”；仓库未提供独立 `LICENSE` 文件。本轮不新增或推断其他开源许可证。
