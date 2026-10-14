# CUDA PoC Generator

基于已有 CUDA 专项 PoC 生成系统的增量研究工程。保留七层分析 Prompt、七维漏洞输入、RAG、CUDA 知识映射和辅助工具，以候选代码生成为起点，逐步建设可复现实验和基于目标条件的验证系统。

**当前版本：Single-shot Generation。生成候选不代表漏洞已验证。**

## 1. 当前已实现能力

- 从七类 JSON 文件加载 CUDA 漏洞研究资料。
- LangChain `ChatOpenAI` 调用 OpenAI 兼容端点；默认使用官方 DeepSeek API。
- 七层 CUDA 根因分析与验证策略 Prompt，输出模型分析 JSON。
- 生成 Python 候选 PoC，去除 Markdown 包装，进行 Python AST 和粗略名称检查；失败时最多请求两次静态纠正。
- 可选本地 CPU embedding + Chroma 持久化检索；可选 Tavily CVE Web 检索。
- 当前 Python 宿主机的 GPU/CUDA/工具链探测，以及可导入的编译、ELF 操作、反汇编工具。

## 2. 尚未实现的功能与边界

主流程没有自动 CUDA 编译、PoC 执行、Compute Sanitizer 验证、运行反馈迭代、CVE 成功 oracle 或 benchmark。`iteration` 配置是保留的历史接口，当前不控制循环；静态纠正也不是运行反馈。

模型 JSON 目前仅做容错解析和顶层字段检查，**没有真正执行输出 schema 校验**。`src/models` 尚未接入主流程，也未完整匹配全部输入格式。AST 通过不代表依赖可导入、CUDA API 正确、可以运行或漏洞触发。静态纠正最终失败仍会保存候选供人工检查。

环境探测仍有已知问题：GPU 架构存在 SM 7.5 硬编码，无 `nvcc` 时会提供预设架构列表；Windows 探测不能表示 WSL 实验环境。不要把这些推断当实测证据。详细位置见 [P0 基线审计](docs/P0_BASELINE_AUDIT.md)。

## 3. 系统架构与真实流程

```text
main.py → CLI 检查 → ConfigLoader（根目录 .env + YAML + CPG_*）
  → CudaPipeline
    → CudaDataLoader：七维原始字典
    → 可选 RAG：本地 embedding / Chroma → 检索文本
    → 可选 Tavily → Web 文本
    → env_probe：当前 Python 宿主机探测
    → CudaSecurityExpert：一次 LLM 分析 → cuda_analysis_v1.json
    → CudaCodeGenerator：一次 LLM 生成 + 最多两次静态纠正
      → cuda_poc_v1.py
```

专家分析使用七维资料和 RAG；环境及 Web 文本只进入代码生成上下文。工具库的引用说明进入 Prompt，主流程不会自动调用这些工具。RAG 检索仍有扁平/包装字段混用问题。

```text
config/default.yaml             默认配置
src/{pipeline,core_expert,code_generator,llm_client}.py
src/{data_loader,config_loader,env_probe,cuda_library,utils}.py
src/models/                     现有未接入的 Pydantic 模型
src/tools/                      compile / env / inspect / elf_ops / search
data/inputs/CVE-*/               受控七维研究输入
data/knowledge_bases/cuda/       受控知识源 .md / .txt
tests/                          离线 CLI / 配置 / Mock 回归
docs/                           基线审计、迁移与验收报告
```

## 4. Windows 10 + VS Code + WSL2

Windows 管理 Git、编辑代码及运行离线测试；使用根目录 `.venv`，不使用 Conda base。WSL Ubuntu 22.04 使用自己的 Linux Python/venv，Linux CUDA 12.8、gcc/g++ 和 Compute Sanitizer。**两套 venv 不可互相复用**，Windows Python 不能直接加载 WSL 的 `libcuda.so`。

源码可位于 Windows 文件系统；从 WSL 进入对应 `/mnt/<盘符>/...`。GPU 实验将由 VS Code 的 WSL 终端在授权和隔离策略下手动执行；当前没有 Windows → WSL 自动执行后端。为使生成阶段探测到 Linux 工具路径，需要在 WSL 中运行生成命令，且仍需人工复核探测结果。

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

仓库含 6 个 CVE、42 个 JSON，本轮检查了合法性、文件齐全及各目录 CVE ID 一致性。数据同时存在扁平和包装形式；加载器原样保留，部分检索字段不能兼容两者。缺失/损坏 JSON 会记录日志并返回空字典，当前并不强制七个维度全部有效。已有数据的版本范围、根因和假设未在本轮逐条核对官方公告，也未进行漏洞实验。

## 11. 候选生成命令与输出

以下命令会调用模型，**本轮未执行真实生成**。先确认密钥、目标资料和输出目录，调用成本以供应商当时计费为准：

```bash
python main.py --cve-id CVE-2024-0124 --no-rag
python main.py --input-dir ./my_data --output-dir ./data/outputs/local --no-rag
python main.py --config config/default.yaml --cve-id CVE-2025-23339
```

`--cve-id` 与 `--input-dir` 互斥。默认输出在 `data/outputs/<CVE>/`：

| 文件 | 意义 |
|---|---|
| `cuda_analysis_v1.json` | 模型分析与拟定策略；不是实验结论 |
| `cuda_poc_v1.py` | 未执行的候选代码；静态失败也可能保存 |

同一 CVE 的重复生成会覆盖 `v1`；现阶段应使用不同 `--output-dir` 手工保留版本。任意输出目录可能影响生成脚本寻找 `src.tools` 的固定回溯逻辑。当前没有运行身份、输入/代码哈希、原始响应或证据目录；不要把手工运行日志塞进受控源文件目录。

## 12. WSL CUDA 工具检查与后续实验

```bash
# 仅查看已经安装的工具，不执行 PoC。
export PATH=/usr/local/cuda-12.8/bin:$PATH
nvcc --version
compute-sanitizer --version
gcc --version
g++ --version
```

本轮只读取到 `nvcc 12.8.93` 和 Compute Sanitizer `2025.1.0.0`。GTX 1660/CC 7.5 是用户提供的实验目标，本轮未实测 GPU 或执行编译 smoke test。

后续实验必须在明确授权和隔离策略下，先审查候选、核对受影响版本与目标条件，再决定编译/执行范围。保留 argv、cwd、运行身份、超时、stdout/stderr、退出码、环境快照和哈希，目标 oracle 独立判定。CUDA 错误码、crash、sanitizer 的通用 OOB 报告都不能自动证明目标 CVE 被验证。本轮不提供默认自动运行样本的步骤。

## 13. 常见问题与测试状态

- `--help` 现在可在未安装第三方依赖时运行；真正生成仍须安装核心依赖。
- 密钥缺失：检查 `.env` 的变量名及 `llm.api_key_env`，不要输出密钥诊断。
- HTTP 401/403：检查账号权限和凭证；404：核对官方模型名和 endpoint；这些错误不会自动重试。
- RAG DLL/模型加载问题：检查 CPU torch 与 Python 的版本兼容性，或临时使用 `--no-rag`；不要盲目强制重装 GPU 软件。
- WSL 工具缺失：检查已安装工具的 Linux 路径和 PATH，Windows 路径不能替代 Linux 动态库。
- 不要自动运行 `_diag.py`：这是历史联网诊断脚本，会进行真实模型请求且包含旧模型配方。`_check_rel.py` 是历史 CUDA 编译脚本，也不属于离线测试。

逐项 PASS/FAILED/NOT_CHECKED、修改前后对比见 [P0 验收记录](docs/P0_VALIDATION.md)。离线 Mock 通过只能证明这些接线和静态行为；真实 LLM、RAG、Tavily、GPU 和漏洞触发不在本轮通过范围。

后续路线：P1 对齐输入/输出 schema 与生成质量；P2 建立独立环境、候选和原始证据身份，并在授权后接入有界 WSL 编译/执行；P3 实现目标 oracle；P4 有界反馈；P5 建立可复现 benchmark。接口和验收标准见基线审计报告。

## 14. 安全边界、来源与许可证说明

仅用于经过授权的安全研究和防御验证。不得自动运行真实漏洞 PoC、提权或破坏性样本；不得把模型结论当客观证据；不得提交 API Key、私有日志、GPU UUID 或主机绝对路径。

本工程继承原有 CUDA 专项系统，并保留原 README 所述 `universal_poc_generator` 设计来源、七层分析、RAG、Prompt、辅助工具及生成能力。保留源码中的作者标识 `CUDA Security Research Framework` 和原免责声明；项目维护仓库为 [Qcx526/cuda_poc_generator](https://github.com/Qcx526/cuda_poc_generator)。

原 README 的许可证说明为“本项目仅供授权安全研究使用”；仓库未提供独立 `LICENSE` 文件。本轮不新增或推断其他开源许可证。
