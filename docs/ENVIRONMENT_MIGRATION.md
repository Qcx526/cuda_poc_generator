# Conda → venv 迁移记录

本轮仅为 `cuda_poc_generator` 建立独立 venv；未删除、覆盖或修改历史 Conda 环境，也未改动 HeteroPoCLab。保留源码算法、CUDA 专项 Prompt、RAG、工具及七维研究输入。

## Windows

基准为原生 CPython 3.12.13，项目根目录 `.venv`。已有 uv 管理的解释器可直接用其绝对路径执行 `-m venv .venv`，并不意味着项目依赖 uv。现有 Windows `py -3.12` 未识别该来源的解释器，故 README 给出 `py -0p` 和绝对路径替代步骤；未更改 Python 注册或 PATH。

VS Code 共享设置从 Conda manager 改为 venv/pip，并将默认解释器指向 `${workspaceFolder}/.venv/Scripts/python.exe`。已经选过解释器的 VS Code 工作区需手动选择一次；本轮没有控制 VS Code UI，因此实际 IDE 选择状态为 `NOT_CHECKED`。所有安装和测试均直接使用该 venv 的 Python，不依赖激活和 Conda 环境变量。

```powershell
.\.venv\Scripts\python.exe -m pip install -c constraints/windows-py312.txt -e ".[dev]"
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m pytest -q
```

## WSL Ubuntu 22.04

沿用现有 Linux Python 3.10.12，在 `/home/pocdev/.venvs/cuda-poc-generator` 创建独立 venv，未复用 `.venv/Scripts`，也未另外安装 Python 3.12。项目支持范围是 `>=3.10,<3.13`；两个 Python 基准分别保存依赖快照。

```bash
cd /mnt/f/qcx/code/cuda_poc_generator
source /home/pocdev/.venvs/cuda-poc-generator/bin/activate
python -m pip install -c constraints/wsl-py310.txt -e '.[dev]'
python main.py --help
python -m pytest -q
export PATH=/usr/local/cuda-12.8/bin:$PATH
nvcc --version
compute-sanitizer --version
```

本轮只读找到 `nvcc 12.8.93`、Compute Sanitizer `2025.1.0.0`；普通 WSL 非交互进程的 PATH 没有包含这两个工具，因此使用已经安装的绝对路径读取版本。后续在 WSL 终端临时设置 PATH 即可；没有重装 CUDA，也没有修改驱动、系统网络或 shell 启动文件。

Remote WSL 工作区单独选择 `/home/pocdev/.venvs/cuda-poc-generator/bin/python`。不要把 Windows `.venv` 的二进制或 DLL 路径注入 Linux 环境。

## 依赖兼容与历史入口

- `pyproject.toml` 拆分核心、`rag`、`search`、`dev`。没有强制 Python CUDA 包或 Windows CUDA Toolkit。
- 核心固定原 requirements 的 LangChain/OpenAI 最低版本：`langchain-openai 1.3.3`、`langchain-core 1.4.7`、`openai 2.26.0`。
- `constraints/core.txt` 固定直接基准；`windows-py312.txt` 和 `wsl-py310.txt` 记录实际安装的核心与开发传递依赖。快照不含本地绝对路径、editable 行和凭证，不含 wheel 哈希；不同平台/Python 不互相冒充已验证结果。
- RAG 0.x 最低下界并不能保证与 LangChain 1.x 兼容，改为兼容的 1.0 集成系列，并保留 sentence-transformers 3.x。仅依赖解析通过，不代表 DLL、模型下载、索引和检索已通过。
- `requirements.txt` 继续提供包含 RAG/search 的兼容安装方式。没有导出或提交历史 Conda 的本机路径/凭证，未声称原 Conda 环境与新 venv 完全一致。

历史 VS Code 的 Conda 开发设置已被 venv/pip 替代；原 README 的中转站和反馈循环说明改为实际默认配置与 Single-shot 流程。其设计来源与作者说明保留在 README，旧说明仍可从稳定 Git 历史查阅，无需复制未实现的功能声明。

真实模型调用、RAG 模型下载、GPU 编译/运行和 CVE 验证另行验收。本轮结果见 [P0 验收记录](P0_VALIDATION.md)。
