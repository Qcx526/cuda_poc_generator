# P0 规范化修改与实际验收

日期：2026-10-14。修改从 `main@321e804ba5fd0d1d1f05b5ded02f5022a80683ac` 出发，在独立分支 `feature/p0-venv-baseline-audit` 实施。原工作区只有 `.env.example` 的用户修改，暂存区为空；其使用 DeepSeek 的配置意图已纳入规范化，旧 `DEEPSEEK_KEY` 仍兼容。未修改真实 `.env`。

完整基线问题、真实架构/数据流、能力表、P0-P5 接口和验收标准见 [基线审计](P0_BASELINE_AUDIT.md)。双环境步骤见 [README](../README.md) 和 [迁移记录](ENVIRONMENT_MIGRATION.md)。

## 完成的修改及原因

| 修改 | 目的与边界 |
|---|---|
| `pyproject.toml`、`constraints/*`、`requirements.txt` | 元数据统一；核心/rag/search/dev 分组；原核心 LangChain/OpenAI 最低版本保留；新增平台核心/dev传递依赖快照；旧 requirements 仍提供完整RAG/search入口 |
| Windows `.venv`、WSL 独立 venv | Windows 原生CPython3.12.13，WSL自身CPython3.10.12；不复用二进制或环境变量，不删旧Conda，不安装CUDA |
| `.vscode/settings.json` | 默认管理器改venv/pip，Windows默认解释器指向`.venv`；WSL Remote需单独选择Linux解释器 |
| `.gitignore`、`.gitattributes` | 运行产物按目录忽略，研究JSON/CUDA/日志fixture继续允许跟踪；共享源码LF规则；本地助手记忆移出索引但保留本地文件，稳定历史不变 |
| README重写、审计与迁移文档 | 删除未实现反馈循环的宣传、不存在CLI参数/文件和损坏NUL尾部；明确Single-shot、静态检查、环境探测缺陷和未验证边界，保留作者与设计来源 |
| YAML、`.env.example`、`ConfigLoader` | DeepSeek默认端点/模型/Key名统一；实例化时仅加载根目录`.env`，既有环境优先；增加类型/范围/布尔/分块校验、明确错误；未知配置字段保留兼容 |
| `LLMClient` | 缺Key明确本地失败，兼容DeepSeek旧变量；自定义供应商不从无关变量回退；保留headers/Responses兼容；模型404说明更清楚；错误不回显响应正文；参数覆盖保留其他生成参数，最终失败不再额外sleep |
| `main.py` | 延迟导入生成流水线，使无第三方依赖的help可用；缺依赖、配置和常见调用错误有可读退出提示；保留原参数和互斥行为 |
| RAG错误说明、banner | 安装指令与extras一致，删除盲目force-reinstall建议；保持默认RAG开启和原构建/检索算法 |
| 29个新增离线用例 | 原6个CLI保留；配置/临时dotenv/Mock生成/错误/边界26项，真实Git hygiene3项，总计35项 |

生成链保护检查确认：`core_expert.py`、`code_generator.py`、`cuda_library.py`、`src/tools`、`src/models`、六案例输入和受控知识源相对基线内容未改。没有删除原功能，也没有重写PoC生成算法。`pipeline.py` 只更新过时banner。

## 修改前后实际测试

`PASS` 限于所列范围；`FAILED` 为实际失败；`NOT_CHECKED` 表示未运行。初始裸解释器失败和原HEAD安装依赖后的结果分开记录，避免把缺依赖归因于生成算法。

| 检查 | 修改前 | 修改后结果与限制 |
|---|---|---|
| Git分支/HEAD/工作区/目录/暂存区 | PASS | PASS：独立feature分支；origin/main读取仍为基线SHA；只暂存审查的工程文件 |
| Python语法 | PASS：24个文件，2个escape警告 | PASS：26个Python文件AST可解析；原code_generator:81与env_probe:532的两个escape警告仍保留，未为了迁移修改Prompt/探测算法 |
| 裸Python3.12核心依赖/CLI/原6测试 | FAILED：缺依赖；help与6测试均被ModuleNotFoundError阻断 | PASS：已建Windows原生venv，实际安装core/dev；`python -S main.py --help`也通过，无Key/重依赖要求 |
| 原HEAD隔离副本控制组 | 安装同核心依赖后PASS | 原HEAD的`--help`和6个unittest在无`.env`的临时archive副本通过；确认初始失败由未安装依赖引起 |
| Windows依赖安装与一致性 | NOT_CHECKED（无项目venv） | PASS：Python3.12.13，core/dev editable安装，46个核心/dev传递版本快照，`pip check`无冲突 |
| WSL依赖安装与一致性 | NOT_CHECKED（初始基线） | PASS：指定Linux路径venv，Python3.10.12，core/dev安装，47个版本快照，`pip check`无冲突；没有复用Windows环境 |
| Windows离线回归 | 原6测试有依赖后PASS | PASS：pytest与unittest总计35个用例；非网络Mock，不执行生成代码 |
| WSL离线回归 | NOT_CHECKED | PASS：pytest与unittest总计35个用例；非网络Mock，不执行CUDA/GPU或生成代码 |
| 核心模块导入 | 裸解释器FAILED | PASS：所有核心、models和tools模块导入；不构造真实模型请求，不调用探测函数 |
| 配置加载/环境覆盖/临时dotenv | NOT_CHECKED | PASS：默认、CPG类型覆盖、根目录临时dotenv及shell优先级、非法YAML/数字/bool/分块参数、Key缺失/旧别名/显式其他供应商 |
| LLM非网络Mock与错误 | NOT_CHECKED | PASS：403/404不重试、429有界重试、终次不sleep、参数保留；真实ChatOpenAI构造/invoke由Mock替代 |
| 专家/生成器/完整pipeline Mock | NOT_CHECKED | PASS：七维与知识进Prompt，分析/候选v1落盘，最多两次静态纠正，静态失败仍候选保存；环境/检索/搜索均Mock |
| JSON解析与schema边界 | 仅源码审查 | PASS（现状边界）：JSON提取可接受不符合schema的字典；测试没有把它说成真正schema校验，后者留待P1 |
| 六案例42 JSON | PASS | PASS：原样加载、JSON合法、文件齐全、目录内CVE ID一致；未核验官方事实 |
| RAG缺依赖降级Mock | NOT_CHECKED | PASS：缺Chroma时给出说明、禁用RAG、不下载模型；不等于实际RAG可用 |
| RAG/search依赖解析 | NOT_CHECKED | PASS（仅解析）：uv分别针对Windows Python3.12与Linux Python3.10解析core+rag+search；Windows119包；未安装可选组件，不验证torch/DLL/model/index运行 |
| Ruff限定错误检查 | NOT_CHECKED | PASS：两平台`ruff check main.py src tests`；规则仅E9/F63/F7/F82，并非全量风格/安全审计 |
| README参数/命令一致性 | FAILED：存在无效参数/不存在文件/错误功能说明 | PASS：真实help、离线命令/解释器路径/平台快照核对、本地文档链接存在；真实模型生成和RAG安装示例只校对，未执行 |
| README编码 | FAILED：22个NUL | PASS：UTF-8、无NUL与替换字符；Markdown源码核对，未做图形界面渲染验收 |
| Git ignore | 原规则不完整 | PASS：真实`git check-ignore --no-index`验证42个产物路径被忽略、18个模板/研究源/fixture路径可跟踪；未创建模拟私有文件 |
| tracked/staged私有文件检查 | `.env`未跟踪、`.workbuddy`已跟踪 | PASS：`.env`及`.workbuddy`不在新索引，本地记忆仍存在；不存在“新增ignore自动解除跟踪”的误判 |
| 工作区/索引/可达历史敏感规则扫描 | PASS（限定） | PASS（限定）：未发现实际provider token/私钥/凭证赋值；只命中历史示例placeholder；只报告路径/行号/类别，不回显内容；未重写历史 |
| Git diff whitespace | PASS | PASS：worktree及staged `git diff --check`，仅有Git行尾转换提醒 |
| DeepSeek官方配置资料 | 文案与默认不一致 | PASS（文档核对）：官方文档列`deepseek-flash`与默认endpoint；未做账号鉴权、模型响应或API schema能力实测 |
| WSL系统工具版本 | PASS（只读补查） | PASS（只读）：nvcc12.8.93、Compute Sanitizer2025.1.0.0、gcc/g++11.4.0；未重装或修改系统工具 |
| VS Code实际解释器选中状态 | NOT_CHECKED | NOT_CHECKED：只修改共享配置，未控制IDE UI，历史缓存选择可能需手动更新 |
| 真实LLM/Tavily请求 | NOT_CHECKED | NOT_CHECKED：没有请求，实际模型/Tavily调用成本为0；若后续需要，应先说明调用范围和预算 |
| 真实RAG安装/embedding/索引/检索 | NOT_CHECKED | NOT_CHECKED：未下载模型、不建真实索引；requirements完整入口的端到端安装未验收 |
| 官方CVE来源/受影响范围真实性 | NOT_CHECKED | NOT_CHECKED：未逐一访问公告/NVD/Talos核验，不把仓库资料当实验记录 |
| GPU设备/CC实测、CUDA smoke编译运行 | NOT_CHECKED | NOT_CHECKED：只读工具版本；未执行nvidia-smi设备探测、nvcc编译或GPU kernel |
| 漏洞PoC/提权/破坏性样本 | NOT_CHECKED | NOT_CHECKED：本阶段不执行 |

测试数据只含无害常量/合成异常/临时JSON。临时`.env`是测试生成的假值；真实项目`.env`加载在回归中被禁用，外部追踪环境清空。原始私有日志未加入报告或Git。

## 可复跑的离线命令

Windows根目录（不用激活）：

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m ruff check main.py src tests
.\.venv\Scripts\python.exe -S main.py --help
git diff --check
git diff --cached --check
```

WSL终端进入项目并激活独立Linux venv：

```bash
source /home/pocdev/.venvs/cuda-poc-generator/bin/activate
python -m unittest discover -s tests -q
python -m pytest -q
python -m pip check
python -m ruff check main.py src tests
python -S main.py --help
```

## 原功能影响、剩余风险与P1

离线回归表明原Single-shot专家→生成→静态纠正→文件输出链仍工作；七层Prompt、RAG算法、领域知识和工具被保留。真实供应商服务、实际RAG和GPU能力未验证，不能声称迁移后已复现任何CVE。

P1优先处理以下已定位问题：

1. 兼容归一化现有flat/wrapped输入，保留原文及来源；核对七维CVE一致性，并接入真正的输出schema验证。
2. 为候选保存静态结果和失败状态，避免“保存成功”被当作执行/漏洞成功；限制错误输出继续流入生成。
3. 修正ELF字段宽度、shell参数拼接、进程退出状态和Linux信号判断，用固定安全fixture验证。
4. 去掉SM7.5及nvcc fallback冒充实测值；分别记录Windows开发机与WSL目标，unknown和来源可追溯。
5. 修正RAG嵌套字段查询、索引身份及失效机制，增加真正离线模型配置；修复assistant角色及异常类型的重试分类。

运行身份/哈希/原始日志存储与WSL后端在P2；目标oracle在P3。单独crash、CUDA错误码、编译成功、sanitizer OOB或LLM结论均不能成为CVE confirmed判据。

## Git交付边界

该报告随feature分支的审查后工程提交交付；完整Commit SHA及Draft PR链接以最终汇报和Git/GitHub记录为准。稳定main历史和标签不改，不force push、不自动合并。被移出索引的`.workbuddy`文件仍保留在本地，旧提交记录保留；`.venv`、真实`.env`、解析缓存、二进制和私有日志均不提交。
