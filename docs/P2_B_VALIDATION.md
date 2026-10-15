# P2-B 验收记录

日期：2026-10-15（Asia/Shanghai）。开发基线为 `main@08ddd72412eccfe587e11cc73d93bc081362a2c0`；开始时本地 HEAD 与 `origin/main` 一致。用户已有 `_diag.py`、`_check_rel.py` 工作区删除，本轮保留、不暂存、不恢复。直接在 main 开发，无 feature branch、PR、历史改写或 force push。

本记录区分离线 Mock、真实无害进程测试和 Windows→WSL 联调；没有付费模型调用、生成候选执行或目标 CVE 实验。最终漏洞状态始终为 `NOT_VERIFIED`。

## 修改前后

| 基线能力/缺口 | P2-B 结果 |
|---|---|
| P2-A 已有严格请求、独立授权、Preflight、平台/工具/候选绑定和固定桥接 | 复用这些合同；增加请求版本 1.1，保留 1.0 路由与旧产物含义 |
| 缺少可复用的生命周期与实际进程观察 | 严格 FSM、唯一 request/run、实际 PID/启动身份、资源/终止/回收记录 |
| launcher 结束不能证明 Linux 已回收 | 固定 CANCEL/STATUS 通道；独立 observer 复核 worker 与任务组；缺少确认保留 UNKNOWN/CLEANUP_FAILED |
| 不能接受任意候选程序 | 固定不可变注册表，只执行六类已审核无害动作；通用 EXECUTE_CANDIDATE 继续 UNSUPPORTED |
| 证据和报告需要完整关联、离线重建 | 版本化 ExecutionRecord/EvidenceManifest、私有原始双流、原始控制包、逐文件长度/哈希和确定性报告 |
| 资源失败、通信失败、磁盘失败可能缺少清楚表达 | 放行前资源门控；异常时限定取消和独立检查；保存失败明确 INCOMPLETE，无法确定执行状态保留 UNKNOWN |

详细接口和真实数据流见 [生命周期合同](P2_B_EXECUTION_LIFECYCLE.md)。

## 双环境回归

使用现有 Windows CPython 3.12 `.venv`，以及 WSL Ubuntu-22.04 / `pocdev` 的独立 CPython 3.10 venv。没有重装依赖、CUDA、驱动或更改 WSL 配置。

| 检查 | Windows | WSL |
|---|---|---|
| 修改前 P0～P2-A 全量 pytest | PASS：350 passed，4 skipped | PASS：354 passed |
| 修改后全量 pytest，490 项 | PASS：460 passed，30 skipped，0 failed | PASS：489 passed，1 skipped，0 failed |
| 本轮新增 136 项（含于全量） | PASS：110 passed，26 skipped | PASS：135 passed，1 skipped |
| Ruff：`main.py src tests` | PASS | PASS |
| `pip check` | PASS | PASS |
| 生成 CLI `main.py --help` | PASS | PASS |
| 生命周期 CLI `python -m src.lifecycle_cli --help` | PASS | PASS |

Windows 的 30 个 SKIP 为原有 4 项平台测试、本轮 24 项 Linux 原生进程测试、2 项 POSIX 文件权限测试；WSL 的 1 个 SKIP 为 Windows/非 Linux 适配拒绝测试。SKIP 不表示对应平台功能已通过。WSL 测试包含真实无害 Python 进程、超时、fork 后代、资源与回收，并非全部采用 Mock；Windows 生命周期桥接负例主要采用 Mock。真实跨环境场景另列于下文。

| 新增测试文件 | 数量 | 主要覆盖 |
|---|---:|---|
| `tests/test_lifecycle_models.py` | 27 | 合法/非法迁移、严格类型、必需字段、ID、边界和科学状态 |
| `tests/test_lifecycle_process.py` | 32 | 固定动作、实际身份、正常/非零、超时/取消、CPU/输出、资源实施失败、后代与 worker 死亡回收 |
| `tests/test_lifecycle_artifacts.py` | 31 | 哈希/长度、缺失/篡改、跨运行混淆、原始授权/包关联、私有权限、磁盘失败、离线重建 |
| `tests/test_lifecycle_bridge.py` | 22 | launcher 异常、nonce/目标/observer 身份、独立恢复、未知回收、限定取消重试、存储失败 |
| `tests/test_lifecycle_worker_audit.py` | 15 | request/run 冲突、授权门控、worker 身份、spawn intent、控制面及独立检查 |
| `tests/test_lifecycle_request_versions.py` | 4 | P2-A/P2-B 请求版本和产物路由隔离 |
| `tests/test_lifecycle_cli.py` | 5 | 无授权不通信、未知动作拒绝、绑定入口、时钟基准、写入失败报告 |

重复/冲突 ID、授权缺失、候选/工具哈希改变、过期授权、资源不支持、输出截断、原始日志缺失、清理失败等均有负例，未修改历史测试或数据来制造通过。

复现命令（项目根目录）：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check main.py src tests
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m src.lifecycle_cli --help
```

WSL 终端使用 Linux 自身解释器：

```bash
cd /mnt/f/qcx/code/cuda_poc_generator
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pytest -q
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m ruff check main.py src tests
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pip check
/home/pocdev/.venvs/cuda-poc-generator/bin/python main.py --help
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m src.lifecycle_cli --help
```

## 真实 Windows→WSL 联调

本轮任务明确授权固定无害动作。Windows 原生 Python 发起固定桥接；WSL 实际核对身份、实施限制、执行、回收并生成记录，再由独立 STATUS observer 检查。最终八例均通过结构化预期检查、原始证据关联/哈希复核与 Markdown 离线重建：

| 场景 | 实际有效状态 | 验收 |
|---|---|---|
| 正常退出 0 | COMPLETED | PASS |
| 固定退出 7 | NONZERO_EXIT | PASS |
| 固定 sleep 超时 | TIMED_OUT | PASS |
| 超量输出 | RESOURCE_LIMIT；truncated=true、capture_complete=false | PASS：正确保留不完整状态 |
| 固定 fork 后代超时 | TIMED_OUT；后代回收确认 | PASS |
| 固定 CPU 计算 | RESOURCE_LIMIT；原始 SIGKILL/CPU 边界诊断保留 | PASS |
| 运行中取消 | CANCELLED；实际 action_started=true | PASS |
| 缺少独立授权 | REJECTED；没有启动 guard/动作 | PASS |

八例独立回收均为 CONFIRMED。这里的 PASS 指符合预期控制行为；非零、超时、取消、资源限制仍是各自执行状态，不能称为正常退出或漏洞验证。请求/run ID、manifest SHA-256、日志位置及真实失败诊断见 [独立联调报告](P2_B_REAL_INTEGRATION.md)。

开发中实际出现过源码哈希不一致、Windows/WSL 时钟偏差导致授权尚未生效、早取消后缓冲 READY 导致错误身份拒绝。这些原始失败均保留。修正时间来源和取消后消息处理后补验，并增加回归；没有放宽身份、授权、资源或回收判据。

## 其他交付检查

| 检查 | 状态与范围 |
|---|---|
| Python 语法 | PASS：AST 解析 78 个源码/测试/fixture 文件 |
| 既有能力保护 | PASS：97 个既有源码、测试、数据和依赖/约束文件与基线字节一致（仅统一 CRLF/LF 后比较） |
| 六套输入/42 个 JSON | PASS：文件保留，既有归一化回归通过 |
| Single-shot Mock 生成与科学状态 | PASS：原测试保留并通过；生成器、Prompt、RAG/Web/LLM 接线与 CUDA 底层工具未改写 |
| 合成 JSON 示例 | PASS：真实模型重新校验；明确标为 synthetic，不是实验或授权证据 |
| 八例原始证据回读 | PASS：原始包、request/run、授权/policy/平台/工具、文件长度/哈希和报告重建 |
| README/文档相对链接与入口 | PASS：链接存在、CLI 参数与实际实现一致 |
| Git ignore/跟踪文件 | PASS：`.env`、venv、私有日志/控制句柄、临时审计脚本被忽略；受控 fixture/示例可跟踪 |
| 工作区/暂存区/可达历史凭证检查 | PASS：限定凭证格式扫描未发现实际密钥；历史模板占位符单独识别；不表示任意格式秘密都可检测 |
| diff whitespace | PASS：`git diff --check` 与暂存区检查 |
| 用户工作区删除 | PASS：`_diag.py`、`_check_rel.py` 保留为未暂存删除，不包含于本轮提交 |

语法检查仍观察到基线 `src/code_generator.py:84` 的 `invalid escape sequence '\d'` SyntaxWarning，属于已有 Prompt 字符串，本轮未修改。Ruff 使用仓库原有选择规则，不能替代完整安全审计。

## 未检查、未支持与限制

| 项目 | 状态/边界 |
|---|---|
| 本轮真实 CUDA 编译、cuobjdump/nvdisasm、GPU kernel、Sanitizer | NOT_CHECKED；没有把 Mock/版本查询当真实 CUDA 测试 |
| 真实模型、RAG 模型下载/检索、Tavily | NOT_CHECKED；无付费调用 |
| 任意生成候选、任意 argv/shell、未知二进制执行 | UNSUPPORTED；候选始终 NOT_EXECUTED |
| CVE Oracle、漏洞触发、自动反馈 | 未实现；验证始终 NOT_VERIFIED |
| cgroup v2 | PASS：只读观察；NOT_CHECKED：delegation；未使用/写入 cgroup 限制 |
| CPU/地址空间 | 已实施并回查每进程 RLIMIT；不是整棵进程树聚合配额；RLIMIT_AS 不是 GPU VRAM 限制 |
| 网络/GPU 驱动隔离、完整不可信样本沙箱 | UNSUPPORTED，不能作为执行高风险代码的隔离依据 |
| 身份与完整性 | 真实进程观察和内容哈希，仍有操作系统时序边界；manifest 不提供数字签名、硬件证明或抵抗同权限操作者伪造 |
| 远端回收无法确认/证据保存失败 | UNKNOWN/CLEANUP_FAILED 或 INCOMPLETE，不能宣称安全完成/完整保存 |

## 交付范围

生产代码新增 `src/models/lifecycle.py`、`src/registered_actions.py`、`src/lifecycle_process.py`、`src/lifecycle_worker.py`、`src/lifecycle_bridge.py`、`src/lifecycle_artifacts.py`、`src/lifecycle_cli.py`；小幅调整 `src/models/execution.py`、`src/execution_bridge.py`、`src/execution_worker.py` 支持明确的版本与固定入口。另有七个测试文件、六个固定 fixture、README、三份 P2-B 文档及两份明确合成的 JSON 示例。

只提交上述工程文件；原始私有日志、控制 token、环境文件、venv 和临时脚本均不提交。验收通过后执行正常 commit/push main；具体提交 SHA 与同步状态以交付消息及 Git 记录为准。完成后停止开发，等待独立审查，不自动进入下一阶段。
