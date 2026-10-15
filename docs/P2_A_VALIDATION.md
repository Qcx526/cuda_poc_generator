# P2-A 验收记录

日期：2026-10-15（Asia/Shanghai）。基线 `main@2eb3837c3aa25a10ae2e8b5d16c4a3f6fdb95159`；`git fetch origin main` 后确认 HEAD 与 origin/main 一致。按要求直接在 main 开发，不创建 feature branch 或 PR。

## 修改前基线与问题

| 项目 | 修改前 | 本阶段处理 |
|---|---|---|
| WSL 身份绑定 | 快照为 `wsl:<distro>`，工具默认 `local`，真实 binding 不一致 | 实际 WSL 环境统一标签、保留严格比对，真实联调完成 binding |
| 工具测量 | 读取失败可能仍进入 Popen | UNKNOWN、允许列表不符、第二次测量变化均 fail-closed，保留 START_FAILED 记录 |
| 执行合同 | 只有 P1-C 的绑定准备，缺少授权和 Preflight | 严格请求、独立操作者授权、可信 policy、机器可读拒绝状态 |
| 快照时效 | scientific ID 有意排除 metadata 时间 | 独立完整快照 SHA-256，禁止仅刷新 started_at 绕过过期限制 |
| Python 源码身份 | 路径导入可能使用未测量 pyc | 固定 bootstrap 校验源码后从内存字节加载项目模块 |
| 证据身份 | 未有 P2 的精确请求/授权/policy 绑定 | packet 保留三类规范摘要，原始 transport/目标字节和私有 manifest 可复查 |

起始工作区已有 `_diag.py`、`_check_rel.py` 删除；本阶段保留该用户状态，不恢复、不加入本提交。其余改动逐文件审查并只暂存工程文件。

## 实际测试矩阵

| 检查 | Windows Python 3.12 `.venv` | WSL Python 3.10 独立 venv |
|---|---|---|
| 修改前全量 pytest | PASS：253；SKIP：3 | PASS：256 |
| 修改后全量 pytest | PASS：350；SKIP：4；FAILED：0 | PASS：354；FAILED：0 |
| 原 P0～P1-C 全量回归 | PASS；保留原 256 项 | PASS；保留原 256 项 |
| 新增 P2-A 98 项 | PASS：97；SKIP：1 | PASS：98 |
| Python AST 语法 | PASS（静态检查，无模块业务执行） | 同一 LF 源码；完整 pytest 导入 PASS |
| Ruff | PASS | PASS |
| 依赖一致性 pip check | PASS | PASS |
| 原 CLI `main.py --help` | PASS；参数保持 | PASS |
| 固定 fixture CLI `--help` | PASS | 入口帮助 PASS；实际 transport 仅支持 Windows |
| 未授权入口阻断 | PASS：flag 缺失、truthy 非 bool、仅声称授权引用均不通信 | 同一离线回归 PASS |
| Windows→WSL 固定 fixture 真实联调 | PASS：最终 READY / FIXTURE_COMPLETED | PASS：固定无害子进程 NORMAL_EXIT / 0 |
| 原始证据回读、摘要和确定性报告 | PASS：原 transport/packet/request/auth/policy/target | PASS：原生 tool evidence、probe 原始产物摘要 |
| Git ignore、跟踪文件/敏感信息审查、diff whitespace | PASS | 由 Windows Git 对共享 checkout 核对 |
| 真实 CUDA nvcc / cuobjdump / nvdisasm smoke | NOT_CHECKED：本轮未单独授权执行 | NOT_CHECKED：未编译或解析 CUDA fixture |
| GPU kernel、生成候选、真实 CVE/Oracle | NOT_CHECKED：本阶段禁止执行 | NOT_CHECKED：本阶段禁止执行 |
| 真实 LLM/RAG/Tavily | NOT_CHECKED：离线 Mock，不产生模型费用 | NOT_CHECKED |

Windows 的四项 SKIP 都要求 POSIX 原生进程/权限/符号链接语义，分别为旧 Linux signal、两项证据文件系统权限检查和新增输入符号链接检查；没有把这些标为 Windows PASS。所有 354 项均在 WSL 实际通过。

主要新增回归：

- `test_p2_identity.py`：19 项。工具缺失/不可读/允许列表错误/替换/哈希期间变化、实际 WSL 标签与 foreign target。
- `test_p2_platform_identity.py`：11 项。缺失或冲突的发行版身份在查询前阻断、实际标签 provenance、snapshot 与 binding 的环境检查。
- `test_execution_preflight.py`：27 项。严格模型、授权来源/范围/期限、完整快照防时间篡改、候选/工具哈希、目录/链接/输入、资源策略、禁止任意 argv/action。
- `test_execution_bridge.py`：20 项。固定注册表、nonce/request/target、真实工具角色、可用资源 hard limits、逐字节 proof、固定源码加载、请求/授权/policy 摘要、矛盾状态拒绝。
- `test_execution_artifacts.py`：11 项。原始字节、篡改、独立期望 request、路径范围、授权入口和 CLI 参数。
- `test_execution_evidence_audit.py`：10 项。相同 request ID 下的授权/policy 替换、重新计算本地 manifest 后仍不允许改写 worker 原始输入、成功 transport 丢弃 packet 的负例。

旧测试唯一的准备代码调整是 `test_platform_probe.packet()` 显式提供合成的 WSL_DISTRO_NAME；原断言和数据判据保留。六套 CVE、42 个 JSON、固定 ELF、生成/分析 Prompt、pipeline、编译/ELF/inspect 工具、依赖与 constraints 均未修改。

AST 静态检查覆盖 58 个 Python 文件；现有 `code_generator.py` Prompt 字符串仍有 Python 3.12 `invalid escape sequence '\d'` SyntaxWarning，非语法错误。本阶段没有改写该生成 Prompt，列为既有维护项，不声称警告已经消除。

## 可复现命令

Windows PowerShell，项目根目录：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m src.fixture_smoke --help
git diff --check
```

WSL 终端，使用自己的 Python 3.10 venv：

```bash
cd /mnt/f/qcx/code/cuda_poc_generator
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pytest -q
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m ruff check src tests
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pip check
/home/pocdev/.venvs/cuda-poc-generator/bin/python main.py --help
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m src.fixture_smoke --help
```

真实固定 fixture 的操作者授权命令见 README；不要将其改成执行候选。真实结果、原始记录摘要和首次 UNKNOWN 的接线问题见 [独立联调报告](P2_A_REAL_INTEGRATION.md)。

## 改动范围与交付

新增核心文件：`models/execution.py`、`execution_preflight.py`、`execution_bridge.py`、`execution_worker.py`、`execution_artifacts.py`、`fixture_smoke.py`。修改范围仅为工具身份 fail-closed、平台标签/源码加载、已有绑定/证据 writer 的严格重新校验和 README。接口细节见 [执行前置合同](P2_A_EXECUTION_CONTRACT.md)，另有合成请求 JSON、固定 fixture 和六个新测试文件。

敏感信息审查覆盖工作树、暂存区及可达 Git 历史的有限凭证模式，不输出匹配内容；历史模板占位值不当作真实密钥。该检查不是所有秘密格式的证明。私有日志、实际授权文件、policy、缓存、venv 和 .env 保持忽略；原用户删除不暂存。依赖无升级，无付费模型调用，无驱动/Toolkit/WSL 配置改动，无 HeteroPoCLab 访问。

只有上述关键检查通过才正常 commit/push main；最终提交 SHA 与同步状态见交付汇报及 `git log -1`。不 force push、不改写历史、不创建或合并 PR。

## 能力边界与 P2 后续

固定 fixture 的联调证明通信、指定平台上的工具身份/前置检查与原始日志保存接线可用，不证明漏洞能力。P1-A 的 Single-shot Mock 生成链和独立静态状态回归继续通过。

本阶段不实现通用候选执行/编译、CVE Oracle、自动反馈、GPU/网络隔离、Windows Job 或任意远端进程树管理。UID/GID 和完整依赖身份尚未独立绑定；按路径哈希与启动仍有普通文件系统竞态，不能当作内核级原子测量。Windows/WSL、资源和授权的具体限制见合同。下一阶段应先设计受审核动作注册表、运行身份与隔离策略和 ExecutionRecord/EvidenceManifest 生命周期，再考虑候选执行；P3 才建立目标漏洞判据。

本阶段交付后停止开发，等待独立审查。
