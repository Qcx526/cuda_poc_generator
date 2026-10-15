# P2-C 验收记录

日期：2026-10-15（Asia/Shanghai）。开始时 HEAD 与 origin/main 均为 `e7995bc444e081c7341f889b4c373ee7ee4cfa5a`，分支 main；用户原有 `_diag.py`、`_check_rel.py` 未暂存删除保留。直接在 main 开发，无 feature branch/PR、历史改写或 force push。

## 已实施范围

- 审计并复用 lifecycle_process/bridge/worker/artifacts/models；CUDA 原生步骤使用与 Python fixture 相同的受控进程核心，未开放通用命令执行器。
- 新增固定 CUDA 注册源、六步固定工具链、新资源 profile、严格版本化授权与平台/工具绑定；既有 compile/inspect 的通用 run_tool 不冒充 CPU/AS 受控执行。
- 新增 Linux 原件索引/传输/独立重查、Windows 原始字节核验、版本化确定性报告、fsync/原子发布与 Windows 目录 fsync 降级说明。
- 新增明确操作者 CLI；主生成流程、LLM/Prompt、RAG/Tavily 和数据不改写。

数据流、模型/API、资源与 ELF 支持边界见 [集成合同](P2_C_CUDA_INTEGRATION.md)。

## 测试结果

| 检查 | Windows Python 3.12.13 | WSL Python 3.10.12 |
|---|---|---|
| P2-B 已记录基线 | 460 PASS、30 SKIP | 489 PASS、1 SKIP |
| P2-C 最终全量，601 项 | **554 PASS、47 SKIP、0 FAILED** | **599 PASS、2 SKIP、0 FAILED** |
| 本轮新增，111 项，包含于全量 | 94 PASS、17 SKIP | 110 PASS、1 SKIP |
| Ruff：main.py src tests | PASS | PASS |
| pip check / 依赖导入 | PASS | PASS |
| main.py --help | PASS | PASS |
| src.cuda_smoke / src.lifecycle_cli --help | PASS | PASS |

Windows 新增 17 个 SKIP 为 Linux 路径/目标前置检查 4 项、实际原生进程/ptrace 11 项、Linux wait-status/signal 常量 2 项；这些不被标为 Windows PASS。WSL 新增 1 个 SKIP 是 Windows/非 Linux 直接启动拒绝测试。原 490 项回归未修改，全部保留。

新测试涵盖固定源码/argv/架构、工具缺失/版本不支持/身份替换、旧新合同隔离、非零/超时/截断、输出冲突、产物缺失/损坏/哈希改变、ELF profile 与边界、跨运行/boot/原授权混淆、原始文件缺失/篡改、独立重查不可访问、原子发布/fsync 失败、确定性报告及 CLI 授权。

真实原生回归只使用固定的已知无害 GNU true/false/sleep/yes 来测试 ptrace、退出、超时、输出和回收；其 CUDA argv builder 显式 Mock，不能算 CUDA 编译测试。合成 ELF/畸形负例只进入 Python 检查，不送原生工具。

复现离线全量：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check main.py src tests
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m src.cuda_smoke --help
```

```bash
# 在 WSL 项目目录，使用 Linux 自身 venv
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pytest -q
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m ruff check main.py src tests
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pip check
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m src.cuda_smoke --help
```

没有安装或升级依赖、驱动、CUDA、服务、网络或系统配置；没有付费 API。

## 真实 CUDA 与历史证据

| 检查 | 结果 |
|---|---|
| Windows 正式 CLI → WSL 新鲜平台/工具描述 | PASS，实际身份与原始版本记录 |
| nvcc 固定无害源码编译 | PASS，实际退出 0，cubin 2600 字节 |
| ELF64LE/EM_CUDA/固定 text/范围/哈希 | PASS，明确 CUDA 12.8 实测 profile |
| cuobjdump / nvdisasm | PASS，实际分别输出 5504 / 4632 字节，退出均为 0 |
| 编译派生进程 | PASS，记录 10 个 exec/9 个派生事件，资源/身份与回收检查 |
| 独立 worker/任务组回收 | PASS：CONFIRMED |
| Linux→Windows 原文件复核 | PASS：31 文件、358092 字节，native VERIFIED |
| 最终 Markdown 离线重建 | PASS，与真实原报告字节相同 |
| 早期 UNKNOWN 与 p2c-1.0 成功记录 | PASS：原件/哈希/报告重建；未覆盖 |
| P2-B 八例真实历史报告 | PASS：原输入/哈希/状态/报告均可重新读取 |

最终 request/run、工具版本、源码/cubin/manifest/index/report 哈希与实际失败过程见 [真实联调报告](P2_C_REAL_INTEGRATION.md)。早期内部格式失败只按其原 manifest/raw 核验，不能作为最终执行合同重放。

本轮确实发现并修复了：工具身份描述/别名拼写差异、WSL 墙上时钟回拨、真实 cubin 的厂商头字段不属于旧 ELF 子集、报告依赖字典插入顺序、后续工具未启动不能倒退已 RUNNING 生命周期、终态 CANCEL 不应修改 immutable 原始索引。每项均保留失败/未知边界，未修改固定 CUDA 源码来绕过问题。

## 工程与安全审计

| 项目 | 状态 |
|---|---|
| AST 语法检查 | PASS：93 个 Python 源码/测试/fixture 文件 |
| 既有受保护文件 | PASS：119 个既有源码、测试、数据、依赖/约束文件按 CRLF/LF 归一后逐字节相同 |
| 六套 CVE / 42 JSON | PASS：原文件保留，原归一化回归通过 |
| 原 Single-shot Mock 生成/状态 | PASS；真实模型生成 NOT_CHECKED |
| API Key、日志、token、venv、cubin ignore | PASS；原件不纳入 Git，固定 .cu fixture 允许跟踪 |
| 工作区/暂存区/可达历史凭证格式检查 | PASS：限定格式扫描，不声称发现任意形式秘密 |
| README/文档命令与相对链接 | PASS |
| 合成示例结构校验 | PASS，明确 synthetic；不是执行证据/操作者授权 |
| git diff --check / 暂存区 whitespace | PASS |
| 固定 CUDA fixture 的 checkout 字节 | PASS：专用 .gitattributes 规则强制 LF，Git blob/工作副本/登记 SHA-256 一致 |
| 两个用户删除 | PASS：保留未暂存，不属于本轮提交 |

保留基线 `src/code_generator.py:84` 的 `invalid escape sequence '\d'` SyntaxWarning；没有为本阶段修改原 Prompt。历史模板密钥占位符与真实凭证分开识别，不输出实际秘密。Ruff 采用仓库既有规则，不等价于完整安全审计。

## 未检查与限制

| 项目 | 状态/含义 |
|---|---|
| GPU kernel launch、生成候选/真实 CVE、畸形 native 输入 | 未执行；候选/kernel NOT_EXECUTED，CVE NOT_VERIFIED |
| Compute Sanitizer、运行期 CUDA API/驱动行为 | NOT_CHECKED |
| 其他 GPU、其他 Toolkit/编译器版本、真实 CUDA 超时/故障注入 | NOT_CHECKED；对应控制分支采用 Mock/无害原生回归 |
| 真实 LLM、RAG、Tavily | NOT_CHECKED，无付费调用 |
| cgroup delegation、整树聚合资源、GPU VRAM 限额 | 未实施，不能从 RLIMIT 推断 |
| 网络/GPU 驱动隔离、完整不可信样本沙箱 | UNSUPPORTED |
| 全部 ELF/CUDA ABI、符号/重定位语义 | 未验证；只支持明确结构子集 |
| Windows 目录 fsync | UNSUPPORTED；记录文件 fsync+原子发布，非数据库事务 |
| 同权限操作者恶意改写/系统供应链/硬件证明 | 无此保证；hash/manifest 不提供签名或硬件 attestation |
| Linux 原件不可访问或回收无法确认 | 保留 UNAVAILABLE/UNKNOWN/CLEANUP_FAILED，不自动成功 |

## 交付与后续审查条件

新增 CUDA registry/guard/adapter/workflow/CLI、native 证据接口、九个新测试文件与固定 .cu fixture，增量修改既有合同、bridge/worker、共享进程核心、证据/报告及显式 ELF profile。原 P2-A/P2-B 入口与已发布版本保留，完整文件列表以本轮 Git commit 为准。

后续人工审核候选执行前，至少需要独立批准精确源码/二进制哈希、已复核目标/受影响版本、可落实且适合真实候选的资源/隔离策略、授权范围及撤销/回收方案。P3 Oracle 必须先定义目标漏洞的必要条件、客观证据引用和失败/未知反例；编译、正常退出、crash 或通用 sanitizer 报告不能替代目标判定。本阶段没有实现这些候选执行/Oracle 能力。

关键验收通过后正常 commit/push main；具体提交 SHA 和同步状态见交付消息/Git。完成后停止开发，等待独立审查。
