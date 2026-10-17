# P3-D-R1 固定无害 Memcheck 执行与证据合同

报告语言：`zh-CN`。合同版本：`memcheck-1.0`。

本文说明新增接口、准入规则与科学边界，不是本机真实实验验收结果。版本查询、离线测试与真实 Memcheck 诊断分别记录；实际 PID、工具哈希、XML、退出状态和回收结论以本轮独立验证报告及原始档案为准。

## 1. 范围与兼容性

本轮新增独立动作 `FIXED_MEMCHECK_DIAGNOSTIC`，只允许以下冻结 CPU fixture：

| task_id | 原文件 | 源码 SHA-256 |
|---|---|---|
| `p3c-normal-v1` | `tests/fixtures/host_diagnostics/normal.c` | `430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107` |
| `p3c-invalid-write-v1` | `tests/fixtures/host_diagnostics/invalid_write.c` | `d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c` |

注册表位于 `src/memcheck_registry.py`。调用方不能传入源码、shell 字符串、自定义编译参数、诊断参数或任意 argv。正常 fixture 必须先完成真实闭环，之后才能在匹配的独立授权下运行 invalid-write fixture；预期错误类别不作为采集结果预填值。

新合同位于 `src/models/memcheck.py`。原有 P2 请求和动作合同、P3-B/P3-C 的 `SYNTHETIC` / `UNVERIFIED_IMPORT` 模型、旧报告与历史原件继续保留。不会通过删掉旧 `ACTION_UNSUPPORTED` 或改名导入数据来取得执行资格。通用 `EXECUTE_CANDIDATE` 仍不在本动作的允许范围。

所有新执行记录的 `cve_id` 为 `null`，候选状态固定为 `NOT_EXECUTED`，漏洞验证状态固定为 `NOT_VERIFIED`。这不否认固定测试程序的实际执行；它明确表示没有执行生成候选或指定 CVE 输入。

## 2. 描述、请求、授权与策略

| 合同 | 主要绑定 | 能力边界 |
|---|---|---|
| `MemcheckDescription` | WSL 目标标签、`PlatformSnapshot`、probe、boot、单调时钟、固定原生工作根、工具及辅助图像哈希、版本原始记录、采集 guard 源码哈希 | `DESCRIBED` 表示描述完整；不表示 Memcheck 已运行或隔离已适配 |
| `MemcheckRequest` | request/run/task、冻结源码、描述与快照 SHA-256、环境/probe/boot、全部工具、辅助图像、资源 profile、授权引用 | 只描述固定动作，不授予执行权 |
| `MemcheckAuthorization` | 请求规范 SHA-256、request/run/task、操作者、授权引用、签发类型、目标 boot、有效单调时钟区间 | 必须由操作者或可信策略边界独立提供；期限最长五分钟 |
| `MemcheckPolicy` | 请求与描述摘要、允许的操作者和授权引用、精确可执行图像允许列表、原生任务根、资源 profile、描述有效期 | 来自受信控制侧，不能由 LLM 或任意请求自行指定为可信 |
| `MemcheckExecutionRecord` | 请求/授权/策略/快照摘要、工具及目标身份、生命周期、两个步骤、worker 身份、原始产物索引 | 只保存执行端观察；不产生 CVE 验证结论 |

工具角色包括 `compiler`、`valgrind`、`valgrind_launcher`、`memcheck`、`bwrap`、`guard_python`。工具必须有实测绝对 POSIX 路径与 SHA-256。编译器辅助进程也必须逐个列入图像允许列表；测量失败、路径替换或同路径哈希冲突均不能继续。

固定参数来自注册表，当前编译步骤为 `-std=c11 -g -O0 -Wall -Wextra -fno-omit-frame-pointer /input/fixture.c -o /out/fixture.bin`；诊断步骤为 `--tool=memcheck --xml=yes --xml-file=/out/memcheck.xml /target/fixture.bin`。具体可执行路径来自独立测量和允许列表。编译成功后保存产物哈希，Memcheck 启动前再次核对该产物，不接受其他二进制替换。

`collector_sha256` 绑定 `src/memcheck_sandbox.py` 的原始源码。桥接同时固定 worker 源码身份；保存 `sandbox_guard.py` 原件用于离线核验。摘要用于内容一致性，不是远程主机硬件认证或数字签名。

## 3. 两级准入与执行顺序

`src/execution_preflight.py:preflight_fixed_memcheck` 执行只读检查：

1. 严格验证新请求、独立授权、策略与平台描述。
2. 比较 request/run/task、源码、描述、快照、环境标签及 probe；核对当前 WSL boot 和目标单调时钟。
3. 检查授权有效期、描述时效、固定工作根与路径边界。
4. 重新读取冻结源码、采集 guard、编译器、Valgrind、bubblewrap、Python 及辅助图像的实际字节。
5. 检查所需 Linux RLIMIT API 及继承的硬限制是否支持当前 profile。

拒绝返回 `REJECTED`；观测不足返回 `UNKNOWN`；明确缺少执行机制返回 `UNSUPPORTED`。`READY` 只允许启动固定 sandbox guard，不宣称必要限制已经生效。每个工具步骤开始前重新执行检查，防止跨步骤替换。

第二级 gate 在 WSL 执行端进行。guard 实际设置限制，检查 namespace、只读输入、目标身份及 Python 图像，然后写出 ready 原件并等待受信 worker 的 GO。worker 从宿主 `/proc` 独立核对 guard 的 PID/start_ticks、实际限制，以及 bubblewrap 的真实可执行图像。未获得这些实测结果，不放行编译器或 Valgrind。

放行后，guard 使用受限 ptrace 观察原生执行图像、argv、继承限制和后代进程。每次原生执行的路径和文件哈希都必须符合允许列表；无法建立观测时停止。这里的 ptrace 用于固定程序的采集与回收确认，不向调用方开放任意调试或任意执行接口。

## 4. Windows→WSL 生命周期

Windows 控制入口是 `src/fixed_memcheck.py`，复用已有 WSL 固定桥接和进程身份工具。没有新增可接受任意命令的桥接端点。

```text
Windows 固定任务调用
  → DESCRIBE：只读测量 WSL 平台、工具和采集器
  → 控制侧依据既有明确授权建立 request / authorization / policy
  → EXECUTE：WSL 严格 preflight
  → compile：资源与文件边界 gate → 固定编译 → 保存原件和目标哈希
  → memcheck：重新 preflight → 同样 gate → 固定 Memcheck
  → 步骤回收与执行记录
  → 独立 STATUS：重新观察 worker、进程组及任务身份
  → Windows 核验传回原件 → XML 解析 → 中文报告 → 独立重新读取与复核
```

记录复用既有生命周期状态和合法迁移。正常链为 `CREATED → AUTHORIZED → PREFLIGHT_READY → STARTING → RUNNING → COMPLETED`；失败可能为 `NONZERO_EXIT`、`TIMED_OUT`、`CANCELLED`、`START_FAILED`、`RESOURCE_LIMIT`、`CAPTURE_FAILED`、`CLEANUP_FAILED`、`REJECTED`、`UNKNOWN` 或 `UNSUPPORTED`。编译和诊断各自保存终态，不能用 Windows launcher 的零退出代替远端步骤完成。

每个任务有独立 request/run ID、随机通信 nonce 和私有控制 token。同 run 目录使用独占创建，不能覆盖旧记录。Windows launcher、Linux worker、外层 bubblewrap、namespace 内 guard、Valgrind 原生进程的身份分别保存；外层 PID 不冒充 Valgrind PID。PID、PGID、session、start_ticks、退出码和回收结果来自执行端观察。

通信异常时，控制侧使用仅绑定本任务的 CANCEL 与独立 STATUS。取消和超时针对本任务新建的 Linux 进程组，并结合 ptrace/子进程回收及宿主 `/proc` 复查；不使用 `wsl --shutdown`。远端身份或回收不确定时保留 `UNKNOWN` / `CLEANUP_FAILED`，不以杀死 `wsl.exe` 宣称清理完成。操作系统意外中止等无法观测的情况也不能提升为成功。

## 5. 资源 profile 与已声明边界

`P3D_FIXED_CPU_MEMCHECK_V1` 与旧 Python fixture、CUDA smoke profile 分开。默认请求如下；实际实施必须由每次 ready、宿主复查及 trace 原件支持。

| 项目 | 默认请求 | 实施/核验方式 |
|---|---:|---|
| 每工具步骤 wall-clock | 30 秒 | worker watchdog 与 guard 截止时钟 |
| CPU 时间 | 每进程 10 秒 | `RLIMIT_CPU`，宿主及原生 exec-stop 核对 |
| 地址空间 | 每进程 4 GiB | `RLIMIT_AS`，请求范围 1～8 GiB，逐次实测 |
| stdout + stderr | 1 MiB | worker 合计采集上限与终止逻辑 |
| XML | 2 MiB | 原始文件大小检查与解析器上限 |
| 单文件 | 4 MiB | `RLIMIT_FSIZE` 和普通文件读取上限 |
| 打开文件 | 128 | `RLIMIT_NOFILE` |
| 被跟踪进程 | 最多 32 | 固定 guard 的后代跟踪上限 |
| core dump | 0 | `RLIMIT_CORE` |

bubblewrap profile 建立私有 user/mount/network/PID/IPC/UTS namespace，清空继承环境并丢弃 capability。工具及运行库目录以只读方式挂载；只额外挂载本任务冻结源码、采集 guard、配置、控制目录、输出目录和已核验目标。没有整个 Windows 工程、用户 HOME、GPU 设备或系统可写目录透传。任务所需文件边界必须在实际 sandbox 中验证，单独的 namespace 可用性探测不算适配完成。

本 profile 的 CPU 和地址空间限制是**每进程**限制，不是后代总量 cgroup 配额。当前不自动配置 cgroup、不申请新权限或安装服务。`cgroup_enforcement` 和 `gpu_vram_limit` 明确为 `NOT_IMPLEMENTED`。`RLIMIT_AS` 不表示实际物理内存或 GPU VRAM 上限；Valgrind 是否能在请求范围内完成必须通过本机真实诊断确认，不能因版本查询成功提前标记通过。

这些边界只针对已审查的固定无害 CPU 测试。没有宣称具备 GPU 驱动安全隔离、任意不可信 native 程序沙箱或适用于真实漏洞样本的完整隔离能力。

## 6. 原始文件、身份与独立复核

WSL 原生任务根为当前用户的 `~/.local/state/cuda-poc-generator/memcheck_tasks/<run_id>/`。Windows 默认独立档案为 `data/outputs/fixed_memcheck/<run_id>/`，控制过程另存于 `data/outputs/fixed_memcheck/controller/<run_id>/`。通用无害诊断拒绝归入 `CVE-...` 目录，也不扩大 ZIP 接口。

每轮保存实际存在的产物：

- 冻结 C 源码、已生成的二进制、采集 guard 源码。
- 每步编译/诊断 argv、配置、ready、宿主身份、trace JSONL、result、进程结果；失败时仅保存真实存在的错误记录。
- 原始 `memcheck.xml`、`compile.stdout.bin`、`compile.stderr.bin`、`memcheck.stdout.bin`、`memcheck.stderr.bin`。
- 请求、独立授权、策略、执行记录、派生解析对象、中文报告及 SHA-256 清单。

不会创建缺失 XML 或不存在日志的虚假占位文件。原始 stdout/stderr、XML、trace 保留原字节；报告使用 UTF-8，语言默认 `zh-CN`。新档案采用受保护 Windows DACL，Linux 目录 `0700`、文件 `0600`；保护或写入失败时不能报告保存成功。历史证据不会被移动或改写。

`src/memcheck_evidence.py` 提供不执行进程的接口：

| 接口 | 输入与输出 |
|---|---|
| `parse_memcheck_evidence(record, request, authorization, policy, raw_files, expected_record_sha256=...)` | 核验独立固定的执行记录、请求/授权/策略及每个原件，返回严格解析对象 |
| `reassess_memcheck_evidence(evidence, expected_record_sha256=...)` | 从对象中嵌入的原始三流重新解析，拒绝被修改的分类、栈帧或派生字段 |
| `render_memcheck_report(evidence)` | 确定性中文视图；不启动程序，不改变状态 |
| `save_memcheck_evidence(evidence, raw_files, output_root=...)` | 独占新建 run 档案，返回目录与清单原始字节 SHA-256 |
| `read_memcheck_evidence(directory, expected_manifest_sha256=...)` | 重新打开所有文件，核对清单、身份与原始控制文件投影，独立重新解析，并逐字节比对中文报告 |

原件验证不仅比较文件摘要，还检查源码/构建身份、编译和诊断标准流、ready/config/result/trace 等结构化投影、宿主独立图像、资源及执行路径。独立复核的清单或记录摘要必须从受信控制侧另行固定。自己重新计算已被修改档案的摘要不能认证采集来源；内容哈希不是操作者签名或远程主机证明。

## 7. XML 解析与结论边界

解析直接复用 P3-B 已有 `_parse` 的 Memcheck XML v4 子集，用只读 adapter 提供实际观察到的内层 argv、Valgrind namespace PID、目标 argv 与原始 XML 身份；不会改动旧解析器或原始 XML。

XML 必须完整、UTF-8、无 DTD/实体，协议必须为 v4/memcheck，最终状态必须符合已支持格式，PID 与 argv 必须匹配原生记录。截断、协议变化、路径不一致或未知格式返回明确拒绝原因，并保留原件。只有独立调查真实协议后才能另行评审解析器扩展，不能替换版本号、PID 或参数制造兼容。

`InvalidWrite` 仅支持 `INVALID_WRITE` 与 `WRITE` 观测；其他结构化类型同理。原始描述可以展示，但不会据此补造访问地址、访问大小、堆/栈区域、生命周期或根因。调用栈只保存 XML 实际字段及精确节点，缺失字段保留未知。正常退出、非零退出、SIGSEGV 或内存错误均不能变成特定 CVE 的验证结论。

真实无害 fixture 的异常仅证明诊断系统能够观察对应测试错误；本阶段不接入生产 CVE `VERIFIED`，不改写既有 Oracle 对象。导入的 `UNVERIFIED_IMPORT` 也不会被重命名为真实采集。

## 8. 控制侧使用方式

Windows `.venv` 的固定任务 CLI：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks run-fixed --task p3c-normal-v1 --authorize-fixed-memcheck --operator-id "your-operator-id" --authorization-reference "approved-fixed-CPU-diagnostic" --linux-project-root "<项目的 WSL 路径>"
```

独立离线复核使用 `python -m src.host_diagnostic_tasks verify-fixed --directory <证据目录> --manifest-sha256 <独立固定的清单摘要>`。也可从受信 Windows 控制程序调用 Python API：

```python
from src.fixed_memcheck import run_fixed_memcheck_wsl

result = run_fixed_memcheck_wsl(
    "p3c-normal-v1",
    authorize_fixed_memcheck=True,
    operator_id="操作者身份",
    authorization_reference="已批准固定无害fixture诊断的独立引用",
    linux_project_root="<项目的 WSL 路径>",
)
```

调用位置必须是受信操作者控制层。`authorize_fixed_memcheck=True` 是该边界的明确意图参数，不能从 LLM 文本自动填充，也不是对真实 CVE 或任意输入的新授权。函数会自动描述、准入、执行、独立 STATUS、保存并重新读取证据；返回 `effective_state`、`parse_status`、`cleanup_confirmation`、证据路径与摘要。必须检查实际状态，不能只判断 Python 调用是否返回。

第一轮正常任务通过后，第二轮才使用独立 request/run ID 与适用授权选择 `p3c-invalid-write-v1`；不能复用旧 run 或预设其 XML 必然出现某个错误。

## 9. 下一阶段候选桥接设计与准入要求

固定 fixture 与真实 LLM 候选的风险不同。本轮完成无害诊断后，后续桥接应形成如下独立对象链：

```text
Windows 本轮生成目录
  → 合法 CVE / generation run / parent run 绑定
  → 实际 PoC 源码字节及 SHA-256
  → Windows→WSL 独占传输副本与接收哈希
  → 当前 WSL environment / probe / boot / 工具身份
  → 独立候选准入记录及新授权
  → 适用于该风险等级的执行器
```

最小 dry-run 必须检查 CVE/run 隔离、原件与传输副本哈希、允许的路径和大小、过期平台、工具替换、缺失授权、未知资源/隔离能力，并返回可机读的拒绝或未知原因。接收副本不应包含 API Key、完整 `.env` 或整个用户目录；路径不属于受信根、包含链接或发生跨 run 绑定时拒绝。

候选准入至少还需要：明确目标 CVE 和受影响环境资格、实际源文件与输入身份、独立操作者/策略授权、可接受动作及期限、精确工具允许列表、风险适配的资源与回收机制、原始证据要求。固定 fixture 的授权、隔离探测或 Memcheck 成功结果不能满足这些候选条件。

本合同不提供候选启动接口、不调用模型、不执行真实 CVE 输入或 GPU kernel。即便未来获准执行候选，执行完成与漏洞判定仍须分离；真实 CVE 的 `VERIFIED` 只能由独立审查后的必要条件、客观证据与 Oracle 规则产生。
