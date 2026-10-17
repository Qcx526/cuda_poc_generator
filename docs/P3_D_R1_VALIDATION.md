# P3-D-R1 验收记录

报告语言：`zh-CN`。本记录依据两轮 Windows→WSL 真实固定无害 CPU 任务的执行记录、原始文件和独立重解析结果填写。每轮使用独立 request/run 身份。原始文件保存在被 Git 忽略的本机目录；本文件只给出核验入口和摘要，不复制原始私有日志。

## 1. 当前可核实结果

| 检查 | 状态 | 已实际获得的结果 | 限制 |
|---|---|---|---|
| Windows Python 3.12 全量离线回归 | PASS | 最终源码 `1190 passed, 50 skipped, 1 warning` | `python -m pytest -q`；warning 为故意构造重复 ZIP 成员的负例，SKIP 不计为真实执行或 GPU 通过 |
| 本轮集中离线回归 | PASS | Windows `80 passed`；WSL `80 passed` | Mock/Synthetic/离线合同检查，不替代真实 Memcheck |
| Windows→WSL 只读 DESCRIBE | PASS | 返回 `DESCRIBED` | 仅确认平台、工具与采集器描述完整，不表示 Memcheck 已运行 |
| CLI 与 Python 语法 | PASS | `python main.py --help`、`run-fixed --help`、`verify-fixed --help` 退出码均为 `0`；`compileall -q src` 通过 | 主 CLI 参数保持原状，新增固定诊断独立入口 |
| `p3c-normal-v1` 真实固定诊断 | PASS | `COMPLETED`、`PARSED`、0 条结构化内存错误、回收 `CONFIRMED` | 仅代表该固定无害程序的实际观测 |
| `p3c-invalid-write-v1` 真实固定诊断 | PASS | `COMPLETED`、`PARSED`、1 条 `INVALID_WRITE`、回收 `CONFIRMED` | XML 观测不提供真实 CVE 根因身份 |
| 两轮真实日志独立重新解析 | PASS | Windows Python 3.12 和 WSL Python 3.10 均按独立清单摘要重新读取、解析，中文报告逐字节一致 | 哈希证明内容一致性，不是硬件证明或签名 |
| WSL Python 3.10 全量离线回归 | PASS | 最终源码 `1235 passed, 5 skipped, 1 warning` | 独立 WSL venv 的 `python -m pytest -q`；warning 同为故意构造重复 ZIP 成员的负例 |
| 真实 CVE 输入、LLM 候选、GPU kernel、付费模型调用 | NOT_EXECUTED | 不在本次执行范围 | 漏洞验证始终 `NOT_VERIFIED` |

首次原始执行链通过后才进行第二轮。两轮的外层 bwrap、实际 Valgrind launcher 与 Memcheck 引擎身份都来自 Linux 执行观察；`--version` 只作为独立描述证据。

## 2. 基线、工作区与保护对象

用户指定开发基线：`main@a684ae4206ef44b6492463655998d63d3eb9cbfa`。开始时本地 HEAD 与 `origin/main` 均为该 SHA，工作区只有两份既有未跟踪 P3-D 文档；最终 Git 状态见文末。

R1 采集验收时按当时要求暂不提交或推送；维护者后续已授权完成验收后正常提交推送。已有 `docs/P3_D_EXECUTION.md`、`docs/P3_D_REAL_VALIDATION.md` 两份历史草稿保持本地未跟踪状态，原始私有证据不纳入提交。本验收文件不改写其内容，不覆盖历史 run，不改变旧 Oracle 或冻结解析器的科学语义。

## 3. 后续真实任务必须引用的原始证据

每一轮必须使用独立 request/run ID，并保存来源与对象摘要。以下字段必须从执行端原件或受信控制记录读取，不能由报告作者或 LLM 补造。

| 证据类别 | 必须引用的字段或文件 |
|---|---|
| 控制身份 | `request_id`、`run_id`、task_id、目标环境、probe、snapshot SHA-256、boot、操作者与独立授权引用 |
| 请求绑定 | request / authorization / policy / description 规范摘要、授权单调时钟有效期、采集器源码 SHA-256 |
| 原始源码与构建产物 | `fixture.c` 和真实生成的 `fixture.bin` 的 SHA-256、字节数；冻结源码与注册表是否一致 |
| 实际工具 | 编译器、Valgrind launcher/native engine、Memcheck、bubblewrap、guard Python 及辅助图像的绝对路径、SHA-256、版本查询原件 |
| 编译过程 | `compile.argv.json`、配置、stdout/stderr、ready、宿主身份、trace JSONL、result、process_result 与步骤终态 |
| 诊断过程 | `memcheck.argv.json`、配置、stdout/stderr、ready、宿主身份、trace JSONL、result、process_result 与步骤终态 |
| 原生进程身份 | 外层 PID/PGID/session/start_ticks、宿主 guard 身份、namespace 内 Valgrind PID、实际图像及 argv；不能混用外层和内层 PID |
| 退出观察 | 外层及内层退出码、Linux signal、启动和结束时间、超时/取消/资源触发、截断及采集失败标志 |
| 资源与文件边界 | 实际 CPU/地址空间/文件大小/打开文件数/core 限制、host `/proc` 复查、namespace 与只读输入/目标观测；未实施的 cgroup/GPU VRAM 限制明确标注 |
| 原始 XML | `memcheck.xml` 原始字节数和 SHA-256、协议、PID、argv、FINISHED；不修补缺失字段或替换版本号 |
| 解析结果 | `PARSED` / `REJECTED`、诊断原因代码、实际错误 kind、精确 XML 节点、实际存在的栈帧及全部未知属性 |
| 回收 | 步骤回收、内层 trace 回收、宿主进程组/后代复查，以及独立 STATUS 的 worker/组状态与任务身份 |
| 完整性与重建 | 受信控制侧固定的记录摘要、包外保存的 manifest 摘要、原始文件逐项复核结果、解析对象比较、中文报告逐字节比较 |

不存在的产物不得补成空日志或虚构 PID。真实 XML 若不符合既有 v4 子集，应保存原件、记录明确不兼容原因并保持解析拒绝；不修改原始 XML 取得 PASS。

## 4. 真实正常任务

状态：`PASS`，`COMPLETED / PARSED / CONFIRMED`。Windows 控制侧依据本轮操作者批准以 `Qcx526`、授权引用 `P3-D-R1-user-approved-fixed-cpu-20261017` 建立独立固定任务请求。

| 字段 | 原始记录核验结果 |
|---|---|
| request / run | `f830ebe3682341328973eef4c4d77805` / `73b72355dff746e19e611679cf406b99` |
| 原始执行记录 SHA-256 | `8a6be0c20d731bdfc2cf8bb2de19abf9a3af9699718747341cf518bf714d1e40` |
| 独立 manifest SHA-256 | `cd16afba82af1f012d7a0e2bc9aec730c28ac920fff44c46597fb59137439278` |
| 冻结 C 源码 / 实际 ELF SHA-256 | `430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107` / `4f58fdc742e450678497a9e823254f22dcfc8f147912aa9c541faaab1845eaf4` |
| 编译步骤 | bwrap 宿主 PID/PGID `800/800`；guard 宿主 PID `802`；namespace 内 compiler PID `3`；内外退出码 `0/0`；`CONFIRMED` |
| Memcheck 步骤 | bwrap 宿主 PID/PGID `808/808`；guard 宿主 PID `810`；namespace 内目标 PID `3`；内外退出码 `0/0`；`CONFIRMED` |
| 原始 XML | `907` 字节；SHA-256 `1f87315f0562f0120c467feeaca09c533a62136cf6f177fd30d0e9659a08f17c`；XML v4 可由既有解析器读取；结构化错误 `0` 条 |
| 原始 stdout/stderr | 编译与诊断各两份均为 `0` 字节；空文件 SHA-256 均为 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 原始文件集合 | `raw/` 共 `22` 个实际文件，合计 `80131` 字节；各项长度和 SHA-256 见 manifest |
| 目录 | `data/outputs/p3d_r1_memcheck/73b72355dff746e19e611679cf406b99/`；中文入口 `report.zh-CN.md`；控制记录在同一根的 `controller/<run_id>/` |

执行端 trace 实测先启动 `/usr/bin/valgrind.bin`，再启动 `/usr/libexec/valgrind/memcheck-amd64-linux`；两者各自 SHA-256 已在执行记录和中文报告中绑定。请求的 CPU 时间 10 秒与 `RLIMIT_AS` 4 GiB 为每进程限制，实际 guard、宿主 `/proc` 和原生 exec-stop 均核对为 `ENFORCED`。wall watchdog、输出上限、进程组和网络 namespace 在本轮固定任务中得到实施记录；未启用 cgroup 总量约束。没有超时、截断或采集失败。随后独立 `STATUS` 观察到 `worker_alive=false`、`group_empty=true`、`identity_match=true`。

即使正常退出且未观察到结构化内存错误，也只说明本轮固定任务在该诊断配置下的观察结果；不能证明任意程序安全或某个 CVE 不存在。

## 5. 真实受控 invalid-write 任务

状态：`PASS`，`COMPLETED / PARSED / CONFIRMED`。正常任务及其 Windows 独立重读先通过；第二轮重新生成 request/run 身份，重新描述平台和工具并执行 preflight，使用相同范围的操作者批准。

| 字段 | 原始记录核验结果 |
|---|---|
| request / run | `205da416715e484cb83e5fe40072ecdf` / `080a8374f30b46c386e2bf03f81d3bd1` |
| 原始执行记录 SHA-256 | `b438416406c2b7f144d53dd016233742d437bf93435677e2e33e600f0b1334f9` |
| 独立 manifest SHA-256 | `f6653852524496e8c4bb0706220776bd15b1bc0d9a596e0d7417c573ef5d3a37` |
| 冻结 C 源码 / 实际 ELF SHA-256 | `d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c` / `776f8d7664e696e79013c5efeb262fa1ec57f94ad2f7b0484aa86424c47c41cd` |
| 编译步骤 | bwrap 宿主 PID/PGID `515/515`；guard 宿主 PID `517`；namespace 内 compiler PID `3`；内外退出码 `0/0`；`CONFIRMED` |
| Memcheck 步骤 | bwrap 宿主 PID/PGID `523/523`；guard 宿主 PID `525`；namespace 内目标 PID `3`；内外退出码 `0/0`；`CONFIRMED` |
| 原始 XML | `1724` 字节；SHA-256 `3a4bbff35f904b538f033988a533d4416d9dbef5b62d6c85908cdbc6beaf90fe`；XML v4 可解析；`/valgrindoutput/error[1]` 中 1 条 `INVALID_WRITE` |
| 原始 stdout/stderr | 编译与诊断各两份均为 `0` 字节；原件和空文件 SHA-256 均收入清单 |
| 原始文件集合 | `raw/` 共 `22` 个实际文件，合计 `80932` 字节；各项长度和 SHA-256 见 manifest |
| 目录 | `data/outputs/p3d_r1_memcheck/080a8374f30b46c386e2bf03f81d3bd1/`；中文入口 `report.zh-CN.md`；独立控制记录位于 `controller/<run_id>/` |

实际 trace 同样分别测量 Valgrind launcher 和 Memcheck 引擎图像。外层/内层退出码均为 `0`，但 XML 客观出现 `INVALID_WRITE`，因此不能用进程退出码判断内存诊断结果。解析器保留访问类型 `WRITE` 和 XML 节点及实际三个调用栈帧；内存区域、错误地址、访问大小和根因身份仍为 `UNKNOWN` 或 `null`，没有由固定源码知识补造为诊断事实。资源观测为 `ENFORCED`，进程回收和独立 STATUS 均为 `CONFIRMED`，后者独立观察到 `worker_alive=false`、`group_empty=true`、`identity_match=true`。没有超时、截断或采集失败。

固定无害 CPU fixture 的内存错误只用于验证诊断后端的观测能力，不属于任何真实 CVE 的复现，不能升级为 `VERIFIED`。

两轮描述原件分别保存版本查询的 stdout/stderr、退出状态和工具字节身份。首轮报告中可核对的实际工具摘要如下；次轮重新测量，不依赖首轮的缓存值。

| 工具 | 版本观测 | 原始工具文件 SHA-256 |
|---|---|---|
| GCC `/usr/bin/x86_64-linux-gnu-gcc-11` | `11.4.0` | `821af3c74506283c179ca413bb33e6b528805a4dd8a5c09df125e5ad560a9e89` |
| Valgrind `/usr/bin/valgrind` | `3.18.1` | `4652774bd116cb49951ef74115ad4237cad5021b2bd4d80002f09d986ec438b9` |
| 实际 native launcher `/usr/bin/valgrind.bin` | trace 中实际启动 | `53ba9655a8f4409df2abb48407c73d2636c47571a9f1ca289e47675efcf4a3c8` |
| 实际 Memcheck 引擎 `/usr/libexec/valgrind/memcheck-amd64-linux` | trace 中实际启动 | `5f749b3284ba9eeea8f5b01d8a6f4e47cad2c1ee5a4ef08697e407baf12e9547` |
| bubblewrap `/usr/bin/bwrap` | `0.6.1` | `bf6cf3d4456665f5d80c14eb79a76e0ce87b39a0883e614a161658b4ec33492c` |

上述 `--version` 记录只建立工具描述；实际启动由 bwrap 宿主 `/proc` 图像、ready/result、原生 exec-stop trace 与原始 Memcheck XML 分别支持。两轮执行时 WSL cgroup v2 可只读观察，但没有委托任务级限制；不能把每进程 RLIMIT 称为进程树内存总量或 GPU VRAM 限制。

## 6. 独立离线复核接口与命令

以下示例仅重新读取已有文件，不编译或启动 fixture，不探测系统，也不调用模型。`expected_manifest_sha256` 应取自受信控制侧单独保存的摘要，不能通过重新计算一个可疑档案的 manifest 来宣称来源认证。

在仓库根目录的 Windows PowerShell 中，将占位值替换为本轮实际证据目录与独立摘要：

```powershell
@'
from src.memcheck_evidence import read_memcheck_evidence, render_memcheck_report
from src.models.lifecycle import canonical_sha256

evidence = read_memcheck_evidence(
    r"<本轮固定诊断run目录>",
    expected_manifest_sha256="<受信控制侧固定的64位小写SHA-256>",
)
print("解析状态：", evidence.parse_status)
print("执行记录SHA-256：", evidence.record_sha256)
print("重新解析对象SHA-256：", canonical_sha256(evidence))
print(render_memcheck_report(evidence))
'@ | .\.venv\Scripts\python.exe -
```

本轮实际从 Windows `.venv` 调用 `verify-fixed` 检查正常 run，返回码为 `0`；随后用 `read_memcheck_evidence` 按上述两个独立 manifest SHA-256 逐项读取两轮原件。WSL Python 3.10 又从项目目录内的 `data/outputs/p3d_r1_memcheck/<run_id>/` 读取同一批保存字节，两轮均得到 `COMPLETED / PARSED`，观测数量分别为 `0` 和 `1`，结论仍为 `NOT_VERIFIED`。这两次离线读取均不启动编译器、Valgrind 或 fixture。

正常任务的 Windows CLI 复核命令如下；受控异常轮将 run ID 和 manifest SHA-256 换为第 5 节所列值：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks verify-fixed --directory data/outputs/p3d_r1_memcheck/73b72355dff746e19e611679cf406b99 --manifest-sha256 cd16afba82af1f012d7a0e2bc9aec730c28ac920fff44c46597fb59137439278
```

`read_memcheck_evidence` 会重新读取并校验全部原始文件、执行/请求/授权/策略绑定及原始控制文件投影，调用已有 XML 解析器重新解析，再比较保存的解析对象和中文报告。报告不一致、日志被篡改、文件缺失、跨 run 绑定或未知格式均不能报告复核成功。

WSL 端应使用独立 Linux venv 中的 `bin/python`，在对应 Linux 仓库路径导入相同接口，并传入 Linux 可读的证据目录；不得复用 Windows `.venv`。该复核接口与真实 WSL 执行是两个独立检查。

逐字节重建只说明相同原件与规则得到相同结果；独立摘要、可信采集记录和原始文件复查承担额外的身份核验。哈希不提供远程硬件证明或数字签名。

## 7. 验收结论、实际未检查项与后续阻断

本轮 A～F 核心验收已取得真实原件：Windows 发起两轮固定任务；WSL 经 preflight 及实测 gate 启动固定编译器和 Valgrind；原始 XML、stdout/stderr、trace、PID、退出码、资源和回收记录按独立 run 保存；既有 XML v4 解析器正常处理两份真实 XML；中文报告可由 Windows 与 WSL 离线逐字节重建。两个 run 的 `candidate_execution_status=NOT_EXECUTED`，真实 CVE `verification_status=NOT_VERIFIED`。实际原始日志与专门中文报告仅在本机忽略目录保存，不进入 Git 提交。

以下能力或故障场景尚未进行真实联调，不能标为 PASS：

| 项目 | 状态与原因 |
|---|---|
| 固定任务真实超时、取消、磁盘满、工具替换或残留后代 | NOT_CHECKED；离线负例覆盖相应状态与拒绝，但没有故意在本机制造这些破坏或故障 |
| cgroup v2 任务级 CPU/内存总量约束 | UNSUPPORTED；本机没有委托可写的任务 cgroup，实际只实施每进程 `RLIMIT_CPU`/`RLIMIT_AS` 等 |
| 任意不可信 native 程序或 GPU 驱动安全隔离 | UNSUPPORTED；此次隔离验证仅适用于两个冻结 CPU fixture |
| 真实 CVE 输入、LLM 候选、GPU kernel、付费模型 API | NOT_EXECUTED；没有对应执行证据或授权 |
| 真实 CVE 根因、受影响/修复版本差分及生产 Oracle | NOT_CHECKED；固定无害内存错误不能证明任一 CVE |

下一阶段从 Windows 生成候选到 WSL 的链路还缺：合法 CVE/run 与父轮次身份、实际候选源码和输入字节 SHA-256、独占传输后的接收哈希、当前 WSL probe/boot/工具身份、候选专项操作者授权、与风险相符的隔离和资源/回收能力，以及该 CVE 事先定义的客观证据要求。合同见 [固定诊断与候选桥接设计](P3_D_R1_MEMCHECK_CONTRACT.md)。现有 `tests/test_execution_preflight.py` 的 `test_arbitrary_candidate_execution_compile_inspect_unsupported` 保持 `EXECUTE_CANDIDATE → UNSUPPORTED / ACTION_UNSUPPORTED`；本轮新控制器测试同样在传输前拒绝该任务标识。固定 fixture 的授权不能复用到候选。

R1 采集验收时的 Git 基线：本地 `main` HEAD 与 `origin/main` 均为 `a684ae4206ef44b6492463655998d63d3eb9cbfa`。维护者后续授权将已验收工程文件正常提交推送，交付 commit 以 Git 历史为准。两份既有历史草稿保持本地未跟踪状态，历史证据与旧 Oracle 对象未移动或改写。
