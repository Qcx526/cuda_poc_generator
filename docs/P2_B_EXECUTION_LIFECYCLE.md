# P2-B：受控执行生命周期与证据合同

本阶段复用 P2-A 的输入、授权、平台、工具身份、Preflight 和已校验源码桥接。开放范围仅为源码注册表中的无害 Python 测试动作；Single-shot Generation 不自动进入此流程。生成候选始终 `NOT_EXECUTED`，漏洞验证始终 `NOT_VERIFIED`。

## 入口和数据流

```text
操作者 --authorize-fixed-actions + 授权引用 + 固定动作 ID
  → P2-A 只读 DESCRIBE：Windows/WSL 分离、目标快照与 Python 身份
  → ExecutionRequest 1.1 + 独立 OperatorAuthorization / PreflightPolicy
  → 唯一 request/run ID、私有控制能力与 WSL 持久任务目录
  → WSL 注册表 / 当前平台 / 实际解释器 / P2-A Preflight
  → AUTHORIZED → PREFLIGHT_READY → STARTING
  → 独立 session/进程组，固定 guard 应用 CPU/AS 与父死亡信号
  → 私有 READY 通道、实际 /proc 身份和 executable 哈希复核
  → 授权/取消/wall 再检查，GO 放行 → RUNNING
  → 完成、非零、超时、取消、输出限制或其他失败
  → 进程组终止、wait4、subreaper/waitpid、独立 /proc 回收检查
  → 原始 ExecutionRecord + 原始输出 + worker 日志
  → Windows 发起另一个 WSL STATUS，独立确认 worker 消失与组为空
  → EvidenceManifest + 有效结果 + 可离线重建的 Markdown
```

执行接口：

- `lifecycle_cli.run_authorized_action()`：操作者入口，不接受候选源码、shell、argv 或未知二进制。
- `lifecycle_bridge.run_task_wsl(request, authorization, policy, snapshot, tool_record, ...)`：复用 P2-A 五类对象；仅由可信操作者代码调用。
- `on_task_created(handle)`：启动前向可信控制器提供 TaskHandle；同任务 `control_task_wsl(handle, operation="STATUS" / "CANCEL")` 可用于另一线程或操作者进程。control token 是私有的取消/查询能力，不是新执行许可。
- `lifecycle_process.run_registered_action()`：Linux 内部适配器；必须先由 WSL worker 授权并前置检查，不能作为 LLM 工具暴露。
- `lifecycle_artifacts.write_execution_evidence()`、`read_execution_evidence()`、`rebuild_execution_report()`：原始关联校验和确定性报告。

旧请求 schema `1.0` 默认行为保留，要求 `stdout.bin / stderr.bin / tool_result.json`；P2-A worker 只接收 1.0。P2-B 明确使用 `1.1`，要求 `stdout.bin / stderr.bin / process_result.json`，worker 只接收 1.1。两版本都严格校验，禁止跨版本混用产物；没有把新进程观测伪装成旧 ToolResult，也没有改写其 CPU/memory 科学含义。

## 固定动作注册表

`src/registered_actions.py` 使用不可变映射和 frozen entry，源字节固定；对应受控 fixture 必须逐字节匹配。候选路径只是受控输入身份；实际执行取注册常量。改变注册表必须经过正常代码审查和提交，不能由请求或 LLM 修改。

| 动作 ID | 固定行为 | 默认 wall / CPU / 地址空间 / 输出上限 |
|---|---|---|
| `p2b-normal-v1` | 固定打印，退出 0 | 5 秒 / 2 秒 / 256 MiB / 4096 字节 |
| `p2b-nonzero-v1` | 固定打印，退出 7 | 同上 |
| `p2b-timeout-v1` | 固定打印后 sleep 30 秒 | 0.8 秒 / 2 秒 / 256 MiB / 4096 字节 |
| `p2b-output-v1` | 有限的 8 MiB 输出生产器，由 capture cap 提前终止 | 5 秒 / 2 秒 / 256 MiB / 4096 字节 |
| `p2b-child-cleanup-v1` | 同进程组 fork 一个固定 sleep 子进程，主进程也等待 | 0.8 秒 / 2 秒 / 256 MiB / 4096 字节 |
| `p2b-cpu-limit-v1` | 固定整数计算循环 | 5 秒 / 1 秒 / 256 MiB / 4096 字节 |

取消演示使用同一个 timeout 动作，将该次显式授权预算 wall 改为 5 秒。终止程序的正常测试失败状态不是 CLI 成功：CLI 只有有效 `COMPLETED` 返回 0，其他结果返回 1，自动验收应检查结构化预期状态。

操作者明确授权该固定无害取消测试时，可在 Windows 项目根目录执行（引用填写自己的批准记录）：

```powershell
.\.venv\Scripts\python.exe -m src.lifecycle_cli --authorize-fixed-actions --action p2b-timeout-v1 --cancel-after 2 --authorization-reference "your-approval-record" --operator-id "your-operator-id" --linux-project-root "/mnt/f/qcx/code/cuda_poc_generator"
```

通用 `EXECUTE_CANDIDATE`、编译动作、任意 shell/argv、外部源码和额外输入仍拒绝或 `UNSUPPORTED`。未接入 CUDA smoke、CVE Oracle 或自动反馈。

## 状态与观察来源

`src/models/lifecycle.py` 定义严格版本化模型，额外字段、bool 伪装 int、非有限数值、模型对象内部非法修改均被拒绝。事件连续编号、时间有序、开始和终态必须与记录一致。

| 前态 | 主要合法后态 |
|---|---|
| CREATED | AUTHORIZED、REJECTED、UNKNOWN、UNSUPPORTED |
| AUTHORIZED | PREFLIGHT_READY，或拒绝/未知/不支持 |
| PREFLIGHT_READY | STARTING，或启动前取消/失败/拒绝/未知/不支持 |
| STARTING | RUNNING，或启动/门控/超时/资源/捕获/清理失败及未知状态 |
| RUNNING | COMPLETED、NONZERO_EXIT、TIMED_OUT、CANCELLED、RESOURCE_LIMIT、CAPTURE_FAILED、CLEANUP_FAILED、UNKNOWN |
| 任一终态 | 无迁移；保留原始记录 |

精确合法集合以 `validate_transition()` 为准。`STARTING` 指可信 guard 启动阶段；`RUNNING` 代表身份和限制已确认并释放 GO，不保证成功结束。缺失运行中观察时 fixture 状态保留 `UNKNOWN`，不会改写成未启动。

PID、PPID、PGID、session、start ticks、UID/GID、开始/结束时间、实际 executable 哈希、CPU usage、原始 wait 状态均来自 Linux 进程观察。实际 fork 子进程通过私有通知及 `/proc` 交叉检查。授权在 Preflight、Popen 前和 GO 前复查；过期、取消、deadline 或日志失败都不能越过动作门控。

P2-B 操作者入口用已保留 DESCRIBE 的真实 WSL ToolResult `finished_at` 建立五分钟授权窗口，执行端始终按目标时钟检查。Windows 与 WSL 时钟可能略有偏差，不能把 Windows 的“现在”直接当成 Linux 的“现在”；没有放宽 not-before/expiry 比较、猜测时差或修改系统时间。若观察已经过旧或时钟发生异常跳变，任务仍拒绝。

`ExecutionRecord` 保存 request/run/action、完整请求/授权/policy/快照摘要、原 candidate/tool/probe/environment 身份、事件、ProcessObservation、资源与清理、证据引用及科学边界。零退出不是漏洞结论；`COMPLETED` 还要求完整 capture 和已确认本地清理。

## 终止与回收

每个任务使用单独 WSL worker、Linux session/进程组。超时、取消、输出限制、启动或 capture 异常只终止本任务的组，不使用 `wsl --shutdown` 或全局进程清理。

worker 用 `PR_SET_CHILD_SUBREAPER` 收集失去父进程的固定后代；通过 wait4/waitpid 回收，另扫 `/proc` 的 group/session 和已观测后代 PID。僵尸、读取失败、身份冲突或残留进程不能标为清理完成。没有完整进程身份且父进程已回收时，不再向可能复用的 PID/组发送信号。

固定 guard 在动作前设置并读取回查 `PDEATHSIG=SIGKILL`，核对父 PID；fork 子进程重新设置该标志并核对其父 PID。该保护减少 worker 异常死亡后的残留时间，不能替代回收确认。独立 native 回归只杀死自己创建的无害 worker，并另行收集固定主/子进程。

WSL 任务目录绑定 request/run、控制 token 摘要、boot ID、worker native identity、spawn intent 与实际进程身份。STARTING 意图在 Popen 前持久化；若 worker 在 Popen 与身份落盘之间死亡，STATUS 返回 UNKNOWN，不能用“没有记到 PID”推断组为空。request 和 run ID 采用独占创建，历史文件不会被下一次运行覆盖。

Windows 的初始 launcher、CANCEL launcher 和独立 STATUS launcher 分别记录。终止 Windows `wsl.exe` 不证明 Linux 已停止。STATUS 由另一个 WSL observer 核对原 worker、启动身份、UID、boot 和任务组；原记录与独立恢复记录分开保留。worker 仍在运行、通信失败或无法确认组为空时，有效结果为 UNKNOWN；确认残留时为 CLEANUP_FAILED，即使原 worker 记录为 COMPLETED 或 REJECTED。

取消早于 durable lease 时按同一任务有限重试；没有接受取消就不声称 CANCELLED。已知 worker 崩溃但组仍在时保持失败/未知，不对无法归属的进程猜测性发信号。独立记录证明执行完成、但初始通信数据丢失时，可以恢复原精确记录；证据完整性仍为 false。

取消/超时后可能还有已缓冲的 READY 消息。终止开始后只记录该消息，不再读取已退出进程的 executable 或释放 GO，避免将已观察到的取消改判为身份拒绝。启动前取消和运行中取消分开保留实际 `action_started`，不伪称已执行动作。

## 资源合同和边界

- Wall watchdog、stdout+stderr 合计 cap、独立进程组由 parent 实施；请求必须在受支持范围且不超过可信 policy。
- 固定 guard 先设置并回查 CPU 时间和地址空间 soft/hard limits，再通过私有 socketpair 报告，parent 核对实际 `/proc` 身份与 executable 后才放行。资源实施失败不执行动作主体。
- CPU/AS 是每个进程的限制，fork 后代继承；不是整个进程树的聚合 cgroup 配额。`RLIMIT_AS` 不是 GPU VRAM 限额。
- cgroup v2 只读检查 controller 文件和当前 unified membership，记录观察状态；本轮没有验证或创建 delegated subtree，没有使用 cgroup 限制，也未安装服务、修改系统或申请权限。
- CPU 固定动作的 hard-limit SIGKILL 结合 wait4 CPU 使用量及 kernel accounting tick 归类为 RESOURCE_LIMIT，记录明确说明这是边界推断，wait status 本身不单独证明 kernel kill 原因。其他崩溃不借此冒充 CPU 触发或 CVE。
- 未提供完整网络隔离、GPU 驱动安全隔离、不可信程序沙箱、Windows Job 或任意进程树执行器。哈希到路径启动、PID 观测到发信号仍有操作系统竞态；对不完整身份保持未知，不声称密码学或内核级原子证明。

依据：[Linux cgroup v2 文档](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)、[Linux subreaper 文档](https://www.man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)。本合同只将其用于所述固定无害测试，不据此宣称一般隔离能力。

## 原始证据和离线重建

Windows 默认 `data/outputs/execution_lifecycle/<request_id>-<run_id>/`；Linux 原始任务在用户 HOME 的私有 state 目录。Windows 写前应用受保护 DACL，Linux 目录 0700、文件 0600；不使用 Windows venv 调用 Linux CUDA 库。

manifest 至少关联原始 stdout/stderr 的字节长度与 SHA-256、完整 ExecutionRecord、process_result、生命周期事件、请求、授权、policy、平台、绑定工具记录、初始/取消/回收三类原始 transport 与 packet、采集器版本、完整/截断/保护状态和 request/run ID。原生 worker 另保留 lease、preflight、原始输出、追加事件日志和最终记录；控制句柄文件同样私有并被 Git 忽略。

manifest 是最后写入的提交标记，历史目录独占创建。写失败抛 `EvidenceWriteError`，附带实际记录、目标目录和 `INCOMPLETE`，不能返回成功。若连控制面观察也无法保存，则 `LifecycleDispatchError` 保留内存 UNKNOWN 结果与确定性失败报告，仍尝试限定取消和独立 STATUS；不能声称磁盘证据已经存在。

reader 重新验证 schema、逐文件长度/哈希、原始 packet 字节、request/run、规范授权/policy 摘要、工具与平台引用、精确进程/生命周期数据和独立回收。不能通过重新计算某个本地文件 hash 改写原 worker 输入。manifest 是完整性索引，不是防同权限操作者伪造的数字签名。

`rebuild_execution_report(folder)` 从验证后的数据返回同样的 Markdown，不覆盖原报告、不调用 LLM。报告说明任务与授权、平台、实际工具、返回状态、资源/终止/清理、原始文件、截断与缺失、状态依据以及 NOT_VERIFIED。拒绝、异常和未知也有报告。超量输出的 SHA 仅覆盖实际保留前缀，不冒称未采集的完整输出。

合成示例见 [ExecutionRecord](examples/P2_B_EXECUTION_RECORD.json)、[EvidenceManifest](examples/P2_B_EVIDENCE_MANIFEST.json)。它们明确标记 synthetic，不能作为真实执行或验证证据。
