# P2-B：真实 Windows→WSL 无害生命周期联调

日期：2026-10-15（Asia/Shanghai）。授权来源为本轮 P2-B 任务，只覆盖固定、已审核的无害程序与失败前置检查；操作者记录为 `session-user`，授权引用 `user:P2-B:fixed-harmless-actions`。没有 CUDA、候选 PoC、真实 CVE、畸形 native 输入或付费模型调用。

Windows Python 3.12 `.venv` 发起固定桥接，WSL Ubuntu-22.04 / `pocdev` / 独立 Python 3.10 venv 执行。每例生成新的 request/run、授权、policy、平台/工具绑定和私有证据目录；目标身份没有由 Windows 信息替代。

## 最终真实场景

| 场景 | 有效状态 | Linux 退出码 | 独立回收 | 输出证据 |
|---|---|---:|---|---|
| `p2b-normal-v1` | COMPLETED | 0 | CONFIRMED | 完整 |
| `p2b-nonzero-v1` | NONZERO_EXIT | 7 | CONFIRMED | 完整 |
| `p2b-timeout-v1` | TIMED_OUT | -9 | CONFIRMED | 完整 |
| `p2b-output-v1` | RESOURCE_LIMIT | -9 | CONFIRMED | 不完整：输出已截断 |
| `p2b-child-cleanup-v1` | TIMED_OUT | -9 | CONFIRMED | 完整 |
| `p2b-cpu-limit-v1` | RESOURCE_LIMIT | -9 | CONFIRMED | 完整 |
| timeout 动作，2 秒后取消 | CANCELLED | -9 | CONFIRMED | 完整 |
| 缺少 OperatorAuthorization | REJECTED | 未启动动作 | CONFIRMED（worker 已退出） | 完整的拒绝记录 |

正常、非零、CPU、超量输出和取消默认 wall 为 5 秒；timeout/child-cleanup 为 0.8 秒。CPU 动作为每进程 1 秒，其余每进程 2 秒；地址空间 268435456 字节，stdout+stderr 上限 4096 字节。所有真正放行的动作都在 READY/GO 前核对实际限制、父死亡保护、PID/PGID/session/start ticks/UID/GID 与 `/proc` executable 哈希。

child-cleanup 实际观察到固定 fork 后代，并经 subreaper/waitpid 回收，最终 group/session/descendant 检查均无残留。取消例明确观察到 `action_started=true` 后收到绑定取消并终止。未授权例没有启动任何 guard 或动作，只保留前置检查与控制面日志。CPU 状态按固定程序、hard-limit 设置、SIGKILL 与 wait4 CPU 边界推断；日志说明 wait status 不能单独证明 kernel kill 原因。

这些是正确处理预期失败的验收 PASS，不把 nonzero、timeout、资源事件或取消称为程序正常完成，也不升级为漏洞验证。

## 原始证据定位和摘要

原始 Windows 证据在本地被忽略的 `data/outputs/execution_lifecycle/<request>-<run>/`；对应 Linux 任务、lease、追加事件、preflight 与原始输出在 HOME 的私有 state 目录。control token、绝对路径、实际 UID/PID 和原始私有日志未纳入 Git。

| 场景 | request ID | run ID |
|---|---|---|
| normal | `ade4dec87f894d90ba130c7b92be5266` | `b34c16aca790473581a167900c5d63ec` |
| nonzero | `a966579661fd40f5a3e2b5a8a5f91d1b` | `de0666b3c8e84eacbbb3acfc2aa73d84` |
| timeout | `b845d8d60ca54670af3b26cffdfc9f59` | `c7c581ca4cbf4c70a0f27eedcaa85bce` |
| output | `e0a32d44d1c0439797574b4d425823a6` | `53ea994f65dd49b19ecccd2793596921` |
| child cleanup | `0ddc4492c1154111bae0b5c58da0a527` | `cc88f475fe404f1199353ae4bf5d23d2` |
| CPU | `0e33d7b89844459182ab6a228637501d` | `eae7df2af294417b9d2d552c7c2a47cf` |
| cancellation | `20dde5e8ee314406a35f0d3451950b87` | `5517dc968fad4f6cb34775669d0cad0b` |
| missing authorization | `72881ae27c1a4578823f610fb1510936` | `fee25482e17e412e8eda3ed200b92c21` |

| 场景 | manifest.json SHA-256 |
|---|---|
| normal | `fff124495a5d6d36a96653c96a50f6c17678ded86105c55667e69156a173bf49` |
| nonzero | `198b77a562ff349bd0332a59012ee9bc39469efd2fae570c19556f2c4f3288b0` |
| timeout | `a36d4e0424ab24d083b600006bb0a0d85a68f46ab38f138965308cfcb1ec8cf9` |
| output | `7e41cbc9b05f2b2ac17a85742ba7d3c08339a51f1d935d4eefcb08e6968ab0b8` |
| child cleanup | `4540f1d6ddf4ed5b07955d25ed40053704d7c2f503f434dd348f79b25c0db388` |
| CPU | `9335bed621af3358a863bdb5ec8e1e3846d7a22d5e632642e3044db80302dadf` |
| cancellation | `635ba887b5822ae5d2cc29e8a3f9593a8910608786987dfbf4c3815aea1d9b88` |
| missing authorization | `94597b1d2d1a52126c4a96a2aff846cc9935c7f959b55c57aa95b3278ef001e4` |

各例实际 Python 文件 SHA-256 为 `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae`。normal 原始 stdout SHA-256 为 `e92e8dfe5ad14678c86a6b7ac5131edd026da2dcf17c89f5d20cf446e2a4bcf1`；output 保留前缀 SHA-256 为 `a2e659dacb4691e887ac0139f8893d04764ee197d70fb73d3190d56113d18e3e`，不能表示未保留的 8 MiB 总输出。其余逐文件字节长度、哈希和输入/授权/平台关联在各自 manifest 中。

八例均经 `read_execution_evidence()` 独立期望 request/run 回读校验，`rebuild_execution_report()` 与原 Markdown 逐字节一致。原始记录没有被总结或 LLM 替换；公共文档只列经过核对的脱敏摘要。

## 实际失败、诊断与修正

- 开发中第一次矩阵在源码并发变更时，被可信源哈希检查阻断。原 DESCRIBE 证据 ID `df4d0d6497ab4649a4b4df697c530917`，launcher 非零，原 stderr 为源码身份不符；未启动动作。之后冻结源码再联调，没有取消校验。
- 一次 CPU 用例 request `5960b5472ade4ba8bff1b1e271b58e1d` / run `b8fea88a9f95471ab29fb622deddcd87` 返回 `REJECTED / AUTHORIZATION_EXPIRED`。原记录表明当时 WSL 时钟稍落后 Windows，实际属于授权尚未生效。修正操作者入口的授权时间基准为真实 WSL 描述记录结束时间，继续严格检查期限；没有修改系统时间、放宽 Preflight 或扩大五分钟窗口。补验 CPU 已通过。
- 一次早取消 request `a792363f564a42c99316b04214276ed2` / run `67032b62b0034adb981821893c21f068`，guard 被取消后仍处理缓冲 READY，读取已退出的 `/proc/<pid>/exe` 导致 `REJECTED`。原记录 `action_started=false`、cleanup CONFIRMED；没有执行动作主体。修复为终止开始后只记录缓冲消息，并新增真实 Linux 负例，验证取消不能改判为身份拒绝、不能释放 GO。最终运行中取消例通过。

失败记录全部保留为失败或拒绝，没有修改旧文件、删除失败数据或把它们算为最终预期执行的 PASS。为聚焦剩余问题，仅补验失败和未完成场景；已通过场景保留各自原始 ID。

## 未检查与能力边界

cgroup v2 只有只读能力观察，本轮不使用 cgroup 限制、不验证 delegation；CPU/AS 是每进程约束，非整树聚合或 GPU VRAM。网络隔离、GPU 驱动隔离、不可信样本沙箱、CUDA compile/解析 smoke、真实 CVE 与 Oracle 均未实施或 NOT_CHECKED。WSL 原生回归另验证了固定 worker 死亡后的父死亡信号和后代回收；它只覆盖自身测试进程，不代表任意远端程序均可管理。

所有场景漏洞结论固定 `NOT_VERIFIED`，生成候选固定 `NOT_EXECUTED`。manifest 是本地完整性索引，不是签名或远程硬件证明。
