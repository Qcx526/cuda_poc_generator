# P2-A：受控请求、前置检查和身份绑定

本阶段在 P1-C 上增量开发，生成算法、Prompt、RAG/Web 可选接口和原有 CLI 不变。仅开放一个固定无害 Python fixture 的 Windows→WSL 联调入口；不提供任意候选执行、CUDA 执行器、漏洞 Oracle 或反馈迭代。

## 真实处理流程

```text
操作者显式授权固定 fixture
  → Windows 测量 wsl.exe，固定 argv / --exec / 独立 Linux Python
  → 校验 Windows 与 Linux 项目源码字节一致
  → WSL 只读 DESCRIBE：新平台快照 + Python 文件身份/版本 + 资源能力
  → CandidateToolBinding：固定 fixture 字节 / 平台 / 工具记录
  → 操作者入口建立短期 ExecutionRequest + OperatorAuthorization + 独立 policy
  → WSL 重新探测当前平台，核对实际解释器和固定注册表
  → Preflight：授权 / 时间 / 范围 / 字节哈希 / 工具绑定 / 资源条件
  → READY 才能启动固定常量源码；子进程先应用 CPU/AS 限制
  → 原始 ToolResult + 资源证明原文 + 身份摘要
  → Windows 再次校验响应并保存私有证据、manifest、确定性 Markdown
```

Single-shot Generation 仍止于候选源码和静态检查；不会自动调用上述入口。生成候选一律 `NOT_EXECUTED`，漏洞状态一律 `NOT_VERIFIED`。

## 请求与授权

`src/models/execution.py` 使用 strict Pydantic、禁止额外字段、拒绝非有限数值，模型对象也重新按 Python 原始类型校验，避免序列化把非法 bool 转成 int。

| 模型 | 必要内容与含义 |
|---|---|
| `ExecutionRequest` | `request_schema_version`、request ID、候选 SHA-256、environment/probe ID、backend、action、授权引用、tool role/文件身份、`CandidateToolBinding`、资源限制、固定产物、候选路径/cwd/输入范围、fixture ID |
| `OperatorAuthorization` | 操作者/可信策略发行类型、操作者 ID、授权引用、完全相同的 request/候选/环境/probe/action/tool/limits/fixture，以及生效和过期时间 |
| `PreflightPolicy` | 独立可信调用者提供的目标环境/probe、完整快照 SHA-256、操作者与授权引用允许列表、工作范围、工具文件允许列表、固定 fixture 哈希、最大时效与资源预算、目标资源能力记录 |
| `PreflightResult` | `READY / REJECTED / UNKNOWN / UNSUPPORTED`、诊断码、检查时间、实测候选/工具 SHA-256，固定 `NOT_EXECUTED / NOT_VERIFIED` |

严格请求示例见 [合成示例](examples/P2_A_EXECUTION_REQUEST.json)。示例是离线 fixture，不是授权文件或真实实验记录。`request_sha256()` 覆盖完整规范请求；`snapshot_sha256()` 覆盖完整快照，包括时间和 metadata，弥补 scientific environment ID 有意排除运行信息的边界。

授权引用本身不授予权限。LLM 不参与授权、policy 构造或命令分派。`issuer_kind="llm"` 被拒绝。Python 库调用者必须是受信任的操作者入口，不能把模型生成的 policy 或授权 JSON 直接传入。授权记录不是数字签名，无法防止拥有同等本机权限的调用者伪造身份；生产部署仍需独立的访问控制和审批来源。

`src/fixture_smoke.py` 只接受操作者显式 `--authorize-fixed-fixture`，同时必须给出授权引用、操作者 ID 和可信 Linux checkout 路径。未给授权 flag 时，连 DESCRIBE 都不会启动。该入口没有候选、shell、argv、提权或任意源码参数；grant 有效期为五分钟，默认完整快照最大年龄为 300 秒。

## 身份和前置条件

- WSL 标签统一为 `wsl:<WSL_DISTRO_NAME>`，核对实际 WSL 内核、实际发行版环境、Windows 选择的发行版、快照 provenance 和 ToolResult。缺失或冲突时拒绝；不删除环境比对。该环境变量是本地启动信息，不是硬件远程证明。
- 原 `CandidateToolBinding` 严格核对 environment/probe/tool record/run/argv/file hash。真实联调使用新的 WSL 版本查询记录完成绑定，而不是仅验证合成对象。
- `preflight_execution()` 在目标侧读取实际文件，不把 Windows 进程当成 WSL 文件系统观察者。候选和 cwd 必须位于可信范围，拒绝路径穿越、符号链接、缺失/非普通文件和额外输入。
- 重新读取源码字节、重新测量工具文件。P2 必须同时满足独立允许列表中的实际路径与 SHA-256。fixture role 必须对应当前 worker 的实际 Python 解释器。
- 拒绝过期/异常未来快照；完整快照摘要还阻止只修改 `started_at` 来刷新旧记录。当前独立重探测的 scientific ID 必须匹配原目标，原 probe ID 不被替换为新 ID。
- `COMPILE / INSPECT / EXECUTE_CANDIDATE` 都返回 `UNSUPPORTED`。模型允许表达这些动作以便清楚拒绝，未实现其分派。
- Windows 引导只使用固定 `wsl.exe --distribution ... --user ... --exec <linux-python> -I -`。项目路径必须显式指定。先核对全部 `src/**/*.py` 与固定 fixture，再由内存中的已校验字节加载 `src` 模块；不读取未校验 `.pyc`。第三方依赖和系统 Python 属于受信任的独立 Linux 环境。

## 资源边界

fixture 默认 wall 10 秒、CPU 2 秒、地址空间 256 MiB、stdout+stderr 合计 4096 字节，以及独立 POSIX 进程组。请求类型允许的最大值仍受独立 policy 进一步约束。

DESCRIBE 从 WSL 只读检查资源 API；执行前再次核对请求与当前 CPU/AS hard limits。UNKNOWN、缺少机制、超出 policy 或已知不可应用的限制都不启动 fixture。固定子进程在无害主体输出前调用 `setrlimit` 并读取回查；只有原始 stdout 中包含完全匹配 request/nonce/CPU/AS 的固定 JSON，加上正常退出且无截断/捕获错误，才标为 `FIXTURE_COMPLETED`。

`RLIMIT_AS` 是虚拟地址空间限制，不是 GPU 内存配额，也不是容器隔离。控制面的 Python/WSL 启动与只读平台查询不受子进程 CPU/AS 限制；它们另有超时和输出上限。ToolResult 中 CPU/memory 的 `NOT_ENFORCED` 仍准确描述通用 runner；fixture 子进程的实际限制单列 `resource_support/resource_proof`，不改写旧合同含义。

Windows launcher 的终止范围仍只有直接子进程；WSL worker 自己负责有界查询、固定 fixture watchdog、输出上限和 POSIX 进程组清理。杀掉 Windows launcher 不能证明任意远端进程已终止。本阶段不声称提供 Windows Job、任意进程树沙箱、网络隔离、GPU 配额或高风险样本隔离。

资源 API 依据：[Python 3.10 resource 文档](https://docs.python.org/3.10/library/resource.html)；系统分别安装 Python 的依据：[Microsoft WSL 开发环境](https://learn.microsoft.com/en-us/windows/wsl/setup/environment)。

## P1-C 工具修正

`measure_tool_identity()` 只读测量；`run_tool(..., allowed_tool_identities={absolute_path: sha256})` 使用同一个测量合同。缺失、读取失败、允许列表不符或启动前再次测量发生变化，都保存 `START_FAILED`，不会调用 Popen。Windows 的 fstat/stat 创建时间可能不同，因此对照文件身份、长度和 mtime；POSIX 同时对照 ctime。

旧工具适配器继续要求可测量的工具身份；P2 额外强制独立允许列表。源码哈希与按路径启动之间仍存在普通文件系统竞态；这不是操作系统级原子可执行文件证明，也不防御已控制宿主/同权限解释器或安装依赖的攻击者。固定 fixture 的主体直接取已审核常量，不从检查后的可变候选文件执行。

## 原始证据

`src/execution_artifacts.py` 默认 Windows 存入被忽略的 `data/outputs/execution_preflight/<id>`，Linux 使用本机 HOME 下的私有 state 目录。Windows 先应用当前进程用户/SYSTEM 的保护 DACL；Linux 要求原生文件系统目录 0700、文件 0600，不能落实则失败。

保留 transport stdout/stderr 原始二进制、完整 transport ToolResult、原始 worker packet、目标 stdout/stderr、目标 ToolResult、请求、原授权和 policy、manifest 和确定性 Markdown。原始平台查询与工具日志分别保存在 Linux 私有 probe/tool 目录，通过记录 ID 和路径引用。日志不加入 Git。

worker packet 绑定规范 request/auth/policy 的独立 SHA-256。writer/reader 核对原 transport 字节、nonce、request、目标、工具 argv/cwd/stdin 哈希、限额、资源证明、原授权/policy 摘要和逐文件长度/哈希。成功 transport 不允许省略 worker packet；错误或截断不伪造成功。reader 还核对确定性 Markdown，不从 LLM 生成实验结论。

manifest 是本地完整性检查，不是不可伪造签名。保留的历史证据按其当时 schema/代码阅读；合同升级前的调试记录不能冒充最终验收记录。

## 后续边界

P2 后续才考虑人工审核的候选编译/运行请求、隔离配置、进程生命周期和执行证据记录。P3 才引入按目标条件判断的 Oracle。正常退出、通信成功、编译成功、崩溃或 sanitizer 报告均不自动等于 CVE 验证成功。
