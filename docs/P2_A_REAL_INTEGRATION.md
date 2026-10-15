# P2-A Windows→WSL 固定无害联调报告

日期：2026-10-15（Asia/Shanghai）。本报告核对真实工具原始记录；不涉及 CUDA 编译、候选 PoC、畸形 native 输入或漏洞验证。

## 范围和授权

授权来源为本轮操作者 P2-A 任务四，仅允许固定无害探测/测试 fixture。入口显式使用 `--authorize-fixed-fixture`；授权引用为 `user:P2-A:task-4:fixed-fixture`，操作者记录为 `session-user`。授权仅覆盖固定注册表 `p2-fixed-print-v1`，不是未来候选执行许可。

Windows Python 3.12 `.venv` 调用固定 WSL transport，选择 `Ubuntu-22.04`、`pocdev` 及独立 Linux Python 3.10 venv。Linux checkout 路径是显式配置；未共用 Windows venv。先只读探测，再做真实 `CandidateToolBinding`，执行前再次独立观察平台与工具身份。

## 实际结果

| 项目 | 真实记录 |
|---|---|
| 最终结果 | PASS：`FIXTURE_COMPLETED`，Preflight `READY` |
| 请求 ID | `0dbb1691ba4b4651ac1dde65ab604c29` |
| DESCRIBE 证据目录 ID | `29c8e5fac5a24e87ad8ffee9a48099f0` |
| FIXED_FIXTURE 证据目录 ID | `463a6d5433994443a161c519acb95aec` |
| 实际目标标签 | `wsl:Ubuntu-22.04`，快照/工具/请求一致 |
| 原 probe ID | `4cb970868c1b493094abd49983258c35` |
| 执行前新 probe ID | `59cf0093a11344be99a2b875bf998dd4`，保留原请求身份并独立复查 |
| scientific environment ID | `sha256:63756e5cce96ff268cb28a963077a000ba7192c25b88265f7b59d5e0da535eeb` |
| Windows transport | `NORMAL_EXIT` / return code `0` |
| WSL fixture | `NORMAL_EXIT` / return code `0`；无截断、无 capture failure；stderr 为零字节 |
| fixture 资源 | wall 10 秒；CPU 2 秒；地址空间 268435456 字节；stdout+stderr 上限 4096 字节；POSIX 进程组 |
| 实际限制确认 | 原始 stdout 中 request ID、nonce、CPU/AS 数值与期望完全一致；固定子进程设置并读取回查 rlimits 后才输出 |
| 候选/CVE 状态 | `NOT_EXECUTED` / `NOT_VERIFIED` |

原始 stdout 是固定无害程序实际输出。此报告只摘录身份及校验摘要，不把报告文本或模型分析当作原始证据。

## 摘要核对

| 对象 | SHA-256 / record ID |
|---|---|
| manifest.json | `97bfb26b46bf9b7fea47fe9195ad2e600cb0399a47ca058a9e367e46a6b89431` |
| 完整请求 | `ab3bc20ae7e87343669c674ca3949542460942c07d98d1ca7c96de1210ce3c8e` |
| 原操作者授权 | `5036c79a1631df52826c51a3323154c94dd2917285d2f73c15c946caea19ddce` |
| 原 policy | `ff2541c48a31fb57cf8ae09022b20e920d928a5da57ec30aa41a8410add70673` |
| fixture 源字节 | `073421764478f91a48c867d5f18f176339a5f0d6b1305ac37f0889bba2d3760a` |
| 目标 Python 文件 | `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae` |
| 原始目标 stdout | `c233af8b24475f1507eff1f39d530e34848963fdd80ef32e04b324f6cec55046` |
| 原始目标 stderr | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| transport ToolResult | `sha256:a1ad7306f732e807fca97c4dfd35ee387935e294eaf0b6b93426ba519cae739e` |
| 目标 ToolResult | `sha256:69cee238086ae989ead48ed44b68197023715c412e48d8b3f3c500e9f64b821d` |

Windows 已通过 `read_execution_evidence(..., expected_request_id=...)` 核对 manifest、原 transport、worker packet、独立请求、原授权/policy、目标输出和确定性 Markdown。另从 WSL 原生文件系统通过 `read_tool_evidence(..., expected_record_id=...)` 核对原目标记录，以及当前 probe 的原始产物哈希；均 PASS。

原始 Windows 证据位于本地被忽略的 `data/outputs/execution_preflight/`，目标原始工具/probe 证据位于 Linux HOME 下的私有 state 目录。Windows DACL、Linux 0700/0600 在写入时落实；日志、绝对路径和私有配置未加入本提交。

## 实际遇到的失败与限制

首次接线中，Windows policy 的资源能力仍为 `UNKNOWN`，真实请求 `36605bbbc1194fe8855d138b40400d4b` 返回 `UNKNOWN / RESOURCE_SUPPORT_UNKNOWN`，没有启动 fixture。调试证据目录 ID 为 `c271b74c9cbc494cbb010b1d33b35a30`。随后补上 DESCRIBE 的 WSL 实测资源能力记录，再由执行 worker 复核 hard limits，最终上述请求通过。早期调试记录使用演进中的 packet 格式，不作为最终 schema 的 PASS 样本。

一次后续 WSL 证据核对命令出现 systemd 用户 session 启动警告，命令随后退出 0 且原始哈希校验通过。本阶段没有修改 systemd、网络、驱动或 CUDA 安装；该警告不被当作 fixture 执行失败或 CVE 证据。

没有进行：真实 CUDA compile/解析 smoke、GPU kernel、生成候选、真实 CVE、付费 API、真实 RAG/Web 请求、Oracle 或反馈迭代。资源证明仅适用于固定可信 fixture，不证明任意候选隔离。实际 UID/GID、完整依赖环境的独立证明和 Windows Job/通用远端清理尚未建立；WSL 用户目前由固定 launcher 的 `--user` 选择并记录，未声称独立身份认证。
