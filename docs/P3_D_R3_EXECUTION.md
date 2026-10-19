# P3-D-R3 固定文件执行与候选只读预检合同

报告语言：`zh-CN`。本合同描述固定无害联调的身份、授权和证据边界；每次实际执行的结果以 [P3-D-R3 验收记录](P3_D_R3_VALIDATION.md)及其独立固定的原始证据摘要为准。

## 1. 本轮对象与状态

| 路径 | 输入 | 准入范围 | 科学结论 |
|---|---|---|---|
| 接收文件执行 | Windows 传输的 `p2b-normal-v1` 精确冻结源码 | 仅限注册表中的固定无害 Python 字节、独立授权及资源门禁 | 可核验接收的落盘文件是否真正作为本轮执行的代码来源 |
| 主机解析器诊断 | 原计划使用本轮固定安全 cubin 与侧载工具 | 自动安全审查阻断了相关子任务；未建立经本轮验收的执行入口 | `BLOCKED / NOT_CHECKED`，无本轮目标 Memcheck 观察 |
| 归档候选预检 | 已归档的指定 CVE/generation run | 只读身份、静态状态、平台及工具核对 | 生成候选不因此取得执行许可 |

旧版 `EXECUTE_CANDIDATE` 拒绝语义保持不变。固定无害 Python 的授权不能扩展到任意 LLM 代码、CVE 输入或 GPU kernel。真实漏洞 `VERIFIED` 必须由独立审查的专项 Oracle 和合格客观证据决定；正常退出、crash 或普通 Memcheck 错误均不足以证明指定 CVE。

## 2. Windows 接收与 WSL 执行绑定

R2 的传输和注册动作执行是两项独立任务，后者没有读取刚接收的文件。本轮的固定动作使用以下链路：

```text
Windows 固定源码原始字节
  → WSL 独占保存 candidate.py 与 transfer_receipt.json
  → Windows 根据远端实测描述建立新的 request / operator authorization / policy
  → WSL preflight 重读 receipt、文件属性与 SHA-256
  → 固定执行适配器保持源文件描述符打开
  → 子进程从同一描述符重读、校验并编译原始字节
  → 子进程向父进程发送 STAGED_SOURCE_READY 身份证明
  → 父进程核对 /proc/<pid>/fd、限制和进程身份后放行
  → 真实 stdout/stderr、退出状态及回收记录
  → Windows 独立重读、校验并渲染中文报告
```

接收目录由远端用户固定的私有根和唯一 `transfer_id` 决定；调用方不能指定任意源码路径。读取逐级拒绝符号链接，检查目录 `0700`、文件 `0600`、常规文件、单一硬链接、属主及字节长度。请求绑定 receipt 原始 SHA-256、源文件 SHA-256、接收端环境、文件 `device/inode`、属主、模式、大小及时间戳。放行前重新测量；任一身份变化、摘要冲突或目标环境冲突都不能继续。

实际子进程的代码字节来自接收文件的受保护文件描述符。固定 bootstrap 只负责资源和字节身份核验，不从注册表另取一份脚本代替。`STAGED_SOURCE_READY` 是控制通道事件，不是普通 stdout 文本；父进程需要同时检查进程 PID、nonce、request/run ID 及 `/proc` 中描述符的对象身份。固定 stdout 只能作为进程观察的补充，不能单独证明文件来源。

| 对象 | 必须绑定的字段 | 独立核对位置 |
|---|---|---|
| Windows 传输 | `transfer_id`、`request_id`、原始源码和 receipt SHA-256 | 本地传输原件与 WSL 接收回执 |
| WSL 落盘源码 | `source_path`、`device/inode`、`uid/gid`、模式、硬链接数、长度、时间戳与 SHA-256 | 执行前受保护文件描述符、子进程控制通道和 `/proc/<pid>/fd` |
| 执行授权 | request/run ID、动作、接收回执、源码、平台、工具、有效期与资源限制 | 独立的 `request.json`、`authorization.json`、`policy.json` 和 WSL preflight |
| 进程与结果 | PID/PGID、工具身份、放行事件、退出状态、原始流、回收状态 | 执行记录、原始证据和独立 `STATUS` |

原始证据按本次 `run_id` 存在被 Git 忽略的 `data/outputs/p3d_r3_staged_fixture/<run_id>/`。`source.bin` 与 `transfer_receipt.json` 是本轮固定传输的 Windows 副本；`request.json`、`authorization.json`、`policy.json` 和 `description.json` 固定执行准入；`raw/` 保存执行端返回的原始文件；`execute.json`、`status.json` 区分启动观察与独立回收观察；`evidence_manifest.json` 索引文件大小和哈希；`report.zh-CN.md` 从结构化结果确定性渲染。私有控制句柄保留在本地，不纳入 Git。不存在的原始日志不填充占位字节。

新的动作使用专属、版本化请求、授权、策略和执行记录；旧 P2 生命周期对象及历史证据不原地改写。授权由操作者在可信控制侧提供，绑定精确动作、request/run、收据及源文件、目标环境和工具身份，并限制有效期。WSL 执行端重新检查授权、目标平台 boot 与探测时效、工具文件身份和资源能力。若任一关键前置条件不满足，返回明确的 `REJECTED`、`UNKNOWN` 或 `UNSUPPORTED`，不启动固定源码。

既有生命周期管理负责独立进程组、wall-clock、`RLIMIT_CPU`、`RLIMIT_AS`、输出上限、取消与后代回收。实施结果须来自执行端观察。CPU/地址空间限制为进程级限制；未提供 GPU VRAM 限额或任务级 cgroup 配额。Windows launcher 返回与 Linux worker、目标子进程、进程组回收是不同观察，不能互相替代。

本动作的独立执行记录可以描述固定测试文件的真实运行；历史生成候选字段仍为 `NOT_EXECUTED`，CVE 验证字段仍为 `NOT_VERIFIED`。这些字段描述不同对象，不应因固定 fixture 成功而合并。

Windows 主控入口仅接受固定模式；以下命令需要已存在、明确覆盖该无害动作的操作者批准记录。项目的 WSL 路径按实际位置填写：

```powershell
.\.venv\Scripts\python.exe -m src.cve_lab execute `
  --mode fixed-staged-normal `
  --authorize-fixed-fixture `
  --operator-id "<操作者标识>" `
  --authorization-reference "<固定无害动作批准记录>" `
  --linux-project-root "/mnt/f/qcx/code/cuda_poc_generator"

.\.venv\Scripts\python.exe -m src.cve_lab evaluate --archive "<本轮执行返回的证据目录>"
```

`execute` 没有候选路径、CVE 触发输入或自由命令参数；`evaluate` 离线读取已保存证据，不重新启动 WSL 程序。当前命令适用范围以实际 CLI 帮助、测试和本轮联调记录核对。

`execute` 返回的 `status` 描述本次固定动作，例如 `COMPLETED`、`REJECTED`、`UNKNOWN` 或 `CLEANUP_FAILED`；`fixed_source_execution_status` 只描述固定文件是否经过执行放行。`candidate_execution_status=NOT_EXECUTED` 和 `verification_status=NOT_VERIFIED` 始终描述尚未运行的模型候选与指定漏洞。`evaluate` 返回的 `integrity_status=VERIFIED` 仅说明保存的证据和中文报告可按当前合同离线核验，绝不是 CVE 的 `VERIFIED`。

## 3. 本轮未完成的目标解析器诊断

R2 已分别观测过固定 CUDA 工具链 smoke 和固定 CPU fixture 的 Memcheck。它们不是“本轮生成输入 → 指定 cuobjdump → Memcheck”这条新链路。本轮原计划将真实 P2-C 安全编译产物、精确侧载 `cuobjdump 12.8.55-1`、受控诊断与原始 XML 绑定，但自动安全审查拒绝了该诊断子任务，理由为可能的网络安全风险。没有继续实现其正式入口，也没有运行这一目标诊断；结果记录为 `BLOCKED / NOT_CHECKED`。

既有侧载工具身份和历史原始证据继续按 R2 文档解释；本轮不会从旧 smoke、普通 Valgrind 版本查询或未验收的代码草稿生成新目标进程证据。若将来单独审查此路径，必须重新确认输入源 run、文件格式、目标二进制身份、独立授权、资源和隔离能力，以及 XML 与进程记录的一致性。

## 4. 离线归档候选准入及剩余门禁

`src.cve_lab preflight` 读取 `data/outputs/<CVE>/runs/<generation_run_id>/` 中该轮的生成记录、清单和 `poc/cuda_poc_v1.py`，验证 CVE/run、状态、原始 SHA-256 与 WSL 目标身份。它不回退读取平铺 `v1` 文件，也不调用模型。已有生成轮次若没有保存可加载的真实候选源码，也必须报告缺失；不能用 Mock、旧平铺文件或固定 fixture 代替。

任意真实模型候选的通用传输与执行、未知 Python/native 程序、真实 CVE 触发输入和 GPU kernel 均不在上述固定动作合同内。进入这些实验还需要逐个提交具体候选及输入 SHA-256、实际用途、目标版本/二进制、资源和隔离边界，经过独立风险审查与明确授权。当前固定 Memcheck 和 CUDA smoke 的成功不能授予这些对象执行资格。

本轮不改历史 P2/P3 证据、七维输入、生成 Prompt 或 Oracle 判定对象。正式中文报告从结构化记录和原始字节确定性渲染，原始日志保持原样；私有证据仅留在被 Git 忽略的本地目录，不进入提交。
