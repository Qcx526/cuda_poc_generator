# P2-C：真实 Windows→WSL CUDA 编译与检查

日期：2026-10-15（Asia/Shanghai）。本轮任务明确授权固定无害 CUDA 编译/检查；批准引用为 `user:P2-C:fixed-safe-cuda-smoke`，操作者记录 `session-user`。没有执行 LLM 候选、真实 CVE、畸形 native 输入、GPU kernel 或付费模型请求。

Windows CPython 3.12.13 `.venv` 发起正式 CLI；WSL Ubuntu-22.04 / 独立 CPython 3.10.12 venv 执行。新鲜 GPU 查询为 GTX 1660、Compute Capability 7.5；`sm_75` 由实测能力及实际 nvcc 支持集合共同确定。没有使用 Windows Toolkit 代替 Linux 工具。

## 最终真实运行

| 身份/结果 | 实际值 |
|---|---|
| 固定动作 | `p2c-cuda-smoke-v1` |
| request ID | `504e97f69d5a400ab399ee8c6585a7be` |
| run ID | `ea2ac1f7897f4c1ba8c497dab09e6946` |
| WSL 平台内容身份 | `sha256:63756e5cce96ff268cb28a963077a000ba7192c25b88265f7b59d5e0da535eeb` |
| 探测 ID | `ca7e6b8f4c5e4798b2f659192b46ace4` |
| 远端/有效执行状态 | COMPLETED / COMPLETED |
| 独立 worker 与全部任务组回收 | CONFIRMED |
| Linux 原始文件核验 | VERIFIED：31 个文件、358092 字节 |
| collector | `p2c-1.1` |
| 候选/kernel/CVE | NOT_EXECUTED / NOT_EXECUTED / NOT_VERIFIED |

| 实际步骤 | 退出码 | stdout 字节 | stderr 字节 | 回收 |
|---|---:|---:|---:|---|
| nvcc --version | 0 | 208 | 0 | CONFIRMED |
| cuobjdump --version | 0 | 216 | 0 | CONFIRMED |
| nvdisasm --version | 0 | 209 | 0 | CONFIRMED |
| nvcc 固定源码编译 | 0 | 0 | 0 | CONFIRMED |
| cuobjdump --dump-elf | 0 | 5504 | 0 | CONFIRMED |
| nvdisasm --no-dataflow | 0 | 4632 | 0 | CONFIRMED |

实际版本分别为 nvcc `12.8.93`、cuobjdump `12.8.90`、nvdisasm `12.8.90`，而非根据 Toolkit 名称推测。工具的真实路径、原始版本文本、哈希和 argv 位于私有记录；公共文档不披露主机私有目录、UID/PID 或 control token。

| 工具 | 实际文件 SHA-256 |
|---|---|
| nvcc | `59e4e55f9a38b78c590df1e28a69dad91052958f18a03868ca4a547c043fbba7` |
| cuobjdump | `9d515ac6f60c246ef63fe87b0a95d209b00ff3e25b716f8f263520010760e8f8` |
| nvdisasm | `250ebe97dd86617574a30daf8d8ee433e6c5d9d10bafff922078779d1ba36073` |

六步都实际观察到原生 exec。编译步骤记录 10 次 exec 与 9 次 fork/vfork/clone 派生事件，包含编译助手；每次相关停止均核对身份、所属组/session 与 CPU/AS 约束，并保留原始事件，最终无残留。这里的数量是该次过程观测，不是性能 benchmark。

每个步骤实际使用 30 秒 wall watchdog、每进程 15 秒 CPU、每进程 4 GiB 地址空间、128 KiB 合计输出 cap。CPU/AS 不代表整树聚合或 VRAM 限额。三个版本查询的准备阶段 ToolResult 与受控执行阶段的 CudaProcessObservation 分别保留。

## 产物与原始证据

固定源码 SHA-256：`50e0b1c170424527056a2343443be06475e500dd19ef6186e4d3aaca1a8c5931`。

实际 cubin 为 2600 字节，SHA-256 `c8ef06222a4d880227780038da67a2c5834e8ed65222f2fdd1a818b6b5cd2c56`；ELF64LE、EM_CUDA=190、ET_EXEC、12 个 section、固定 kernel text 为 128 字节。原始头字段 OSABI=51、ABI=7、e_version=128，以显式 `NVCC_12_8_OBSERVED_ELF64` 支持集校验；没有改写字节。

| 证据 | SHA-256 |
|---|---|
| Windows manifest.json | `d7e3d701873566666aa0b8f7adba8259af3612bede1eaaa6ba1527d8eda2b58c` |
| Linux 原始 native index | `cc2d3d2e80df037415366350eccfd9bddf135fe11cac1dec246e6d9825e2db1d` |
| 规范化 ExecutionRecord | `c94d2218f529937264b3f6aac9549bbee222194f5c83d57c4db5030f907e323e` |
| 确定性 report.md | `bd5a65d7df629013e16b5ac2aebe0870bb32fed10dd98e431cbb7e5fc253e995` |
| cuobjdump 原始 stdout | `81e047f7a6ff0a413985192f138ff8897d574ad35858304dc327cfe0d8822929` |
| nvdisasm 原始 stdout | `15b66161f30743317eaec8087f065cd027abe114d5ffa2ca43b7d88ac4826d91` |

编译双流均为空，SHA-256 为 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`；空输出不代表缺失文件，原始零字节文件、退出状态和产物单独验证。

本地 Windows 证据位置为被 Git 忽略的 `data/outputs/execution_lifecycle/504e97f69d5a400ab399ee8c6585a7be-ea2ac1f7897f4c1ba8c497dab09e6946/`，其中：

- `report.md`：实际自动生成的私有报告。
- `native_evidence_index.json`：Linux 原始索引字节，未重新构造。
- `native_execution_record.json`、`native_lease.json`、`native_worker_events.jsonl`：Linux 原生记录。
- `native_steps_compile_process_result.json` 及各 step 的 stdout/stderr：真实进程与原始输出。
- `native_work_safe_smoke.cu`、`native_work_out_safe_smoke.cubin`：同任务源码与产物。
- `worker_packet.json`、`recovery_packet.json` 与 launcher 原始双流：首次传输及独立回读。

对应 WSL 原件位于该操作者 HOME 的私有 lifecycle_tasks/run 目录；其实际绝对路径留在私有证据中。Windows 与 Linux 的索引、原文件、输入/授权/policy/平台/工具和 request/run 均已精确关联。独立 STATUS 重新读取 Linux 原始文件与原索引，Windows 再验证传输前后大小与哈希。离线 `read_execution_evidence()` 通过，`rebuild_execution_report()` 与实际 report.md 字节相同。

真实报告依次展示任务/授权、controller/目标、实际进程和生命周期、原始证据表、跨环境复核、GPU/Toolkit、六步实际命令/身份/退出/限制/回收及科学边界。其结论摘录为：

```text
Remote recorded status: COMPLETED
Effective status after independent cleanup check: COMPLETED
Independent cleanup confirmation: CONFIRMED
Native original-file verification: VERIFIED
Candidate execution: NOT_EXECUTED. Vulnerability verification: NOT_VERIFIED.
```

Windows 文件 fsync 与同目录原子发布已执行；目录 fsync 为 UNSUPPORTED，未冒称完整目录持久化或事务保证。Linux 原索引执行文件/目录 fsync。

## 实际失败与保留的历史

1. 准备阶段证据目录 ID `48c9c3bbca8442c58281fa03dc57bfca` 返回 UNKNOWN。版本查询正常，但初测 ToolIdentity 与原 ToolResult 的 requested spelling/provenance 不完全相同。修复为先严格比较实际解析路径和文件哈希，再保留原始 ToolResult 身份；没有删掉目标或哈希校验，也未启动编译。
2. request `3868c272ffb94b77abc49086235a527b` / run `8ac63e756f4545d8b1491051b4414419` 返回 UNKNOWN。真实 WSL 时间在准备/启动期间回拨，授权门控与旧有序墙上时间模型不能建立成功记录。原始 STATUS 确认 worker/任务组已回收；缺少完整执行记录仍保持 UNKNOWN。修复采用同一 WSL boot 的真实 monotonic 观测，不调整系统时间或猜测 Windows 时差。
3. request `42174d0374fe46be8daaca9e3c33fd36` / run `2615a1472ded4045964a1ea8c2ed0ec0`：nvcc 实际成功，ELF 被旧 version=1 子集拒绝，状态 UNKNOWN；尚未把产物交给两个原生检查工具。原始产物保留，分析后增加显式 CUDA profile，通用规则不变。该 UNKNOWN 记录、原始字节、native 索引与旧报告仍可核验重建。
4. request `4b30263820734687b9e4c1c397bf67fd` / run `b9785b7a1b2e456d9ba3eb1f743cdf48` 完成首轮六步联调，collector 为 `p2c-1.0`。之后报告增补 controller 详情，最终使用新的 run 和 `p2c-1.1`，没有覆盖旧记录；旧成功报告仍可离线重建。

最早内部 P2-C 开发失败的输入不符合最终 boot-clock 合同，不能重新作为最终执行请求使用；其原始 JSON、双流与原 manifest 的逐文件哈希已独立回读核验。没有把失败文件修改为最终 PASS，也未删除或覆盖失败证据。

## 能力边界

本次 PASS 只证明这份固定源码在该次实际环境的编译、有限结构校验、工具检查、回收和证据关联。不是生成 PoC 的执行结果，不证明 CUDA 运行、完整 ABI、GPU 隔离或 CVE 触发。未启动 kernel、未调用 Compute Sanitizer、未测试任意其他 Toolkit/驱动/GPU、未运行真实 CUDA 超时/恶意样本。工具链失败测试主要采用 Mock，另有实际无害 GNU 进程的超时/非零/输出/回收回归；二者不替代此处真实 CUDA 联调。
