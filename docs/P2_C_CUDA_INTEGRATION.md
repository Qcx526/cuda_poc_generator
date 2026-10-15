# P2-C：固定无害 CUDA 工具链集成合同

基线：`main@e7995bc444e081c7341f889b4c373ee7ee4cfa5a`。本阶段复用 P2-A 授权/Preflight、P1-C 身份/架构/ELF 检查和 P2-B 生命周期/证据/报告。只开放固定 CUDA 源码的编译与检查，不加载编译产物，不启动 GPU kernel，不接收 LLM 候选、任意 argv、flags 或未知 cubin。

## 修改前后与入口

修改前：Windows 操作者授权 → WSL 固定 Python fixture → 资源门控 → 执行/回收 → Windows 保存传回的记录；Linux 原生文件另行保存，尚无跨环境逐文件核验。

修改后保留原流程，另增明确的固定动作：

```text
Windows --authorize-safe-cuda-smoke + 操作者/批准引用
  → 固定 DESCRIBE_CUDA：新鲜 WSL 快照、三个 --version、工具文件哈希
  → request 1.2 / authorization 1.1 / policy 1.1
  → 绑定源码、GPU/nvcc 架构、全部工具、目标身份和 WSL boot 时钟
  → Linux 独占任务/work/out 目录，写入注册源码的精确字节
  → 新鲜目标复查 + 既有 Preflight + 每步授权/身份/资源门控
  → 三个受控版本步骤 → nvcc --cubin → 纯 Python ELF/哈希检查
  → 同一产物哈希 → cuobjdump --dump-elf → nvdisasm --no-dataflow
  → 每一步进程组/后代回收，实际 PID/exec/资源/原始双流
  → Linux 原始文件索引与传输包
  → Windows 独立 STATUS：确认 worker/全部任务组回收，重新读取原始文件
  → Windows 逐字节/身份关联核验 → manifest 最后发布 → Markdown
```

Windows PowerShell，在仓库根目录使用 Windows venv。`<项目的 WSL 路径>` 填实际 `/mnt/...` checkout 路径，批准引用填写自己的真实批准记录：

```powershell
.\.venv\Scripts\python.exe -m src.cuda_smoke --help
.\.venv\Scripts\python.exe -m src.cuda_smoke --authorize-safe-cuda-smoke --backend wsl --authorization-reference "your-approval-record" --operator-id "your-operator-id" --linux-project-root "<项目的 WSL 路径>"
```

可选 `--arch sm_75` 必须与本次描述中由实测 GPU 与 nvcc 支持集合共同确定的架构一致；`sm_75` 不是默认常量。当前自动入口要求唯一可确定的实测 GPU 架构，多架构歧义拒绝。默认 WSL 发行版、用户和解释器与既有配置一致，可通过 `--distro`、`--wsl-user`、`--linux-python` 显式配置。两套 venv 不互用；原 `main.py` 和 Single-shot Generation 参数保持兼容。

没有授权 flag 时，入口在任何 WSL 通信前失败。CLI 仅在有效执行状态 COMPLETED 且 native 文件核验 VERIFIED 时返回 0。其他情况返回非零；打印私有报告目录及证据引用，不打印控制 token。缺少工具、未知版本或通信失败在准备阶段也保存确定性报告，不伪造 ExecutionRecord。

## 固定输入、工具与版本

`src/cuda_registry.py` 注册 `p2c-cuda-smoke-v1`，源码对应 `tests/fixtures/cuda/safe_smoke.cu`：

```cuda
extern "C" __global__ void cuda_poc_safe_smoke() {}
```

完整登记字节还包含用途注释与换行。工作副本必须逐字节一致；没有 main、host launch、CUDA API、内存访问或外部 include。源码写入本任务私有目录；已有目录/源码/输出冲突不覆盖。

固定六步 ID 为 `nvcc_version`、`cuobjdump_version`、`nvdisasm_version`、`compile`、`cuobjdump`、`nvdisasm`。编译 argv 只包含登记选项：`--cubin`、已验证的 `--gpu-architecture`、`--std=c++14`、已测 host compiler、固定 source/output 路径。每个检查只消费本任务成功编译后、再次核对哈希的 `out/safe_smoke.cubin`。

首轮支持范围明确限定为三个工具均能观测到 CUDA 12.8 系列版本。nvcc 路径来自平台探测；cuobjdump/nvdisasm 取同一实际 Toolkit 的固定 sibling；host compiler 来自固定系统搜索路径。不能根据 Toolkit 版本推测检查工具版本或身份。描述阶段的 ToolResult 只记录真实只读查询所实施的 wall/output 限制，不宣称 CPU/AS 已实施；执行阶段另保存六个受控 CudaProcessObservation。

工具身份的说明文字和 requested spelling 与文件身份分开。描述入口先比较解析后的绝对路径和 SHA-256，再保留原始 ToolResult 的完整 provenance；不会因 symlink 拼写差异放弃文件哈希或目标环境校验。

## 受控进程和资源

`lifecycle_process._run_controlled_action()` 是 Python fixture 与 CUDA 适配器共用的 Popen/capture/终止/回收路径。新增 `cuda_process.run_registered_cuda_tool()` 只接受固定 step、受控工具对象和工作目录；argv 由注册表生成。新 guard 在独立 session/进程组中应用并回查 RLIMIT，使用已打开、已哈希的文件描述符 exec。

首个原生 exec-stop 由 Linux ptrace 观察：从 `/proc/<pid>/exe` 的内核 image handle 读取哈希，并核对当前 inode、路径、UID/GID、PGID/session 和 `/proc` 限制，再允许工具指令继续。FORK/VFORK/CLONE/EXEC 的后代受有界跟踪，最多 128 个 tracee、512 个身份事件；实际启动的编译助手必须符合启动前测量的固定 Toolkit/GCC/系统助手允许表。未知 exec、ptrace/EXITKILL 不支持或证据写入失败均不能静默放行。

这不是完整供应链证明；动态加载器/共享库不是完整逐文件允许表。不宣称可管理任意逃逸进程、不可信样本或 GPU 驱动攻击。父死亡保护、EXITKILL、任务进程组终止、wait4/waitpid/subreaper 与独立 `/proc` 检查相互补充。Windows launcher 停止不能替代 Linux 回收证明，禁止全局 WSL shutdown。

| 项目 | 固定 CLI 配置与含义 |
|---|---|
| Wall watchdog | 每个工具步骤 30 秒，最多六步；Windows launcher 另有 300 秒上限 |
| CPU | 每进程 15 秒，后代继承并在 ptrace stop 回查；非整树聚合配额 |
| 地址空间 | 每进程 4 GiB，后代继承并回查；不是 GPU VRAM 限额 |
| 输出 | 每步 stdout+stderr 合计最多保留 128 KiB；超限终止且标截断 |
| 环境 | 原生步骤使用最小显式 env；不继承 NVCC flags、CC/CXX、LD_PRELOAD 或 Python 注入变量 |
| cgroup/网络/GPU 隔离 | cgroup 只读观察，不创建 delegation；不提供完整网络或 GPU 驱动隔离 |

旧 Python fixture 的 256 MiB 默认配置和原有资源上限未放宽。CUDA 的 CudaResourceLimits 单独绑定到 request/auth/policy，不能混入旧版本合同。真实 CPU hard-limit 归因仍注明 wait status 并不唯一证明 kill 原因；普通 nonzero/signal/crash 都不构成 CVE 结论。

## 实测 ELF 兼容性

首次真实 nvcc 编译退出 0，但产物被旧通用校验器以 `Unsupported ELF version` 拒绝，原始文件和 UNKNOWN 记录保留。逐字节检查发现 ELF64LE、EM_CUDA=190、ET_EXEC、OSABI=51、ABI=7、e_version=128；没有把 e_version 改写为 1。

增量支持是显式 `NVCC_12_8_OBSERVED_ELF64` profile，只接受该确切头字段组合；未知版本/ABI 仍拒绝。普通 `validate_elf_structure(data)` 的默认 version=1 规则不变。新 profile 继续检查所有原有 section/table/string/范围规则，并检查 program header payload 的文件范围、filesz/memsz 与对齐；不会通过执行畸形样本证明解析器正确。

此 profile 是本机固定源码、已测 nvcc 12.8 产物的有界兼容支持，不推断 e_version=128 的完整厂商语义，不宣称支持全部 cubin、符号/重定位 payload 或 CUDA ABI。送原生检查工具的资格还必须来自同任务固定源码、成功编译、合法结构和持续匹配的产物 SHA-256；仅伪造这个 ELF tuple 不能获得执行许可。

## 原始证据和报告

Linux native 索引绑定 request/run、目标、请求/授权/policy/快照/record/tool 身份。固定文件集合包含 lease、原输入、preflight、追加事件、最终原始 record、每步原始双流/进程记录、固定源码和编译产物；单文件最多 4 MiB、总计 8 MiB。索引原始字节和每个文件以大小、SHA-256 与 base64 传输，Windows 不从 LLM 或报告摘要重建原文件。

独立 STATUS 根据已保存的原始索引重新读取 Linux 文件。缺失、替换、截断、跨运行或身份冲突不能得到 VERIFIED。执行状态、回收状态、native 核验状态和保存状态分开：远端可以确已 COMPLETED，但 native 为 UNAVAILABLE/FAILED，此时报告不完整且 CLI 返回非零。无法保存时抛带实际观察的 INCOMPLETE 错误；没有 manifest 的部分目录不能作为成功证据集。

Windows 使用独占目录、受保护 DACL，Linux 使用 0700/0600。Windows 文件通过独占保留目标、同目录临时文件、flush/fsync 和原子 replace 发布，manifest 最后发布；Linux native index 另 fsync 目录。Windows 目录 fsync 明确为 UNSUPPORTED，不宣称数据库级事务、数字签名或硬件证明。

Windows 默认路径为被 Git 忽略的 `data/outputs/execution_lifecycle/<request>-<run>/`；native 原件在 WSL 用户 HOME 的私有 state 中。`native_evidence_index.json` 是原始 Linux 索引；`native_steps_<step>_stdout.bin` 等是精确转存的 native 字节。原始 packet、launcher 双流和控制结果也保留。control token 和私有路径不发布。

原报告引擎 `render_execution_report()` 按版本增量展示授权、主机/目标、GPU/Toolkit、工具版本/身份、每步实际命令、退出/signal、PID/PPID/PGID/session/start ticks/UID/GID、资源、回收、raw 文件和哈希。collector `p2c-1.1` 补充 controller 的实际命令、身份和时间；旧 `p2b-1.0` 与首轮 `p2c-1.0` 的报告格式保持读取路径。`rebuild_execution_report(folder)` 离线校验后返回 Markdown，不覆盖历史报告、不调用 LLM。

## 真实时间与版本兼容

本机联调实际观察到 WSL 墙上时钟回拨。新 CUDA 请求把平台时效、授权窗口和生命周期顺序绑定到同一真实 WSL boot ID 与 CLOCK_MONOTONIC：描述端实测起始/结束 ns，操作者授予最多五分钟的目标时钟窗口，执行端实测同一 boot 并严格检查。原始 UTC/timezone 时间戳仍完整保存，发生回拨明确诊断，不改写成有序时间。

本地单调时钟只用于同一 boot 的次序和预算，不拼接 Windows/WSL 硬件时间线，不修改系统时间或使用猜测时差。旧 request 1.0/1.1、authorization/policy 1.0、record/manifest 1.0 保持原有字段、哈希和墙上时钟规则。

参考：[NVIDIA nvcc 12.8](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-compiler-driver-nvcc/index.html#nvcc-environment-variables)、[NVIDIA Binary Utilities 12.8](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-binary-utilities/index.html)、[LLVM CUDA OSABI/ABI 常量](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELF.h)、[Linux ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)、[Linux resource limits](https://man7.org/linux/man-pages/man2/getrlimit.2.html)。关于 e_version=128 的支持依据是本轮保存的真实原始产物，不将公开资料未定义的含义编造成规范。

验收与真实 ID/哈希分别见 [P2-C 验收](P2_C_VALIDATION.md)、[真实联调](P2_C_REAL_INTEGRATION.md)。生成候选始终 NOT_EXECUTED，kernel 始终 NOT_EXECUTED，目标 CVE 始终 NOT_VERIFIED。

严格结构的 [ExecutionRecord 合成示例](examples/P2_C_EXECUTION_RECORD.json) 与 [EvidenceManifest 合成示例](examples/P2_C_EVIDENCE_MANIFEST.json) 明确标记 synthetic，仅说明字段和关联，不能当作原始证据、真实实验或操作者批准。
