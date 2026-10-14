# P1-B 平台合同（schema 1.0）

## 范围与真实数据流

本阶段只运行固定的只读平台查询，不编译源码、不运行 CUDA kernel 或候选 PoC，不调用 LLM。原 Single-shot 分析/生成、RAG、Tavily 和静态检查继续保留。

修改前：七维归一化 → RAG/Web → 当前宿主的旧环境字典（可能含默认架构、历史列表及自动 smoke）→ 严格专家分析 → 候选生成。Windows 探测不能表示 WSL。

修改后：七维归一化与原始哈希 → 可选 RAG/Web → 新鲜平台探测与模型校验 → 严格专家分析 → 目标平台生成视图 → 候选与独立状态。默认 `local`；只有显式 `wsl` 才经 Windows 调度 Linux 查询。平台上下文只进入代码生成，专家仍使用源资料和 RAG。P1-A 输入、分析合同及原始模型文本机制不变。

只读入口独立于生成：

```text
Windows .venv Python
  → 本机隔离只读 worker → Development host 快照
  → wsl.exe --list --quiet → 检查显式发行版
  → wsl.exe --distribution <distro> --user <user> --exec <Linux Python> -I -
    → stdin 发送可信标准库 worker 源码与 JSON 请求
    → Linux 固定工具查询 → JSON 响应
  → nonce/probe_id/后端/结构/内容哈希/原始字节摘要校验
  → 独立私有目录 → 原始记录 + 确定性 Markdown 报告
```

无需 SSH、网络服务或 Windows → Linux 路径转换；不依赖在 WSL 从共享目录导入项目或 Pydantic。Linux Python 路径属于操作者可信配置，不允许 LLM 构造。工具发现依赖当地 PATH/已存在文件，不能证明系统软件未被替换。

## 模块及接口

| 模块 / 接口 | 输入 | 输出与边界 |
|---|---|---|
| `src.models.platform.PlatformSnapshot` | 完整快照 dict | 严格 Pydantic v2；拒绝额外字段、非法状态/值/来源及哈希不一致 |
| `src.platform_identity.compute_environment_id` | 快照映射 | 科学字段规范 JSON 的 SHA-256；不修复、不校验已有快照 |
| `src.platform_worker.probe_platform` | 请求 ID、nonce、后端及界限 | 固定只读查询的 packet；纯标准库，不收任意命令 |
| `src.probe_process.run_bounded` | 内部可信 argv、界限 | 原始双流字节、摘要、时间、退出状态；不是公开执行器 |
| `src.wsl_bridge.probe_wsl` | 可信 distro/user/Linux Python、probe_id、nonce | 本次 WSL 快照或 `None`、诊断、传输与命令证据 |
| `src.platform_probe.run_platform_probe` | 显式 backend 和可选配置 | 保存完整记录，返回 status/snapshot/host_snapshot/transport/run_directory |
| `src.platform_probe.read_snapshot` | 文件及预期 probe_id | 校验存储的原哈希/身份；不重封、不改 ID |
| `src.probe_artifacts.render_report` | 结构化探测结果 | 确定性路径脱敏 Markdown；不使用 LLM |
| `CudaPipeline.run` | 原参数 + 可选 target_backend/wsl_distro | 原生成报告 + platform_status/environment_id/记录引用；失败阻断生成 |

## 字段与认识状态

每个能力字段使用同一种包装；下列只是结构片段，不是本机实测或完整快照：

```json
{
  "cuda_toolkit_version": {
    "status": "OBSERVED",
    "value": "12.8",
    "source_ids": ["nvcc_version"],
    "method": "nvcc --version release"
  },
  "cuda_driver_api_version": {
    "status": "NOT_CHECKED",
    "value": null,
    "source_ids": [],
    "method": "CUDA Driver API not loaded by read-only probe"
  }
}
```

| 状态 | 含义 |
|---|---|
| `OBSERVED` | 当地工具、Python 标准库或文件读取提供；必须有已记录来源 |
| `INFERRED` | 明确推导方法；例如从实际 CC `7.5` 转写 `sm_75`，不是按 GPU 名称猜测 |
| `CONFIGURED` | 操作者设置；例如后端选择，不能当成实测 |
| `UNKNOWN` | 无充分观测；值必须为 null，不能用默认架构/False/0 填充 |
| `NOT_CHECKED` | 本阶段明确没有查询；值必须为 null |
| `FAILED` | 已尝试查询或解析失败；值必须为 null，记录命令/诊断 |

根字段：`schema_version="1.0"`、`platform_type=windows/linux/wsl`、`execution_backend=local/wsl`、`environment_id`、`probe_status=COMPLETE/PARTIAL/FAILED`、`provenance`、`diagnostics`、`metadata`。WSL 分类来自 Linux 内核 Microsoft 标记，其推断方法另外保存在 metadata；不能将分类称为硬件证明。

包装能力字段：`host_os`、`kernel`、`architecture`、`python_version`、`gpu_devices`、`driver_release`、`cuda_driver_api_version`、`driver_reported_cuda_version`、`cuda_toolkit_version`、`nvcc_path/version`、`supported_architectures`、`compute_sanitizer_path/version`、`host_compiler`。

GPU 为逐设备包装列表，包含 index/name/compute_capability/sm_arch；成功返回空列表表示观测数量为 0，工具缺失/失败时整个值为 null。Compute capability 查询不被支持时，仅回退查设备名称/驱动，CC 仍 UNKNOWN。各设备索引唯一，sm 表示必须与 CC 一致且标为 INFERRED。`host_compiler` 为 gcc/g++/msvc 的包装映射。Linux 工具路径必须是 POSIX 绝对路径。

### 四种版本不能混用

- **Driver Release**：`nvidia-smi --query-gpu=driver_version` 的发行号。
- **CUDA Driver API Version**：API 返回的整数；标准 worker 不加载 CUDA 动态库，不初始化上下文，当前 NOT_CHECKED。兼容 helper 仅在明确调用时访问当前 OS 的 `cuDriverGetVersion`，失败返回 None。
- **Driver Reported CUDA Compatibility**：只解析 `nvidia-smi` 的 `CUDA Version:` 字段；不是本地安装 Toolkit。遇到 `CUDA UMD Version:`，另存 literal metadata，当前不解释为最大兼容版本。
- **Toolkit / nvcc**：当地 `nvcc --version` 的 release 与完整 compiler build 分别记录。支持架构仅来自当地 `--list-gpu-code` / `--list-gpu-arch` 成功输出。

预定 API 查询未执行本身不让 worker 失败；所需工具缺失、字段未知、查询/解析失败或预算耗尽会使结果 PARTIAL。完全无法获得有效当前 worker 响应才是调度结果 FAILED（snapshot 为 None）。这些标签只描述平台采集。

## 身份、传输与限制

`environment_id` 哈希包括 schema、平台/后端、OS/kernel/architecture/Python、GPU 及状态、四类标准版本、架构列表和 host compiler。列表架构排序；不包括运行时间、nonce、probe_id、诊断、方法、来源 ID、工具路径及全部 metadata。UMD literal metadata 当前不属于规范科学字段。它是内容完整性身份，不是可信硬件证明，也不是机器唯一 ID。

每次新 probe 生成独立 ID/nonce。packet 必须有精确 envelope，UTF-8 JSON，不允许重复键/非有限数值；必须匹配后端与 ID/nonce，校验快照原有哈希、命令双流摘要、环境标签、时间/输出界限与来源引用。旧快照不会被修补后当本次结果。读取历史快照需要显式提供它自身的预期 probe_id；当前生成流程不支持自动复用历史快照。

界限：外层每个 local/WSL worker 默认 45 秒、总 stdout+stderr 1 MiB，发行版查询最多 10 秒；worker 各工具默认 3 秒、32 KiB，总启动查询预算最多 40 秒。Windows host 和 WSL target 顺序采集，**45 秒不是整个双环境操作的总耗时上限**；杀进程与收尾还有有限等待。达到输出界限只保留明确标注截断的字节，不解析截断 JSON。

外层 launcher 返回码与通过响应校验后的 `worker_reported_exit_code` 分开记录。Linux 单条工具原始返回码在 commands 中。超时杀死本机 launcher 不保证远端进程树已终止；worker 同时有内部界限。P2 必须另外实现后端进程组/作业生命周期及资源限制，不能把当前桥接称为完整隔离执行器。

允许动作仅为 Python/platform、`/etc/os-release` 读取、nvidia-smi 只读查询、nvcc version/架构查询、sanitizer version、gcc/g++ version、无源文件输入的 cl banner 查询。无 shell 拼接、编译、smoke、kernel、PoC、UUID 查询或网络请求。

## 证据与访问控制

```text
data/outputs/platform_probes/<probe_id>/
  platform_snapshot.json  # 失败为 null，绝不放旧快照
  host_snapshot.json      # 当有有效 development host 时
  commands.json           # argv、环境、UTC、界限、状态/返回码、双流 base64/hash
  probe_stdout.log        # 外层 target launcher 的原始捕获字节
  probe_stderr.log
  probe_result.json       # 调度结果、诊断、两种退出码、ACL、原始产物摘要
  probe_report.md         # 确定性人类摘要，路径仅保留 basename
```

嵌套工具和 host launcher 原始双流在 commands.json，不把它们重写成模型解释。清单对快照、命令、原始双流文件记录 SHA-256；不自哈希清单/报告。标准库/文件观测的具体值在快照中，`/etc/os-release` 原始字节另外保留。完整 argv、路径和原始日志均为私有产物。

新目录在任何日志写入前先应用权限：Windows 受保护 DACL（当前进程用户和 SYSTEM，子文件继承），POSIX 目录 0700/文件 0600。无法应用访问控制会失败；它不等于加密，也不防当前用户、系统管理者或同身份程序访问。默认目录全部 Git ignored，自定义输出根由操作者负责避免纳入 Git。

报告标明 development host 和 selected target，含每字段状态/方法/来源，不输出 GPU UUID，也不输出原始命令/完整绝对路径。公开分享仍需复核环境版本和设备型号是否适合公开。可提交的 [报告示例](examples/P1_B_PROBE_REPORT.md) 全部使用离线合成 fixture。

## 集成及兼容性

保留旧 CLI；`--target-backend local` 指当前 Python 宿主（Windows Python 是 Windows，WSL Python 是 Linux），默认同此。`--target-backend wsl --wsl-distro Ubuntu-22.04` 显式选择 WSL。生成流程配置使用 platform.wsl_distro/wsl_user/wsl_python/timeout_seconds/max_output_bytes；不从配置隐式选择 WSL。

`probe_environment()` 现返回 PlatformSnapshot dict，旧直接读取 gpu/toolchain 的外部调用需要迁移到包装字段。本仓库主流程已迁移。无 schema 的旧 Mock/外部环境字典仅能以 NOT_CHECKED 进入 Prompt，不提升为 OBSERVED。`get_gpu_compute_capability()`、`get_cuda_driver_version()` 未知返回 None；调用方必须显式处理，不能再依赖 sm 默认值或 0。旧 MSVC/ELF/compile helper 保留，私有 `_run_nvcc_smoke` 历史函数不在任何当前探测入口中调用。

生成视图复制源资料、合格分析及 RAG/Web 文本，对 Linux 目标屏蔽其中 Windows drive / UNC 路径；保留其余分析文字。源输入、原始哈希、raw 模型响应和已保存合格分析完全不变。这个视图不是跨平台路径翻译器，也不证明模型会遵守 Prompt；候选仍须后续审查。平台失败会产生 CONTEXT_ERROR 并阻止专家与代码生成请求，无旧/本机替代。

候选状态始终独立：GENERATED、STATIC_VALID/STATIC_INVALID、NOT_EXECUTED、NOT_VERIFIED。PARTIAL 平台可用于研究候选生成，UNKNOWN/FAILED/NOT_CHECKED 必须原样表达；不会升级为执行前置条件已满足。

## 下一阶段接口建议

P1-C：为 compile/inspect helper 定义 `ToolResult(argv,cwd,returncode,stdout_bytes,stderr_bytes,timeout,truncated)`，保留兼容适配层；修复 ELF header 类型/索引与尺寸检查；所有错误码只能表示工具事件。先用固定合法 fixture 和合成进程离线回归，真实编译另行授权。

P2：新建显式 `ExecutionRequest(candidate_sha256,environment_id,probe_id,backend,authorized_action,resource_limits)`，与只读 ProbeRequest 分离。Executor 不接受 LLM 命令，使用允许的工具与模板，绑定新鲜平台/候选身份；Linux worker 维护 PID/进程组、cwd、运行身份、超时/输出限制及原始 EvidenceManifest。执行记录与静态/验证状态分离，oracle 等 P3 再接入。本阶段交付后停止，等待审查。
