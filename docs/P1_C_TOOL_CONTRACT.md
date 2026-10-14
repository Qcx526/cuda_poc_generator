# P1-C 底层工具合同（schema 1.0）

## 1. 范围与调用关系

底层工具提供明确进程结果、保守编译接口和 ELF 结构检查，不提供候选自动执行、授权引擎或漏洞 Oracle。生成主流程不会调用编译、检查器或 `run_tool`。

```text
输入归一化 → 平台只读前置检查 → 模型初始化 → RAG/Web → 严格专家分析 → 候选生成

操作者显式调用工具（与生成流程分离）
  → 架构/参数/路径或 ELF 输入检查
  → 固定 nvcc / cuobjdump / nvdisasm argv
  → 当前 OS run_tool → ToolResult → 私有原始文件 + evidence_manifest
  → 单独的编译产物/结构检查；不升级为执行或漏洞验证
```

P1-B 仍使用独立标准库 worker 和允许的只读查询；没有把其 request 或 CLI 改成任意命令执行接口。平台失败先停止，LLM 客户端、embedding 下载、RAG 和 Web 检索均不初始化。输入/分析/raw 文本合同及候选四组独立状态不变。

## 2. ToolResult

`src/models/tool_result.py` 的严格 Pydantic v2 模型是内部工具进程合同。原始字节使用 base64 保存，并提供 `stdout_bytes()` / `stderr_bytes()`。解码为文本仅用于 legacy 视图，不替换原字节。

| 字段组 | 内容 |
|---|---|
| 实例与完整性 | schema_version、run_id、record_id |
| 调用 | 实际 argv、绝对 cwd、target_environment、platform_type |
| 状态 | start_status、end_status、returncode、linux_signal、windows_exception_code |
| 捕获 | timed_out、truncated、capture_failed、原始双流 base64 和 SHA-256 |
| 时间/界限 | UTC started_at/finished_at、monotonic duration_seconds、resource_limits |
| 输入 | 可选 stdin_sha256 / stdin_size_bytes；不保存环境变量映射 |
| 来源 | command_identity.source/argv_sha256、tool_identity 的请求名/实际路径/测量文件哈希/状态/来源 |
| 证据边界 | diagnostics、evidence_directory、NOT_EXECUTED / NOT_VERIFIED |

| end_status | 判据 |
|---|---|
| NORMAL_EXIT | 已启动、退出码 0、没有超时/截断/捕获失败 |
| NONZERO_EXIT | 普通非零退出；没有其他优先结果 |
| TIMED_OUT | 时间界限达到；返回码仍记录实际终止结果 |
| START_FAILED | 没有成功启动进程，returncode 为 null |
| SIGNAL_TERMINATED | Linux/WSL 的负进程返回码，对应 signal 编号 |
| WINDOWS_EXCEPTION | Windows 返回值匹配明确列举的异常/status 码 |
| OUTPUT_LIMIT | 总输出界限达到，truncated 为 true |
| CAPTURE_FAILED | 管道/回收失败，或启动后无法取得返回码 |

优先级：启动失败 → 超时 → 输出限制 → 捕获失败 → signal / 已识别 Windows 码 → 普通退出。独立保留捕获失败和截断标志：TIMED_OUT 同时 capture_failed=true 时，不能宣称日志完整。模型重算返回码、signal/异常码与状态关系，拒绝矛盾组合或错误 OS 终止范围。

Linux 负数语义依据 [Python 3.12 subprocess 文档](https://docs.python.org/3.12/library/subprocess.html)。Windows 普通高位退出码不自动解释为异常；仅识别模型中的有限代码集。`is_access_violation` 仅识别 Windows `0xC0000005` 或其有符号表示，参见 [Microsoft NTSTATUS 定义](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)。应用也能主动返回这些数值，匹配码不证明 OS 实际抛出异常，更不证明 CVE。

完整的 [JSON 示例](examples/P1_C_TOOL_RESULT.json) 是明确标注的合成离线 fixture，外层 `example_kind` 不属于 ToolResult；验证内层 `tool_result`。示例不是实验原始证据。

`seal_tool_result` 只封装新观测，规范合法默认值及浮点表示后计算身份；读取旧记录只做验证，不能重新计算身份来掩盖损坏。record_id 覆盖所有标准结果字段（除自身及 evidence_directory）；run_id/时间参与身份。argv_sha256 单独覆盖实际参数序列。普通本地哈希不证明软件来源可信，工具文件在启动前测量并使用该解析路径启动；不防测量后的文件替换。

## 3. 当前 OS 进程适配器与证据

`src/tools/process.py::run_tool` 是可信内部调用的 argv 适配器，不是公开执行 CLI、WSL 调度器或 LLM 工具。它只运行当前 OS，拒绝外部平台标签和外来 cwd。`shell=False`，不拼接 shell；实际 argv[0] 使用已解析工具路径，请求名称仍保存在身份字段。工具发现失败时，内部 `_startup_error` 记录 START_FAILED 而不调用 Popen，也不猜测或尝试固定 fallback 路径；此时 argv 是未执行的计划参数，原始双流为空、工具身份 UNKNOWN。

时间最多 300 秒，聚合 stdout+stderr 最多 16 MiB；默认 30 秒 / 1 MiB，编译默认 120 秒。到限只保留明确标注的字节前缀，哈希覆盖保留字节。启动及收尾调用可能有额外有限等待；CPU/内存额度为 null / NOT_ENFORCED。POSIX 使用独立 session/process group 并终止该组；Windows 目前只终止直接子进程，不能称为进程树隔离。

默认记录：Windows `data/outputs/tool_runs/<run_id>/`（Git ignored）；Linux `~/.local/state/cuda-poc-generator/tool_runs/<run_id>/`（原生 HOME 文件系统）。显式 artifact_root 可覆盖，但必须通过权限检查。

```text
<run_id>/
  stdout.bin
  stderr.bin
  tool_result.json
  evidence_manifest.json
```

在启动前创建唯一受保护目录：Windows protected DACL 当前用户/SYSTEM；Linux 实际验证 0700/0600。chmod 返回成功不足以证明权限落实，DrvFS 不支持时明确拒绝。P1-B Linux 默认探测目录同步改为原生 HOME 的 platform_probes，Windows 桥接目录不变。默认用户 Conda/Windows venv 不被用作 Linux Python。

manifest 记录三份原始产物的字节长度/文件 SHA、run_id/record_id、权限状态、capture_complete；不自哈希 manifest。`read_tool_evidence` 使用有限读、固定文件名单、拒绝 symlink/重复 JSON 键/非有限数值，验证文件哈希、模型身份、双流逐字节一致、捕获状态及可选预期 run/record ID。权限控制不等于加密或硬件证明。

保存失败使用 `ToolEvidenceError`：启动前权限失败不运行工具；运行后写盘失败保留 `.tool_result` 中的实际捕获字节及尝试目录，显式失败，不声称文件已成功持久化。读 manifest 时缺少/损坏任何记录均拒绝。公开文档不包含实际 argv、设备标识或私有原始日志。

## 4. 编译接口与迁移

| 接口 | 返回 |
|---|---|
| compile_cubin_result(source, output, arch=None, …) | CompileResult：ToolResult + 独立 artifact_status/路径/诊断 |
| compile_cubin(同上) | 保留成功的输出路径；失败 CompileError.result 保留结构化结果 |
| compile_kernel_source(source_text, arch=None, …) | 保留成功的 `(cubin_path, source_path)`，位于每次独立 task 目录 |
| prepare_msvc_environment(env=None) | 验证操作者已经准备的环境；不运行 batch，不编译 |

`arch` 现在默认 None：没有合格平台信息就必须明确给出，例如 `arch="sm_75"` 是操作者配置，不是通用实测值。提供 snapshot 时要求严格模型、当前平台一致、唯一实测 CC 派生架构（未显式 arch 时）、架构在 OBSERVED nvcc 支持集合内，且实际选中的 nvcc 等于该快照 OBSERVED nvcc_path。不同 GPU 架构需要显式选择；没有自动跨 OS 或 WSL 编译。

extra_flags 支持旧简单字符串或 token 列表，但只接受保守集合：debug/lineinfo、-O0..3、C++11/14/17/20、maxrregcount 0..255 等。具体集合见 validate_compile_flags；不转发 -Xcompiler、响应文件、任意输出路径、外部编译器、shell 片段或任意 -I/-D。语法允许的标志也可能被实际 Toolkit 拒绝；以原始 nvcc 状态为准。[NVIDIA nvcc 12.8 文档](https://docs.nvidia.com/cuda/archive/12.8.1/cuda-compiler-driver-nvcc/index.html)用于核对选项，不作为本机编译 PASS 证据。

Windows 先使用 [Visual Studio developer terminal](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170) 准备 MSVC，再调用项目 `.venv` Python。prepare/旧 setup_msvc_env 仅验证 cl 可发现、INCLUDE/LIB 及明确请求的 VCToolsVersion，不能证明所有 SDK 文件或 CUDA/MSVC 组合兼容；实际 nvcc 编译会单独记录失败。旧自动 vcvarsall/编译 shell 链移除。

输出先构建到唯一同文件系统临时目录，正常退出后做有界 ELF64LE + EM_CUDA=190 结构检查，再使用排他 hard link 发布。已有输出默认拒绝；显式 overwrite=True 才原子替换。文件系统不支持 hard link 时返回 ARTIFACT_PUBLICATION_FAILED，不偷偷覆盖。

产物状态单独区分 NOT_COMPILED、INVALID_COMPILER_OUTPUT、ARTIFACT_PUBLICATION_FAILED、COMPILED_ELF_CUDA。最后一项只表示正常工具退出及有限结构检查，并不证明真实 CUDA 指令有效或可运行。

成功返回的源码不再删除；调用者负责清理 task 目录。失败只删除本次新建且解析路径确认属于预期父目录的临时目录，原用户输入/既存输出不删。清理异常不能覆盖原始编译失败；以 CLEANUP_FAILED 诊断或异常属性保留。原始 ToolResult 记录独立存放。迁移时停止依赖旧固定 `_kernel.cu` 名称或已经删除的源码路径。

## 5. ELF 字段和边界

依据 [System V gABI Elf64_Shdr](https://www.sco.com/developers/gabi/latest/ch4.sheader.html)，标准格式 `<IIQQQQIIQQ`，总 64 字节：

| 索引 / 字段 | 偏移 | 宽度 |
|---|---:|---:|
| 0 sh_name | 0 | 32 bit |
| 1 sh_type | 4 | 32 bit |
| 2 sh_flags | 8 | 64 bit |
| 3 sh_addr | 16 | 64 bit |
| 4 sh_offset | 24 | 64 bit |
| 5 sh_size | 32 | 64 bit |
| 6 sh_link | 40 | 32 bit |
| 7 sh_info | 44 | 32 bit |
| 8 sh_addralign | 48 | 64 bit |
| 9 sh_entsize | 56 | 64 bit |

仅支持 ELF64 little-endian、普通编号。ELF32、大端、sectionless/扩展编号均明确拒绝。校验 header/表范围与尺寸、全部 section（没有只查前100个的遗漏）、索引、文件内容范围、重叠、对齐、字符串表及名称，按规定检查 link/info 的索引语义。名称扫描/解码明确最多4096字节，超过限制的合法变体也拒绝，不声称所有 ELF 都受支持；避免重复巨大字符串形成无界扫描或输出。NOBITS 只有概念大小/偏移，不要求文件中存在对应字节；NVIDIA 自定义 section type 保持不透明，不猜测修复。

所有输入先验证。append/replace 校验结果并保留源数据，拒绝不支持的变体；patch_section_field 则允许研究人员显式产生结构无效的候选字节，但校验源文件、索引、值范围和精确宽度，绝不跨字段。patch 后必须重新调用 validate_elf_structure，不能把改写成功称为 ELF 合法或漏洞成功。低层 _patch_shdr 只允许完整已知字段的 offset/width 对；sh_link/sh_info 需要 width=4。

结构检查不涵盖所有 symbol/relocation payload、程序段加载语义或 CUDA 指令语义。native CUDA 检查器仅接受通过这组有限前置检查及默认 64 MiB 大小上限的 EM_CUDA ELF；这不是对 native parser 安全性的完整保证，不得自动拿它执行畸形研究样本。

## 6. 检查器兼容视图

cuobjdump_result / nvdisasm_result 返回完整 ToolResult。cuobjdump_elf 保留 raw/sections/symbols，增加 ok/error/tool_result；输入拒绝时没有启动进程，tool_result 为 None，不编造退出码。nvdisasm_run 保留 `(ok, stdout_text, stderr_text, rc)`，ok 只在正常退出0时为真；legacy -1 可能代表无真实返回码，新调用必须读取 ToolResult。

stderr 非空不是失败判据；非零、超时、输出限制或捕获失败不能返回 True。nvdisasm_has_relocation_sections 通过有界 ELF 读取检查 SHT_REL/SHT_RELA，绝不使用输出字符串 `REL` 宣布触发。工具结果、结构事实与目标 CVE 判定完全独立。

## 7. P2 绑定与建议接口

本阶段新增纯接口 CandidateToolBinding / bind_candidate_to_tool：计算候选原始 bytes SHA，重新校验 PlatformSnapshot 和 ToolResult，检查独立提供的预期 probe/record ID、相同平台和环境标签，以及 OBSERVED 工具文件身份。返回 candidate SHA、platform environment ID/probe ID、tool record/run ID、工具文件/argv SHA 和实际路径。**不会执行候选，也不授予授权**；绑定工具版本记录不表示该工具已经处理候选。P2 必须在执行时重新读取/哈希输入和工具，并检查快照时效。

P2 建议按三个独立合同推进（以下是设计，不是已实现执行器）：

- ExecutionRequest：request_id、CandidateToolBinding、受控 action=COMPILE/RUN/SANITIZE、操作者授权引用、后端与资源 policy、工具注册角色、预期原始产物集合。不得接收 LLM argv 或任意 shell。
- ExecutionRecord：request/run ID、请求身份、实际阶段、源/工具执行时哈希、PlatformSnapshot 引用、ToolResult 列表、运行用户/PID/进程组/cwd、开始/结束时间、明确资源实施状态及证据写入状态。失败阶段分为前置检查/启动/工具/产物/证据保存。
- EvidenceManifest：schema、request/run/candidate/environment/probe/tool IDs，原始 artifact 路径/类型/长度/SHA、采集器版本、capture completeness、存储保护及记录身份。确定性报告只引用原始产物；目标 Oracle 留待 P3。

P2 单独实现 Linux worker 生命周期、Windows Job/远端进程组清理、CPU/内存/GPU 限制与隔离；不得把当前有限工具适配器称为漏洞执行引擎。编译成功不等于可运行，运行成功/崩溃/Sanitizer 事件都不等于目标 CVE 已验证。P1-C 交付后停止，等待独立审查。
