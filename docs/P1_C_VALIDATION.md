# P1-C 验收记录

日期：2026-10-14。开始时本地 main、HEAD、origin/main 及 fetch 后远端均为 `9c42a8413c74bd73da451475d3b019c3872fa59d`，工作区干净。直接 main 开发，不创建功能分支/PR，不修改历史或标签。

## A. 修改前后行为

| 基线问题 / 源码位置 | 修改后 |
|---|---|
| tools/compile.py：命令字符串 + shell=True，默认 sm_75 | 固定 argv、架构显式或合格 snapshot、保守参数白名单 |
| compile.py：vcvarsall 与真正编译混为一个命令 | Windows 仅验证操作者已准备的 MSVC 环境；nvcc 单独 ToolResult |
| compile_kernel_source：返回已删除路径、work_dir 固定文件名 | 每次独立 task 目录，成功返回两个实际保留文件；失败仅清理本次目录 |
| 编译只查 ELF magic、截取错误文本 | 有界 ELF64LE/EM_CUDA 结构检查、独立 artifact_status、完整原始双流与状态 |
| elf_ops.py：sh_flags/sh_addr 写32位，sh_link/sh_info 写64位 | 10字段独立精确偏移/宽度与 uint 范围，邻接保护 |
| ELF 缺少 class/endian/表索引/range 检查，仅验证前100个 section | 不支持的变体拒绝；全部 section、字符串表、索引、文件范围与重叠检查 |
| inspect.py：nvdisasm 非零返回 True、cuobjdump timeout 未捕获、REL 字符串启发式 | ToolResult 统一退出/超时/捕获语义；实际 sh_type；native inspector 前先拒绝非法结构 |
| is_access_violation：把部分其他异常及大负数当 AV | 仅 Windows 精确 AV 状态；Linux signal、普通非零及其他状态独立 |
| pipeline：模型初始化/RAG/Web 先于平台检查 | 输入通过后先平台检查，失败不构建模型/embedding、不联网检索 |
| WSL DrvFS：chmod 成功可能仍为0777 | 验证实际权限，Linux 默认私有记录移至原生 HOME；Windows DACL 保留 |

领域库仅更新了 Prompt 中 nvcc_compile 的默认架构签名；其余 CUDA 知识/辅助能力保留。核心专家和代码生成 SYSTEM Prompt 原样保留，未重构生成算法。

## B. ToolResult 与接口

模型、状态优先级、编译/检查 legacy 适配、原始证据读写、示例和 P2 设计见 [P1_C_TOOL_CONTRACT.md](P1_C_TOOL_CONTRACT.md)。完整 [JSON 示例](examples/P1_C_TOOL_RESULT.json) 为合成离线 fixture，不是实验结果。

新增 ToolResult、ToolResourceLimits、CommandIdentity、ToolIdentity、run_tool、ToolEvidenceError、read_tool_evidence、CompileResult/CompileError、compile_cubin_result、prepare_msvc_environment、cuobjdump_result、nvdisasm_result、CandidateToolBinding/bind_candidate_to_tool。模型验证信号/异常码与原始返回值、状态优先级、资源实施范围、base64/哈希及身份一致性；即使重新封装也不能使矛盾状态通过。

## C. ELF 验证

固定合法源 fixture：`tests/fixtures/elf64_le_rel.hex`，解码 **656 bytes**，SHA-256：

```text
fd9119b01caf56fe810d6f1bd79fcbfa20ca8188844d02a3325d092ba6086750
```

它是独立按格式构造的 ELF64LE ET_REL / EM_X86_64，含 text、NOBITS、字符串/符号及 RELA；不是生成 PoC 或真实 CUDA 编译产物。详见 [fixture 来源](../tests/fixtures/README.md)。Mock CUDA 工具测试只更改 EM_CUDA 标识作为结构 fixture，不称为真实 cubin。

ELF **32 项**离线测试在 Windows、WSL 均通过。涵盖全部10字段的最大32/64位值及邻接字节、非法类型/索引/长度、class/endian/扩展编号、截断/重叠/字符串表、100个以上 sections、NOBITS 概念范围、append/replace 对齐、4096字节名称支持界限、非法输入不落盘及修改前源字节保留。

WSL 实际 `readelf -h -S -s -r` 解析固定合法 fixture：退出码 **0**、stderr **0 bytes**，仅解析、不加载/执行 ELF。最终统一 ToolResult run ID：`542cca0c523947e8b9d8145b46ffbec5`，原始文件重读哈希校验 PASS。负例只在内存中构造，不提交给 native CUDA parser 或执行畸形文件。

## D. 双环境检查

修改前两边 pytest 均 **148 PASS**。最终收集 **256 项**：原148回归保留，新增108项（ELF32、编译/检查27、进程37、集成/绑定/权限12）。

| 检查 | Windows Python 3.12.13 .venv | WSL Python 3.10.12 独立 venv |
|---|---|---|
| pytest -q | PASS：253 PASS / 3 SKIP | PASS：256 PASS |
| unittest discover -s tests -q | PASS：256 collected / 3 SKIP | PASS：256 项 |
| Ruff main.py src tests | PASS | PASS |
| pip check（已有依赖，无安装升级） | PASS | PASS |
| AST 语法检查 | PASS：45个Python文件 | 同一共享源码；全部测试导入/Ruff PASS |
| 原 main.py CLI / 无第三方 -S help | PASS | CLI 回归 PASS |
| P0/P1-A/P1-B 148项回归 | PASS | PASS |
| 严格分析阻断、原始输入/模型文本、Mock Single-shot | PASS | PASS |
| 无害 Python 进程采集与持久化 | PASS：实际执行 print(123) | PASS：实际执行 print(123) |
| 合法 ELF readelf 解析 | 不单独运行 GNU readelf | PASS，固定合法fixture，未执行 ELF |
| 真实 nvcc 编译 smoke | NOT_CHECKED：没有执行 | NOT_CHECKED：没有执行 |
| native cuobjdump/nvdisasm 针对 CUDA 产物 | NOT_CHECKED，Mock覆盖 | NOT_CHECKED，Mock覆盖 |
| CUDA kernel / 候选 PoC / 真实 CVE | NOT_CHECKED，未执行 | NOT_CHECKED，未执行 |
| paid LLM / 真实 RAG / Tavily | NOT_CHECKED，请求次数0 | NOT_CHECKED，请求次数0 |

Windows 三项跳过仅为真实 POSIX signal、工具 POSIX 文件系统权限和共享探测目录 POSIX 权限；三项均在 WSL 通过，不把跳过标为 PASS。Windows 异常码使用离线数值测试，没有实际制造 Windows 崩溃。TimeoutExpired（包括 wait API）、输出前缀/截断、启动失败、未准备编译器、非零退出、信号、已识别/未识别 Windows 码、日志损坏、磁盘/权限失败均有负例回归。

## E. 实际原始记录

以下仅是无害 **Python 工具采集检查**，不是 CUDA 编译 smoke，更不是候选执行：两套解释器调用 `[sys.executable, "-I", "-c", "print(123)"]`，正常退出0，并经 read_tool_evidence 核对实际文件哈希、预期 run/record ID 和原始字节。

| 环境 | 实际 run_id | 状态 |
|---|---|---|
| Windows | 427d5851aac6451388835b2732c32c4b | NORMAL_EXIT / rc0，原始文件重读 PASS |
| WSL | 1cace6d06a7b4cb78ac6ed1da14d8955 | NORMAL_EXIT / rc0，原生 HOME 保存和重读 PASS |

Windows 记录在 ignored `data/outputs/tool_runs/<run_id>/`；Linux 记录在 `~/.local/state/cuda-poc-generator/tool_runs/<run_id>/`。raw stdout/stderr、ToolResult JSON、manifest 独立保存，无 LLM 改写，未上传 Git。权限在运行前应用并验证；输出限额只保证保留前缀，capture_complete 对截断/不完整捕获为 false。写盘失败显式 ToolEvidenceError，并保留内存中的实际原始 ToolResult，不能宣称保存成功。

## F. 原能力、源码与 Git 审计

原测试未弱化，原6套 CVE / 42个 JSON、规范化与分析模型、LLM客户端、七层专家代码、核心 SYSTEM Prompt、配置/约束/依赖及 P1-B worker/桥接协议保持原样。源码只对明确工具缺陷、生成前置顺序、绑定接口及权限真实性做增量处理。没有 Conda/CUDA/驱动/WSL 网络或系统配置修改，也未修改 HeteroPoCLab。

README 命令/链接、JSON 示例内层模型、受控 fixture/hash、Git ignore 和 whitespace 均核对。工作区/暂存区/可达历史采用限定 provider token、私钥和凭证赋值规则检查；旧 README/.env.example 的明确示例占位值与实际凭证区分，不回显内容，不改历史。该检查不是任意秘密格式的完整证明。.env、venv、缓存、实际工具原始记录和临时审计文件不提交。

阶段开发中曾发现并修复：嵌套模型默认值导致新结果封装哈希不一致、返回码/状态元数据矛盾、超时后错误宣称捕获完整、未限定文件读取及清理错误遮盖原始结果。工具发现失败也不再尝试假定不存在的固定路径，以防意外执行当地同名文件。最终测试保留相应负例，不通过改数据/判据制造 PASS。Python 3.12 AST 对既有核心 Prompt `\d` 产生 SyntaxWarning，策略原样保留，不是本轮语法或测试失败。

## G. 限制

本阶段没有执行授权引擎、远端候选调度、Windows Job进程树隔离、CPU/内存/GPU限额、目标 Oracle 或反馈迭代。候选执行和验证状态始终 NOT_EXECUTED / NOT_VERIFIED。未运行真实 CUDA 编译或 native CUDA 产物检查，不能据 Mock 宣称实际版本组合兼容。

ELF 支持子集明确，结构通过不等于 payload 语义合法/native parser 无漏洞。保留的历史未调用参考字符串/私有 smoke 函数不是本阶段可信执行接口，不能用来绕过新的适配器。legacy tuple/-1 不能可靠表达全部状态，新代码应使用结果模型。工具/记录哈希不是硬件或软件真实性证明，也不防 TOCTOU。P2 在实际执行时需要重新哈希与隔离。

## H–I. 交付与下一阶段

完整阶段提交 SHA 和 main 同步结果见最终交付 / Git 记录。仅审查后的工程文件提交，正常 push origin/main，无 PR、force push、历史修改或私有日志上传。

P2 使用明确 ExecutionRequest，绑定候选内容、PlatformSnapshot 的环境/实例身份、实际工具文件身份与授权动作；ExecutionRecord 引用 ToolResult 并记录资源真正实施、生命周期及证据存储状态；EvidenceManifest 引用原始字节/哈希、完整性、运行身份和采集器版本。具体字段和边界见工具合同。执行记录先保持 NOT_VERIFIED，目标 Oracle 留给 P3。本阶段交付后停止开发，等待独立审查。
