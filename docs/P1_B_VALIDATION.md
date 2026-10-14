# P1-B 验收记录

日期：2026-10-14。基线：`main@aaf52ae97c9a4d3648e23781a368609b50e77f29`。开始时工作区干净，main/HEAD/origin/main 一致；按用户要求直接 main 开发，不创建分支或 PR。阶段提交 SHA 见最终交付和 `git log`，不重写历史。

## A. 完成内容与修改前问题

| 修改前问题 | 本阶段处理 |
|---|---|
| 无 GPU/查询失败时出现默认 sm，nvcc 缺失给历史架构列表 | 主探测无默认能力，逐 GPU 实际查询，失败/未知保留状态 |
| 宿主探测被当目标环境；Windows/WSL 路径可能混用 | 显式后端、新鲜双环境快照，Linux 路径校验及生成视图屏蔽 Windows drive / UNC 路径 |
| 驱动发行号被换算成 CUDA API 整数 | helper 删除错误换算；标准探测四种版本分别记录，API NOT_CHECKED |
| 自动编译 smoke 混入环境探测 | 当前入口只读，smoke NOT_RUN；历史私有函数保留但不调用 |
| 无 Windows → WSL 正式自动只读入口 | 受控 wsl.exe argv、Linux 独立 Python、标准库 worker、结构/身份校验 |
| 无独立探测原始证据及摘要 | 每次独立私有目录、字节与哈希、两种退出状态、确定性 Markdown |

保留核心 Prompt、严格分析合同、七维输入/RAG、辅助函数库和原 CLI；未引入依赖、执行器、LangGraph、Oracle 或反馈循环。

## B–C. 数据流与模块合同

修改前后流程、完整字段状态与模块输入/输出、迁移说明、示例 JSON 均见 [P1-B 平台合同](P1_B_PLATFORM_CONTRACT.md)。

原生成路径仍为 Single-shot：归一化 → 专家分析 → 严格 schema/CVE 校验 → 生成与有限静态纠正。新平台路径只提供选定目标的观测上下文及证据；平台失败阻止专家与生成请求，无历史/本地替代。合格 Mock 仍生成 `cuda_poc_v1.py` 和 `cuda_analysis_v1.json`，执行与验证状态保持独立。

## D. 真实 Windows → WSL 通信

最终接口实际执行命令（不是 Mock、没有手动进入 WSL）：

```powershell
.\.venv\Scripts\python.exe -m src.platform_probe --backend wsl --distro Ubuntu-22.04
```

记录 ID：`f67b3f11df6344a5a9c0fdbabd07afac`。默认忽略目录 `data/outputs/platform_probes/<probe_id>/`；未上传原始产物。只读 CLI 返回 **0**；Windows launcher 返回 **0**，通过校验的 worker reported exit code **0**。Windows + WSL 合并采集结果 **PARTIAL**，两个快照自身也是 PARTIAL；这不表示所有能力已知，更不表示 CUDA 执行或 CVE 验证。

| 字段 | Windows development host | WSL selected target | 来源 |
|---|---|---|---|
| OS/kernel | Windows / 10.0.19045 | Ubuntu 22.04.5 LTS / 6.6.87.2-microsoft-standard-WSL2 | platform；Linux /etc/os-release |
| Architecture/Python | AMD64 / 3.12.13 | x86_64 / 3.10.12 | platform 模块 |
| GPU 数量/型号 | 1 / NVIDIA GeForce GTX 1660 | 1 / NVIDIA GeForce GTX 1660 | nvidia-smi gpu_query |
| CC / sm notation | 7.5 OBSERVED / sm_75 INFERRED | 7.5 OBSERVED / sm_75 INFERRED | compute_cap 查询；表示转换 |
| Driver Release | 617.42 OBSERVED | 617.42 OBSERVED | gpu_query driver_version |
| CUDA Driver API | NOT_CHECKED / null | NOT_CHECKED / null | 标准探测不加载驱动 API |
| Driver reported compatibility | UNKNOWN / null | UNKNOWN / null | 未返回 `CUDA Version:` 标签 |
| Literal CUDA UMD Version | 13.4 OBSERVED | 13.4 OBSERVED | smi_banner；不转写为兼容/API版本 |
| Toolkit release / nvcc build | 11.2 / 11.2.67 OBSERVED | 12.8 / 12.8.93 OBSERVED | nvcc --version |
| Sanitizer | 2020.3.0 OBSERVED | 2025.1.0.0 OBSERVED | compute-sanitizer --version |
| Host compiler | MSVC 19.29.30159 OBSERVED | gcc / g++ 11.4.0 OBSERVED | 无源文件 cl banner / gcc/g++ --version |

支持架构分别取当地 nvcc 的实际两种 list 查询，未使用历史默认列表。Windows 工具路径没有用作 Linux 路径。Driver compatibility 的两条明确未知诊断保存在各自快照及合并报告；未将 UMD 标签意义扩展为未经确认的事实。

## E. 证据与报告

本次共有 **18 条**外层/嵌套命令记录，包含实际 argv、环境、UTC、界限、状态、返回码以及原始双流 base64/SHA-256。快照、命令及两份外层原始流的 **5 个**文件摘要已逐一核对，存储快照通过当前严格模型和原内容哈希校验。

私有目录在日志写入前应用 Windows 受保护 DACL，仅当前进程用户和 SYSTEM；`probe_result.json` 记为 APPLIED。离线 Linux 产物测试确认目录 0700（生成文件 0600）。这是访问控制，不是加密或硬件证明。

`probe_report.md` 从结构化结果确定性生成、路径隐藏目录、不查询 UUID，不使用模型生成解释。可提交的 [报告示例](examples/P1_B_PROBE_REPORT.md) 是全部合成的离线 Windows/WSL fixture，**不是上述真实探测记录**。真实摘要只在上表列出可公开的版本/型号；私有命令、绝对路径和原始日志没有进入 Git。

## F. 实际测试

基线 Windows：P0/P1-A **107 项 pytest PASS**。本阶段新增 **41 项**离线回归，原测试和 6 套 CVE / 42 个 JSON 不改，未弱化判据。

| 检查 | Windows Python 3.12.13 .venv | WSL Python 3.10.12 独立 venv |
|---|---|---|
| pytest -q | PASS，148 项 | PASS，148 项 |
| unittest discover -s tests -q | PASS，148 项 | PASS，148 项 |
| Ruff main.py/src/tests | PASS | PASS |
| pip check（已有依赖，无升级） | PASS | PASS |
| Python AST 语法检查 | PASS，37 个文件 | 同一共享源码；pytest 导入及 Ruff PASS |
| main.py --help / CLI 回归 | PASS，另有 `-S` 无第三方依赖检查 | PASS，离线 CLI 回归 |
| 正式 probe CLI --help | PASS | 共享入口导入 PASS；本轮未单独运行 Linux help |
| 原 Single-shot Mock / P1-A 阻断 | PASS | PASS |
| 原 SYSTEM Prompt / 受控源资料保持 | PASS，逐字/文件对比 | 同一共享文件 |
| Windows → WSL 真实只读通信 | PASS，实际执行上列正式命令 | 真实 worker 返回；探测状态 PARTIAL |
| Windows ACL / Linux 权限 | PASS，实际 Windows 私有目录及离线测试 | PASS，离线产物权限检查 |
| Git ignore / whitespace / 限定凭证扫描 | PASS，工作区/索引/可达历史 | Windows 管理同一 Git 仓库 |
| 真实 paid LLM / RAG / Tavily | NOT_CHECKED，调用次数 0 | NOT_CHECKED |
| cuDriverGetVersion / CUDA context | NOT_CHECKED | NOT_CHECKED |
| CUDA smoke / kernel / 编译 / PoC / CVE | NOT_CHECKED，未执行 | NOT_CHECKED，未执行 |

重点离线覆盖：无 GPU（成功空列表）/不可访问/缺失 SMI、多 GPU 不同 CC、不支持 compute_cap、缺失/失败 nvcc/sanitizer、驱动与 Toolkit 不同、UMD 不冒充 compatibility、Windows/Linux 路径、缺失 WSL/发行版、超时/非零退出/非法 JSON/重复键/超限/旧 nonce、内容/双流哈希损坏、异常命令元数据、不同环境 provenance、认识状态及 Prompt、失败产物、合格/失败生成链。

runner 的实际子进程测试仅运行无害 Python fixture（固定输出、sleep、固定退出码），从未执行生成候选。unittest 中故意构造错误的日志是负例测试输出，不是测试 FAILED。

敏感审计仅使用限定的 provider token / 私钥 / 长凭证赋值规则。工作区/当前索引没有命中；可达历史规则命中 README、.env.example 的两个旧 blob，逐项符合 DeepSeek/Tavily `your-<文字示例>` 占位形式，未发现实际凭证，不改历史。它不是对任意格式秘密的完整证明。`.env` 未读取内容或修改，虚拟环境、私有日志、缓存和本地审计脚本全部 ignored。Git diff whitespace 通过，CRLF→LF 提示来自既有 gitattributes，不是 whitespace 错误。

语法审计会出现既有 `_CUDA_CODEGEN_SYSTEM_PROMPT` 中 `\d` 的 Python 3.12 SyntaxWarning；核心 Prompt 为保持分析策略原样保留，该提示不导致本轮测试失败。历史 compile/ELF/输出路径 helper 的已知问题仍待 P1-C。

## G. 未实现与边界

本阶段无执行隔离、CPU/GPU 限制、远端进程树终止保证、CUDA 能力 smoke、候选执行器、目标 Oracle、反馈循环或 benchmark。工具的存在/版本/列举架构不证明可编译或可运行；GPU 信息不证明目标 CVE 适用。哈希不是硬件证明。报告中 UNKNOWN / NOT_CHECKED 均保留，未计为功能 PASS。

目标选定后仍需候选静态/人工审查；屏蔽 Windows 路径及 Prompt 约束不保证 LLM 输出正确。历史私有 `_run_nvcc_smoke` 和工具函数保留，但本次公共探测不会调用。未安装或更新 CUDA/驱动、Python、依赖、WSL 网络/系统配置；未修改 HeteroPoCLab。

## H. 变更与 Git

审查后提交的工程文件：README、config/default.yaml、main.py、src/config_loader.py、src/env_probe.py、src/tools/env.py、src/pipeline.py、src/code_generator.py；新增 models/platform、platform_identity、platform_worker、probe_process、wsl_bridge、platform_probe、probe_artifacts、tests/test_platform_probe；新增本合同、验收和 synthetic report 示例。

在本地 main 完成检查后正常 commit/push origin/main；不创建 PR、不 force push、不改旧提交/标签。最后同步及完整提交 SHA 以交付消息和 Git 记录为准。原始实验产物不提交。

## I. P1-C / P2 建议

P1-C 先统一 compile/inspect 工具的原始进程结果、明确非零退出、校验 ELF header 字段类型/尺寸/索引，保留旧 helper 的兼容适配；固定 fixture 离线回归后再单独验收真实无害编译。

P2 将只读探测和执行授权接口分开，ExecutionRequest 显式绑定 candidate_sha256/environment_id/probe_id/授权动作/资源界限；Linux worker 增加进程组清理、运行身份、cwd、EvidenceManifest 和原始日志。Oracle 交给 P3，执行结果继续 NOT_VERIFIED，不能以 crash/错误码宣布 CVE 成功。具体接口见平台合同。本阶段结束后停止开发，等待独立审查。
