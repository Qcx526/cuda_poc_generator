# P3-D-R2 执行与候选身份合同

报告语言：`zh-CN`。本合同记录本轮增加的身份核验和固定无害联调边界，不开放任意模型代码执行，也不改变 P2/P3 已冻结的执行状态和 Oracle 语义。

## 1. 当前能力边界

当前分成三条独立路径：

1. **生成产物身份读取**：读取指定 CVE 和 generation run 下已归档的 `poc/cuda_poc_v1.py` 原始字节、生成记录和 `artifact_manifest.json`，验证三者的 CVE、run、状态和 SHA-256。不会回退读取旧版平铺文件，也不会调用 LLM。
2. **WSL 目标只读预检**：由 Windows 桥接调用固定的 DESCRIBE 操作，测量平台快照、probe、CUDA 工具和版本原始记录。它不接收候选源码，也不启动候选。
3. **固定无害联调**：Windows 可以传送注册表中 `p2b-normal-v1` 的精确固定源码到 WSL 接收端，并单独调用既有固定动作执行流程。接收端重新校验动作 ID、字节数与 SHA-256。该流程只验证固定内容传输和固定动作运行；它不表示接收的生成候选被执行。

`CandidateAdmission.execution_admission` 固定为 `UNSUPPORTED`，候选状态固定为 `NOT_EXECUTED`，漏洞状态固定为 `NOT_VERIFIED`。`python -m src.cve_lab preflight` 是身份记录和目标观察接口，不是执行授权或漏洞测试命令。当前 CLI 没有 `execute` 子命令；任意 `EXECUTE_CANDIDATE` 仍被拒绝。

固定 fixture 的授权不会继承到模型生成代码。即使模型候选拥有 `STATIC_VALID`，也只说明原有静态检查通过，不证明代码可运行、安全或与特定 CVE 有关。

## 2. 固定目标工具档案

只读 CUDA 工具描述保留 P2-C 的 `system-toolkit` profile，并新增版本化的 `cuobjdump-12.8.55-1` profile。新档案使用 schema `1.1`；旧默认 profile 仍使用 schema `1.0`，序列化时保留原有默认 JSON 形状。

侧载工具只有同时满足以下身份条件才会被版本查询和后续固定 smoke 使用：

- 路径位于固定用户侧载目录，并且与 nvcc 同级工具档案区分。
- 目标文件测量状态为 `OBSERVED`。
- 二进制 SHA-256 精确为 `ad1d0f0699f46603416eb58e7b9fdf9a293e95f9312c9df7fd6fda56a6c30d41`。
- `--version` 原始输出包含 `V12.8.55` 和 build `35351055_0`。

执行 DESCRIBE 时先检查二进制身份，再调用其版本查询。缺失身份返回 `UNKNOWN`，文件哈希或路径不符返回 `REJECTED`。候选预检也复用同一判定函数。系统 CUDA 12.8.90 的工具路径和哈希仍单独保存，不能由版本号相近推断为同一二进制。

Windows 控制侧从同一测量描述的 `native_task_root` 推导远端用户目录：必须先核对绝对 POSIX 路径及固定 `.local/state/cuda-poc-generator/lifecycle_tasks` 后缀，再拼接固定侧载相对路径。它不会用 Windows 的 HOME 代替 WSL 用户目录，也不会省略工具路径、SHA-256 或 build 校验。WSL 本地检查继续使用自身用户目录。

公开来源将 `cuobjdump 12.8.55` 列为 CVE-2025-23339 的已确认受影响版本，NVIDIA 公告列出 CUDA Toolkit 13.0 前的受影响范围；因此该 profile 仅用于准确识别研究目标，不能因识别成功就启动恶意输入或候选。[Cisco Talos 报告](https://talos.talosintelligence.com/vulnerability_reports/TALOS-2025-2155)；[NVIDIA CUDA Toolkit 安全公告](https://nvidia.custhelp.com/app/answers/detail/a_id/5661/kw/overlay)。

## 3. 机器接口

`src/candidate_adapter.py` 提供：

- `load_generation_candidate(cve_id, generation_run_id, output_root=...)`：从不可变归档读取候选，验证生成记录、CVE/run、候选状态和字节哈希；只返回 `CandidateArtifact`。未传 `output_root` 时与归档模块统一使用项目根目录下的 `data/outputs`。
- `assess_candidate_admission(candidate, description)`：绑定候选身份与 WSL 平台/工具描述，返回 `CandidateAdmission`。无论身份是否匹配都不会授予执行准入。
- `transfer_registered_candidate_wsl(action_id="p2b-normal-v1", ...)`：只接受注册动作的冻结源码，Windows 侧创建唯一 transfer ID，WSL 接收端以 `O_EXCL` 保存后再校验；生成传输收据和清单。它不会启动接收文件。
- `CandidateExecutionAdapter.run_registered_harmless_smoke(...)`：在显式固定动作授权下串接传输与现有固定注册动作执行流程，分别保存 transfer、execution 和 chain 身份。执行日志中的 action ID、候选摘要和接收来源必须相符，否则拒绝链接。

`src/cve_lab.py` 提供仅用于 Windows 主控的 `preflight` CLI：

```powershell
.\.venv\Scripts\python.exe -m src.cve_lab preflight `
  --cve CVE-2025-23339 `
  --run-id <生成轮次ID> `
  --linux-project-root "<项目的 WSL 路径>"
```

它要求归档中存在真实的 `GENERATED_CANDIDATE_RESEARCH` 记录，否则失败。输出目录 `data/outputs/candidate_preflights/<preflight_id>/` 保存只读目标描述、准入 JSON 和 UTF-8 中文报告。目标身份 `VERIFIED` 仅说明探测记录与登记的工具 build/哈希一致；报告中的执行准入仍是 `UNSUPPORTED`。

## 4. 固定 CUDA 工具链 smoke

固定 smoke 由 P2-C 既有操作合同控制，执行输入来自仓库冻结的 `tests/fixtures/cuda/safe_smoke.cu`。本轮侧载 profile 使用 `cuobjdump --dump-elf` 检查刚由固定无害源编译的 cubin，并运行固定 `nvdisasm` 检查；不调用生成候选，不运行 cubin，不启动 GPU kernel，也不提供 CVE 输入。

因此，成功只证明这一组固定无害工具调用在本次环境中有实际进程记录、工具身份和原始日志。它不证明受影响程序对 CVE 输入发生错误，也不证明真实漏洞根因。

## 5. 后续任何候选执行的独立准入要求

当前资源合同、bwrap profile 和回收验证只覆盖冻结无害 fixture。任意 Python、native 程序或 CUDA kernel 的风险不同。继续实现候选执行前，至少需要独立审查候选内容和实际输入，确认固定目标调用面、目标版本适用性、隔离能力、所有资源限制及后代回收能力，并建立绑定候选 SHA、CVE/run、环境快照、工具身份、动作范围与有效期的操作者授权。缺少任何一项时保持拒绝/未知。

授权不能由候选本身、LLM 输出、模型置信度或通用固定动作授权产生。退出 0、非零退出、崩溃或 Memcheck 错误都不能自动升级为 `VERIFIED`。生产 CVE `VERIFIED` 仍受 P3-A/P3-B Oracle 合同限制。
