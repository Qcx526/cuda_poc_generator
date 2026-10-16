# 按 CVE 统一归档合同（P3-B，1.0）

本模块提供不可覆盖的资料审查和 Single-shot 候选生成归档。**归档完整性通过不等于真实漏洞验证通过。** 本阶段只有 `RESEARCH_ONLY`、`INCOMPLETE` 和 `GENERATION_RESEARCH_INCOMPLETE`，没有“完整 CVE 实验已验证”包类型。

实现：`src/models/artifact_package.py`、`src/artifact_packaging.py`、`src/artifact_cli.py`。所有正式中文入口默认 `report_locale: zh-CN`，UTF-8 编码。现有科学对象不增加归档字段；归档是独立呈现与复制合同。

## 目录和不可覆盖规则

```text
data/outputs/CVE-2025-23308/
  runs/<32位小写十六进制run_id>/
    input/
    analysis/
    poc/
    execution/
    evidence/
    oracle/
    reports/
    README.zh-CN.md
    artifact_manifest.json
  packages/CVE-2025-23308_<run_id>.zip
  index.json
```

`CVE-[0-9]{4}-[0-9]{4,}` 是严格完整匹配；资料审查导入另外要求在已审查六个 CVE 的注册目录中。`run_id` 不是任意目录名。不同 CVE、run 和父轮次清单哈希不能交叉绑定。

每轮使用排他创建，重复 run 或 ZIP 拒绝。CVE 目录的排他 `.packaging.lock` 防止合作进程之间并发更新索引；残留锁只意味着任务中断，需要操作者审查，不能自动解除并宣称恢复完成。索引采用新临时文件、文件 `fsync` 和原子替换；**未宣称 Windows/WSL 断电后目录元数据一定持久化**。磁盘写入失败时保留本次不完整目录以便诊断，不改动原始数据，不宣称成功。

`parent_run_id` 与 `parent_manifest_sha256` 成对保留；资料审查导入会校验同一 CVE 的父轮次。P4 的候选重试调度尚未实现。

## 注册导入接口

### 公开资料审查

```powershell
$runId = [guid]::NewGuid().ToString('N')
.\.venv\Scripts\python.exe -m src.artifact_cli import-review --cve CVE-2025-23308 --run-id $runId
.\.venv\Scripts\python.exe -m src.artifact_cli package --cve CVE-2025-23308 --run-id $runId
```

`import_review_run()` 仅调用已有 `load_reviewed_claim()`，按 P1-A 来源哈希复制七个原始 JSON，保存结构化 `VulnerabilityClaim` 与公开资料引用元数据，再调用现有中文呈现器。它不下载或伪造公告全文，不调用模型，不读取私有执行日志。其 `evidence_domain` 为 `DOCUMENTED_PUBLIC_REVIEW`。

实际文件是：七维输入、`analysis/vulnerability_claim.json`、`evidence/public_source_references.json`、`reports/review.zh-CN.md`、中文入口和清单。`poc/`、`execution/` 没有虚构日志，状态为 `NOT_EXECUTED`；`oracle/` 为 `NOT_EVALUATED`。空目录不强制写入 ZIP。

### Single-shot 生成产物

```python
create_generation_run(
    cve_id, run_id, source_directory, run_record,
    output_root=output_root, input_directory=original_input_directory,
)
```

此接口只接受实际 `cuda_run_v1.json` 与本轮记录完全一致的调用；候选源码、分析、原始模型响应、输入清单和候选状态必须出现在本轮固定产物映射中，且其原始 SHA-256 一致。旧 `preexisting_artifacts` 不能变成本轮候选。固定文件名注册表拒绝任意路径、文件映射或执行请求。

生成归档的 `evidence_domain` 是 `GENERATED_CANDIDATE_RESEARCH`。源码存在仅表示 `GENERATED`；静态检查保持原有语义。执行始终 `NOT_EXECUTED`，真实 CVE 始终 `NOT_VERIFIED`。失败也可归档本轮实际产物；没有候选时不复制旧源码。七维原始文件不可获得时，只保存真实输入清单，类别标记 `MISSING`；绝不把反序列化后的 JSON 重新序列化来冒充原始字节。

现有 v1 输出保留，归档只制作独立副本。原始英文历史报告、P2-C 日志、旧 Oracle 和 Prompt 不原地修改。平台探测、通用 smoke 和通用 Synthetic Oracle 不能使用公开资料导入接口伪装成 CVE 实验；它们原有独立存储继续保留。

## 清单与完整性

`artifact_manifest.json` 记录版本、CVE/run、可选父轮次、资料声明或生成记录规范哈希、每份文件的安全相对路径、原始 SHA-256、字节数、产物类型、来源阶段、源记录 ID/哈希、各类缺失状态及 `NOT_EXECUTED` / `NOT_VERIFIED`。清单不包含自身哈希；ZIP 自身哈希只写包外 `index.json`，避免自引用。

ZIP 根目录必须有 `README.zh-CN.md`、`artifact_manifest.json`、实际生成的 `reports/` 文件。中文入口包含：

> 本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。

原始文件逐字节复制，stdout/stderr 如后续受支持时必须保持原字节，本阶段没有从摘要重造的日志。ZIP 按清单枚举，不打包绝对路径、符号链接、Windows 重解析点、路径穿越、大小写重复名、设备名或特殊文件。归档根及祖先目录也拒绝链接。

每文件最多 16 MiB，总原始数据最多 64 MiB，最多 257 个 ZIP 成员（含清单）。验证先核对目录声明总量，再有界读取；不把 ZIP 解压到磁盘。仅支持 STORE/DEFLATE，不接受加密或未知压缩格式。新生成 ZIP 使用固定顺序、时间戳和普通文件权限，之后重新打开逐项核对长度、SHA-256、内容、来源绑定及中文报告重建结果。

```powershell
.\.venv\Scripts\python.exe -m src.artifact_cli verify --package '<zip路径>' --expected-sha256 '<独立获取的64位SHA-256>'
.\.venv\Scripts\python.exe -m src.artifact_cli rebuild-report --cve CVE-2025-23308 --run-id $runId
```

`verify` **必须显式提供包外摘要**。包与摘要来自同一个不可信来源时不能证明真实性，返回 `authenticity: UNAUTHENTICATED_EXTERNAL_HASH_PIN`。`INTEGRITY_VERIFIED` 是归档字节状态，不是 Oracle 的 CVE `VERIFIED`。离线校验不调用 CUDA、WSL、网络或 LLM，不根据 Markdown 重建客观事实。

## 限制

P3-B 尚未注册真实 CVE_TRIGGER、专项诊断执行包或自动执行导入器；不接受任意文件夹作为“完整实验”。此限制阻止未经审核的旧执行、Synthetic 或未知二进制被包装成真实验证。必要的根因绑定、可信受影响/修复 build、授权和隔离条件仍是后续实验的前置阻断条件。
