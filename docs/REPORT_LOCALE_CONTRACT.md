# 中文正式报告合同（P3-B，1.0）

新增正式报告默认简体中文 `zh-CN`、UTF-8、LF。技术标识、CVE/CWE、工具名、API、SHA-256、原状态枚举保留。原始 stdout/stderr/XML/模型响应不翻译、不重新生成；中文解释只来自严格对象与确定性模板，不调用 LLM。

## 科学对象与呈现分离

`src/report_locale.py` 的 `ReportViewManifest` 包含 `report_schema_version`、`report_locale=zh-CN`、`renderer_version=p3b-zh-1.0`、`report_kind`、`source_domain`、源文件及报告的字节数/SHA。语言字段不插入旧 PlatformSnapshot、ExecutionRequest、ExecutionRecord、EvidenceManifest、OraclePlan 或 OracleResult，既有 canonical SHA 和判定不变。

来源域区分 SYNTHETIC、DOCUMENTED_PUBLIC_REVIEW、GENERATED_CANDIDATE_RESEARCH、READ_ONLY_CAPABILITY、RECORDED_EXECUTION、UNVERIFIED_IMPORT。它是明确的呈现来源标签，不是签名或真实采集认证。已有原生执行记录没有 Synthetic 字段时，导入默认 UNVERIFIED_IMPORT；已知合成测试的调用者必须显式降格标为 SYNTHETIC。Oracle/主机证据的合成标签从其严格源对象派生，不能凭 Markdown 重新解释。

源内存字段、地址、栈帧和进程状态不由翻译生成。未知与不支持均保留，中文解释给出缺失证据/绑定/方法/采集/回收等原因。术语及原始字段路径可按技术原文展示；未解释诊断原文属于证据附件，不充当中文结论。

## 入口与兼容性

| 入口 | 新正式报告 | 冻结兼容内容 |
| --- | --- | --- |
| `main.py` | 默认启用按 CVE/run 归档的 `reports/generation.zh-CN.md`；失败亦有中文报告 | 原有六个 v1 产物/状态保持；代码生成算法及 Prompt 不变 |
| `CudaPipeline.run()` | 新调用可传 `archive_artifacts=True`，或由正式 CLI 设置实例属性 | 未启用时保留 v1 API 的六文件布局，避免破坏既有 Python 调用方 |
| `src.platform_probe` | 返回 `report_locale` 和独立中文视图路径 | 原探测原件与 v1 probe_report.md 不改写 |
| `src.lifecycle_cli` / `src.cuda_smoke` | 默认返回中文执行/前置检查视图；异常正文中文 | 原 P2 manifest、原始流、英文 v1 完整性兼容载体保留 |
| `src.oracle_cli` | 同目录名后缀 `.zh-CN` 的独立视图；CLI rebuild 默认中文 | 旧 Oracle bundle 仍由冻结 v1 renderer 核对，不改旧结论 |
| `src.host_diagnostics_probe` | 中文诊断能力报告及离线 rebuild | 版本查询原始流逐字节保留 |
| `src.host_parser_report` | 中文专项诊断与 A～F 证据要求 | 原 XML、frame 字段、ToolResult 与 collection 哈希不改变 |
| `src.artifact_cli` | 中文 ZIP 根导航和 CVE 报告；可离线 rebuild | 包只复制原字节，不移动历史证据 |

冻结的 `render_oracle_report`、`rebuild_oracle_report`、P2 v1 reader/renderer 等仍是历史完整性兼容 API；它们不是本阶段新正式呈现入口。新入口复用同一 `_associate`、严格对象、证据读取器和 Oracle，未另造验证逻辑。英文兼容载体仍可能随 v1 科学记录保存；面向用户的正式入口指向中文视图，不将旧英文文件原地替换。

异常时若无法落盘，CLI 输出中文失败说明及 UNKNOWN/INCOMPLETE；原兼容诊断作为明确标注的原文附录保留，不伪称证据保存成功。Windows CLI 设置 UTF-8/LF；此设置只影响 CLI 文本，不触碰子进程原始输出通道。

## 资料翻译的事实约束

六例中文事实模板仅适用于已注册的公开资料核心 SHA，不能只凭相同 CVE 编号套用。如果声明的版本/机制/来源变更，与已审查核心不匹配，则显示未审查提示和原始声明，不静默替换为目录事实。核心比较排除 input_assertions（它们保持 UNVERIFIED，文件路径可能随宿主变化），不排除来源、受影响范围或机制。

这组固定译文不是新的受影响版本判据；资格和漏洞状态来自原科学对象或 UNKNOWN，不从中文正文重新解析。正式包 `INTEGRITY_VERIFIED` 也只表示字节及关联检查。

## 独立视图格式

```text
<new-report-view>/
  sources/<fixed-source-name>.json
  report.zh-CN.md
  report_view_manifest.json
```

目录独占创建，原始源文件按字节复制/固定序列化，报告有界、转义 Markdown/HTML/控制字符，拒绝链接、危险路径、未知源集合与覆盖。报告不是执行沙箱，也没有恶意本机管理员抵抗或签名承诺。私有原记录仍须存放在操作者可信目录；不得提交到 Git。

## 离线重建与独立重评估

重建：检查源字节哈希、严格 schema、关联与同版本确定性渲染，结果必须与产物逐字节相同。

独立重评估：另外取得原始诊断/XML/ToolResult/索引及独立固定的 collection/plan/manifest 摘要，重新运行 parser/Oracle；重新采集不属于重建。单纯成功渲染报告不证明原始采集来源真实，也不确认当前平台状态。

```powershell
.\.venv\Scripts\python.exe -m src.report_cli --help
.\.venv\Scripts\python.exe -m src.report_cli render --kind host-parser --source <evidence.json> --source-sha256 <independent-file-sha256> --output-dir <new-view-directory>
.\.venv\Scripts\python.exe -m src.report_cli rebuild --report-dir <view-directory>
```

`render` 支持 claim、oracle、generation、platform、execution、host-parser、failure。Oracle/执行导入必须提供原 bundle 清单的独立 SHA，并先经已有 reader 校验。其他源文件也要求独立文件 pin。未支持的 locale 会明确拒绝，不偷偷回落到英文或改写历史文件。
