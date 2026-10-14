# P1-A 输入归一化与严格分析合同

本阶段在 P0 的 Single-shot Generation 上增量接入输入和分析校验，不增加执行器、漏洞 oracle、LangGraph 或运行反馈循环。CLI 参数、原七层专家 SYSTEM Prompt、代码生成 SYSTEM Prompt、CUDA 库、RAG/Tavily 接口和双 venv 保留。

## 修改前后的真实流程

```text
P0：原始七维字典 → 可选检索/宿主探测 → LLM分析容错提取/顶层检查
    → 无条件进入生成 → 静态纠正 → 分析JSON与候选源码

P1-A：读取原始字节/哈希 → flat/wrapped归一化 → 关键字段/类型/CVE/冲突检查
      ├─ 不合格：INPUT_INVALID，模型客户端未初始化
      └─ 合格：可选RAG/Tavily/宿主探测 → 一次专家LLM
          → 完整JSON解析 → 严格Pydantic合同/目标CVE检查
          ├─ 不合格：解析/结构/CVE失败报告，原文保留，不调用生成器
          └─ 合格：cuda_analysis_v1.json → 原生成器 + 最多两次静态纠正
              → cuda_poc_v1.py + 独立状态/哈希 + 调用报告
```

通用 `LLMClient.structured_generate(json_schema=...)` 的 schema 参数用于提示；CUDA 分析的真正结构校验在 `validate_analysis()`，并由专家、pipeline 和生成器入口执行。专家 Prompt 的输出 schema 从同一个 `ExpertAnalysis` 模型生成。旧 `_safe_parse_json()` 仅作为手动兼容 helper，主流程不用它。

## 七维输入与来源

公开入口：`normalize_input_files(directory, input_files=None)` 与 `CudaDataLoader.load_normalized_inputs(directory=None)` 返回 `NormalizedInput`。无效资料也返回诊断模型；调用 `require_valid()` 才放行，否则抛 `InputValidationError(ValueError)`，携带 `.result` 和 `.diagnostics`。

| 字段 | 意义 |
|---|---|
| `dimensions` | 统一七维逻辑字典，各维解开同名 object 包装、保留外层补充字段及目标 `cve_id` |
| `raw_inputs` | 通过读取、解析与深度检查的原始 object 深拷贝，不丢自定义字段；缺失、不可解析、非 object、超深或重复冲突为 `null` |
| `sources` | 相对于输入目录的来源文件、读取时原始字节 SHA-256 和长度 |
| `field_states` | JSON Pointer → `MISSING/UNKNOWN/CONFLICT/VALID/INVALID` |
| `provenance` | 逻辑路径、来源文件和原始字段路径、状态、`input_assertion/unverified` |
| `diagnostics` | 安全的 code/severity/path/reason；不回显字段值 |
| `is_valid` | 归一化结果的结构检查是否通过，不能解释为事实已经证实 |

实际检查：七个文件均为 UTF-8 JSON object、CVE ID 为 ASCII `CVE-YYYY-NNNN...` 且一致；组件 `name` 或 `component_name`、攻击入口 `entry_point`、CWE、根因 `summary` 或 `vulnerable_code_summary` 必须有非空、非未知内容。已知字段检查类型；CWE ID 格式和已有 CVSS 数字/数字字符串范围 `[0,10]` 检查。CVSS 原字符串不被覆盖成新数字。

OS/GPU 等未知环境信息允许保留，`null`、空字符串和明确 unknown/未知等标为 `UNKNOWN`；没有字段标 `MISSING`，错误类型标 `INVALID`。不要求用假默认值填齐环境。自定义 JSON 字段原样保留，不为未知领域字段编造语义 schema。

重复同名 JSON 键不同值、同一逻辑路径外层/包装不同值、七文件 CVE 不同、明确共享环境键不同均拒绝，冲突叶不任意取一方。相等重复字段可保留其来源位置。`name` 与 `component_name` 在已有样例分别是短名和正式组件描述，不自动折叠为一个值；检索同时使用两者。不同自然语言描述、工具路径或修复版本字段不作无依据的语义等价判断。

输入 JSON 容器最多128层；超深、重复冲突、非法 UTF-8、非有限数字等返回 `INPUT_JSON_ERROR` 或对应冲突诊断。原文件不修改；无法无损表达为 dict 的文件保留来源和精确哈希，不声称其 `raw_inputs=null` 是原始 object。读取后的文件若被外部更改，manifest 哈希仍指向当次读取；本阶段未实现不可变字节快照存储。

例如同一维度的两个形式等价（仅演示结构，不是目标实验结论）：

```json
{"cve_id":"CVE-2024-0124","summary":"研究资料声明，待外部复核"}
```

```json
{"cve_id":"CVE-2024-0124","root_cause":{"summary":"研究资料声明，待外部复核"}}
```

归一化均为 `dimensions.root_cause = {"cve_id": "CVE-2024-0124", "summary": "研究资料声明，待外部复核"}`，但 provenance 的原始路径分别是 `/summary` 与 `/root_cause/summary`，来源哈希分别反映原始字节。

## 严格分析合同

`validate_analysis(raw, expected_cve_id=None) -> ExpertAnalysis`。成功模型可 `model_dump(exclude_unset=True)` 回到已有 dict 接口。错误为 `AnalysisValidationError(ValueError)`，`.category` 为 `SCHEMA_ERROR/CVE_MISMATCH`，诊断只有字段路径和错误 code，不含响应字段值。

- `root_cause_analysis` 的 CVE、CWE、攻击面、类别、原语、根因说明、代码路径、可控性、缓解列表全部必需；字符串必须非空白、CVE/CWE 为 ASCII 标识符格式。
- `verification_strategy` 的 goal、preconditions、steps、confidence、CUDA版本和GPU架构范围全部必需。列表元素必须是规定类型，steps 不能为空。
- 每个 step 必须有 `step_id/description/pseudocode/success_condition/failure_condition/expected_cuda_behavior`。ID 唯一、连续、按 `S01,S02,...` 排列。
- confidence 为有限 JSON 数字，范围 `[0,1]`，接受数值0/1，拒绝字符串、bool、NaN/Infinity。没有空默认字段制造合法分析。
- 拒绝未知输出字段；保留可选历史 `expected_outcome` 和 `evidence`。模型引用的 evidence 只是未经核验的来源声明。
- 目标 CVE 必须与输入一致；公开专家和生成器入口也检查上下文目标，避免绕过 pipeline gate。

`StructuredResponse(dict)` 保留 `.raw_response`，`StructuredOutputError(ValueError)` 的 category 为 `PARSE_ERROR`，携带完整原始文本及安全诊断。严格解析接受完整单个 object 或完整单个 JSON Markdown 围栏；拒绝空白、截断、根节点非 object、额外杂文、多 object、重复键、非有限数字。SDK返回的文本 `content` 在 strip 前保存；供应商 HTTP envelope、usage/reasoning metadata 不属于本阶段文本原文文件。

**结构纠正重试次数是0。** 供应商请求沿用现有有界重试；解析或结构错误不被当作 HTTP 网络错误重试。原有候选静态纠正最多2次，属于代码生成阶段，不能称分析或执行反馈迭代。

下面是可通过结构合同的离线示例；并不表示这些文字是该 CVE 的真实根因或有效策略：

```json
{
  "root_cause_analysis": {
    "cve_id": "CVE-2024-0124",
    "cwe_id": "CWE-416",
    "cuda_attack_surface": "Offline fixture",
    "vulnerability_class": "fixture",
    "primitive": "fixture",
    "root_cause_description": "Test data only; no vulnerability claim.",
    "affected_code_path": "fixture",
    "controllability": "fixture",
    "relevant_mitigations": []
  },
  "verification_strategy": {
    "goal": "Exercise generation without execution",
    "preconditions": [],
    "steps": [{
      "step_id": "S01",
      "description": "Generate a harmless fixture",
      "pseudocode": "print a constant",
      "success_condition": "A candidate file exists",
      "failure_condition": "Candidate generation fails",
      "expected_cuda_behavior": "No CUDA calls"
    }],
    "confidence": 0.5,
    "cuda_version_range": "Not applicable",
    "gpu_arch_range": "Not applicable"
  }
}
```

## 独立状态与输出

`CandidateResult` 四个状态组独立：

| 组 | 值 | 含义 |
|---|---|---|
| generation | `NOT_GENERATED/GENERATED/GENERATION_FAILED` | 是否保存了本次候选；空响应是生成失败 |
| static | `NOT_CHECKED/STATIC_VALID/STATIC_INVALID` | 原 AST/struct 格式/名称启发式检查；未修改其算法或科学含义 |
| execution | `NOT_EXECUTED` | 本阶段未编译或执行候选 |
| verification | `NOT_VERIFIED` | 没有目标漏洞验证证据 |

状态文件还含生成调用 `run_id`、相对源码名、真实落盘字节 SHA-256、静态纠正次数及错误。源码哈希允许两平台行尾不同，各自反映实际文件；分析 raw 用 UTF-8 write_bytes 保存，精确保留首尾空白和 CRLF。`GENERATED+STATIC_INVALID` 仍保存供审阅，不能被解释为验证成功。

保留 `cuda_analysis_v1.json`、`cuda_poc_v1.py`。新增 `input_manifest_v1.json`、`cuda_analysis_v1.raw.txt`、`cuda_poc_v1.status.json` 和 `cuda_run_v1.json`。run 报告的 `status` 为 `COMPLETE` 或明确失败状态：`INPUT_INVALID/ANALYSIS_PARSE_ERROR/ANALYSIS_SCHEMA_ERROR/ANALYSIS_CVE_MISMATCH/PROVIDER_ERROR/CONTEXT_ERROR/GENERATION_FAILED`。`COMPLETE` 仅表示生成流程完成，可能仍 `STATIC_INVALID`。

每次调用更新当前报告和 sidecar；失败不删除旧源码/旧合格分析，但这些旧文件仅出现在 `preexisting_artifacts`，不会被引用为当前成功。没有收到文本时不新建 raw 文件；旧 raw 也不会冒充本次。输入无效时报告在输出根目录，否则在 CVE 子目录。复用 pipeline 对象不会重复嵌套 CVE 子目录。

## 外部接口迁移

1. `CudaDataLoader.load_inputs()` 不变，仍返回原始字典；需要新合同的调用方使用 `load_normalized_inputs().require_valid().dimensions`。旧 `models/vulnerability.py` 字段视图保留，但不是主流程的归一化合同。
2. `CudaSecurityExpert.analyze()` 成功仍返回 dict，可增加 `expected_cve_id`；非法结果现在抛明确异常，不再返回垃圾字典。没有 target 的手动空上下文不作目标绑定；生产流程应使用合格 bundle。
3. `LLMClient.structured_generate()` 成功仍可作为 dict 使用；失败从 `{"raw": ...}` 改为异常，需按 category 处理，不能继续生成。自定义客户端应提供 `StructuredResponse(parsed, original_text)`；仅返回 dict 时没有真实原文，程序不会凭空合成一个“原始响应”。
4. `CudaCodeGenerator.generate()` 成功仍返回源码字符串；机器调用方另读 `.last_result` 或 sidecar。直接传入非法分析会阻止模型调用。
5. `CudaPipeline.run()` 现在成功返回本次 report；失败先保存诊断再抛出，CLI 沿用既有异常处理并非零退出。LLM/专家/生成器延迟初始化，构造 pipeline 时这些属性为 `None`。

默认运行产物都在被忽略的 `data/outputs/`。raw/manifest 可含私有研究信息，不提交 Git；自定义输出目录须由调用方保护。没有真实 API、RAG 模型或 CUDA/PoC 实验结果，验收范围见 [交付记录](P1_A_VALIDATION.md)。
