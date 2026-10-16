# P3-B 主机侧解析器证据合同

本合同只增加离线、只读的结构化观测能力，不执行目标工具或输入，不授权候选执行，不修改 P2-C 和 P3-A 的冻结证据与判定。内存诊断不是指定 CVE 的证明。生产漏洞验证始终为 `NOT_VERIFIED`。

## 模块与版本

| 模块 | 职责 |
|---|---|
| `src/models/host_parser.py` | 严格、冻结、禁止额外字段的 `1.0` 合同 |
| `src/host_parser_evidence.py` | `p3b-memcheck-xml4-parser-1.0` 原始字节解析与离线重评估 |
| `src/host_parser_oracle.py` | 固定 A～F 准备条件及 P3-A 合成兼容投影 |

`HostParserCollection` 绑定 CVE、request/run、平台/probe/snapshot、宿主二进制 SHA-256、组件 build 声明及版本记录哈希、输入身份与格式、诊断器身份/版本/哈希、原始 `ToolResult`、采集 PID、原始 XML/stdout/stderr 哈希、完整性与回收状态。原有 `ToolResult` 中退出码、Linux signal、原始流、资源界限、工具身份和内容 record ID 保持原意。

输入容器 `ELF32`、`ELF64`、`CUDA_FATBIN` 和负载 `CUDA_CUBIN`、`DEBUG_INFO`、`RELOCATION_DATA` 分开记录；它们不是同义词。格式未独立确认时保留 `UNKNOWN`。P2-C 的无害 ELF64 profile 不替代目标输入格式。

状态 `OBSERVED`、`DOCUMENTED`、`INFERRED`、`UNKNOWN`、`UNSUPPORTED`、`NOT_CHECKED` 分开表达。文档记载和推测不能变成实测 build。版本记录哈希只是绑定信息，不构成版本来源认证。

## 明确支持的诊断输入

仅支持明确声明 `VALGRIND_MEMCHECK_XML_V4` 的 UTF-8 XML 子集，要求：

1. `protocolversion=4`、`protocoltool=memcheck`。
2. PID、完整目标 argv、诊断 argv 与独立固定的采集记录一致。
3. 具有唯一的最终 `FINISHED` 标记。
4. 原始字节哈希、长度与采集记录一致，stdout/stderr 与原 `ToolResult` 逐字节一致。
5. 采集未截断、未超时、未失败且回收状态为 `CONFIRMED`。

XML 上限 2 MiB、深度 32、节点 20,000、错误 128、每条错误栈帧 256；拒绝 DTD、实体声明、命名空间、未知 protocol、损坏或缺少完成标记的 XML。其他 Valgrind 协议版本不猜测兼容。`ASAN_UNSUPPORTED` 和 `UBSAN_UNSUPPORTED` 保留原始字节并返回 `UNSUPPORTED`，不匹配自然语言摘要。

Valgrind 官方手册说明 XML 与普通文本采用不同输出通道，协议说明随源码提供；本实现没有声称支持所有版本或所有错误类型。[输出选项](https://valgrind.org/docs/manual/manual-core.html)、[Memcheck 能力与限制](https://valgrind.org/docs/manual/mc-manual.html)（资料访问日：2026-10-16）。安装或 `--version` 成功不证明诊断有效。

## 客观字段和明确未知项

`InvalidRead`、`InvalidWrite` 等只按 XML `<kind>` 枚举产生 `INVALID_READ`、`INVALID_WRITE` 等观测。`InvalidWrite` 表示无效写，不能独立区分越界写、释放后写、堆或栈。`<what>` 文本原样保留为 `UNINTERPRETED_DIAGNOSTIC_PROSE`。

故障地址、访问大小、堆/栈区分及生命周期类别不从文本中猜测，当前均为空或 `UNKNOWN`。栈帧只读取明确的 `<ip>`、`<obj>`、`<fn>`、`<dir>`、`<file>`、`<line>`；缺失字段保持缺失，每个字段绑定原始 XML 节点，例如：

```text
memcheck.xml / SHA-256
/valgrindoutput/error[1]/kind[1]
/valgrindoutput/error[1]/stack[1]/frame[2]/ip[1]
```

节点位置与原始 XML SHA-256 共同定义出处。指令指针不是故障访问地址。普通退出 0、非零退出或单独 `SIGSEGV` 只保留为进程观察，不产生内存诊断或 CVE 成功状态。

## 原始字节、信任边界与独立重评估

```python
from src.host_parser_evidence import parse_host_parser_evidence

evidence = parse_host_parser_evidence(
    collection,
    diagnostic_bytes=xml_bytes,
    stdout_bytes=original_stdout,
    stderr_bytes=original_stderr,
    expected_collection_sha256=operator_pinned_collection_sha256,
)
```

独立固定的 collection SHA-256 由操作者或可信策略提供，不由模型响应提供。更换工具、输入、request、run、平台或来源会改变 collection 身份；原 pin 不再接受。XML 中 argv 与 PID 另行核对。

`HostParserEvidence.raw_artifacts` 保留三个完整原始字节流的 base64、长度和 SHA-256。`reassess_host_parser_evidence` 从这些原始字节重新解析，并拒绝原始字节、解析分类、栈帧或结果身份被修改的记录。报告可内部重放解析与准备条件来检查派生字段一致性，但没有新的独立来源信任；独立重评估须使用另行固定的原始 collection 摘要，并重新核对解析与准备条件。

**哈希不是签名，也不能证明主机或采集器可信。** P3-B 只注册合成与未认证导入两类来源，不注册生产 `CVE_TRIGGER` 采集器。`IMPORTED_OBSERVATION` 可以解析，但始终 `production_qualification=UNSUPPORTED`、`qualified_for_cve_verification=false`。声明一个 JSON 字段不能绕过这一边界。

## 两个 CVE 的 A～F 准备条件

| 条件 | 当前实现与结果 |
|---|---|
| A 精确受影响 build / 实际二进制 | 保留身份；准确适用性与可信版本来源仍 `UNKNOWN` |
| B 输入身份 / 文件格式 | 保留身份和格式声明；原始输入与专项结构未独立验证，`UNKNOWN` |
| C 目标执行路径 | XML args 与已固定采集身份一致时，只支持该路径观测 |
| D 客观内存异常 | 结构化 `InvalidWrite` 可支持一般无效写观测；不是堆/栈根因证明 |
| E 位置 / 公开机制关联 | `UNIMPLEMENTED` / `UNKNOWN` |
| F 根因 / 受影响与修复 build 差分 | `UNIMPLEMENTED` / `UNKNOWN` |

`evaluate_host_parser_requirements` 固定输出 `NOT_VERIFIED`；不能修改这些必要条件来升级结论。准确堆/栈分类、访问大小、公开位置绑定、根因及充分修复差分均未完成。

`project_host_parser_to_p3a` 只为明确 `SYNTHETIC` 来源生成原有 `EvidenceReference`、`OraclePlan` 和 `EvidenceCorpus`，引用只读派生 JSON，同时保留原 XML 哈希和节点。它复用原有 P3-A 评估器，不修改其生产 allowlist；A/B/E/F 保持未知，不能产生真实 CVE `VERIFIED`。未认证导入转为生产 corpus 明确返回 `UNSUPPORTED`。

## 测试与示例

`tests/test_host_parser_evidence.py` 的所有诊断与进程记录均为明确标记的 `SYNTHETIC`，不是真实目标运行。覆盖正常/非零/signal、读/写、释放诊断、堆/栈/UAF 文本不能越权分类、部分栈、身份混淆、损坏、截断、来源替换、不支持格式、离线重评估及 P3-A 接入。

示例位于 `docs/examples/p3_b/host/`。其中的 CVE 编号只是合成规则目标，不代表执行或复现。当前真实 CVE 的根因证据、受影响版本实验、修复版本对照、生产诊断采集与安全隔离均未验收。
