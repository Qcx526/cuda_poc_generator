# 主机诊断合成示例（SYNTHETIC）

这里的 XML、进程记录、工具与输入身份、解析结果均为 **SYNTHETIC 合成测试数据**，不是真实主机观测，不是公开漏洞输入，不含可执行恶意样本。

两个 CVE 编号只用于验证目标隔离与规则接口；它们不表示执行、复现或漏洞成功。

| 文件后缀 | 用途 |
|---|---|
| `.xml` | 固定合成 Memcheck XML v4 原始字节 |
| `_collection.json` | 严格采集身份声明；所有路径都是合成路径 |
| `_evidence.json` | 原始字节 base64、哈希、精确 XML 节点与保守解析结果 |
| `_assessment.json` | A～F 准备条件；真实 CVE 始终 `NOT_VERIFIED` |
| `_p3a_plan.json` | 原有 P3-A 模型的合成兼容计划 |
| `_p3a_result.json` | 原 P3-A 评估器结果；根因与差分仍未知 |
| `_report.zh-CN.md` | 确定性中文报告 |

`InvalidWrite` 不自动变成堆越界、栈越界、访问大小或根因结论。报告中的指令指针来自合成 XML 的明确字段，故障访问地址保持未知。

离线复核接口：

```python
from pathlib import Path
from src.models.host_parser import HostParserEvidence
from src.host_parser_evidence import reassess_host_parser_evidence
from src.host_parser_report import render_host_parser_report_zh

folder = Path("docs/examples/p3_b/host")
evidence = HostParserEvidence.model_validate_json(
    (folder / "host_CVE-2025-23308_evidence.json").read_bytes()
)
rebuilt = reassess_host_parser_evidence(
    evidence, expected_collection_sha256=evidence.collection_sha256
)
assert render_host_parser_report_zh(rebuilt).encode("utf-8") == (
    folder / "host_CVE-2025-23308_report.zh-CN.md"
).read_bytes()
```

这里以示例内 pin 演示内部一致性，不证明采集来源可信。生产使用须由操作者或可信策略独立提供 pin；P3-B 没有已认证的生产主机诊断采集器。
