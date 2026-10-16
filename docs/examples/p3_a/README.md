# SYNTHETIC Oracle 示例

synthetic_* 输入、输出、Markdown 均为 **SYNTHETIC**。虚构目标 CVE-2099-0001、身份、版本与根因字段只验证规则，不是真实漏洞、运行日志或实验结果。每个输出的 real_cve_verification 固定 NOT_VERIFIED。

| 场景 | 输入 | 输出 verdict | 条件总结果 |
| --- | --- | --- | --- |
| 全部必要条件满足 | synthetic_positive_input.json | VERIFIED（仅规则） | SATISFIED |
| 必要异常条件不匹配 | synthetic_negative_input.json | NOT_VERIFIED | NOT_SATISFIED |
| 环境必要证据缺失 | synthetic_unknown_input.json | UNKNOWN | UNKNOWN |
| 关键观察支持、根因证据缺失 | synthetic_partial_input.json | SUPPORTED | UNKNOWN |

对应 *_output.json / *_report.md 是确定性结果，pytest 会从原始 fixture JSON 字符串重新取值、运行 Oracle 并核对完整结果及 Markdown。输入结构明确包含 label、scenario、plan、artifacts（保存原始 JSON 字符串）、binding。不得删除 label 或将 domain 改成 OBJECTIVE。

运行命令、固定正例计划摘要见 [合同](../../P3_A_ORACLE_CONTRACT.md)。其他场景的 canonical plan SHA 位于对应输出 plan_sha256；这些摘要仅适用于合成规则演示。cve_review_a.json、cve_review_b.json 是公开资料审查，不是合成漏洞数据或客观执行 Evidence。
