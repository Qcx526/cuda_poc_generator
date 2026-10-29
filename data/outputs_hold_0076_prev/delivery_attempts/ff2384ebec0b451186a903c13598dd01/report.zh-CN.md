# 单次生成与 ZIP 交付报告

报告语言：zh-CN。

本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。

| 项目 | 本轮结果 |
|---|---|
| 目标 CVE | CVE-2024-0076 |
| run_id | ff2384ebec0b451186a903c13598dd01 |
| 生成流程 | CONTEXT_ERROR |
| 归档状态 | ARCHIVED |
| 打包与独立校验 | NOT_PACKAGED |
| 本轮归档目录 | F:\qcx\code\test\cuda_poc_generator\data\outputs\CVE-2024-0076\runs\ff2384ebec0b451186a903c13598dd01 |
| ZIP 文件 | 未产生 |
| 包外 SHA-256 | 未产生 |
| 清单 SHA-256 | 未产生 |
| 错误类别 | 未产生 |

## 结果说明

生成流程未完成，仅保存本轮不完整研究材料；没有交付 ZIP。

缺少真实执行、专项根因和受影响/修复版本差分证据。ZIP 完整性校验不是来源认证或漏洞验证。
候选执行：NOT_EXECUTED；漏洞验证：NOT_VERIFIED。

## 离线复核

使用包外 SHA-256 调用 artifact_cli verify 重新读取 ZIP；使用 artifact_cli rebuild-report 重建生成报告。
本交付报告可由 delivery.json 确定性重建；失败回执不会回退到旧 run。
