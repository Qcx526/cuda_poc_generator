# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|
| CVE-2022-21821 | SUPPORTED | 2 | SUPPORTED | LABEL_CONFLICT | 822 | 受控样本 31/88 个产生崩溃退出码 |
| CVE-2023-0196 | ERROR | 1 | — | STAGE_ERROR | 184 | stage generate failed: generation produced no candidate: 型: deepseek-v4.1-flash, 单次读取超时: 600s [2026-10-20 19:46:10] WARNING  cuda_poc_generator.llm_client — LLM |
| CVE-2024-0076 | ERROR | 1 | — | STAGE_ERROR | 164 | stage generate failed: generation produced no candidate:  RAG 知识增强           ║ ║                                                              ║ ║  [!] 仅供授权安全研究使 |
| CVE-2024-0109 | ERROR | 1 | — | STAGE_ERROR | 54 | stage generate failed: generation produced no candidate:  RAG 知识增强           ║ ║                                                              ║ ║  [!] 仅供授权安全研究使 |
| CVE-2024-0110 | SUPPORTED | 2 | SUPPORTED | LABEL_CONFLICT | 791 | 受控样本 8/34 个产生崩溃退出码 |
| CVE-2024-0111 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 779 | 受控样本 3/8 个产生崩溃退出码 |
| CVE-2024-0124 | EXHAUSTED | 2 | UNKNOWN | UNCLASSIFIED | 775 | 没有可识别的受控样本执行记录；无法判定复现 |
| CVE-2024-0125 | SUPPORTED | 2 | SUPPORTED | HARNESS_STEP_FAILED | 1603 | 受控样本 23/35 个产生崩溃退出码 |
| CVE-2024-53877 | EXHAUSTED | 2 | UNKNOWN | UNCLASSIFIED | 1159 | 没有可识别的受控样本执行记录；无法判定复现 |
| CVE-2025-23247 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 773 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2025-23308 | EXHAUSTED | 2 | NOT_VERIFIED | LABEL_CONFLICT | 761 | 标签冲突：cannot override a recognisable artifact label |
| CVE-2025-23338 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 761 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2025-23339 | SUPPORTED | 1 | SUPPORTED | — | 343 | 受控样本 11/11 个产生崩溃退出码 |
| CVE-2025-23340 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 646 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2025-23346 | EXHAUSTED | 2 | UNKNOWN | INCONCLUSIVE | 732 | 缺少良性基线（benign.cubin），无法排除工具对任意输入崩溃；补跑基线并用 --controls 附加结果后重新评估 |

## 汇总

- 总数：15
- `SUPPORTED`：5（一轮收敛 1）
- 其余：10
