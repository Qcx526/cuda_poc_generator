# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2025-23338 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 0/1 | 739 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2024-0111 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 584 | 受控样本 4/12 个产生崩溃退出码 |
| CVE-2024-0124 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 576 | 受控样本 10/34 个产生崩溃退出码 |
| CVE-2024-0125 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 681 | 受控样本 1/4 个产生崩溃退出码 |
| CVE-2025-23308 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 0/1 | 848 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2025-23346 | EXHAUSTED | 2 | NOT_VERIFIED | UNCLASSIFIED | 0/1 | 1316 | EVIDENCE_MISSING：trusted 记录里没有任何工具调用 |

## 汇总

- 总数：6
- `SUPPORTED`：3（一轮收敛 3）
- success@1：3/6 = 50%
- 其余：3
