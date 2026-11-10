# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2025-23346 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 629 | 受控样本 4/5 个产生崩溃退出码 |
| CVE-2025-23308 | EXHAUSTED | 1 | UNKNOWN | UNCLASSIFIED | 0/1 | 714 | 机制对照 1/15 个同样崩溃；所声称的触发条件未得到支持，崩溃不可归因于受控变量 |
| CVE-2025-23338 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 284 | 受控样本 14/70 个产生崩溃退出码 |
| CVE-2024-0111 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 576 | 受控样本 3/10 个产生崩溃退出码 |
| CVE-2024-0124 | SUPPORTED | 2 | SUPPORTED | NO_OBSERVATION | 1/1 | 1283 | 受控样本 1/5 个产生崩溃退出码 |
| CVE-2024-0125 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 582 | 受控样本 9/20 个产生崩溃退出码 |

## 汇总

- 总数：6
- `SUPPORTED`：5（一轮收敛 4）
- success@1：5/6 = 83%
- 其余：1
