# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-53877 | SUPPORTED | 2 | SUPPORTED | NO_EFFECT | 1/1 | 1104 | 受控样本 3/6 个产生崩溃退出码 |
| CVE-2025-23247 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 0/1 | 1344 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2025-23339 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 777 | 受控样本 1/3 个产生崩溃退出码 |
| CVE-2024-0109 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 471 | 受控样本 4/6 个产生崩溃退出码 |
| CVE-2024-0110 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 477 | 受控样本 10/12 个产生崩溃退出码 |
| CVE-2023-0196 | SUPPORTED | 2 | SUPPORTED | NO_EFFECT | 1/1 | 1560 | 受控样本 2/2 个产生崩溃退出码 |

## 汇总

- 总数：6
- `SUPPORTED`：5（一轮收敛 3）
- success@1：5/6 = 83%
- 其余：1
