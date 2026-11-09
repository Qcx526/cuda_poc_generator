# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2025-23338 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 296 | 受控样本 2/6 个产生崩溃退出码 |
| CVE-2024-0111 | SUPPORTED | 2 | SUPPORTED | NO_OBSERVATION | 1/1 | 1358 | 受控样本 6/6 个产生崩溃退出码 |
| CVE-2024-0124 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 281 | 受控样本 2/2 个产生崩溃退出码 |
| CVE-2024-0125 | SUPPORTED | 1 | SUPPORTED | — | 1/1 | 579 | 受控样本 2/2 个产生崩溃退出码 |
| CVE-2025-23308 | SUPPORTED | 2 | SUPPORTED | NO_EFFECT | 1/1 | 1339 | 受控样本 2/2 个产生崩溃退出码 |
| CVE-2025-23346 | SUPPORTED | 2 | SUPPORTED | NO_OBSERVATION | 1/1 | 1104 | 受控样本 8/10 个产生崩溃退出码 |

## 汇总

- 总数：6
- `SUPPORTED`：6（一轮收敛 3）
- success@1：6/6 = 100%
- 其余：0
