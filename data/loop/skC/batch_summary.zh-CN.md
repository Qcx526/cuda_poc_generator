# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | SUPPORTED | 2 | SUPPORTED | NO_EFFECT | 1/3 | 1124 | 受控样本 1/4 个产生崩溃退出码 |
| CVE-2025-23338 | SUPPORTED | 2 | SUPPORTED | NO_EFFECT | 3/3 | 883 | 受控样本 1/1 个产生崩溃退出码 |
| CVE-2025-23339 | SUPPORTED | 1 | SUPPORTED | — | 1/3 | 484 | 受控样本 7/8 个产生崩溃退出码 |

## 汇总

- 总数：3
- `SUPPORTED`：3（一轮收敛 1）
- success@3：5/9 = 56%
- 其余：0
