# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | SUPPORTED | 1 | SUPPORTED | — | 3/3 | 317 | 受控样本 1/4 个产生崩溃退出码 |
| CVE-2025-23338 | SUPPORTED | 1 | SUPPORTED | — | 3/3 | 236 | 受控样本 1/35 个产生崩溃退出码 |
| CVE-2025-23339 | SUPPORTED | 2 | SUPPORTED | HARNESS_STEP_FAILED | 2/3 | 1115 | 受控样本 7/7 个产生崩溃退出码 |

## 汇总

- 总数：3
- `SUPPORTED`：3（一轮收敛 2）
- success@3：8/9 = 89%
- 其余：0
