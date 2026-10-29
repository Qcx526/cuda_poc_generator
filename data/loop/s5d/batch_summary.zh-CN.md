# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | SUPPORTED | 2 | SUPPORTED | HARNESS_STEP_FAILED | 5/5 | 1064 | 受控样本 1/4 个产生崩溃退出码 |
| CVE-2025-23339 | SUPPORTED | 1 | SUPPORTED | — | 4/5 | 317 | 受控样本 4/4 个产生崩溃退出码 |

## 汇总

- 总数：2
- `SUPPORTED`：2（一轮收敛 1）
- success@5：9/10 = 90%
- 其余：0
