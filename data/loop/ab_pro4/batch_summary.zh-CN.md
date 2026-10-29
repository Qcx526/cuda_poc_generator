# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | EXHAUSTED | 2 | UNKNOWN | INCONCLUSIVE | 0/3 | 647 | 缺少良性基线（benign.cubin），无法排除工具对任意输入崩溃；补跑基线并用 --controls 附加结果后重新评估 |

## 汇总

- 总数：1
- `SUPPORTED`：0（一轮收敛 0）
- success@3：0/3 = 0%
- 其余：1
