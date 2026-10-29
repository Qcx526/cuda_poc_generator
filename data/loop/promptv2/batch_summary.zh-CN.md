# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|
| CVE-2023-0196 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 772 | 受控样本 7/12 个产生崩溃退出码 |
| CVE-2025-23338 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 616 | 受控样本 2/5 个产生崩溃退出码 |
| CVE-2025-23340 | EXHAUSTED | 1 | NOT_VERIFIED | UNCLASSIFIED | 150 | 未观察到任何样本退出码；输入可能未到达解析器 |

## 汇总

- 总数：3
- `SUPPORTED`：2（一轮收敛 0）
- 其余：1
