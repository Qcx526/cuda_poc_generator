# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | ERROR | 1 | — | STAGE_ERROR | 0/2 | 101 | stage generate failed: generation produced no candidate: 2/3 — 模型: deepseek-v4.1-flash-1017, 单次读取超时: 600s [2026-10-26 18:50:39] WARNING  cuda_poc_generator.llm_ |

## 汇总

- 总数：1
- `SUPPORTED`：0（一轮收敛 0）
- success@2：0/2 = 0%
- 其余：1
