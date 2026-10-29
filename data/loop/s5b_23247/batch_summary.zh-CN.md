# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2025-23247 | EXHAUSTED | 2 | NOT_VERIFIED | HARNESS_STEP_FAILED | 0/5 | 668 | 步骤失败：[CUDA_STEP:S02] generate legal cubin/fatbin with .nv_debug_source — FAIL: baseline cubin/fatbin without a parsable .nv_debug_source |

## 汇总

- 总数：1
- `SUPPORTED`：0（一轮收敛 0）
- success@5：0/5 = 0%
- 其余：1
