# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | EXHAUSTED | 2 | NOT_VERIFIED | HARNESS_STEP_FAILED | 0/3 | 1297 | 步骤失败：[CUDA_STEP:S02] Inspect baseline ELF64 layout and select the section to mutate — FAIL: empty section header table: e_shnum=0 |

## 汇总

- 总数：1
- `SUPPORTED`：0（一轮收敛 0）
- success@3：0/3 = 0%
- 其余：1
