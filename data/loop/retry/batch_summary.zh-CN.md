# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|
| CVE-2023-0196 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 539 | 受控样本未产生崩溃退出码（所有步骤均报告 OK） |
| CVE-2024-0076 | EXHAUSTED | 2 | NOT_VERIFIED | HARNESS_STEP_FAILED | 604 | 步骤失败：[CUDA_STEP:S02] generate a baseline valid cubin and verify normal parsing — FAIL: RuntimeError: no cubin baseline could be produced or located |
| CVE-2024-0109 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 495 | 受控样本 99/240 个产生崩溃退出码 |

## 汇总

- 总数：3
- `SUPPORTED`：1（一轮收敛 0）
- 其余：2
