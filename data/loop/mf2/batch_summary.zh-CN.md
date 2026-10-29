# 工具链闭环批跑结果

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |
|---|---|---|---|---|---|---|---|
| CVE-2024-0076 | ERROR | 1 | — | STAGE_ERROR | 0/1 | 365 | stage execute failed: Command '['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--tmpf |

## 汇总

- 总数：1
- `SUPPORTED`：0（一轮收敛 0）
- success@1：0/1 = 0%
- 其余：1
