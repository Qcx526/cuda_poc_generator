# 证据包：工具链复现率

口径：每次独立运行记一次，`success@k` = 成功次数 / 独立运行次数。

| CVE | success@k | 成功率 | 95% CI | 平均轮数 | 终止诊断 | 规格 |
|---|---|---|---|---|---|---|
| CVE-2024-0076 | 5/5 | 100% | [57%, 100%] | 2 | HARNESS_STEP_FAILED | 有 |
| CVE-2025-23339 | 4/5 | 80% | [38%, 96%] | 1 | — | 有 |

## 汇总

- 独立运行：10 次，成功 9 次
- **success = 90%**，95% CI [60%, 98%]
- 至少一次成功的 CVE：2 / 2

> 区间宽度说明样本量：CI 越宽，结论越只能当方向看。

## 判定依据

每个 `SUPPORTED` 都满足三条：受控样本崩溃、良性基线干净、单变量对照未全崩。
只有 `SUPPORTED` 计入上表；`NOT_VERIFIED` 与 `UNKNOWN` 都算未成功。

## 复现命令

```bash
python -m src.batch_loop --cve --cve CVE-2024-0076 --cve CVE-2025-23339 --iterations 2 --repeat 5 --workdir data\loop\s5d
python -m tools.make_table --workdir data\loop\s5d
```
