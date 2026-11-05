# F6 四组实验记录

所有组使用 DLL v2（cf8c619f…），max_calls=200，mutation_seed=11，2 轮。
v1 实验（f6-A…）因预算 40 触发耗尽，已作废；下为 f6b-*。

| arm | 轮 | ran | level | calls | escape | distinct | first_trigger | oracle |
|---|---|---|---|---|---|---|---|---|
| A | 1 | True | TRIGGER_CONFIRMED | 200 | 195 | 98 | 50 | True |
| A | 2 | True | TRIGGER_CONFIRMED | 200 | 192 | 95 | 18 | True |
| B | 1 | True | TRIGGER_CONFIRMED | 200 | 194 | 189 | 10 | True |
| B | 2 | False | NO_EXECUTION | 0 | 0 | 0 | None | False |
| C | 1 | True | TRIGGER_CONFIRMED | 42 | 30 | 21 | 17 | True |
| C | 2 | True | TRIGGER_CONFIRMED | 41 | 29 | 27 | 10 | True |
| D | 1 | True | TRIGGER_CONFIRMED | 200 | 194 | 184 | 171 | True |
| D | 2 | True | TRIGGER_CONFIRMED | 62 | 46 | 30 | 18 | True |

结论：四组首轮均触发 AUTHZ_BYPASS，未出现 OOB_READ；
A 组（仅契约）在 R1 即触发，说明当前 benchmark 对这两个缺陷难度偏低（天花板效应）。
C 组 API 调用数显著低于 A/B/D（42 vs 200），提示变异上下文改变了探索效率而非成功率。