# P4-J 工具链 CVE 批量闭环结果

报告语言：`zh-CN`。15 个工具链类 CVE（cuobjdump / nvdisasm 家族）经同一闭环流程
（生成 → 容器执行 → 差分评级 → 诊断 → 反馈）跑完一轮，`--iterations 2`。

| CVE | 状态 | 轮数 | 判定 | 终止诊断 | 耗时(s) |
|---|---|---|---|---|---|
| CVE-2022-21821 | SUPPORTED | 2 | SUPPORTED | LABEL_CONFLICT | 822 |
| CVE-2023-0196 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 539 |
| CVE-2024-0076 | EXHAUSTED | 2 | NOT_VERIFIED | HARNESS_STEP_FAILED | 604 |
| CVE-2024-0109 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 495 |
| CVE-2024-0110 | SUPPORTED | 2 | SUPPORTED | LABEL_CONFLICT | 791 |
| CVE-2024-0111 | SUPPORTED | 2 | SUPPORTED | INCONCLUSIVE | 779 |
| CVE-2024-0124 | EXHAUSTED | 2 | UNKNOWN | UNCLASSIFIED | 775 |
| CVE-2024-0125 | SUPPORTED | 2 | SUPPORTED | HARNESS_STEP_FAILED | 1603 |
| CVE-2024-53877 | EXHAUSTED | 2 | UNKNOWN | UNCLASSIFIED | 1159 |
| CVE-2025-23247 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 773 |
| CVE-2025-23308 | EXHAUSTED | 2 | NOT_VERIFIED | LABEL_CONFLICT | 761 |
| CVE-2025-23338 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 761 |
| CVE-2025-23339 | SUPPORTED | 1 | SUPPORTED | — | 343 |
| CVE-2025-23340 | EXHAUSTED | 2 | NOT_VERIFIED | NO_EFFECT | 646 |
| CVE-2025-23346 | EXHAUSTED | 2 | UNKNOWN | INCONCLUSIVE | 732 |

## 汇总

- 总数：15
- `SUPPORTED`：6（40%）
- 未达成：9

## 失败分布

| 诊断 | 数量 | 含义 |
|---|---|---|
| `NO_EFFECT` | 4 | 候选跑通但样本未崩溃：变异没打到解析器消费的字段 |
| `UNCLASSIFIED` | 2 | 证据不足且无法归因（如无法判定角色） |
| `HARNESS_STEP_FAILED` | 1 | 候选自身步骤失败（前置条件问题） |
| `LABEL_CONFLICT` | 1 | 候选自己声明的角色与文件名矛盾，且两轮未改对 |
| `INCONCLUSIVE` | 1 | 缺良性基线，无法判断区分力 |

## 读法

- `SUPPORTED` = 受控样本崩溃 + 良性基线干净 + 机制对照未全崩；不等于 CVE 级 `VERIFIED`。
- `NO_EFFECT` 是当前最大的一类失败：不是流水线坏，而是“输入到达工具但没触发缺陷”，
  属于生成策略问题，需要更强的变异先验（字段语义、对齐、长度边界）。
- 本轮修掉的流水线缺陷：打包失败被当成生成失败、生成失败无日志、标签冲突抛异常。
