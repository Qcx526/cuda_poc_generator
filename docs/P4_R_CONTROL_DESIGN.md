# P4-R 对照设计的缺陷与修复方案（待应用）

报告语言：`zh-CN`。记录一个由 success@3 实验首个数据点暴露的提示词缺陷。
**本文件只记录方案，代码修改等实验跑完后应用**，以免污染正在测量的系统。

## 1. 现象

`CVE-2025-23339` 在 success@3 的第 1 次运行中，两轮均为 `FALSE_POSITIVE`：

> The one-variable controls crashed too, so the observed crash is not
> attributable to your trigger.

同一个 CVE 此前一轮就 `SUPPORTED`。判据本身没错——**对照也崩了，证据就不成立**。

## 2. 根因：提示词对"对照"的定义不完整

当前第 24 条只说：

> 触发必须崩，而对照——同一文件、只改一个变量——不崩。

问题在于**没有规定改成什么值**。模型可以：

- 正确做法：把 `sh_size` 改回**良性基线里的原始值**（0076 的 `shsize_original` 就是这么做的）；
- 错误做法：把 `sh_size` 改成**另一个同样越界的值** → 对照也崩 → 证据作废。

这不是模型"不听话"，是我们给的约束不够具体。

## 3. 修复措辞（实验结束后应用）

把第 24 条改为：

```text
24. **Differential Is The Definition of Success**: the trigger must crash while
    the control does not. A control MUST restore the mutated field to the value
    it has in the benign baseline (or to a value you can justify as safe) and
    keep every other byte identical. A control built from another crafted value
    is not a control: if it crashes too, your evidence is void and you must say
    so instead of claiming success. Name controls `<field>_restored_<value>` so
    the harness can tell them apart from triggers.
```

同时在 `[EVS]` 的 oracle 行后补一句基线值提示（若规格里知道原始字段值）。

## 4. 预期收益

`FALSE_POSITIVE` 在 23339 上连续两轮出现，说明这不是偶发。修复后：

- 对照变成"恢复基线值"，与良性样本同源，崩溃概率应接近 0；
- 判定链路 `恶意崩 + 对照不崩 + 基线净` 才成立，减少无效迭代。

## 5. 验证方式（实验纪律）

1. 先跑完当前配置的 success@3（5 个 CVE），记作 **A 组**；
2. 应用本修复，用完全相同的 5 个 CVE、同样 3 次重复跑 **B 组**；
3. 比较 `success@k` 与 `FALSE_POSITIVE` 占比 —— 这就是"对照设计"的消融实验。

两组之间**不做任何其他改动**，否则结论无法归因。
