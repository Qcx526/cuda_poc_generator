# P13-4-F1：四组实验合同与指标

本文件定义 A/B/C/D 四组共用同一套生成、执行与评价条件。任何一组偏离合同，其结果不与其他组比较。

## 1. 四组的唯一差别

| 组 | 输入 | 是否含变异 |
|---|---|---|
| A | CVE 描述 + 已验证 ABI | 否 |
| B | A + Binary Static Facts（`data/driver/static_facts/`） | 否 |
| C | A + Stateful Mutation（`src/driver_mutation.py`） | 是 |
| D | A + Static Facts + Stateful Mutation | 是 |

**除上表外，一切必须相同**：模型与温度、轮数、token 预算、ABI 版本（`src/driver_abi.py` 的哈希）、初始种子集合（`data/driver/seeds/corpus.json`）、反馈格式（`CPG_DRIVER`/`CPG_CLAIMS`/`CPG_EXTERNAL`）、停止条件、安全边界。

## 2. 一次实验 = 一个多轮过程

- 一个实验目录（`data/driver/<label>/CVE-…/roundN/`）算**一个样本**。
- 同一过程的各轮**不独立**，不得把 2 轮当 2 个样本统计。
- 组间比较至少需要 3 个独立实验目录（不同随机种子/不同起始假设），当前只有 1 个。

## 3. 随机性来源

- `random.Random(seed)` 固定，seed 写入实验目录的 `seed.txt`。
- LLM 侧无法完全复现时，必须记录模型名、温度、请求时间；缺失即标记 `NOT_REPRODUCIBLE`。

## 4. 安全边界（硬约束）

允许在唯一 Windows 主机执行：公开、无害的 D3DKMT 调用（adapter/device/context 建立与释放、空 escape）。

不得执行：厂商私有 Type/命令体、越权对象组合、可能触发 BugCheck 的输入。

这类候选只允许**生成 + 离线检查**，留在可恢复隔离环境中执行。

## 5. 指标定义

| 指标 | 定义 | 数据来源 |
|---|---|---|
| 代码生成成功率 | 产出 `poc.py` 且能解析的轮次 / 总轮次 | `poc.py` + `ast.parse` |
| 可运行比例 | 进程正常退出并留下 `CPG_RESULT` 的轮次 / 总轮次 | `run.log` |
| 对象状态建立率 | 出现 `STATUS_SUCCESS` 的 open_adapter 与 create_device 的轮次 / 总轮次 | `CPG_CLAIMS.calls` |
| 有效且不同的输入数 | 结构化参数组合去重后的数量 | `src/driver_mutation.py :: Corpus` |
| 修正率 | 相对上一轮代码哈希变化、且失败点发生移动的轮次 / 可比较轮次 | 哈希 + `CPG_DRIVER.state` |
| 无进展重复率 | 连续两轮同一失败调用（`driver_feedback.is_repeat`）的占比 | `repeat_roundN.json` |
| 组间覆盖差异 | 状态集合与参数组合集合的差异 | 指标汇总脚本 |
| **内核覆盖率** | **不可用** | 本机无独立内核观测器 |

最后一行必须显式标注 `kernel_coverage: UNAVAILABLE`；**不得用 NTSTATUS 的种类数替代覆盖率**。

## 6. 汇总命令

```bash
python -m tools.driver.experiment_metrics data/driver/<label>
```

输出含 `rounds / with_calls / states / calls / distinct_statuses / code_hashes /
code_changed_between_rounds / abi_reuse / abi_redefined / kernel_coverage`。

## 7. 当前进度

- A、B 各跑过一轮 2 轮实验（`p13_3h2_a`、`p13_3h3_b`），仅用于验证流程可比较性。
- C、D 尚未运行：变异模块与种子语料已就绪，但还没有把变异注入生成循环。
- 因此本文件目前是**合同**，不是结论。
