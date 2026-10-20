# P4-I 通用闭环方法：失败分类学、反馈生成与迭代报告

报告语言：`zh-CN`。本文件描述与具体 CVE 无关的通用机制。目标是：**换一个漏洞，
只需要提供输入证据与样本，其余环节不变。**

## 1. 为什么"通用"落在失败分类学上

不同漏洞的触发手段千差万别，但**失败的原因只有有限的几种**。把失败归一化成
十个代码，每个代码配一条可执行指令，模型在下一轮收到的就是"该怎么改"，
而不是"你的 PoC 不行"。这是方法论层面的泛化，不是函数层面的复用。

| 诊断码 | 触发条件（证据） | 处置指令要点 |
|---|---|---|
| `SYNTAX_ERROR` | 候选不通过语法解析 | 只修语法，策略不动 |
| `LINT_VIOLATION` | 命中领域 lint | 按 lint 指名的点修 |
| `EXECUTOR_FAILURE` | 执行器返回非零 | 修 harness/超时，不动触发逻辑 |
| `STAGE_ERROR` | 阶段异常 | 修即时错误；复发说明策略不可实现 |
| `PATH_NOT_REACHED` | 插桩显示目标函数从未执行 | 重建入口条件（API 序列/格式/指令/profile/版本门），禁止盲改字节 |
| `PRECONDITION_VIOLATED` | `NOT_INITIALIZED`、版本门 | 先建立环境状态，再发同一触发 |
| `FALSE_POSITIVE` | 机制对照全崩 | 重设计变量隔离；继续变异只会复现同一假阳性 |
| `INCONCLUSIVE` | 缺良性基线 | 先补一条不该崩的基线 |
| `NO_EFFECT` | 无任何可观测效果 | 证明输入到达解析器、字段被消费 |
| `UNCLASSIFIED` | 不匹配任何模式 | 先加插桩区分"没到达/到达无效/被抑制"，且**不重试** |

两条设计原则：

1. **`PATH_NOT_REACHED` 优先级最高**。只要插桩证明目标函数没跑，文本理由一律
   让位——此时任何字节变异都是浪费时间。这条直接来自 0107 的教训（cdb 断点
   从未命中）。
2. **`UNCLASSIFIED` 不重试**。归因不了就不烧预算，宁可人工介入。

## 2. 两条反馈通道

```text
静态失败（语法/lint） ──┐
                        ├─→ IterativeCandidateGenerator ─→ 新候选
动态失败（诊断指令） ───┘
```

- 静态通道在**一轮生成内部**重试（默认 3 次），错误信息逐字回传；
- 动态通道在**跨迭代**生效：控制器把上一轮的诊断指令塞进下一轮 prompt，
  并把上一版候选一并带上（注明"已被否决，保留仍正确的部分"）。

`src/iterative_generator.py` 与 CVE 无关，只负责 prompt 组装与静态门禁。

## 3. 控制器与报告

- `src/closed_loop.py`：有界状态机，产出 `LoopResult.trace`（每轮判定 + 诊断码 +
  处置指令）；内核层默认 `BLOCKED`，执行层强制单发。
- `src/loop_report.py`：把 trace 渲染成中文 Markdown，可直接作为论文附录。

报告结尾固定写明边界：`SUPPORTED` ≠ `VERIFIED`。

## 4. 接入一个新 CVE 需要什么

1. 七个输入的结构化证据（`input_manifest`）；
2. 样本集与命名约定（`benign*` / `_ctrl*` / `malicious*`），或显式标签；
3. 选择执行层：`userland_toolchain` / `driver_userland` / `driver_kernel`。

其余（生成、静态门禁、执行、差分评级、诊断、反馈、报告）全部复用。

## 5. 当前完成度

| 环节 | 状态 |
|---|---|
| 失败分类学 | ✅ `src/failure_taxonomy.py`，10 个诊断码 + 12 个用例 |
| 迭代生成器 | ✅ `src/iterative_generator.py`，静态重试 + 动态指令注入 |
| 控制器 | ✅ `src/closed_loop.py`，诊断接入 trace |
| 报告 | ✅ `src/loop_report.py` |
| 执行阶段 | ⚠️ `docker_matrix_stage` 骨架，待接样本发现与证据落盘 |
| 生成阶段 | ⚠️ 待包 `main.py --package` 子进程调用 |
| 插桩观测 | ⚠️ `reached` 参数已就绪，待接 cdb 判据（0107 已有手工方法） |

## 6. 下一步（把 ⚠️ 变 ✅）

1. `samples.py`：按命名约定发现样本并生成显式标签；
2. `generate_stage`：子进程调用现有 CLI，读回候选路径与静态状态；
3. `probe_reached`：用 cdb 断点命中与否填充 `reached`，让 `PATH_NOT_REACHED`
   从手工判断变成自动信号——这是 0107 这类"打不中"的漏洞的关键一环。
