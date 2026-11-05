# P13-4-F7-R1：盲测合同与 CVE 判据硬化

基线 `6bddcf3`。本阶段只修 F7 暴露的科研有效性问题。

## 一、Step 1：历史信息泄漏审计

### 1.1 原 `--freeze-history` 只屏蔽了一个字段

`src/spec_model.py` 的 `prompt_brief()` 在冻结模式（`CPG_SPEC_FROZEN=1`）下仅跳过
`history.observed`，以下内容**仍然进入 Prompt**：

| 泄漏项 | 原状态 | 证据 |
|---|---|---|
| `parser.entry_function` + 每个字段的 `offset/size/check/semantics` | 总是注入 | `field %-18s off=%-6d ...` |
| `oracle: <field> must satisfy <condition> -> <effect>` | 总是注入 | 内部触发公式 |
| `claims` 中 `verified_by=execution` 的条目 | 总是注入 | `verified by execution: ...` |
| `history.refuted` | 总是注入 | `already refuted (do NOT repeat)` |
| `observable.value`（实测崩溃现象） | 总是注入 | `observable: signal=SIGSEGV` |
| `mutation.seed`（历史 PoC 文件名） | 随完整 prompt 进入 | 规格 `mutation` 段 |

**结论：F7 那次 `--freeze-history` 运行并非盲测。**

### 1.2 新增公告级投影

`VulnSpec.public_brief()`，仅在 `CPG_BLIND_CONTRACT=1` 时启用，只输出：

```
cve / component / cwe / affected(版本窗口) / target / invoke / input(格式与 magic)
note: 输入内部结构与触发条件未公开，需自行推导
```

实测（CVE-2025-23340）：完整 brief 1468 字符 → 盲测 228 字符，`parser` / `oracle` /
`observed` / `refuted` / `field` 全部消失。

顺带修掉一个 bug：`affected` 原先把 `to_evidence()` 的布尔值打印成 `affected: True`，
对模型零信息；现改为 `11.0..12.9 (fixed in 13.0)`。

### 1.3 端到端检查

`tests/test_blind_contract.py` 对**磁盘上全部 9 个规格**逐一断言投影不含禁用词，
并要求盲测仍然给出目标标识（组件、调用方式、输入格式），避免"为了不泄漏而变得无用"。

## 二、Step 2：判据分级

`src/cve_grading.py`，五级：

```
TOOL_EXECUTED → CRASH_OBSERVED → DIFFERENTIAL_SUPPORTED
→ CVE_MECHANISM_SUPPORTED → CVE_ATTRIBUTED（永不自动授予）
```

规则：

- **样本数与工具执行数分开统计**（4 样本 × 2 工具 = 8 次执行，不是"1/4 样本"）；
- 崩溃必须来自**公告点名的工具**才计入机制级；
- 机制级还必须 `single_field_differential=True`；
- 基线（BENIGN）或对照（CONTROL）任一崩溃，即退回 `CRASH_OBSERVED`；
- 版本身份取**容器 banner**（`CUDA Version 11.2.2`），不采信候选自述。

### 0076 重新分级

| 项 | 值 |
|---|---|
| 样本 / 工具执行 / 崩溃 | 4 / 8 / 2 |
| 崩溃工具 | `cuobjdump` |
| benign / control 干净 | 是 / 是 |
| 单字段差分 | **False** |
| **最高级别** | **DIFFERENTIAL_SUPPORTED** |

原来那个 `SUPPORTED` 应读作"观察到崩溃"，**不是**"复现了 CVE 机制"，更不是归属。

## 三、Step 4：CVE-2025-23340 盲测闭环

命令：

```bash
python -m src.batch_loop --cve CVE-2025-23340 --iterations 2 \
  --workdir data/loop/f7r1 --image cpg/cuda112-py3:1.0 \
  --tier userland_toolchain --blind-contract
```

结果：`EXHAUSTED`，it=2，`UNKNOWN / UNCLASSIFIED`，1843 秒。

| 轮 | 样本 | 运行 | 判据 |
|---|---|---|---|
| 1 | `poc_rela_sh_size_11.cubin` + 2 对照 | 4 次，全部 exit=0 | `TOOL_EXECUTED` |
| 2 | `poc_rela_sh_size_8.cubin` + 1 对照 | malicious exit=139，**control 也 exit=139** | `CRASH_OBSERVED` |

**第二轮的修改是反馈驱动的**：PoC 文件名、尺寸取值（11 → 8）与对照设置都变了，
说明模型读到了第一轮"全部 exit=0"的公开反馈并换了取值。但第二轮**对照组同样崩溃**，
按分级规则不能算差分成立——这正是分级设计要拦住的情形。

## 四、Step 3：证据留档缺口（未解决）

本次仍只有：

```
iteration_1_candidate.txt   运行日志
iteration_1_observation.txt 观测
loop_report.zh-CN.md        报告
```

**没有**：送入模型的完整 Prompt、模型原始 Response、生成的 PoC 源码与其 SHA256、
生成输入的 SHA256、目标工具可执行文件 SHA256。

即 Step 3 要求的"每轮归档"**当前管道做不到**，本轮未伪称已补齐。这是下一阶段必须先改的
（在 `code_generator` 落盘 prompt/response，在 run 目录落 artifact 清单与哈希）。

## 五、回归

```
tests/test_blind_contract.py   9 个规格 × 2 类断言 + 2 条结构性断言
tests/test_cve_grading.py      7 条（含 0076 矛盾回归）
```

## 六、结论

| 项 | 状态 |
|---|---|
| 盲测合同 | 已实现并端到端测试 |
| 判据分级 | 已实现，0076 重分级为 DIFFERENTIAL_SUPPORTED |
| 23340 盲测闭环 | 已跑，两轮均未达差分 |
| 反馈驱动修改 | 观察到（代码结构变化），但被对照崩溃否证 |
| 每轮证据留档 | **未达成** |
| CVE_ATTRIBUTED | 无任何一条达成 |
