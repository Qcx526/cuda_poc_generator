# F10-Step1-R1：测量可信度修复与约束优先对照

基线 `f54ecab`。本轮不追求崩溃，先让测量可信，再测"V2 是否改善约束推理"。

## 一、修正实验归档（不改历史）

`summary.json` 当初把 B 组 `exit=1` 记为 `anomaly=true` / `OBSERVED_ANOMALY`，
与后来 `evaluation.json` 的 `REJECTED` 冲突。**原始日志与 summary 一律保留**，
新增 `data/driver/f10step1/reclassification.json`，明确标注"来自原始观测的重新解释"。

新的状态阶梯（`src/exec_evidence.py`）七级：

```
GENERATION_COMPLETED → CANDIDATE_STARTED → INPUT_CREATED → TARGET_TOOL_INVOKED
→ TARGET_TOOL_RETURNED → OBSERVED_ABNORMAL_TERMINATION → VULNERABILITY_VERIFIED
```

判据：**只有信号（exit<0 或 ≥128）或超时才叫异常终止**；`exit=1` 是干净拒绝。
`VULNERABILITY_VERIFIED` 不由本模块授予，必须有独立差分。

重分类结果：

| 组 | 最高状态 | 说明 |
|---|---|---|
| A | `CANDIDATE_STARTED` | 脚本自身 `struct.error`，从未调用工具 |
| B | `TARGET_TOOL_RETURNED` | 工具返回 1（拒绝），非异常终止 |

## 二、可信执行证据：本轮缺口如实标记

B 组候选内部可能循环多次调用 nvdisasm，但**只保留了最后一次退出码**，
输入哈希与工具 stderr 都丢了。因此：

```
per_invocation_records: EVIDENCE_MISSING
input_sha256:           EVIDENCE_MISSING
stderr_of_tool:         EVIDENCE_MISSING
```

**不据 `EXIT=1` 补造逐次数据**，也不把它当作"一次目标程序执行"。
`ToolInvocation` 已按"每次调用一条记录"建模（工具名/版本、输入 SHA256、退出码、
stdout/stderr、超时、信号、run_id），供下一轮使用。

## 三、冻结的 A/B 输入

`data/driver/f10step1r1/frozen_inputs.json` 记录了两次输入的确切内容与哈希：

| | A | B |
|---|---|---|
| 形式 | 纯文本 7 行 | JSON（V2 PUBLIC_ONLY payload） |
| 字符数 | 556 | 1964 |
| 引用方式 | 无 id，只能引原文片段 | 有 id（A1–A6） |
| 额外字段 | — | `entry_surface.trust_boundary`、`contract` |

**信息差异如实记录**，不假装等价；差异方向对 B 略有利（多两个字段），
但都是公告级信息，不含触发配方。

## 四、约束优先对照（真实模型，各一次）

任务改为**只出结构化分析**，不出代码：要求给出 `facts`（附逐字 quote）、
`hypotheses`（附 `evidence_request.observable` 与 `would_refute_if`）、`unknowns`。

评价器不看关键词，只看可核对的事实：

- 引用的 id 是否存在；
- `quote` 是否**逐字出现在该组输入文本中**；
- 是否出现输入里没有的具体数值/地址；
- 每条假设的 EvidenceRequest 是否同时给出可观测项与推翻条件。

| 指标 | A | B |
|---|---|---|
| facts / hypotheses | 4 / 3 | 4 / 3 |
| 引用错误 | 0 | 0 |
| quote 可核对 | 4/4 | 4/4 |
| 无据断言 | 0 | 0 |
| 编造数值 | 无 | 无 |
| ER 含可观测项与推翻条件 | 3/3 | 3/3 |

原始输出：`data/driver/f10step1r1/arm_{A,B}_response.txt`、`evaluation.json`。

### 4.1 唯一可辨的差异：引用形式

- A 的 `cites` 是原文片段（`"cve: CVE-2025-23340"`），人能读，**机器无法校验结构**；
- B 的 `cites` 是 id（`A3`、`A6`），可直接与投影比对。

这是**可审计性**的差异，不是推理质量的差异。

### 4.2 内容差异

A 在 `unknowns` 里点名了 `sh_size / sh_entsize / sh_info / sh_link`——这些是它**推测**的可能字段，
放在 unknowns 是正确位置；B 的 unknowns 更概括（"具体字段及取值范围"）。
两者都没有把推测写成事实。

## 五、GO / NO_GO

**扩大样本量：NO_GO（现在）。**

理由：两组在四项客观指标上**完全持平**，唯一区别是引用形式。
在这种状态下增加 n，只会得到"更多持平"，浪费调用预算。

**先做三件事再考虑扩样**：

1. 把 `ToolInvocation` 真正接进执行器，补齐逐次证据（当前是 EVIDENCE_MISSING）；
2. 让两组的**证据 id 对称**（A 也带上 from-source id），否则引用形式差异会一直掩盖真实差异；
3. 增加一个**有区分度的判据**：不看"是否给了 ER"，而看"ER 所指向的观测能否区分两个竞争假设"。

**值得继续：YES**，但方向是提高判据分辨率，不是加样本。

## 六、静态证据口径修正

`0x733e240` 指向 UTF-16 字符串 `EnableDirectFlip`，**作为 Escape 回调的假设记 REFUTED**。

但必须同时写明：

> `.pdata` 没有覆盖 ≠ 绝对不是代码。当前分类器只回答"该 RVA 是否落在 .pdata 记录内、
> 首字节像不像 UTF-16"，**不是对执行语义的穷尽证明**。
> `code=0` 的统计也只覆盖本窗口内的 57 个 lea 目标。

## 七、回归

```
1912 passed / 68 skipped / 0 failed
```

## 八、边界

未重跑 CUDA CVE、未改 P11/P12、未执行内核 Escape、未新增 Mock；
模型调用 2 次（每臂 1 次），无重试。
