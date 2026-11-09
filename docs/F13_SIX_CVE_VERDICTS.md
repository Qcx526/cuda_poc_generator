# F13：六 CVE 完整收口与机制判据纠正

基线 `f9897b9`。后台批量 `jePAt4` 已自然结束（1h19m），六个 CVE 全部有终态。

## 一、六个 CVE 的最终状态（循环判定）

| CVE | 循环状态 | 轮数 | 耗时 | 证据 |
|---|---|---|---|---|
| CVE-2024-0111 | **SUPPORTED** | 1 | 584s | trusted 1 / script 1 / 24 invocations |
| CVE-2024-0124 | **SUPPORTED** | 1 | 576s | 1 / 1 / 38 |
| CVE-2024-0125 | **SUPPORTED** | 1 | 681s | 1 / 1 / 42 |
| CVE-2025-23338 | EXHAUSTED | 2 | 739s | 2 / 2 / 42 |
| CVE-2025-23308 | EXHAUSTED | 2 | 848s | 2 / 2 / 42 |
| CVE-2025-23346 | EXHAUSTED | 2 | 1316s | 2 / 2 / **6** |

`EXHAUSTED` 是"预算内没做出差分"，不是错误。三条都保留失败轮次的候选、观测与 trusted 记录。
23346 只有 6 次工具调用，说明候选构造的输入基本没被工具处理——这条线索留给下一轮，本轮不改判据。

**证据完整度**：六个 CVE 均有 `iteration_*_trusted.json` 与 `iteration_*_script.py`，无缺失。

## 二、机制判据的三处纠正

### 2.1 先纠正一个事实出入

任务描述说"有两条 `CVE_MECHANISM_SUPPORTED`"，并提到 23308、23346。
实际旧文件（`f13-verdicts.prev.json`）是**三条**，且**不含** 23308/23346：

| CVE | 旧状态 | 崩溃工具 | 崩溃次数 |
|---|---|---|---|
| CVE-2024-0111 | CVE_MECHANISM_SUPPORTED | cuobjdump（=advisory） | 4 |
| CVE-2024-0124 | CVE_MECHANISM_SUPPORTED | cuobjdump, nvdisasm | 10 |
| CVE-2025-23338 | CVE_MECHANISM_SUPPORTED | nvdisasm（=advisory） | 2 |
| CVE-2025-23308 | TOOL_EXECUTED | — | **0** |
| CVE-2025-23346 | TOOL_EXECUTED | — | **0** |

23308/23346 从未产生崩溃，因此不存在"保留目标工具差分支持"这回事——它们连差分都没有。

### 2.2 旧判据为什么错

```python
mechanism = differential and tool in crashing_tools and control
```

即：**advisory 指定的工具崩了 + 良性/对照干净 ⇒ 判为机制成立**。

这把"工具在这个输入上崩溃"当成了"该 CVE 的漏洞机制已得到证明"。
nvdisasm 段错误和 UAF、越界写、堆溢出、NULL 解引用是不同层次的命题，前者推不出后者。

### 2.3 现在的六级模型

```
TOOL_EXECUTED → CRASH_OBSERVED → DIFFERENTIAL_SUPPORTED
→ TARGET_TOOL_DIFFERENTIAL_SUPPORTED → CVE_MECHANISM_SUPPORTED → CVE_ATTRIBUTED
```

- 前四级由 trusted 记录直接推出；
- **第五级必须有独立的根因证据**：`data/driver/f13-mechanism/<CVE>.json` 里显式声明
  `mechanism_evidence`，且能对上该 CVE 声称的机制（UAF / OOB / 空指针等）；
- 第六级还要求该证据包含 attribution 字段；
- 文件不存在 = **UNKNOWN**，不是"大概没问题"。

重算结果（`data/driver/f13-verdicts.json`，旧文件保留为 `.prev.json`）：

| CVE | 新状态 | 机制 |
|---|---|---|
| CVE-2024-0111 | TARGET_TOOL_DIFFERENTIAL_SUPPORTED | **UNKNOWN** |
| CVE-2024-0124 | TARGET_TOOL_DIFFERENTIAL_SUPPORTED | **UNKNOWN** |
| CVE-2025-23338 | TARGET_TOOL_DIFFERENTIAL_SUPPORTED | **UNKNOWN** |
| CVE-2024-0125 | DIFFERENTIAL_SUPPORTED | UNKNOWN（崩的是 cuobjdump，advisory 是 nvdisasm） |
| CVE-2025-23308 | TOOL_EXECUTED | UNKNOWN |
| CVE-2025-23346 | TOOL_EXECUTED | UNKNOWN |

**全库现在没有任何 `CVE_MECHANISM_SUPPORTED`，也没有 `CVE_ATTRIBUTED`。**

## 三、判定只认 trusted 记录

`tools/cuda/f13_verdicts.py` 的 `evaluate()` 在无 `iteration_*_trusted.json` 时直接返回
`EVIDENCE_MISSING`，**不回退候选的 `[CPG_RUN]` 自述**。这条在真实数据上得到验证：

| 批次 | 结果 |
|---|---|
| `f10s2b`（F10 六例） | 全部 `EVIDENCE_MISSING`——当时只存了运行日志 |
| `f12b` CVE-2024-0124 / 0125 / 23338 | `EVIDENCE_MISSING`——接线前跑的三例 |

它们此前都被判成过 SUPPORTED。现在判定器拒绝给结论，而不是拿候选自述凑数。

## 四、Windows/WSL 四组 API 复测（保留）

`data/driver/f13-api-recheck/recheck.json`，四个组合全部 `RAN`、exit 0、8 次 API、API 序列与上一轮一致：

| 平台 | 任务 | 结果 | 数据 |
|---|---|---|---|
| windows | normal | exit 0 | `DATA=OK` |
| windows | boundary | exit 0 | `BOUNDARY=DONE` |
| linux | normal | exit 0 | `DATA=OK` |
| linux | boundary | exit 0 | `BOUNDARY=DONE` |

信任标注保持分离：`exit/signal = HARNESS_OBSERVED`，`API 行与数据 = CANDIDATE_REPORTED`。
后者仍是候选打印，未升级为独立观测。

## 五、回归

```
1913 passed / 67 skipped / 0 failed
```

## 六、边界

未新增 CVE、未改原始证据、未放宽判据；`f13-verdicts.json` 是重新评价的产物，
旧文件原样保留为 `f13-verdicts.prev.json`。
