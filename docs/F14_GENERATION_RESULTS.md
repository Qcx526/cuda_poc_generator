# F14：生成质量改进与六 CVE 完整复测

基线 `323fa35`（本轮起点），交付于 `f14b` 批次。

## 一、开场审计四条：核实结果

| 审计条目 | 结论 | 处理 |
|---|---|---|
| `src/trusted_grading.py` 远程缺失 | **属实**：只在磁盘，`git ls-tree` 无此文件 | 已提交，干净克隆可运行判定器 |
| `tests/test_trusted_grading.py` 缺失 | **属实** | 已提交（6 个用例通过） |
| `loop_stages` 仍是旧 `make_grader()` | **不准确**：`require_trusted` 参数已存在，`loop_runner.py:57` 对 toolchain 传 `True`；真问题是依赖模块没提交 | 无需改代码 |
| `public_brief()` 重复分支 + 空 versions 遮蔽 | **属实**：`elif self.affected` 出现两次 | 已去重，保留顶层回退 |

**干净克隆验证**：`git clone --depth 1` 后在克隆目录运行
`python -m tools.cuda.f13_verdicts`，20 行判定正常输出——判定器不再依赖本地未提交文件。

## 二、CVE-2025-23346：为什么"几乎没有有效输入"

F13 记录的 6 次调用不是生成失败，而是**两处测量缺陷叠加**：

1. **重放用错了 argv**。候选调用 `cuobjdump -elf <file>`，重放跑裸 `cuobjdump <file>`。
   同一文件：裸调用 exit 0，`-elf` exit 139。
2. **旧格式声称没被解析**。候选打印 `[CPG_RUN] name exit=-11`（无工具名），
   解析正则强制要求 `::tool`，于是"声称崩溃"从未与重放结果比对。

修复后本轮（f14b）该案例：**1 轮收敛、15 次调用、4 次解析器崩溃、达到
TARGET_TOOL_DIFFERENTIAL_SUPPORTED**。F13 的"没有有效输入"是假阴性。

## 三、生成流程的实际改动

| 改动 | 解决的问题 | 位置 |
|---|---|---|
| `[CPG_RUN] <name>::<tool> exit=N`，tool 取值 `nvdisasm` / `cuobjdump` / `cuobjdump-elf` / `cuobjdump-all` / `cuobjdump-sass` | 证据无法归因到具体 argv（23346 假阴性的直接原因） | `src/code_generator.py` 规则 21 |
| 重放按 argv 矩阵展开（nvdisasm 裸调；cuobjdump 四种模式） | 只测裸调用会把真实崩溃记成 exit 1 | `src/trusted_exec.py` |
| 字段用 Unit Separator 传输 | `\|` 在空字段处错位，整行解析失败 | 同上 |
| 产物 ELF 魔数预检（`format_ok`） | 区分"输入本身不是 ELF"与"工具拒绝合法 ELF" | 同上 |
| 重放读取 `_stale_*` 归档目录 | 产物被隔离后重放读到 0 个文件 | `tools/cuda/replay_modes.py` |
| 声称崩溃必须可复现，否则记 mismatch | 候选可以打印一个它没造成的崩溃 | `src/trusted_exec.py` |

## 四、六例复测结果

### 4.1 循环层（f14b）

| CVE | 状态 | 轮数 | 耗时 |
|---|---|---|---|
| CVE-2025-23346 | SUPPORTED | 1 | 629s |
| CVE-2025-23308 | EXHAUSTED | 1 | 714s |
| CVE-2025-23338 | SUPPORTED | 1 | 284s |
| CVE-2024-0111 | SUPPORTED | 1 | 576s |
| CVE-2024-0124 | SUPPORTED | 2 | 1283s |
| CVE-2024-0125 | SUPPORTED | 1 | 582s |

### 4.2 严格判定（可信记录）

| CVE | F13 判定 | F14 判定 | 变化 |
|---|---|---|---|
| CVE-2025-23346 | CRASH_OBSERVED | **TARGET_TOOL_DIFFERENTIAL** | ↑ |
| CVE-2025-23308 | CRASH_OBSERVED | CRASH_OBSERVED（崩在 cuobjdump，advisory 是 nvdisasm） | — |
| CVE-2025-23338 | CRASH_OBSERVED | CRASH_OBSERVED（无干净配对） | — |
| CVE-2024-0111 | TARGET_TOOL_DIFFERENTIAL | TARGET_TOOL_DIFFERENTIAL | 保持 |
| CVE-2024-0124 | TARGET_TOOL_DIFFERENTIAL | TARGET_TOOL_DIFFERENTIAL | 保持 |
| CVE-2024-0125 | DIFFERENTIAL | **TARGET_TOOL_DIFFERENTIAL** | ↑ |

目标工具差分：**2 → 4**。机制归因仍为 **0**（无逐案例根因证据）。
`CVE_ATTRIBUTED`：0。

### 4.3 量化对照

| 批次 | CVE | 候选 | 有效输入 | 工具调用 | 正常拒绝 | 解析器崩溃 |
|---|---|---|---|---|---|---|
| f13 | CVE-2024-0111 | 1 | 7 | 24 | 5 | 4 |
| f13 | CVE-2024-0124 | 1 | 18 | 38 | 8 | 8 |
| f13 | CVE-2024-0125 | 1 | 17 | 42 | 13 | 7 |
| f13 | CVE-2025-23308 | 2 | 20 | 42 | 18 | 0 |
| f13 | CVE-2025-23338 | 2 | 17 | 42 | 4 | 2 |
| f13 | CVE-2025-23346 | 2 | 2 | 6 | 1 | 0 |
| f14b | CVE-2024-0111 | 1 | 3 | 30 | 3 | 3 |
| f14b | CVE-2024-0124 | 2 | 3 | 20 | 0 | 1 |
| f14b | CVE-2024-0125 | 1 | 5 | 45 | 3 | 9 |
| f14b | CVE-2025-23308 | 1 | 6 | 35 | 4 | 3 |
| f14b | CVE-2025-23338 | 1 | 15 | 85 | 1 | 12 |
| f14b | CVE-2025-23346 | 1 | 2 | 15 | 1 | 4 |

读法：23346 调用 6→15、崩溃 0→4；23308 崩溃 0→3；23338 崩溃 2→12。
0124 输入数从 18 降到 3 但结论不变——候选减少了无谓 sweep，调用数也下降。

## 五、六个问题的回答

1. **23346 为什么几乎没有有效输入，是否改善？**
   不是生成问题，是重放 argv 错误 + 声称格式未解析。修复后 1 轮收敛、4 次真实崩溃、
   达到目标工具差分。**已改善。**

2. **23308 失败主要在推理还是输入生成？**
   输入生成：35 次调用、6 个输入、3 次崩溃，但崩溃发生在 **cuobjdump**，而 advisory
   指向 nvdisasm。模型把"ELF 解析器"整体当成一个目标，没有锁定 nvdisasm 的代码路径。

3. **23338 的未分类崩溃能否形成有效独立差分？**
   本轮 12 次崩溃含 nvdisasm，但**没有一组干净的 benign/control 配对**，所以仍停在
   CRASH_OBSERVED。它可作为 FINDING_CANDIDATE 单独登记，不能归到 CVE。

4. **可复用文件构建库是否改善质量？**
   **未实现**，这是本轮最大的缺口。目前仍由模型每次手写 ELF 变更代码。

5. **哪些改进可迁移？**
   工具+模式的观测行、argv 矩阵重放、ELF 魔数预检、声称-观测对账——这四项与具体 CVE
   无关，任何"工具链 PoC"类任务都可以直接复用；对 OpenCL/Vulkan 同样适用。

6. **是否提高了到达率与差分支持率？**
   是：目标工具差分 2/6 → 4/6；23346 从 6 次调用提升到 15 次并首次拿到差分。
   但机制归因仍为 0，且 23308/23338 未突破。

## 六、未完成项（如实）

1. 可复用 cubin/ELF 构建辅助库（任务第二重点明确要求）——未做；
2. 失败反馈仍以诊断码为主，未把真实工具 stderr 全文回灌（D/E 只部分满足）；
3. 23308/23338 的针对性约束修正未做。

## 七、回归与产物

```
1937 passed / 67 skipped / 0 failed
```

产物：`data/loop/f14b/*`（6 例全部候选源码、trusted 记录、观测、报告）、
`data/driver/f13-verdicts.json`（含 f14b 重评）。
