# P4-N 可执行漏洞规格（EVS）：把输入从档案变成契约

报告语言：`zh-CN`。本文件定义一套**属于本项目自己的输入模型**，用于替代对七层 JSON 的
依赖。它不是对师兄框架的否定——那套框架解决"流水线怎么跑"，本文解决"输入凭什么支撑生成"。

## 1. 为什么必须换

七层输入回答"这个漏洞是什么"，EVS 回答"这个解析器吃什么字节、凭什么说打中了"。
批跑数据已经把差距量化：

- 唯一 17/17 的 23339，一轮收敛；
- 13 个 9/17 的，全部缺"函数/伪代码/字段"，成功率 31%；
- 全部 23 个输入的可执行层评分 **0/21**。

也就是说：现有输入里**没有任何一个字段**能告诉生成器"改哪个字节"。
再优化提示词也只是让模型猜得更聪明，而不是让它知道得更多。

## 2. 模型定义

`src/spec_model.py` 实现，一份 `specs/<CVE>/spec.json`，由五个部分组成：

| 部分 | 内容 | 回答什么 |
|---|---|---|
| `anchor` | 二进制、调用模板、输入格式与魔数、**基线构造配方**、版本区间 | 怎么跑起来、什么算合法输入 |
| `parser` | 入口函数与 RVA、解析循环伪代码、**consumed_fields**（偏移/长度/语义/边界检查） | 改哪里、为什么这里不安全 |
| `observable` | 复现的判定信号（signal / exit_code / stderr_pattern / hresult） | 什么算打中 |
| `oracle` | 触发前提（字段 + 条件 + 预期效果） | 生成前必须声明什么 |
| `claims` + `history` | 每条断言带 `verified_by` 与置信度；尝试记录与**被证伪的假设** | 这条信息有多可信、哪些路已堵死 |

`consumed_fields` 是整套模型的核心：它同时回答"改哪里"和"为什么没被检查"。

## 3. 三个创新点如何落在代码上

### I1 输入即约束

`oracle` 与 `consumed_fields` 一起构成可判定的触发条件。提示词要求生成器先声明、
运行时回读打印 `[CPG_ORACLE]`。于是"模型是否真的理解了这个漏洞"变成**可观测量**，
而不是靠人读代码判断。

### I2 质量驱动策略（本文最核心的贡献）

```python
strategy = MUTATE_DIRECT  if consumed_fields and coverage >= 0.6
           PROBE_THEN_MUTATE if descriptive_coverage >= 0.4
           RECON_FIRST     otherwise
```

关键设计：**`consumed_fields` 是硬前置条件**。覆盖率再高，只要不知道解析器消费哪些字段，
就不允许"直接变异"——因为此时变异仍是猜测。这条规则直接把"输入质量"接到"搜索策略"上。

可消融：同一批 CVE，固定策略 vs 路由策略，比较成功率、收敛轮数、成本。

### I3 输入是活的（history）

`history.refuted` 会被渲染进提示词（"already refuted — do NOT repeat"）。
0107 的教训（ps_5_0 无 D3DSIO_SINCOS）这类负知识一旦写入，同类目标不再重犯。

## 4. 与七层的关系：导入，而不是抛弃

`from_legacy()` 把七层目录转成 EVS，所有断言标为 `advisory`。
这带来一个有用的性质：**旧输入导入后 operational 覆盖率天然很低**，
策略自动落到 `PROBE_THEN_MUTATE` 或 `RECON_FIRST`，不需要人工判断"这份数据够不够"。

迁移路径：
1. 现有 23 个 CVE 全部 `from_legacy` 导入（零成本，行为不变）；
2. 对重点 CVE 手工补 `anchor` / `parser`（23339 已完成，100% 覆盖）；
3. 补全手段逐步自动化：版本区间从 NVD 抽、入口函数从二进制抽、基线配方从工具文档抽。

## 5. 提示词注入

`CudaPipeline._spec_brief()` 在生成前把规格渲染成一段紧凑文本：

```text
[EVS] CVE-2025-23339 | component=... | strategy=MUTATE_DIRECT | operational=100%
binary: cuobjdump
invoke: cuobjdump --dump-elf {artifact}
baseline: nvcc -cubin -G sample.cu -o benign.cubin
parser: DWARF .debug_abbrev parser 0x00443f20
  field abbrev_code  off=0  size=1  check=none  LEB128, terminates on 0
  ...
oracle: abbrev_code must satisfy ... -> ...
already refuted (do NOT repeat): ...
unknown (do not invent): ...
```

只放"会改变代码行为"的事实，叙述性内容留给报告。`unknown` 一行明确告诉模型
"别编"，这是抑制幻觉最便宜的手段。

## 6. 怎么验证（论文实验）

| 组 | 输入 | 预期 | 指标 |
|---|---|---|---|
| B0 | 七层（现状） | 6/15 | 基线 |
| B1 | EVS 导入 + 手工补 3 个 | 手工补的 3 个显著提升 | 单案例对照 |
| B2 | EVS + 策略路由 | 收敛轮数下降 | 消融 |

必做的三个消融：
1. 去掉 `consumed_fields` → 验证"字段布局是硬前置"这条论断；
2. 去掉 `oracle` 声明 → 验证"显式化前提"的贡献；
3. 去掉 `history.refuted` → 验证负知识的价值。

## 7. 论文叙事建议（方法章结构）

1. **问题**：现有 LLM PoC 生成的输入是 advisory 形状，缺可执行锚点（用 40% 与 0/21 说话）；
2. **模型**：EVS 三层 + history（本文定义）；
3. **机制**：质量驱动策略路由 + oracle 契约 + 负知识回写；
4. **实现**：闭环（生成→执行→差分→诊断→反馈），附失败分类学；
5. **评估**：15 个工具链 CVE 的批跑 + 3 个消融 + 0107 案例研究（说明边界）。

## 8. 单案例验证：CVE-2024-0076 从"步骤失败"到 `SUPPORTED`

**改前**（无规格，2026-10-20 批跑）：`HARNESS_STEP_FAILED` ——
`[CUDA_STEP:S02] generate a baseline valid cubin — FAIL: no cubin baseline could be produced`。
注意那一轮**恶意样本其实已经打崩了**（`exit=-11`），只是被"造不出基线"卡死在判定之前。

**改后**（EVS 规格，只加了一份 `specs/CVE-2024-0076/spec.json`）：

| 轮次 | 判定 | 诊断 |
|---|---|---|
| 1 | `NOT_VERIFIED` | `LABEL_CONFLICT`（候选把 benign 声明成别的角色） |
| 2 | **`SUPPORTED`** | — |

证据（第 2 轮观测）：

```text
[CUDA_STEP:S02] Compile a benign cubin baseline with nvcc — OK
[CPG_LABEL] benign.cubin BENIGN
[CPG_RUN]   benign.cubin exit=0
[CPG_ORACLE] sh_size actual=0xfffffffffffffff0 expected=0xfffffffffffffff0
[CPG_ORACLE] sh_offset actual=0x198 expected=inside file (<2536)
受控样本 2/6 个产生崩溃；良性基线 1 个全部未崩溃
```

起作用的是规格里的三条信息：
1. `baseline_recipe`（nvcc 命令 + "本镜像实测 1896 字节可用"）直接解掉了 S02；
2. `history.refuted` 告诉模型"只改 sh_offset 不会崩，要改 sh_size"，少走一轮弯路；
3. `oracle` 让模型先声明 `sh_size/sh_offset` 再回读验证，产出可审的证据。

**这是论文里最能打的一张表**：同一模型、同一提示词、同一执行环境，唯一变量是输入形态。

## 9. 反例：CVE-2025-23340 为什么仍然不可复现

给 23340 也建了完整规格（`specs/CVE-2025-23340/spec.json`，100% 覆盖），但实测发现：
它在这个环境里**不可观测**，原因有三，且都不是"规格没写好"：

1. **崩溃不可见**：CWE-131 那 24 字节堆越界写落在 glibc 堆内，不触发 SIGSEGV；
   Talos 是用 Valgrind 的 `Invalid write` 判定的。
2. **Valgrind 装不上**：容器内无法连代理（`apt-get` 全部失败），ASAN 运行时虽在，
   但 `LD_PRELOAD` 对该二进制不生效。
3. **构造入口困难**：nvdisasm 只接受带 CUDA 架构信息的 cubin；
   在真实 cubin 上追加 SHT_RELA 节后，处理分支并未进入（只做边界校验）。

结论：**观测信号的选择本身就是方法的一部分**。这条反例正好支撑 EVS 里
`observable` 必须是显式字段的主张——没有它，"打不中"和"看不见"无法区分。

## 10. 当前状态与缺口

| 项 | 状态 |
|---|---|
| EVS 模型与校验 | ✅ `src/spec_model.py`，8 个用例 |
| 七层导入 | ✅ `from_legacy`，advisory 标记 |
| 策略路由 | ✅ 含"字段布局硬前置"规则 |
| 提示词注入 | ✅ `_spec_brief`，19 个流水线用例通过 |
| 真实规格 | ✅ 1 份（23339，100% 覆盖） |
| 失败 CVE 的规格 | ⚠️ 需要逐个做逆向，这是下一阶段的人工成本 |
| 回写（history 自动写入） | ⚠️ 模型支持，闭环尚未调用 `record_attempt` |

**结论**：模型、路由、注入三段已经能跑；真正的工作量在"给失败 CVE 补规格"。
但这恰恰是论文里最有说服力的部分——因为它证明了"补齐可执行信息"能把失败变成成功，
而不是靠换更强的模型。
