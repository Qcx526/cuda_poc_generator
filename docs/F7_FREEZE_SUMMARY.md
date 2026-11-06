# F7 冻结总结：CUDA 工具链支线

时间范围：P13-4-F7 → F7-R2。冻结后 CUDA 工具链支线不再迭代，下一阶段回到 GPU 驱动。

## 一、这条支线现在能证明什么

| 能力 | 状态 | 证据 |
|---|---|---|
| 在真实 CUDA 11.2.2 容器里执行 LLM 生成的 harness | 成立 | `data/loop/f7/CVE-2024-0076/iteration_1_observation.txt` |
| 观察到崩溃并做良性/对照差分 | 成立 | 同上（`cuobjdump` exit=139，基线对照干净） |
| 两轮闭环在失败时真的改变代码 | 成立 | `data/loop/f7r1/CVE-2025-23340/`（R1 全 0 → R2 改取值并产生崩溃） |
| 盲测合同（公告级信息） | 成立 | `src/blind_context.py` + `tests/test_blind_context.py` |
| 五级判据且不自动归属 | 成立 | `src/cve_grading.py` |

## 二、这条支线不能证明什么

1. **任何一条 CVE 的根因归属。** 最高只到 `DIFFERENTIAL_SUPPORTED`，
   `CVE_ATTRIBUTED` 从未授予。
2. **"两个新崩溃点属于 CVE-2024-53877"** —— README 的原句缺证据，已在 F7 报告中
   记为未证；`data/findings/novel/CVE-2024-53877/` 为空目录。
3. **0076 的"SUPPORTED"** 应读作"观察到一个崩溃"：崩溃来自 `cuobjdump`，
   而生成程序自评 `NOT_REPRODUCED`（`nvdisasm` 未崩），且 `single_field_differential=False`。
4. **23340 的第二次尝试**：崩溃确实出现，但**对照组同样崩溃**，差分不成立。

## 三、已修的真实缺陷（按发现顺序）

| # | 缺陷 | 修法 |
|---|---|---|
| 1 | `--freeze-history` 只屏蔽 `observed`，parser/oracle/claims/refuted 仍进 Prompt | 新增 `public_brief()`，`CPG_BLIND_CONTRACT=1` 生效 |
| 2 | `affected` 打印布尔值 `True` | 改为版本窗口 `11.0..12.9 (fixed in 13.0)` |
| 3 | 七维 bundle 原样进 Security Expert（含 `0x45ada0` 与对齐公式） | `src/blind_context.py` 在专家之前投影，盲测下同时关闭 RAG 与在线检索 |
| 4 | 两段 LLM 的 prompt/response 未留档 | `expert.last_prompts` / `code_gen.last_messages` + 落盘到 `evidence/` 并附 SHA256 |
| 5 | 判据只有单一 verdict | 五级分级器 + 报告附加 `grading` 块（旧 verdict 原样保留） |

## 四、冻结时仍未解决的问题（F8 Step 0 补记）

1. **盲测没有经过真实 LLM 端到端复验。** 投影是代码级修正，`public_brief()` 与
   `blind_context.project()` 都有测试，但**没有任何一次真实生成**是在纯盲测下跑完的。
   已有的 0076 与 23340 实验都发生在投影之前或部分投影之下。
2. **原始响应没有覆盖全部重试。** `code_generator.last_messages` 只保留最后一次
   messages；静态修正重试（lint 修复）时的中间 messages 与原始响应未落盘。
3. **五级判据仍是实验性离线分级器。** `cve_grading` 未接入 `ClosedLoopController`
   的停止条件，`enrich_report()` 是附加字段；闭环仍用旧 `make_grader()`。
4. **回归曾出现一项未独立排除的失败。**
   `test_generation_delivery::test_default_python_api_keeps_exactly_six_v1_files`
   曾在本机报 `safe-delete: exit 1`（沙箱禁止 rmtree），`git stash` 后同样复现；
   在 F8 收尾的完整回归中该失败不再出现（1856 passed / 0 failed），
   但**只在同一台机器上观察到**，仍不能算已在独立环境排除。
5. **投影曾经漏掉 `attack_vector`。** 该字段在 23340 上写着"sh_size 取 1..11"，
   与 `vulnerability_type.subtype` 一起直到 F8 Step 0 才被移除。

## 五、遗留

- 闭环主流程仍用旧 `make_grader()`；五级结果目前是**附加**信息，未进入自动停止条件。
- `data/loop/` 默认被 git 忽略，历史实验需 `git add -f` 才能审计。
- 流水线会把 `history.attempts` 回写进 `specs/*.json`，本轮已用 `git checkout` 复原；
  建议后续改为只写实验目录。

## 五、对驱动线的意义

CUDA 支线验证的是**方法论**：LLM 能生成、能执行、能在失败后改代码；同时暴露了
**判据才是瓶颈**——没有独立观测时，"崩溃"很容易被当成"复现"。
这正好对应驱动线卡住的同一个问题：`0xC000000D` 到底意味着什么，没有内核观测就无法回答。
