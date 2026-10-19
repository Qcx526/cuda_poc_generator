# 主线仓库选择与数据迁移规则

报告语言：`zh-CN`。本文件记录一个工程决策：在两个同源代码目录之间选哪条主线，
以及另一份代码里的资产如何进入主线。决策依据均为本地实测，不是偏好。

## 1. 两个目录的关系（实测）

| 项 | 本仓库（`test/cuda_poc_generator`） | 师兄目录（`poc_generator/cuda_poc_generator`） |
|---|---|---|
| 版本管理 | Git，14 个阶段提交，已推 GitHub | 无 Git |
| 源码规模 | 86 个文件 / 约 35,400 行 | 12 个文件 / 约 4,100 行 |
| 测试 | 61 个测试文件、1292 个用例 | 1 个文件、51 行 |
| CVE 输入 | 6 个 | 23 个 |
| 真实产物 | 无（`data/outputs` 为空） | 23 份 PoC、209 个 cubin、真实崩溃日志 |
| 反馈闭环 | 无 | 源码已删，仅存 `.pyc` |
| 合同/验收 | P0–P3-D-R3 逐阶段合同与验收 | README 宣称五阶段与反馈迭代，代码未实现 |

同源判定：`src/utils.py`、`src/models/vulnerability.py`、`src/tools/search.py` 三个文件
与本仓库**字节完全相同**；其余 13 个核心文件已被重写。本仓库第一个提交 `321e804`
即为重写后版本。因此两者是**同一母体的两条分支**，不是两个项目。

## 2. 决策

**主线继续用本仓库；师兄目录只作为"只读数据源 + 设计参考"，不作为新主干，也不整体上传。**

## 3. 理由

1. **重写成本不可回收**：从 4.1k 行到 35.4k 行的严格合同、证据链、双环境执行基座与
   1292 个回归，是 P0–P3 十四个阶段的产物。换回旧代码等于把 C01–C26 那批问题
   （shell 注入、ELF 字段宽度错误、状态语义混乱、README 不实宣称等）重新引入。
2. **旧代码无法承接"行业标准"**：51 行测试覆盖不了一条 CLI 之外的任何行为，
   没有合同、没有证据哈希、没有失败路径验收。
3. **旧代码的独特价值是数据与设计，不是架构**：23 个 CVE 输入、23 份真实 PoC、
   209 个 cubin、真实崩溃日志、被删除的 `feedback_loop` 设计。这些正好补本仓库
   最缺的东西，且**可以独立迁移**。
4. **公开仓库的合规风险**：师兄目录无 LICENSE，`__author__` 为
   `CUDA Security Research Framework`。整体上传前必须取得原作者确认；而本仓库
   已有部分文件与其字节相同，来源关系应记录而不是再复制一份代码。

## 4. 数据迁移规则

### 4.1 输入（允许迁移）

- 师兄的 23 个 CVE 输入**已通过本仓库严格归一化校验：23/23 有效**（实测）。
- 但两边**字段 schema 不同**：师兄侧是扁平旧字段（`os_name`、`cuda_driver_version`、
  `trigger_command`、`component_name`），本仓库是包裹后的新字段
  （`operating_systems`、`driver_version`、`key_dependencies`、`affected_binary`）。
  归一化层同时接受两种形态，因此迁移可行。
- **不得覆盖同名 CVE**：`CVE-2022-21821`、`2023-0196`、`2024-0076`、`2025-23339`
  两侧 7 个文件全部不同，且本仓库版本经过人工校正（例如把 `gpu_architecture`
  从 `sm_75（仅用于生成 base cubin）` 改为 `N/A（纯 CPU 工具，不涉及 GPU 执行）`，
  这直接影响环境档案判定）。这 4 个保留本仓库版本，差异逐字段人工合并。
- `CVE-2024-0124`、`2025-23308` 两侧字节相同，无需处理。
- 其余 17 个按原样新增，导入后必须重新跑归一化与全量回归。

### 4.2 产物（禁止进入 Git）

- 师兄侧的 `data/outputs/`（23 份 PoC、209 个 cubin）与 `_exp_logs/` 属于私有实验证据，
  **不提交**。它们只作为复现对照与 fixture 来源。
- 如需固化为测试 fixture，必须脱敏（移除主机绝对路径、时间戳、GPU UUID），
  并在 fixture 说明中标注"由真实运行衍生、已脱敏"。

### 4.3 反馈闭环设计（重建，不复制）

- 师兄侧的 `feedback_loop.py`、`models/{feedback,state,report}.py` 源码已删除，
  仅有 3.14 字节码。可从字节码还原**接口与字段**（见下），但实现必须按本仓库的
  严格模型重写：判定枚举、证据引用、每轮独立 run、不覆盖历史。
- 还原到的接口：`CudaFeedbackLoop.parse_feedback / analyze_failure /
  _match_known_errors / auto_investigate / apply_fixes`；
  `Verdict{CONFIRMED, NOT_REPRODUCED, INCONCLUSIVE, ENVIRONMENT_ERROR}`；
  `AgentState{attempts, observations, investigation_results, artifacts, iteration}`；
  `FinalReport{target_version_in_range, benign_control_result,
  ruling_out_false_positives, malicious_*}`。

## 5. 验收门

主线是否"真的能干活"，以一条硬标准判定：

> 用师兄侧已记录的 `CVE-2025-23339` 真实结果（`cuobjdump 11.2` 对恶意 cubin，
> `exit=3221225477`，9 步 `[CUDA_STEP]` 日志）作为对照，本仓库必须能独立产出
> 同等强度的证据（原始 stdout/stderr、退出码、工具 SHA-256、判定与报告）。

达不到这条的"能力扩展"一律视为文档工作，不计入完成。

## 6. 尚未决定

- 师兄是否同意把 17 个 CVE 输入公开到 GitHub 仓库（数据来自其工作）。
- 是否把本仓库与师兄目录的来源关系写入正式 `PROVENANCE` 说明。
