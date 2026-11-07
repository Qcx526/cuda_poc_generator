# P13-4-F10-Step2 / F11：多 CVE 端到端与 CUDA Driver API 后端

基线 `0c36595`。本阶段按"完整实验 → 定位 → 修复 → 重跑完整实验"执行。

## A. F10-Step2：6 个新工具链 CVE 端到端

### A.1 第一次运行：0/6，全部 STAGE_ERROR

每个 CVE 在 70–94 秒内死于同一处：`Expert analysis rejected (CVE_MISMATCH)`。

**根因定位**（重现 + 抓取模型原始输出）：

1. F8-R2 引入的盲测投影（正确地）剥掉了各维输入里的 `cve_id`；
2. 但 `_build_user_prompt` 只渲染七个维度的节，**顶层 `cve_id` 从未被渲染**；
3. 模型看不到编号，从 advisory URL 推断：
   `CVE-2024-53877` 被写成 **`CVE-2024-53871`**、又写成 **`CVE-2025-23280`**；
4. 身份合同正确地拒绝了它。

**修复**：`_build_user_prompt` 顶部渲染 `## Target Identity (authoritative)`，
并加系统规则"CVE ID 逐字符复制，禁止凭记忆更正"。
提示词基线守卫改为**精确差异检查**：允许且仅允许这一条已记录的插入。
单 CVE 复测：`RESULT: OK`。

**教训**：合同要求模型逐字复制的字段，必须真的出现在它的输入里。

### A.2 第二次运行（完整重跑）：5 SUPPORTED / 1 EXHAUSTED

| CVE | 状态 | 轮数 | 耗时 | 关键观测 |
|---|---|---|---|---|
| CVE-2024-53877 | **SUPPORTED** | 2 | 1104s | benign 0/0；PoC `cuobjdump exit=139`（nvdisasm exit=1）； |
| CVE-2025-23247 | EXHAUSTED | 2 | 1344s | 两轮未产生可区分异常 |
| CVE-2025-23339 | **SUPPORTED** | 1 | 777s | benign 0；PoC 139；**恢复字段对照全 0** |
| CVE-2024-0109 | **SUPPORTED** | 1 | 471s | 观测含 SIGSEGV |
| CVE-2024-0110 | **SUPPORTED** | 1 | 477s | 差分成立 |
| CVE-2023-0196 | **SUPPORTED** | 2 | 1560s | 两轮迭代后差分成立 |

产物：`data/loop/f10s2b/CVE-*/`（每轮 candidate/observation/报告）、
`batch_summary.zh-CN.md`、`quick_status.json`。

**口径**：`SUPPORTED` = 观察到异常终止 + 良性对照干净 + 单字段恢复对照干净。
这是差分证据，**不是 CVE 归因**：没有根因级证明（无内核观测、无符号级确认），
归因仍为 UNKNOWN。`EXHAUSTED` = 预算内未产生差分，如实保留。

### A.3 修复前后对照

| | 修复前（f10s2） | 修复后（f10s2b） |
|---|---|---|
| 完成 CVE 数 | 0（全部 CVE_MISMATCH） | 6 |
| SUPPORTED | 0 | 5 |
| 平均耗时 | ~80s（快速失败） | 471–1560s（真实执行） |

## B–F. F11：CUDA Driver API 后端（API_SEQUENCE）

### B. 后端实现

- `src/cuda_api_backend.py`：环境探测、nvcc 编译（**含 MSVC 环境注入**）、
  真实 GPU 执行（`ToolInvocation` 逐次记录）、API 返回码解析、状态阶梯复用。
- 与 FILE_INPUT 后端**复用**：`exec_evidence` 状态阶梯、`ToolInvocation`、
  V2 Case、`build_context`、候选目录结构、验证口径。
- 平台差异：载荷从"畸形文件"变为"C 源码"；执行器从容器变为本机 nvcc + nvcuda.dll。

### C. 真实环境记录（`data/driver/f11/environment.json`）

```
cuInit=0 · cuDriverGetVersion=13030（API 兼容版本，非驱动发行版）
设备: NVIDIA GeForce GTX 1660 · 计算能力 7.5
nvcc: release 11.2, V11.2.152
```

注意：WSL 在本会话被安全策略禁用，F11 改在 **Windows 主机**直接经 `nvcuda.dll` 执行——
这是真实 GPU 执行，不是模拟。

### D–E. 端到端实验（修复前后对照）

**第一次运行：0/2，全部编译失败**。根因：harness 未给 nvcc 配 MSVC 环境
（`Cannot find compiler 'cl.exe' in PATH`），且失败反馈只送了空的 stderr
（错误其实在 stdout），模型没有诊断可用。

**修复**：`_msvc_env()` 注入 cl.exe/INCLUDE/LIB；反馈同时携带 stdout+stderr。

**第二次运行（完整重跑）：2/2，均第一轮通过**：

| 实验 | 结果 | API 序列 |
|---|---|---|
| normal | exit 0，`DATA=OK` | cuInit/cuDeviceGet/cuCtxCreate/cuMemAlloc/cuMemcpyHtoD/cuMemcpyDtoH/cuMemFree/cuCtxDestroy 全部 CUDA_SUCCESS |
| boundary | exit 0，`BOUNDARY=DONE` | 无上下文 cuMemAlloc → `CUDA_ERROR_INVALID_CONTEXT`；无效句柄 cuCtxDestroy → `CUDA_ERROR_INVALID_VALUE` |

这证明后端**能区分**：构建失败 / API 参数错误 / 正常完成——
`CUDA_ERROR_INVALID_VALUE` 被记录为**预期参数错误**，从未当作漏洞证据。

每轮产物：`data/driver/f11/{normal,boundary}/round{N}_{prompt,response,candidate*.c,compile.log,run.json}`。

### F. 复用关系

同一 LLM Provider、同一 `build_context` 入口、同一状态阶梯与 `ToolInvocation`、
同一候选/证据目录约定。新增的只有 nvcc 编译与 nvcuda.dll 执行两个环节。

### G. 真实 Runtime/Driver API CVE 验证：**未完成**

在 GTX 1660（Turing，驱动 610.47/610.62 时代 API）上未找到
**版本匹配 + 公开触发描述 + 可独立验证**的 Runtime/Driver API CVE。
宁缺毋滥：不拿不匹配版本的失败结果冒充等价验证。此项 BLOCKED，原因如上。

## 回答交付问题

1. **两种 PoC 形态？** 是。FILE_INPUT（6 个 CVE 跑通）与 API_SEQUENCE（2 个实验跑通）共用同一套 Case V2/推理/执行证据模型。
2. **API_SEQUENCE 是真执行吗？** 是：nvcc 真编译、GTX 1660 真跑、API 返回码逐条采集。
3. **发生了什么问题？** ①盲测投影吞掉了模型必须复制的 CVE 字段（6/6 失败）；②nvcc 缺 MSVC 环境（2/2 失败）；③失败反馈漏掉 stdout。
4. **修复后改善？** 0/6 → 5 SUPPORTED + 1 EXHAUSTED；0/2 → 2/2 一轮通过。
5. **可通用的能力？** 状态阶梯、ToolInvocation、Case V2 投影、build_context、差分判据——全部与后端无关；OpenCL/Vulkan 只需新的执行器。
6. **距离自动复现 Driver API CVE 的障碍？** 无版本匹配的公开 CVE；WSL 在本会话被禁；内核观测缺失（同 F8 结论）。
7. **下一步优先级？** 先把 `ToolInvocation` 接进 FILE_INPUT 执行器（当前逐次证据仍缺），再考虑 Driver API 漏洞研究——测量基础设施仍优先于新实验。

## 回归

```
1912 passed / 68 skipped / 0 failed
```

（提示词基线守卫已改为"精确差异检查"：允许且仅允许已记录的 CVE-ID 规则插入。）

## 边界

未执行内核 Escape、未改 P11/P12、未新增 Mock；
模型调用：6 CVE × ≤2 轮 × 2 阶段 + F11 6 次生成，全部有留档；
实验在授权的隔离用户态容器与本机 GPU 用户态进行，无高风险内核探测。
