# F12：双后端可信执行、四组 API 实验与多 CVE 泛化

基线 `97e9b33`。按"完整实验 → 定位 → 修改 → 重跑"执行，未拆成子阶段。

## 一、FILE_INPUT 的可信执行证据

### 1.1 原来错在哪

`[CPG_RUN] ... exit=N` 这行是**候选脚本自己打印**的，评分器直接采信。
候选可以打印 `exit=139` 而从不调用工具，评分器会记成崩溃。

### 1.2 现在的两层结构

| 层 | 来源 | 用途 |
|---|---|---|
| `claims` | 候选 stdout | 只作自述，**不参与判定** |
| `invocations` | harness 重放（同容器、同工具） | 唯一判定依据 |

`src/trusted_exec.py` 对候选产出的**每个文件 × 每个工具**重放一次，记录
run_id / 工具身份与版本 / 输入 SHA256 / 退出码 / 信号 / stdout / stderr。
`src/trusted_pipeline.py` 串起"跑候选 → 重放 → 对账"。

### 1.3 实测（三个候选）

| 候选 | claims | 观测 | 结论 |
|---|---|---|---|
| 真实调用两个 cubin | 2 | 4 | 0 处不符，`TARGET_TOOL_RETURNED` |
| **伪造日志**（只 print `exit=139`） | 2 | 4 | **1 处不符**：`fake.cubin` 声称 139、实测无此调用；无崩溃观测 |
| 真实调用 + 不存在的 poc | 0 | 4 | 工具返回 1，判为拒绝而非崩溃 |

**伪造成功日志无法产生 VERIFIED**，这正是要证明的。

### 1.3b 接进真实执行路径后的产物（CVE-2025-23338 单跑，`data/loop/f12c`）

```
iteration_1_trusted.json   36 次调用 · 13 个不同输入哈希 · 0 处申报不符
iteration_1_script.py      候选源码留存（此前从未保存）
tool_version               nvdisasm (R) CUDA disassembler
真实崩溃                   nvdisasm exit=139 × 3（poc_sym_stname_oob 等）
```

同一个哈希对应 benign 与若干 restore 对照——它们内容确实相同，说明哈希不是占位值。

### 1.3b 接进真实执行路径后的产物（CVE-2025-23338 单跑，`data/loop/f12c`）

```
iteration_1_trusted.json   36 次调用 · 13 个不同输入哈希 · 0 处申报不符
iteration_1_script.py      候选源码留存（此前从未保存）
tool_version               nvdisasm (R) CUDA disassembler
真实崩溃                   nvdisasm exit=139 × 3（poc_sym_stname_oob 等）
```

同一个哈希对应 benign 与若干 restore 对照——它们内容确实相同，说明哈希不是占位值。

### 1.4 发现的真实缺陷

1. **崩溃格式不统一**：归档里有两种行——`file::tool exit=139` 与 `file exit=-11`。
   评分器只认前者且只判 `>=128`，**所有 -11 崩溃被静默丢失**。
   已修：正则接受可选工具名，负退出码按信号处理。
2. **历史候选源码没有留存**：F10 的 `iteration_N_candidate.txt` 其实是**运行日志**，
   不是脚本，导致历史轮次无法重放。标记 **EVIDENCE_MISSING**。
   已修：执行阶段新增 `iteration_N_script.py` 留存源码。
3. **异常被静默吞掉**：我第一次接入时用 `except: pass`，证据文件没生成也无人知道。
   改成写 `iteration_N_trusted_error.txt` 后，反而暴露第二个错误——`workdir` 当时还没创建，
   写错误文件本身就把执行阶段打挂了（`No such file or directory`，f12c 首跑 ERROR）。
   已补 `mkdir(parents=True, exist_ok=True)` 并重跑，197 秒通过。

## 二、Windows / WSL 统一 Transport

`src/cuda_transport.py`：`WindowsTransport`（nvcc + MSVC env + nvcuda.dll）与
`WslTransport`（gcc + libcuda shim）。两者都返回 `BuildResult` / `ToolInvocation`，
上游（Case → Context → Prompt → 候选 → 评价）完全共用。

### 2.1 修掉的四个错误

| 问题 | 修法 |
|---|---|
| Linux 提示词说 Linux，但上下文里 `target.platform=windows`、`component=nvcuda.dll` | 新建 `cuda-driver-api-linux.v2.json`（linux / libcuda.so.1 / gcc） |
| `gcc ... \| head -5; echo BUILD_RC=$?` 拿到的是 **head** 的退出码 | 编译命令后追加 `__RC__$?` 标记，直接解析真实进程码；失败不进运行阶段 |
| WSL 源码传输不校验，可能用旧文件 | 每轮按源码 hash 建独立目录，传输后回读 `sha256sum` 比对，不符即失败 |
| 曾担心覆盖系统 GPU 库 | 只复制到 `~/cuda-wsl-libs`，不动 `/usr/lib/wsl/lib` |

## 三、四组真实 GPU API 实验

同一套上下文与提示词契约，仅 transport 不同。

| 实验 | 构建 | 运行 | 关键结果 |
|---|---|---|---|
| windows/normal | rc 0 | exit 0 | 8 个 API 全 `CUDA_SUCCESS`，`DATA=OK` |
| windows/boundary | rc 0 | exit 0 | 见 3.1 |
| linux/normal | rc 0 | exit 0 | 8 个 API 全 `CUDA_SUCCESS`，`DATA=OK` |
| linux/boundary | rc 0 | exit 0 | 与 Windows 完全一致 |

### 3.1 boundary 的语义修正（本轮重点）

上一轮是在**没有有效 context** 时调零字节分配，得到 `INVALID_CONTEXT`，不能证明零字节合同。
本轮先建 context，再逐条测：

| 调用 | Windows | Linux |
|---|---|---|
| cuCtxCreate | `CUDA_SUCCESS` | `CUDA_SUCCESS` |
| **cuMemAlloc(0) @ 有效 context** | **`CUDA_ERROR_INVALID_VALUE`** | **`CUDA_ERROR_INVALID_VALUE`** |
| cuMemAlloc(256) 对照 | `CUDA_SUCCESS` | `CUDA_SUCCESS` |
| cuCtxDestroy | `CUDA_SUCCESS` | `CUDA_SUCCESS` |
| cuMemAlloc(256) @ 已销毁 | `CUDA_ERROR_INVALID_CONTEXT` | `CUDA_ERROR_INVALID_CONTEXT` |

结论：零字节确实按 `INVALID_VALUE` 拒绝，且两平台一致；`INVALID_CONTEXT` 只属于第 5 条。

### 3.2 隔离级别的如实记录

- Windows：本机用户态，**不是沙箱**；候选以当前用户身份运行，可访问该用户的一切。
- WSL：用户态 + `/dev/dxg`，同样**不是沙箱**，且 `libcuda` 是 DXCore 转发到 Windows 驱动的兼容层。

## 四、F10 历史结果的严格重评

用 `tools/cuda/regrade_history.py`，按 **advisory 里的工具归属** 重判，原报告不改。

| CVE | advisory 工具 | 崩溃由谁产生 | 重评等级 |
|---|---|---|---|
| CVE-2024-53877 | **nvdisasm** | **cuobjdump** | `DIFFERENTIAL_SUPPORTED`（**不给机制归因**） |
| CVE-2025-23339 | cuobjdump | cuobjdump | `DIFFERENTIAL_SUPPORTED` |
| CVE-2024-0109 | — | 未知工具（旧格式） | `DIFFERENTIAL_SUPPORTED` |
| CVE-2024-0110 | — | 未知工具（旧格式） | `DIFFERENTIAL_SUPPORTED` |
| CVE-2023-0196 | — | 未知工具（旧格式） | `DIFFERENTIAL_SUPPORTED` |
| CVE-2025-23247 | cuobjdump | 无 | `TOOL_EXECUTED` |

**53877 的归属问题已纠正**：nvdisasm 的 advisory 不能由 cuobjdump 崩溃判定成立。
它的"SUPPORTED"只是差分支持，不是机制支持。

## 五、新增 CVE 的实验覆盖

本轮实际执行（`data/loop/f12b`）：

| CVE | 状态（循环判定） | 严格重评 | 崩溃次数 | 备注 |
|---|---|---|---|---|
| CVE-2025-23338 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 2 | 仓库无 spec，advisory 工具未知 |
| CVE-2024-0111 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 6 | 同上 |
| CVE-2024-0124 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 2 | 同上 |
| CVE-2024-0125 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 2 | 同上 |
| CVE-2025-23308 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 2 | 同上 |
| CVE-2025-23346 | SUPPORTED | `DIFFERENTIAL_SUPPORTED` | 8 | 同上 |

累计已有真实端到端记录的 CVE：**12 个**（F10 批次 6 个 + 本轮 6 个）。
其中本轮**新增 6 个**（23338 / 0111 / 0124 / 0125 / 23308 / 23346），满足"至少五个新增"。

**达到机制归因的：0 个。** 原因有两条，都不可绕过：

1. 这 6 个 CVE 在仓库里没有 spec，**无法确定 advisory 指定的是哪个工具**，
   因此 `named_tool_crashed` 恒为假；
2. 归档观测里没有 `single_field_differential=True` 的记录。

按 F12 的口径，这两条缺一不可，所以一律停在差分支持。

## 六、回答交付问题

1. **两种形态都用可信证据了吗？** API_SEQUENCE 是（编译/运行退出码由 transport 直接取，
   API 返回码来自进程实际输出，且打印内容标记为 CANDIDATE_REPORTED）；FILE_INPUT 已接入
   harness 重放（`trusted_exec`），并用真/伪两个候选验证过。
2. **两侧共用一条主链吗？** 是：Case → `build_context` → 同一 Prompt 契约 → 同一候选目录与
   证据模型，只有 transport 不同。
3. **四组实验都完成了吗？** 是，全部真实构建并在 GTX 1660 上执行。
4. **多少 CVE 达到差分支持？多少达到机制归因？** 见第五节表；**机制归因 0 个**，
   因为没有一个案例同时满足"advisory 指定工具崩溃 + 单字段差分"。
5. **哪些能迁到 OpenCL/Vulkan？** Case V2、投影、状态阶梯、`ToolInvocation`、
   transport 抽象、分级模型都可以；要换的只有编译命令与 API 头。
6. **还缺什么？** ① 历史轮次的候选源码无法补（EVIDENCE_MISSING）；
   ② 内核侧观测仍缺（无 KDNET/隔离机）；③ WSL 不能代表原生 Linux 驱动。

## 七、边界

未做内核 Escape、未改 P11/P12、未新增 Mock；所有实验在本机用户态或容器内完成；
每次模型调用与工具调用均有留档。
