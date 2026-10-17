# P3-D-R2 验收记录

报告语言：`zh-CN`。本记录只汇报固定无害链路、只读身份测量和离线回归。未生成或执行真实 LLM 候选，未运行真实 CVE 输入，未启动 CUDA kernel，未调用付费模型。

## 1. 基线和工作区保护

| 项目 | 结果 |
|---|---|
| 开发基线 | `main@a684ae4206ef44b6492463655998d63d3eb9cbfa` |
| 开始时 `HEAD` / `origin/main` | 相同，均为上述 commit |
| 提交与推送 | 维护者后续已授权验收完成后正常提交推送；实际 commit 以 Git 历史为准 |
| P3-D-R1 文档与原始证据 | 保留，未恢复、覆盖或删除 |
| 生成 Prompt、原始七维输入、Oracle 与历史报告 | 未修改 |

R1/R2 已完成的源码、测试和正式文档一并交付。两份既有历史草稿 `docs/P3_D_EXECUTION.md`、`docs/P3_D_REAL_VALIDATION.md` 保持原样和本地未跟踪状态；私有原始证据不纳入提交。

## 2. P3-D-R1 只读复核

本轮按每个独立 manifest SHA-256 重新打开两轮原始文件，并调用既有 `read_memcheck_evidence` 离线重新解析。观察结果与历史报告一致：

| 固定 fixture | request/run | 进程与解析结果 | 独立报告重建 | CVE 状态 |
|---|---|---|---|---|
| `p3c-normal-v1` | run `73b72355dff746e19e611679cf406b99` | `COMPLETED / PARSED`，0 条结构化错误；compile 与 Memcheck 回收均 `CONFIRMED` | 与已保存中文报告逐字节一致 | `NOT_VERIFIED` |
| `p3c-invalid-write-v1` | run `080a8374f30b46c386e2bf03f81d3bd1` | `COMPLETED / PARSED`，1 条 `INVALID_WRITE`；compile 与 Memcheck 回收均 `CONFIRMED` | 与已保存中文报告逐字节一致 | `NOT_VERIFIED` |

独立清单摘要分别为 `cd16afba82af1f012d7a0e2bc9aec730c28ac920fff44c46597fb59137439278` 和 `f6653852524496e8c4bb0706220776bd15b1bc0d9a596e0d7417c573ef5d3a37`。这些是无害 CPU 诊断 fixture，不属于 CVE 执行。

## 3. 本轮修改和离线测试

本轮新增了严格的生成 run 候选身份读取、WSL 只读预检、固定动作传输接收器、固定 CUDA 工具 profile 以及中文合同文档。任意候选执行仍 `UNSUPPORTED`。

提交前兼容性复核另修复两项确定性问题：候选 Python API 的默认 manifest 路径与归档模块统一为 `data/outputs`；Windows 目标身份检查从远端描述的固定任务根推导 WSL 用户目录，不再读取 Windows HOME 来匹配 Linux 工具路径。默认/显式归档根、合法远端 sidecar、目录与后缀错配、路径穿越和哈希冲突均有离线回归；修复后的双环境聚焦测试各为 `21 passed`。

| 检查 | Windows Python 3.12 | WSL Python 3.10 |
|---|---:|---:|
| P0～P3-C 全量离线回归 | **PASS**：1211 passed、50 skipped、0 failed、1 warning | **PASS**：1256 passed、5 skipped、0 failed、1 warning |
| 提交前集中回归（候选归档根、远端工具身份与路径） | **PASS**：21 passed、0 skipped | **PASS**：21 passed、0 skipped |
| `compileall -q src tests` | **PASS** | NOT_CHECKED |
| `python -m src.cve_lab --help` 与 `preflight --help` | **PASS**，均显示无 execute 子命令 | NOT_CHECKED |
| 测试期间真实模型 API / CVE / kernel | 未调用 / 未执行 | 未调用 / 未执行 |

两边唯一 warning 都来自 ZIP 恶意样例负例刻意创建重复 `README.zh-CN.md` 成员。提交前全量结果文件位于被忽略的 `data/outputs/p3d_r2_audit/precommit/`。开发过程中曾有一轮测试构造尝试修改冻结的 `ToolIdentity` 对象并失败；测试已改为使用 Pydantic 不可变副本，最终双环境全量回归通过。

修改前基线分别为 Windows 1190 passed / 50 skipped、WSL 1235 passed / 5 skipped。R2 提交前全量比基线各增加 21 个测试；平台 skip 数不变。

## 4. 实际 Windows→WSL 固定无害联调

### 固定源码传输与注册动作

修正 Windows 汇总层状态字段映射后再次真实发起固定动作链。WSL 接收注册动作 `p2b-normal-v1` 的 3060 字节固定源码，receiver PID `392`，重新核验 SHA-256 `a69c83e61b0fc66ed5b776e2c7ac45d801578be2ed6ebc189f21455f9dcf1bf5`。传输 request ID 为 `9250592cff3c45fa8c2390d80eb360de`，transfer ID 为 `65591ae22bb1495ca207cc0544af73a3`；传输清单中的 6 个文件均通过长度和 SHA-256 重读。

独立固定动作 run `58729e2f6fe14b22bd67460d607bf13b`（request `87993e4cc46441e4a8f1c2c4c8ac2663`）在 WSL PID `542` 正常退出，退出码 `0`，进程组回收 `CONFIRMED`。stdout 原始 26 字节，SHA-256 为 `e92e8dfe5ad14678c86a6b7ac5131edd026da2dcf17c89f5d20cf446e2a4bcf1`；stderr 为空，未截断。P2-B `EvidenceManifest` 的 `capture_complete=true`、`effective_status=COMPLETED`。P2-B 证据读取器报告 `native_verification=UNAVAILABLE`（该固定动作没有 P2-C native 文件包）；这不影响其进程原始流清单核验，也不能被表述成 native evidence `VERIFIED`。transfer 和 execution 的 action ID 与源码摘要一致，chain ID `d292342c9b9e4706985d51b3135bf810` 的清单核验通过，中文报告按渲染函数逐字节重建一致。

**限定**：该测试真实验证的是固定源码传输接收与另一独立运行中的固定注册动作。接收端暂存文件没有作为任意脚本被解释执行；因此不把这次无害联调表述为真正运行过生成候选。候选字段继续为 `NOT_EXECUTED`，CVE 仍为 `NOT_VERIFIED`。

### 固定 CUDA 工具链 smoke

在哈希门禁加入后，Windows 再次发起已授权的 P2-C 固定 CUDA smoke，使用仓库冻结的无害 `safe_smoke.cu` 编译 cubin 后执行固定工具检查。WSL 目标为 `wsl:Ubuntu-22.04`，snapshot environment ID 为 `sha256:63756e5cce96ff268cb28a963077a000ba7192c25b88265f7b59d5e0da535eeb`，probe ID 为 `e26a5bcbecb74bc3864d0e0cddb9799f`。独立 `read_execution_evidence` 重读返回有效记录，request `ade4dff8beec4dc1ae9708f864a32c6b`、run `73b0b21c0d364bc5a739686f199d5f09` 为 `COMPLETED`，回收确认 `CONFIRMED`，`candidate_execution_status=NOT_EXECUTED`、`verification_status=NOT_VERIFIED`。

| 角色 | 观察到的工具身份 | 实际结果 |
|---|---|---|
| nvcc 12.8.90 | `/usr/local/cuda-12.8/bin/nvcc`，SHA-256 `59e4e55f9a38b78c590df1e28a69dad91052958f18a03868ca4a547c043fbba7` | 编译固定 CUDA smoke 源码，PID 572，退出码 0 |
| 侧载 cuobjdump 12.8.55-1 | `<用户侧载根>/root/usr/local/cuda-12.8/bin/cuobjdump`，SHA-256 `ad1d0f0699f46603416eb58e7b9fdf9a293e95f9312c9df7fd6fda56a6c30d41`，build `35351055_0` | `--dump-elf` PID 586，退出码 0；stdout 5504 字节、SHA-256 `81e047f7a6ff0a413985192f138ff8897d574ad35858304dc327cfe0d8822929`；stderr 0 字节 |
| 系统 cuobjdump 12.8.90 | `/usr/local/cuda-12.8/bin/cuobjdump`，SHA-256 `9d515ac6f60c246ef63fe87b0a95d209b00ff3e25b716f8f263520010760e8f8` | 单独描述、未与侧载工具混用 |
| nvdisasm 12.8.90 | `/usr/local/cuda-12.8/bin/nvdisasm`，SHA-256 `250ebe97dd86617574a30daf8d8ee433e6c5d9d10bafff922078779d1ba36073` | 固定 cubin 检查 PID 587，退出码 0 |

侧载与系统 cuobjdump 的 `readelf -d` 和 `ldd` 记录均成功，动态依赖均解析到本机 Linux `libpthread`、`libdl`、`libm`、`libc` 等系统库。依赖原始记录清单摘要为 `209d20c3bab732e45ac27a52838d27351b5337af783ff09591ee81b9981d644e`。这里只完成无害 cubin 的编译和静态解析工具调用；没有执行 cubin，没有启动 GPU kernel。

公开摘要使用角色占位表示用户目录；完整实测路径仍保留在本机原始证据中，原始字节和身份哈希未改写。

Smoke 原始档案保存在被忽略的 `data/outputs/p3d_r2_target_smoke/ade4dff8beec4dc1ae9708f864a32c6b-73b0b21c0d364bc5a739686f199d5f09/`。工具版本输出、实际 PID、每步 stdout/stderr、native evidence index、execution record 和报告均在目录中；原始文件通过项目的生命周期证据读取器复核。清单 SHA-256 为 `d2f2cb6fcf4d3775746b0835a8335108c0dbac0fd13c0a38f0ce7a17ffdc76b7`，清单记录 `capture_complete=true` 和 `cleanup_confirmation=CONFIRMED`。

## 5. CVE 资格与未完成项

公开公告把 CUDA Toolkit 13.0 前版本列为 CVE-2025-23339 的受影响范围；Talos 报告列出 `cuobjdump 12.8.55` 为已确认版本。当前侧载工具的观察版本/build 与此版本族相符，但现有无害 smoke 没有提供漏洞输入、解析异常或根因证据，因此它既不证明该构建存在特定触发行为，也不构成 CVE 复现。[NVIDIA 公告](https://nvidia.custhelp.com/app/answers/detail/a_id/5661/kw/overlay)，[Cisco Talos 报告](https://talos.talosintelligence.com/vulnerability_reports/TALOS-2025-2155)。

| 项目 | 状态 | 原因 |
|---|---|---|
| 已归档 LLM 生成 run 的真实目标身份预检 | NOT_CHECKED | 当前未对某个本轮真实生成候选执行 `cve_lab preflight` |
| LLM 真实候选生成/API | NOT_EXECUTED | 没有发起模型请求，也没有产生候选源文件 |
| 任意候选 Python 执行 | UNSUPPORTED | 固定动作 gate 不适用于不可信模型代码；没有候选专项执行器/隔离证明 |
| CVE-2025-23339 特定格式触发输入 | NOT_EXECUTED | 本轮只使用仓库固定安全编译输出；没有畸形或 CVE 输入 |
| Valgrind 对真实 cuobjdump CVE 输入诊断 | NOT_CHECKED | R1 的真实 Memcheck 仅针对固定 CPU fixture；本轮没有目标 CVE 输入可诊断 |
| CVE 根因条件与 P3-A Oracle VERIFIED | NOT_VERIFIED | 缺少输入绑定、目标路径触发、特定错误位置/根因和独立专项证据 |
| 真实 CUDA 驱动或 GPU kernel 行为 | NOT_CHECKED | smoke 没有执行 cubin 或 kernel |
| 自动重试和有界反馈 | NOT_IMPLEMENTED | 不属于已完成的接线能力 |

Talos 对该漏洞描述了 crafted fatbin 与 cuobjdump DWARF parsing 路径，并报告高风险原生控制流影响。故未知 LLM 代码和真实漏洞输入不会进入当前固定 fixture 执行门。以后如果重新评估真实实验，需要独立审查候选与输入、确认准确目标文件类型/版本/身份、资源/隔离/清理能力，定义可验证的专项必要条件，并取得明确候选与目标绑定授权；这些要求不能由本轮测试结果替代。

## 6. P3-D-R2 代码定位和下一步阻断

- `src/candidate_adapter.py`：generation run 原始字节与身份核验；候选准入强制 `UNSUPPORTED / NOT_EXECUTED / NOT_VERIFIED`；固定动作安全传输与 chain 报告。
- `src/candidate_transfer_worker.py`：WSL 仅接受并暂存固定注册表 `p2b-normal-v1` 的精确字节，不执行暂存文件。
- `src/cve_lab.py`：Windows 只读 `preflight` CLI，无候选执行子命令。
- `src/cuda_smoke.py` / `src/cuda_smoke_worker.py`：安全 smoke 的固定工具 profile，侧载 cuobjdump 在版本调用前按路径、build 和 SHA-256 拒绝未知二进制。
- `src/lifecycle_bridge.py` / `src/lifecycle_worker.py`：DESCRIBE 消息的显式 profile 传递和 WSL 返回值校验。
- `tests/test_candidate_adapter.py`、`tests/test_cuda_smoke_profiles.py`：新增传输身份、授权边界、序列化兼容及错误工具身份回归。

后续如果继续走安全路线，首先应让受信受审的固定良性输入路径真正复用接收端落盘字节，而不是把传输测试和独立注册动作运行合并表述；再单独设计不含漏洞触发内容的目标工具诊断合同。任意 LLM 候选执行和真实 CVE 触发需要另行安全审查与授权，本报告不提供这类执行能力。

当前固定源码暂存 bootstrap 从受信 WSL 工程导入模块，尚未复用既有执行 worker 的 checkout 源码固定机制；它只接收不可变注册表的无害字节，不执行暂存文件。后续扩展前应补齐该来源固定能力。

维护者后续要求每轮完成并通过适用验收后直接正常提交推送 `origin/main`。本次只纳入工程源码、测试和正式文档，原始私有证据和两份既有历史草稿保留本地。
