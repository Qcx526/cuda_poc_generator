# P4-C 验收记录：CVE-2025-23339 对照实测

报告语言：`zh-CN`。本文件只记录本轮实际执行与客观结果。所有退出码来自
`src.tools.process.run_tool` 的原始证据，未做人工改写。

## 1. 环境（实测）

| 项 | 值 |
|---|---|
| GPU | NVIDIA GeForce GTX 1660（Turing，sm_75） |
| 驱动 | 551.61 |
| Toolchain | `CUDA v11.2`，`nvcc 11.2.152` |
| 被测工具 | `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\cuobjdump.exe` |
| 工具 SHA-256 | `da9f5983bd9c003d6b468b4ba66c6f496fa9e340ccf6051331c2102e8a198e6b` |
| 命令 | `cuobjdump --dump-elf <artifact>` |

## 2. 对照执行结果

对 6 个**非恶意**样本执行，超时 60 s，单次输出上限 1 MiB：

| 样本 | 退出码 | 结果 |
|---|---|---|
| `benign.cubin` | 0 | NORMAL_EXIT |
| `_ctrlA_zero_content.cubin` | 0 | NORMAL_EXIT |
| `_ctrlB_offset_restored.cubin` | 0 | NORMAL_EXIT |
| `_ctrlC_size_shrunk.cubin` | **3221225477** | WINDOWS_EXCEPTION（0xC0000005） |
| `_ctrlD_benign_content_at_eof.cubin` | 0 | NORMAL_EXIT |
| `_ctrlE_zero_payload.cubin` | 0 | NORMAL_EXIT |

原始证据：`data/outputs/control_runs/<run_id>/`（Git 忽略），索引在
`data/outputs/CVE-2025-23339/controls_evidence.json`。

## 3. 判定

把上表作为外部对照附加到历史运行日志后：

```text
判定：SUPPORTED
受控样本：2 个，崩溃 2 个
良性基线：1 个，崩溃 0 个
机制对照：5 个，崩溃 1 个
```

理由：受控样本崩溃、基线未崩溃、版本在区间内；但**机制对照 `_ctrlC` 同样崩溃**，
说明该崩溃不独属于恶意载荷，单一变量的隔离结论未成立。

## 4. 本轮的真实发现

`_ctrlC_size_shrunk.cubin` 是把声明的 section size 改回去的对照，它**依然崩溃**。

这与该 CVE 的根因描述一致：解析循环的终止条件取自输入数据自身，`sh_size`
并不构成上界。但它同时意味着：

- 仅凭"恶意样本崩了"无法把崩溃归因到 LEB128 载荷本身；
- 需要一个能把 `_ctrlC` 与 `malicious_*` 区分开的观测（RIP 是否落在可控值上）。

因此判定停在 `SUPPORTED`，没有、也不会升级为 `VERIFIED`。

## 5. 已知限制（必须随结论一起引用）

1. **构建号不一致**：历史日志的崩溃来自 `cuobjdump 11.2.0`（2020-11-30 构建），
   本轮对照跑在重装后的 `11.2.152`（U2）上。两者是同一受影响区间内的不同构建，
   严格对照应在同一构建上重跑恶意样本。
2. **未执行恶意样本**：本轮只跑 6 个非恶意样本；`malicious_*` 与
   `_ctrl_size_restored_malicious_*` 均未执行。
3. **无寄存器级证据**：日志里 `S07 confirm return-address control — OK` 是 PoC
   自述，不是调试器观测；`root_cause_proof_recorded` 保持 `False`。
4. **无隔离**：本轮直接在宿主运行 `cuobjdump`，没有容器或沙箱；仅因样本非恶意
   才可接受。

## 6. 下一步

1. 在同一构建（11.2.152）上重跑恶意样本，消除构建号差异。
2. 在隔离环境（容器）中执行，并采集崩溃时的寄存器/RIP，作为根因级证据。
3. 若 `_ctrlC` 与 `malicious_*` 的 RIP 可从输入推出且不同，则 `_ctrlC` 的崩溃
   属于另一条路径，可恢复单变量隔离结论；否则应重新设计对照集。
