# P4-C 验收记录：CVE-2025-23339 对照与容器实测

报告语言：`zh-CN`。本文件只记录本轮实际执行与客观结果。所有退出码来自
`src.tools.process.run_tool` 或容器内 shell 的 `$?`，未做人工改写。

## 1. 环境（实测）

| 项 | 宿主（Windows） | 容器（Linux） |
|---|---|---|
| 平台 | Windows 10 19045，GTX 1660（Turing） | `nvidia/cuda:11.2.2-devel-ubuntu20.04` |
| 镜像 digest | — | `sha256:65879f7299f35cd232f3b54e24081d569db2be1f31820728aef8a44240a305a8` |
| 驱动 | 551.61 | 未挂载 GPU（`WARNING: NVIDIA Driver was not detected`） |
| Toolkit | CUDA 11.2，`nvcc 11.2.152` | CUDA 11.2.2，`nvcc 11.2.152` |
| 被测工具 SHA-256 | `da9f5983…a198e6b`（Windows cuobjdump.exe） | `564fd4fc…8d9f63b7`（Linux cuobjdump） |
| 命令 | `cuobjdump --dump-elf <artifact>` | 同左 |

## 2. 宿主侧对照（6 个非恶意样本）

超时 60 s、输出上限 1 MiB、原始证据落 `data/outputs/control_runs/<run_id>/`：

| 样本 | 退出码 | 结果 |
|---|---|---|
| `benign.cubin` | 0 | NORMAL_EXIT |
| `_ctrlA_zero_content.cubin` | 0 | NORMAL_EXIT |
| `_ctrlB_offset_restored.cubin` | 0 | NORMAL_EXIT |
| `_ctrlC_size_shrunk.cubin` | **3221225477** | WINDOWS_EXCEPTION（0xC0000005） |
| `_ctrlD_benign_content_at_eof.cubin` | 0 | NORMAL_EXIT |
| `_ctrlE_zero_payload.cubin` | 0 | NORMAL_EXIT |

## 3. 容器内全矩阵（同一构建、隔离执行）

隔离参数：`--network none --cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /tmp --pids-limit 128 --memory 1g --cpus 1`，样本目录只读挂载。
原始输出：`data/outputs/CVE-2025-23339/container_run/raw/matrix.txt`。

| 样本 | 退出码 |
|---|---|
| `benign.cubin` | 0 |
| `base.cubin` | 0 |
| `template.cubin` | 0 |
| `_ctrlB_offset_restored.cubin` | 0 |
| `_ctrlD_benign_content_at_eof.cubin` | 0 |
| `_ctrlA_zero_content.cubin` | 1（错误返回，非崩溃） |
| `_ctrlE_zero_payload.cubin` | 1（错误返回，非崩溃） |
| `_ctrlC_size_shrunk.cubin` | **139（SIGSEGV）** |
| `malicious.cubin` | **139** |
| `malicious_41414141.cubin` | **139** |
| `malicious_42424242.cubin` | **139** |
| `_ctrl_size_restored_malicious.cubin` | **139** |
| `_ctrl_size_restored_malicious_41414141.cubin` | **139** |
| `_ctrl_size_restored_malicious_42424242.cubin` | **139** |

判定：`SUPPORTED`——受控样本 6/6 崩溃、良性基线未崩溃、版本在区间内；
机制对照 1/5 同样崩溃，归因限制保留。

## 4. 本轮的真实发现

1. **`_ctrlC_size_shrunk.cubin` 在两个平台都崩溃**（Windows `0xC0000005`、Linux `SIGSEGV`）。
   它把声明 size 改回原值仍然崩，与该 CVE 的根因描述一致：循环终止条件取自输入数据
   自身，`sh_size` 不是上界。但这意味着"恶意样本崩了"不能单独归因到 LEB128 载荷。
2. **`_ctrl_size_restored_malicious_*` 同样崩溃**，进一步说明声明 size 不构成保护。
3. **对照集并非全部独立**：`_ctrlA_zero_content` 与 `_ctrlE_zero_payload` 的 SHA-256
   完全相同（`245cde44…3012e`），`template.cubin` 与 `benign.cubin` 相同
   （`6395873f…35df`）。实际独立变量少于文件数，报告不按文件个数夸大观测数。
4. **平台差异**：`_ctrlA/_ctrlE` 在 Windows 返回 0，在 Linux 返回 1。两者都不是崩溃，
   但说明同一工具的不同平台构建对同一输入的错误路径不同。

## 5. 已知限制（必须随结论一起引用）

1. **平台不同**：历史崩溃来自 Windows `cuobjdump 11.2.0`；本轮容器是 **Linux**
   `cuobjdump 11.2.152`。工具版本对齐到 11.2.x，但二进制不同，属**跨平台独立复现**，
   不是同一二进制的重复实验。
2. **无寄存器级证据**：未采集 RIP，无法证明 `0x41414141` 控制流劫持；
   `root_cause_proof_recorded` 保持 `False`。
3. **容器未挂 GPU**：本轮目标是用户态工具，不需要 GPU；GPU 相关系列仍待单独验证。

## 6. 下一步

1. 在容器镜像里加入 `gdb`，对 `malicious_41414141.cubin` 取崩溃时的 RIP，
   判断是否落在可控地址上。
2. 用 RIP 区分 `_ctrlC` 与 `malicious_*` 的路径；若两者 RIP 不同，可恢复单变量隔离结论。
3. 把上述流程固化为 `src/container_runner.py`，使任意 CVE 都能重复这条链路。
