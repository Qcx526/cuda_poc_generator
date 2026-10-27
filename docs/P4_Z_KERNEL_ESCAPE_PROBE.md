# P4-Z 内核 escape 入口探测：实测记录与五条否证

报告语言：`zh-CN`。全部结论来自本机实测（GTX 1660 / 驱动 535.98 / Windows 10）。
每条结论都标注了**验证方式**，因为本次探测中反复出现"看起来通了、其实没通"的情况。

## 1. 结论摘要

**入口可达，但在到达驱动分发之前就被拒绝。**

已经能稳定完成：打开 adapter、创建设备、创建上下文，三者句柄均经返回值验证。
`D3DKMTEscape` 调用也能发出，但无论发送哪个 escape 码，返回都只有两种，且**与码无关**：

| 配置 | 返回 | 含义 |
|---|---|---|
| `Flags = 0` | `0xC000000D` STATUS_INVALID_PARAMETER | 参数校验未通过 |
| `Flags = 1`（HardwareAccess） | `0xC0000022` STATUS_ACCESS_DENIED | 校验通过，被权限拦下 |

进程已是管理员（`IsUserAnAdmin=True`），所以拒绝访问不是提权问题。

## 2. 已建立的能力（可直接复用）

| 步骤 | 调用 | 实测结果 | 验证方式 |
|---|---|---|---|
| adapter（不可用） | `OpenAdapterFromHdc` | `0x40000000` | 后续 CreateDevice 全部 `0xC000000D` |
| adapter（可用） | `OpenAdapterFromLuid`（LUID 取自上一步） | **`0x40000040`** | CreateDevice 成功 |
| device | `D3DKMTCreateDevice` | **`0x40000080`** | `DestroyDevice` 返回 0 |
| context | `D3DKMTCreateContext` | **`0x400000c0`** | 返回 0，句柄位于偏移 32 |

### 2.1 两个与头文件不一致的地方

**① 设备句柄不在偏移 0。** `D3DKMT_CREATEDEVICE` 按 WDK 是 union（hAdapter 进、hDevice 出）。
实测：发一个全零请求，回读缓冲区，只有两处非零——

```
offset 0  : 0x40000040  （传入的 adapter，未变）
offset 12 : 0x40000080  （驱动写回的 device）
```

用偏移 0 的值调 `DestroyDevice` → `0xC000000D`；用偏移 12 的值 → **0**。以此确认。

**② `D3DKMT_ESCAPE` 里 `Flags` 在 `EscapeCode` 之前**（偏移 8 / 12）。
顺序写反时永远返回 `0xC000000D`，看起来像"驱动不认这个码"。

> **方法提示**：当结构体不确定时，**发全零请求并回读哪些字节发生变化**，
> 比照着头文件猜偏移可靠得多。头文件描述的是某个版本，不是这台机器上的这个构建。

## 3. 五条否证

| # | 假设 | 实验 | 结果 | 结论 |
|---|---|---|---|---|
| 1 | NVAPI 通过 `DeviceIoControl` 访问驱动 | 在自身进程内替换 nvapi64 的 `DeviceIoControl` IAT 槽（槽内原指针 `0x7ffc17c958d0`，位于 kernelbase） | 调用 `GetFullName`/`GetThermalSettings` 均返回真实数据，**拦截到 0 次调用** | 文档化 NVAPI 不经过 `kernel32!DeviceIoControl` |
| 2 | 二进制里 `0x1000xxxx` 立即数就是 escape 码 | 扫描 `nvapi64.dll` 31 个 DeviceIoControl 调用点，提取 4 个码 | 发到 `NvAdminDevice` 全部 `ERROR_INVALID_FUNCTION`；设备类型解码为 `WAVE_OUT`/`ACPI` | 提取到的是音频/电源路径，不是 GPU 数据面 |
| 3 | 提取的码是 escape 码 | 检查出现位置 | `0x10001002` 与 `0x10000402` **总是成对出现在相隔约 60 字节处** | 这是结构体**版本检查**的形态，不是分发表 |
| 4 | 设备缺命令缓冲导致硬件 escape 被拒 | 带 64 KB command buffer 重建 + 重发 escape | 返回与之前**完全一致** | 与命令缓冲无关 |
| 5 | 可以从 UMD 的导入项抄到真实调用 | 检查 `nvwgf2umx.dll`（100 MB）导入表 | **不导入任何 D3DKMT 函数** | 现代 UMD 通过 `D3DDI_DEVICECALLBACKS` 回调表访问内核，IAT 补丁无处可打 |
| 6 | ETW 能采到真实 escape | 采样 `Microsoft-Windows-DxgKrnl`（全关键字，level 5），同时创建一个 D3D11 硬件设备 | 收到 **58,165 个事件**（ETL 6.3 MB），其中**没有一个与 escape 相关**；提供程序清单 7,417 行里唯一含 Escape 的事件是 `MiracastUmdSendMiracastEscape` | DxgKrnl 不跟踪通用 `D3DKMTEscape`，ETW 无法作为观测手段 |

## 4. 发现的真实结构

在 535.98 的 `nvlddmkm.sys` 中，按"8 KB 窗口内引用多少个不同 `0x1000xxxx` 常量"排序，
出现两处**连续编号**的簇，形态与 switch/case 一致：

```
文件偏移 0x9e000：
  0x10000000, 0x10000101, 0x10000102, 0x10000103,
  0x10000104, 0x10000105, 0x10000106, 0x10000107

文件偏移 0xa0000：
  0x1000010a, 0x1000012b, 0x1000012c, 0x1000012d, 0x1000012e, 0x1000012f
```

与"成对版本字"的区别在于**连续**：版本字是 `0x1000_1002` 这类带尺寸编码的值，且成对出现。

**但实测 `0x10000101/102/103` 仍全部返回 `0xC000000D`** —— 所以目前无法判断
这些是 escape 码还是别的分派域（例如内部操作码）。

## 5. 过程中发现的四个"静默错误"（方法论价值最高）

这四类错误的共同点：**不报错，给出一个看起来很确定的错误结论**。

| 错误 | 表现 | 根因 |
|---|---|---|
| PE 段头字段顺序 | "该 DLL 导出 0 个符号" | `VirtualSize` 与 `VirtualAddress` 读反 |
| 导入描述符偏移 | "该 DLL 不调用任何 API" | 从描述符内部偏移读，整体错位 |
| capstone 线性扫描 | "0 个调用点" | 遇到第一个非法字节就停止，7.8 MB 只扫了开头 |
| 驱动文件选择 | 分析了 560.94，而运行的是 535.98 | 按修改时间取"最新"，而 DriverStore 保留所有历史版本 |

> **对策**：任何"零结果"或"全命中"都要用**第二条独立证据**交叉验证。
> 例如：导出 0 个 → 换 kernel32 验证（1636 个）；调用点 0 个 → 检查扫描覆盖率。

## 6. 可复用方法（GPU 驱动 PoC 的入口判定）

```
1. 确认目标版本
   nvidia-smi → 版本号 → 在 DriverStore 中按版本匹配 nvlddmkm.sys（不是按时间）
   Windows 版本 → NVIDIA 版本：31.0.15.3598 → 5 + 3598 → 535.98

2. 打通 D3DKMT 三步
   OpenAdapterFromHdc（只为取 LUID）→ OpenAdapterFromLuid → CreateDevice → CreateContext
   每步都用"能否销毁/能否继续"验证句柄，不以返回 0 为准

3. 判定 escape 是否到达分发
   同一码，flags=0 与 flags=1 各发一次：
     两者返回相同 → 卡在更早的参数校验，先修结构体
     两者不同     → 结构体正确，问题在权限或码

4. 只有到达分发后，码的扫描才有意义
```

## 7. RAG 条目（供生成器检索）

```yaml
target: nvidia_kernel_escape
applies_to: [CVE-2026-24193, GPU driver kernel OOB]
entry_chain:
  - D3DKMTOpenAdapterFromLuid   # HDC 句柄不可用
  - D3DKMTCreateDevice          # 句柄在偏移 12
  - D3DKMTCreateContext         # 句柄在偏移 32
  - D3DKMTEscape                # Flags 在 EscapeCode 之前
known_blockers:
  - "Flags=0 恒返回 0xC000000D：结构体或参数不对，与码无关"
  - "Flags=1 恒返回 0xC0000022：非合法 UMD 客户端被拒"
  - "UMD 不导入 D3DKMT*，无法用 IAT 补丁观测"
verification_rules:
  - "句柄有效性的判据是能否被销毁，不是创建返回 0"
  - "零结果必须用第二条证据交叉验证"
```

## 8. 未解决

1. 我们的 `D3DKMT_ESCAPE` 仍缺一个内核认可的字段（最可能是句柄来源必须为合法 UMD 客户端）。
2. `0x100001xx` 族是否属于 escape 分派域，未验证。

**剩余手段只剩一种**：内联钩 `gdi32!D3DKMTEscape`（改写函数头 12 字节跳转到 detour，
并自建 trampoline 保存原指令）。它是唯一能观察到真实调用的方式，但改错指令边界会直接崩溃进程，
且中断点难以调试，属于高风险手段。

**已排除的观测手段**：IAT 补丁（UMD 无导入项）、回调查表（位置未定位）、ETW（提供程序不记录）。
