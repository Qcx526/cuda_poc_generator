# P11 D3DKMT ABI 与历史证据审计

审计日期：2026-11-02。范围：`tools/probe_d3dkmt.py`、`tools/driver/escape_probe.py`、
`docs/P4_Z_KERNEL_ESCAPE_PROBE.md`、`docs/P5_A_GPU_POC_FEASIBILITY.md`。

## 0. 审计基线（修订版补充）

本次审计所依据的仓库状态与运行环境，逐项记录如下。**未保存的数据标 `NOT_CAPTURED`，不补造。**

| 项 | 值 |
|---|---|
| 分支 | `main` |
| baseline HEAD | `39e31e56a793683c0ffef9b9e3383a9393408a59` |
| 原始 Git 状态（审计开始前） | 工作区干净；本次审计仅新增本文件（`A docs/P11_ABI_AND_HISTORY_AUDIT.md`） |
| `tools/probe_d3dkmt.py` | `ccb6520ca5344c22529f25cd3283aa9c9ca2d9805946966422c507a2ed7e0b59` |
| `tools/driver/escape_probe.py` | `6ec2bcf31e291936a215730e564b48a447ce47686902490a818b9194e2ef7fef` |
| `docs/P4_Z_KERNEL_ESCAPE_PROBE.md` | `5c47278367b922ca782dd448ecc11c4968fa3e077c6514007c874f7b29150cb7` |
| `docs/P5_A_GPU_POC_FEASIBILITY.md` | `afad3cb8258a212c82093dc4e1c29fcf75de0e51ccf77dabb0406a67cc7d4705` |
| `tests/test_probe_d3dkmt.py` | `4c5d5888437a5db31379012dffa1f3b97f4e415193fb1bc9afbd84071a34b564` |
| Python 版本 | `3.12.13` |
| 进程位数 / 机器 | `64bit` / `AMD64` |
| 本文件（本行记录的是**本次修订前**的版本） | `18fff047e3d1bcb197035029b84e82d5d048dbbcf739748575be62b0885118a1` |
| P4-Z 实验时的脚本与参数 | `NOT_CAPTURED`（见 §3.2） |
| P4-Z 的 `D3DKMTCreateContext` 实现 | `NOT_CAPTURED`（仓库内不存在） |

`ctypes.sizeof` 与字段偏移实测输出（本次审计，同一环境）：

```
escape_probe.D3DKMT_ESCAPE       sizeof=32
escape_probe.D3DKMT_CREATEDEVICE sizeof=24
probe_d3dkmt.ESCAPE              sizeof=32
probe_d3dkmt.CREATEDEVICE        sizeof=64

probe_d3dkmt.OPENADAPTERFROMHDC  sizeof=24
  hDc            offset=0
  hAdapter       offset=8
  AdapterLuid    offset=12
  VidPnSourceId  offset=20
```

## 0.1 本文的性质

这是**审计记录**，不是修复报告，也不是对历史的改写。

- 原始报告（P4-Z / P5-A）保持原样，不修改。它们记录的是当时按当时理解所做的实验，
  那个记录本身是真实的。
- 本文只追加三样东西：当时的结构体定义错在哪、那些结果因此能说明什么、
  以及在此之前的结论应当降到哪个证据等级。
- 已发生的事实不因为后来发现解释有误而消失；消失的是**由它推出的结论**。

## 1. 证据等级定义（本文统一使用）

| 等级 | 含义 |
|---|---|
| `OFFICIAL` | 厂商/平台官方文档或公告原文 |
| `MEASURED_REPRODUCIBLE` | 本机实测，且有产物（脚本/输出）可再次运行复现 |
| `MEASURED_UNREPRODUCIBLE` | 本机实测过，但缺少可再次运行的产物 |
| `DOCUMENTED_EXPERIMENT` | 仅见于文档叙述，无脚本、无原始输出 |
| `STATIC_INFERENCE` | 由反汇编/结构定义推断，未执行 |
| `UNMAPPABLE` | 原始参数与所用脚本无法对应，任何解释都不成立 |

---

# 2. 第一部分：D3DKMT ABI 审计

## 2.1 官方定义（`OFFICIAL`，Microsoft Learn，d3dkmthk.h）

`D3DKMT_ESCAPE`，x64 共 32 字节：

```
偏移 0   D3DKMT_HANDLE      hAdapter
偏移 4   D3DKMT_HANDLE      hDevice
偏移 8   D3DKMT_ESCAPETYPE  Type          ← 不是 Flags
偏移 12  D3DDDI_ESCAPEFLAGS Flags
偏移 16  VOID               *pPrivateDriverData
偏移 24  UINT               PrivateDriverDataSize
偏移 28  D3DKMT_HANDLE      hContext
```

`D3DKMT_CREATEDEVICE`，x64 共 64 字节：

```
偏移 0   union { D3DKMT_HANDLE hAdapter; VOID *pAdapter; }   ← 含指针，占 8 字节
偏移 8   D3DKMT_CREATEDEVICEFLAGS Flags
偏移 12  D3DKMT_HANDLE            hDevice
偏移 16  VOID                    *pCommandBuffer
偏移 24  UINT                     CommandBufferSize
偏移 32  D3DDDI_ALLOCATIONLIST   *pAllocationList
偏移 40  UINT                     AllocationListSize
偏移 48  D3DDDI_PATCHLOCATIONLIST *pPatchLocationList
偏移 56  UINT                     PatchLocationListSize
```

注意 `Flags` 落在偏移 8、`hDevice` 落在偏移 12，**不是驱动特例**：union 里含 `pAdapter`
指针，x64 下就是 8 字节。P4-Z 把这一点写成"WDK 的 union 描述不适用于这个 build"，
这个判断本身是错的（该说法列为本审计第 4 条待更正记录）。

## 2.2 两个脚本必须分开解释

这是本次审计的核心修正：**两个脚本错的位置不同，因此不能用同一句话概括历史结果。**

先看两个脚本实际做了什么（以仓库当前版本为准，SHA 见 §0）。

`tools/probe_d3dkmt.py` 的 `send_escape(h_adapter, h_device, code, payload)`：

```python
request.hAdapter = h_adapter
request.hDevice  = h_device
request.EscapeCode = code          # 结构体里偏移 12 的字段
# request.Flags 从未赋值 → 偏移 8 保持 0
```

`tools/driver/escape_probe.py` 的 `escape(handle, command, size, fill=0x00, device=0)`：

```python
buffer = (ctypes.c_ubyte * max(size, 8))()
ctypes.memset(buffer, fill, len(buffer))            # 全缓冲先按 fill 填充
memmove(buffer,            command, 4)              # payload 第 0 个 DWORD = command
memmove(buffer + 4,        size,    4)              # payload 第 1 个 DWORD = size
request.hAdapter = handle
request.hDevice  = device
request.Flags    = 0                                # 常量，无 flags 参数
```

**注意：该函数没有 `flags` 参数。** `request.Flags` 是硬编码的 0。

由此得到的对照：

| | `probe_d3dkmt.py` | `tools/driver/escape_probe.py` |
|---|---|---|
| `D3DKMT_ESCAPE` 大小 | 32 字节（正确） | 32 字节（大小对，字段错位） |
| 偏移 8 的字段名 | `Flags` | `Flags` |
| 偏移 12 的字段名 | `EscapeCode` | 无（被当作 padding） |
| 偏移 8 实际被写入 | 从未赋值 → **恒 0** | `request.Flags = 0` → **恒 0** |
| 偏移 12 实际被写入 | **`code`（来自 `--escape-code`）** | 无 → **恒 0** |
| 真实含义（官方） | 偏移 8 = `Type`，偏移 12 = `Flags` | 同左 |
| 后果 | `Type` 恒为 0（DRIVERPRIVATE）；传入的 `code` **变成 Flags 位** | `Type` 与 `Flags` **都恒为 0**；唯一变化的是 payload |
| `D3DKMT_CREATEDEVICE` 大小 | 64 字节（符合官方） | **24 字节**（官方 64） |

**结论一**：两个脚本都没有能力改变 `Type`。`probe_d3dkmt.py` 改的是 `Flags`，
`escape_probe.py` 连 `Flags` 都不改——它只改 payload。

**结论二**：历史记录 `Flags=0 → INVALID_PARAMETER` / `Flags=1 → ACCESS_DENIED` 的
**可能来源不止一个**，且不能唯一定位：

| 可能来源 | 它写入偏移 8（`Type`）的值 | 它写入偏移 12（`Flags`）的值 | 能否产生 "Flags=0/1" 的差异 |
|---|---|---|---|
| `probe_d3dkmt.py` 的 `send_escape(code, ...)` | 从未赋值 → 0 | **`code`** | **能**：`code=0` 与 `code=1`（bit0 = HardwareAccess） |
| 未入库的一次性脚本（`r.Flags = flags`） | **`flags`** | 未赋值 → 0 | 能，但写的是 `Type` 而非 `Flags` |
| `escape_probe.escape()` | 0（硬编码） | 0（padding） | **不能**：两者都不可变 |

`probe_d3dkmt.py` 这一条最贴合 P4-Z 的叙述：`code` 正好落在 `Flags`（偏移 12），
而 `code=1` 正好置起 `HardwareAccess` 位——与"`Flags = 1`（HardwareAccess）"逐字对应。

但"最贴合"不等于"已确认"。P4-Z 没有保存当时的命令行参数，无法把每一条记录绑定到具体脚本，
因此：

> 具体记录的来源标 `UNMAPPABLE`；上表只用于说明**存在哪些可能**，不用于断言某条记录属于哪种。

同时明确两点，都是否定式的：

- **不得**断言历史记录对应 `Type=1` 或 `Type=2`。没有任何证据表明那次实验改变过 `Type`。
- **不得**把 `ACCESS_DENIED` 直接归因于 OS 或 NVIDIA，理由见 §3.3。

这条更正替换本文件上一版 §2.2 与 §3.2 中"只可能来自一次性脚本"的说法——那个说法是错的。

## 2.2.1 模块函数与一次性脚本都可能产生历史差异

上一版审计把历史记录归因于一次性脚本，理由是"`escape_probe.escape()` 无 `flags` 参数"。
这个理由成立，但**结论过头**：它只排除了 `escape_probe.escape()` 一个来源，
没有排除 `probe_d3dkmt.py`——后者的 `send_escape` 恰恰有一个 `code` 参数落在 `Flags` 上。

正确表述是：仓库内**只有** `probe_d3dkmt.send_escape` 能让 `Flags`（偏移 12）随参数变化；
`escape_probe.escape()` 两个字段都不可变；未入库脚本若存在，则可能让 `Type`（偏移 8）变化。
三者中以第一种最贴合 P4-Z 的措辞，但参数未保存，无法坐实。

## 2.3 关于 64 字节缺口的准确表述

`escape_probe.py` 的 `D3DKMT_CREATEDEVICE` 只有 24 字节，而 API 约定为 64 字节。
这构成 **ABI 违约**（calling convention / struct layout violation）。

**本文不断言 API 实际写出了结构体之后的 40 字节。** 理由：

- 未做过内存检测（未在结构体后放置金丝雀并回读）。
- 官方也未承诺"必写满 64 字节"，各字段按需填充。
- 从行为看，`CreateDevice` 返回 0 而后读回的 `hDevice` 等于传入的 `hAdapter`，
  与"句柄没有落在我们读取的位置"一致，但**不能反推越界写已经发生**。

结论等级：`STATIC_INFERENCE`（ABI 违约成立）+ `UNVERIFIED`（是否越界写，待内存检测）。

**复用风险**：在该结构体修复并做金丝雀检测之前，禁止用它产生新的实验结论。

## 2.4 两个脚本的私有数据都不是有效命令，但原因不同

**不能说"两个脚本都发送了全零缓冲区"**——它们的 payload 完全不同：

| | `probe_d3dkmt.py` | `escape_probe.py` |
|---|---|---|
| payload 来源 | `payload = bytes(args.payload_size)`（`--payload-size` 默认 16） | `size` 与 `fill` 参数 |
| 内容 | **零填充** | 第 0 个 DWORD = `command`，第 1 个 DWORD = `size`，其余按 `fill` 填充 |
| 默认情况 | 全零 | 头部是命令号+大小，其余为零 |

统一结论只有一句，且必须限定范围：

> **没有任何一次实验被证明发送过符合 NVIDIA 厂商私有协议的有效命令。**

理由分两层：

1. **结构层**：`escape_probe.py` 的 `D3DKMT_CREATEDEVICE` 只有 24 字节，device 句柄不可信；
   在没有可信 device 的前提下，即使 payload 结构正确也无法断言请求到达了 KMD。
2. **内容层**：`probe_d3dkmt.py` 的 payload 为零；`escape_probe.py` 只写了自拟的
   `{command, size}` 头部——**这是我们的假设，不是已确认的 NVIDIA 协议格式**。
   仓库中没有任何依据证明该头部与实际驱动接受的格式一致。

因此"发过私有命令"这一命题在两层上都不成立，而两层的失败原因不同，不能合并叙述。

## 2.5 `D3DKMT_OPENADAPTERFROMHDC` 的 ABI 核对

上一版把这一项标为"未核对"。本次补上，并区分**官方定义**与**本机实测**。

**官方定义**（`OFFICIAL`，Microsoft Learn，`ns-d3dkmthk-_d3dkmt_openadapterfromhdc`）：

```c
typedef struct _D3DKMT_OPENADAPTERFROMHDC {
  [in]  HDC                            hDc;
  [out] D3DKMT_HANDLE                  hAdapter;
  [out] LUID                           AdapterLuid;
  [out] D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
} D3DKMT_OPENADAPTERFROMHDC;
```

**本机实测**（`MEASURED_REPRODUCIBLE`，`tools/probe_d3dkmt.py` 的 `OPENADAPTERFROMHDC`）：

```
sizeof = 24
  hDc            offset=0     ← HDC 为指针，8 字节
  hAdapter       offset=8     ← D3DKMT_HANDLE，4 字节
  AdapterLuid    offset=12    ← LUID { DWORD LowPart; LONG HighPart; }，8 字节
  VidPnSourceId  offset=20    ← UINT，4 字节
```

**对照结论**：偏移与大小均与官方一致（`hDc` 占 0–7 → `hAdapter` 必在 8，LUID 8 字节
使 `VidPnSourceId` 落在 20，总长 24）。这一项与 `CREATEDEVICE`、`ESCAPE` 不同，
**不存在布局偏差**。

`tests/test_probe_d3dkmt.py` 对该结构断言了 24 字节与 `hAdapter@8`，与官方一致，
因此这条断言本身是正确的（该文件的问题在 `ESCAPE` 的命名，见 §4.1）。

---

# 3. 第二部分：P4-Z 历史结果的重新映射

## 3.1 P4-Z 原始记录（保持原样引用）

P4-Z 记载（原文语义）：

| 配置 | 返回 |
|---|---|
| `Flags = 0` | `0xC000000D` STATUS_INVALID_PARAMETER |
| `Flags = 1`（HardwareAccess） | `0xC0000022` STATUS_ACCESS_DENIED |

当时由此推出："校验通过，被权限拦下"，并进一步解释为 NVIDIA 的授权检查。

## 3.2 重新映射（逐条，按脚本）

P4-Z 描述的是"改 `Flags` 的两个取值"。`probe_d3dkmt.py` 确实具备这条路径：
`send_escape(h_adapter, h_device, code, payload)` 把 `code` 写进偏移 12（= `Flags`），
`Type`（偏移 8）保持 0。`code=0` 得到 `Flags=0`，`code=1` 置起 `HardwareAccess`——
与 P4-Z 的两行记录逐字对应。

因此这批记录或与本文件 §2.2.1 的三种来源之一或多条一致；**在没有参数留档的前提下，
任何一条具体记录都无法绑定到某个脚本**：

> **具体记录一律标 `UNMAPPABLE`。**

可陈述的只有各来源的静态能力（`STATIC_INFERENCE`），且不用于断言历史事实：

- `probe_d3dkmt.send_escape`：`Type` 恒 0（DRIVERPRIVATE），`Flags` 随 `code` 变化。
- `escape_probe.escape()`：`Type` 与 `Flags` 都恒 0，变化只有 payload。
- 未入库一次性脚本（若存在）：写的是偏移 8，即 `Type`；内容不可考。

三点限定：

1. **不得**据此断言历史 `Type` 为 1 或 2——没有任何证据显示那次实验改过 `Type`。
2. **不得**把 `ACCESS_DENIED` 归因于 OS 或 NVIDIA 任一侧，理由见 §3.3。
3. 若日后找到当年的命令行参数或脚本副本，可回到本节逐条重新映射；在此之前保持 `UNMAPPABLE`。

## 3.3 `ACCESS_DENIED` 能说明什么、不能说明什么

| 命题 | 判定 |
|---|---|
| "D3DKMTEscape 这次调用返回了 ACCESS_DENIED" | 可以记录（`API_CALL_OBSERVED`） |
| "拒绝发生在 Windows 图形内核的参数/权限检查" | **不能断言**，需调用路径证据 |
| "拒绝来自 NVIDIA KMD 的授权检查" | **不能断言**，需调用路径证据 |
| "这就是 CVE-2026-47571 的那处授权检查" | **不成立** |

要跨越这条线，至少需要以下之一。注意它们都是**条件性手段**，可用性取决于验证结果：

| 手段 | 状态 |
|---|---|
| ETW `Microsoft-Windows-DxgKrnl` 捕获对应 escape 事件 | **条件性**：P5-A 记录在 58,165 个事件中未发现通用 escape 事件（含 Miracast 专用事件一次）。不能预设该通道能观测到我们关心的调用。使用前须先证明该 provider 在本机确实记录此路径。 |
| 内核调试器（KDNET）在 `DxgkDdiEscape` 或 KMD 入口断下抓栈 | 条件性：需要第二台主机与被调试目标，当前环境未具备 |
| 改变某一层检查后同一请求状态码随之变化，且变化可归因于该层 | 条件性：需要先能分辨层级，否则回到循环论证 |

在取得其中之一之前，`ACCESS_DENIED` 只能记为 `OS_GATE_RESULT_OBSERVED`（层级未定）。

---

# 4. 第三部分：历史实验可信度修订表

按要求拆成三行，不合并等级，并单列"当前 ABI 复验"一栏——**历史实测不等于当前 ABI 已重新验收**。

| 能力 | 历史记录 | 仓库产物 | 修订等级 | 当前 ABI 复验 |
|---|---|---|---|---|
| **Adapter** | P4-Z：`OpenAdapterFromLuid` → `0x40000040`，后续 CreateDevice 成功 | `probe_d3dkmt.py` 含对应实现 | `MEASURED_REPRODUCIBLE` | **未做**（本次仅审计，未执行） |
| **Device** | P4-Z：句柄位于偏移 12，`DestroyDevice` 返回 0 | 同上，结构体 64 字节符合 ABI | `MEASURED_REPRODUCIBLE` | **未做**；且回归测试未覆盖该偏移（见 4.1） |
| **Context** | P4-Z：句柄位于偏移 32，返回 0 | **无实现、无原始输出** | `DOCUMENTED_EXPERIMENT` | 不适用 |

补充说明：

- Adapter 一行给 `MEASURED_REPRODUCIBLE`，指的是"当时有过实测且有可再跑的脚本"，
  不代表本次审计已重新跑过。复验栏因此写"未做"。
- Device 一行同理。它的历史可信度比 Adapter 稍强（`DestroyDevice` 返回值构成二次验证），
  但**测试套件没有锁住这一点**，见 4.1。
- Context 一行不给任何实测等级。文档里描述的"句柄位于偏移 32"无法核对：
  没有可运行的实现，也没有保存当时的缓冲区。

## 4.1 回归测试的覆盖情况（本次审计新增）

`tests/test_probe_d3dkmt.py` 共三条断言，实际覆盖如下：

| 断言 | 内容 | 与官方是否一致 |
|---|---|---|
| `OPENADAPTERFROMHDC` 24 字节、`hAdapter@8` | 结构体布局 | **已核对，与官方一致**（见 §2.5） |
| `ESCAPE.hAdapter@0`、`hDevice@4`、**`Flags@8`**、**`EscapeCode@12`** | 字段偏移 | **命名与官方相反**：官方为 `Type@8`、`Flags@12` |
| `CREATEDEVICE.hAdapter@0` | 仅首字段 | **未断言 `hDevice@12`，未断言 `sizeof == 64`** |

其 docstring 写"hAdapter in, hDevice out, in the same four bytes"，与官方布局相反
（官方 `hDevice` 在偏移 12）。

**结论：现有测试不但没有覆盖 Device 的 `hDevice@12`，还把 `ESCAPE` 的错误命名固化成了断言。**
测试全绿（1645 通过）在这一点上不构成正确性证据。

## 4.2 需要更正的一处历史判断

P4-Z 将"Flags 在 8、hDevice 在 12"描述为驱动与 WDK 不一致的特例。
按官方文档，这**正是** WDK 的布局（`CREATEDEVICE` 的 union 含 `pAdapter` 指针，占 8 字节）。
记录为 `HISTORICAL_MISJUDGEMENT`，但不改动原报告。

---

# 5. 第四部分：CVE-2026-47571 当前证据等级

本节不重复调研，只把已有证据按等级归档。

| 命题 | 等级 | 来源 |
|---|---|---|
| GTX 1660 + Windows + 610.47 落在受影响范围 | `OFFICIAL` | CSAF 2026/5861：GeForce Windows R610 < 610.60，无架构限制 |
| 该 CVE 仅 Windows | `OFFICIAL` | 表中无任何 Linux 条目 |
| 本机可打开 adapter | `MEASURED_REPRODUCIBLE` | 见 §4 |
| 本机可创建 device | `MEASURED_REPRODUCIBLE` | 见 §4 |
| 本机可创建 context | `DOCUMENTED_EXPERIMENT` | 无实现 |
| 曾向 KMD 发送合法私有命令 | **不成立** | payload 为零填充（`probe_d3dkmt.py`）或自拟 `{command,size}` 头部（`escape_probe.py`），且 device 句柄不可信；见 §2.4 |
| 观察到 NVIDIA 授权检查 | **不成立** | 见 §3.3 |
| 目标 Handler 可达 | **不成立**（无证据） | — |

**结论：47571 目前只有"环境在范围内"这一条官方支撑的成立项；触发路径证据为零。**

---

# 6. 第五部分：Phase 0 验收标准（修订版）

按审计意见，删除三条不合理要求，替换如下。

## 6.1 结构体一致性

- `D3DKMT_ESCAPE` 用 `sizeof` 断言 == 32；字段偏移与官方表逐项对齐，含 `Type`。
- `D3DKMT_CREATEDEVICE` 用 `sizeof` 断言 == 64。
- 两个结构体都以**官方文档**为唯一依据，不以"驱动实际写了什么"反推布局。

## 6.2 越界风险的检测（替代"断言越界已发生"）

- 在结构体后放置金丝雀（前后各 32 字节），调用后回读比对。
- 记录**是否**发生越界写，而不是预设它发生。
- 未做此检测前，不得声称"API 写出了 40 字节"。

## 6.3 Device 创建的可复现性

- `CreateDevice` 后 `hDevice` 非 0 且 ≠ `hAdapter`。
- `DestroyDevice(hDevice)` 返回 0。
- 以上在**新结构体**下重跑一次，与 P4-Z 的历史值比对，记录异同。

## 6.4 关于 `ACCESS_DENIED` 的表述（已删除原第 5 条）

原验收要求"改变 HardwareAccess 后状态码应变化"，现**删除**。理由：
状态码是否随该位变化，取决于 OS/KMD 哪一层先拒绝，不是 ABI 正确性的必要条件。

新要求只有一条：

- 对每一次 `ACCESS_DENIED`，必须标注**层级未定**（`OS_GATE_RESULT_OBSERVED`），
  除非取得 §3.3 所列三类证据之一。

## 6.5 关于私有数据（已删除原要求）

原验收要求"发送任意非零私有数据"，现**删除**。理由：
发送任意非零数据既不证明 ABI 正确，也可能在低层触发未预期行为。
私有数据只在**有明确命令结构假设**时构造，且假设须单独记录。

## 6.6 复用禁令

- 旧版 `escape_probe.py` 在修复并通过 6.1～6.3 之前，**不得用于产生新结论**。
- 历史数据可用，但须按 §3.2 标注 `UNMAPPABLE` 或对应脚本来源。

---

# 7. 未决问题（留待 Phase 1）

1. P4-Z 那批 `Flags=` 记录由哪个脚本产生，**仍无法确定**。仓库内 `probe_d3dkmt.send_escape`
   具备该能力（`code` → 偏移 12 的 `Flags`），未入库脚本亦可能，两者不可区分。
   在找到当年的命令行参数或脚本副本之前，具体记录保持 `UNMAPPABLE`。
2. 若确认来自 `probe_d3dkmt.send_escape`，则 `Type` 恒为 0（DRIVERPRIVATE），
   该记录只说明"不同 `Flags` 位下状态码不同"，不说明 `Type` 被改过。
   本节**不推定**任何 `Type` 取值。
3. Context 的历史实现是否存在于仓库之外（其他分支、本地脚本、其他机器）。
4. `D3DKMT_CREATEDEVICE` 的 64 字节缺口是否真的造成过越界写（需金丝雀检测）。
5. **回归测试需要修正**：`tests/test_probe_d3dkmt.py` 目前把 `Flags@8 / EscapeCode@12`
   的错误命名固化为断言，且未断言 `hDevice@12` 与 `sizeof==64`。修正前，测试全绿不能作为
   ABI 正确性证据。
6. `ACCESS_DENIED` 的层级归属（OS 侧 / KMD 侧）仍是开放的，见 §3.3 的三条条件性手段。

# 8. 本文引用的证据来源

| 来源 | 用途 | 等级 |
|---|---|---|
| Microsoft Learn `ns-d3dkmthk-_d3dkmt_escape` | 字段顺序与偏移 | `OFFICIAL` |
| Microsoft Learn `ns-d3dkmthk-_d3dkmt_createdevice` | union 大小与字段偏移 | `OFFICIAL` |
| Microsoft Learn `ns-d3dkmthk-_d3dkmt_openadapterfromhdc` | 字段顺序（§2.5） | `OFFICIAL` |
| `tools/probe_d3dkmt.py` 源码 | 实际结构体与写入位置 | 仓库文件 |
| `tools/driver/escape_probe.py` 源码 | 同上 | 仓库文件 |
| `ctypes.sizeof` 实测（本次审计） | 24 / 32 / 64 字节 | `MEASURED_REPRODUCIBLE` |
| `docs/P4_Z_KERNEL_ESCAPE_PROBE.md` | 历史结论原文 | `DOCUMENTED_EXPERIMENT` |
| `docs/P5_A_GPU_POC_FEASIBILITY.md` | 11 条否证与 ETW 记录 | `DOCUMENTED_EXPERIMENT` |
| `tests/test_probe_d3dkmt.py` 源码 | 现有断言内容（§4.1） | 仓库文件 |
| CSAF `2026/5861` | 47571 受影响范围 | `OFFICIAL` |

---

# Appendix A. P12-F1 历史成功路径丢失事件

记录日期：2026-11-02。性质：**事故记录**，不修改正文，不修改 P4-Z / P5-A。

## A.1 曾经存在的过程叙述

在 P12（2026-11-02 上午）的一次真实运行中，LLM 生成的候选在 Windows 宿主机上
完成了以下调用并打印了结果（叙述来源：当轮会话记录与随后的阶段汇报）：

```
device=\\.\DISPLAY34 attached=2 luid=0x0000000055e59596
hAdapter=0x40000040  hDevice=0x40000080
CreateContext ntstatus=0x00000000  hContext=0x400000c0
escape ntstatus=0xc000000d size=16 zeroed payload
```

这条叙述当时的用途是"证明 LLM 能生成可运行的驱动探针"。

## A.2 当前可以检索到的真实执行记录

`history_index.scan()` 对 `data/driver/llm_poc`、`data/driver/p12f`、
`data/driver/p12f2` 做只读扫描，结果：

| 实验 id | 分类 | 调用序列（前 3） |
|---|---|---|
| `02d53d9514a10843` | `D3DKMT_ESCAPE_CALL_OBSERVED` | EnumDisplayDevicesW → CreateDCW → OpenAdapterFromHdc |
| `d98a1ba291666710` | `D3DKMT_ESCAPE_CALL_OBSERVED` | EnumDisplayDevicesW → CreateDCW → OpenAdapterFromHdc |
| `e21addca7c2381d4` | `D3DKMT_ESCAPE_CALL_OBSERVED` | CreateDCW → OpenAdapterFromHdc → OpenAdapterFromLuid |
| `6308621103861159` | `NO_EVIDENCE` | CreateDCW |
| `ee638984ff1a57a5` | `NO_EVIDENCE` | CreateDCW |
| `2709608a3ca17c5b` | `NO_EVIDENCE` | （无调用记录） |

**`SETUP_PATH_SUCCESS` 为 0 条。**

## A.3 无法恢复的原始产物

A.1 那条运行对应的 `run.log`、`poc.py`、`llm_response.txt` 已被覆盖：同一目录在
随后的三轮实验中被写入 `round1..round3`，原 `round2` 内容不复存在。

恢复尝试与结果：

| 途径 | 结果 |
|---|---|
| `git log -- data/driver/llm_poc` | **无记录**（该目录从未提交） |
| 仓库内备份/副本（`*.bak`、重复 round 目录） | 无 |
| `data/driver/p12f`、`p12f2` | 只有 CreateDCW 失败的记录，无 setup 成功 |

结论：**该产物不可恢复。** 不作补造。

## A.4 当前能够支持的结论

| 命题 | 能否成立 | 依据 |
|---|---|---|
| 当时存在一次运行，其候选代码调用了 adapter/device/context 相关 API | 只能作为**过程叙述**成立 | §A.1，非仓库产物 |
| 该次运行的 hDevice/hContext 是驱动真实返回的句柄 | **不能确认** | 无原始 run.log，无状态码记录 |
| 该次运行可作为 `SETUP_PATH_SUCCESS` 供后续复用 | **不成立** | 无执行记录可用 |
| 仓库中另有文件提到 `hDevice=0x…` | 不能作为证据 | 那些是 prompt / 模型输出文本 |

因此索引中该路径不存在；P12-F2 的模型实际复用的是
`D3DKMT_ESCAPE_CALL_OBSERVED` 类实验的调用序列，而不是一条 setup 成功路径。

## A.5 由此确立的规则

1. **Prompt 文本与 LLM 输出不是执行证据。** 只有 `run.log` 中带状态码的调用记录
   （`CPG_DRIVER` / `CPG_RESULT`）才参与索引。
2. **状态码不是"到达"的证据。** escape 返回 `0xC000000D` 只记为
   `D3DKMT_ESCAPE_CALL_OBSERVED`；升级为 `DRIVER_INTERFACE_REACHED` 需要独立的
   运行时命中记录（断点命中 / probe 命中）。
3. **实验目录不得在用 `rm -rf` 清理**。清理前必须先提交或复制到归档目录，
   否则一次实验的所有权证据会随目录消失。
