# P13-4-F8-Step2：D3D11/DXGI 正常业务基线

基线 `61da41c`。本阶段建立**确定合法**的图形调用基线，并回答"能不能证明进了内核/私有分派"。

## 一、实验身份（本轮实测）

| 项 | 值 |
|---|---|
| 主机 | Windows x64（`data/driver/f8s2_baseline.json` 的 `host` 字段） |
| GPU | NVIDIA GeForce GTX 1660，`VendorId=0x10de`，`DeviceId=0x2184` |
| 枚举到的 NVIDIA 适配器 | **4 个**（LUID `0:b33b765e`、`0:00044326`、`0:0004401d`、`0:00043755`），另有 1 个 Microsoft Basic Render Driver（`0x1414:0x008c`，VRAM=0） |
| 选定适配器 | index 0，LUID `00000000:b33b765e`（显式按 VendorId 选硬件，未用 WARP/Basic Render） |
| 驱动文件 | `nvlddmkm.sys`，120,295,144 字节 |
| SHA256 | `31af1ce957c6065d0b4b01ba2a7ad27df386e32c15b536ce653a162e3425fa9c` |

原始记录：`data/driver/f8s1_probe.json`（Step 1）、`data/driver/f8s2_baseline.json`（本轮）。

## 二、任务一：ABI 约束的编译期核实

不再靠推算。`tools/driver/abi_sizes.c` 用 MSVC 直接打印：

```
D3DKMT_HANDLE 4
CREATEDEVICE size=64 flags=8 hDevice=12
GETDEVICESTATE size=56 stateType=4
  ExecutionState=4 PresentState=40 ResetState=4
  PresentStateDWM=48 PageFault=32
QUERYADAPTERINFO size=24 type=4 data=8 size_field=16
DRIVERVERSION 输出为 UINT（4 字节）
```

### 2.1 由此修掉的一个真 bug

`handle_validity.D3DKMT_GETDEVICESTATE` 原先只声明了 4 字节的联合体成员，
**结构体总长 44 字节，而真实结构是 56 字节**——驱动写回时会越界 12 字节。
已改为 48 字节联合体缓冲，`sizeof` 实测 56，与编译结果一致。

### 2.2 `QueryAdapterInfo(DRIVERVERSION)` 的失败不是尺寸问题

按编译事实，该类型输出只需 4 字节 UINT，而 Step 1 传的是 64 字节缓冲，**尺寸充足**。
它在**有效 adapter** 上仍返回 `0xC000000D`。因此不能把它解释成"驱动不支持该查询"，
也不能解释成"adapter 无效"——**原因是 UNKNOWN**，本轮不做推断。

### 2.3 CreateDevice 失败即中止

`handle_validity.run()` 现在在 `CreateDevice` 非 0 时直接跳过后继依赖调用，
并关闭 adapter，避免留下半初始化资源。

## 三、任务二：正常 D3D11 业务

程序：`tools/driver/d3d11_baseline.c`（正式公开 API，无私有请求）

```
DXGI_FACTORY hr=0x00000000
ADAPTER index=0 vendor=0x10de device=0x2184 luid=00000000:b33b765e
        vram=6255804416 name=NVIDIA GeForce GTX 1660
CHOSEN vendor=nvidia
D3D11_DEVICE hr=0x00000000 feature_level=0xb000
DEVICE_ADAPTER luid=00000000:b33b765e matches_chosen=yes
SWAPCHAIN hr=0x00000000
RTV hr=0x00000000
RENDER clear=ok
PRESENT hr=0x00000000
DEVICE_REMOVED reason=0x00000000
RELEASED all
```

- Feature Level `0xb000` = 11_0；
- 交换链、RTV、Clear、Present 全部 `S_OK`；
- `GetDeviceRemovedReason` = 0；
- 所有 COM 对象按引用顺序释放。

第一次运行 `matches_chosen=no`，原因是我的程序在循环里复用 `desc`，
比较时拿到的是最后一个适配器（Basic Render Driver）。已改为保存 `chosen_luid`，
复跑后为 `yes`。**这是实现错误，不是驱动行为。**

## 四、任务三：证据分级

| 级别 | 结论 | 依据 |
|---|---|---|
| A. DXGI 适配器身份 | **已确认** | VendorId/DeviceId/LUID/显存/名称齐全，且排除了 Basic Render Driver |
| B. D3D11 Device 创建 | **已确认** | `hr=0`，Feature Level 11_0 |
| C. 正常渲染 | **已确认** | Clear 成功、RTV 创建成功 |
| D. Present 成功 | **已确认** | `hr=0`，device removed reason 0 |
| E. 进入 Windows 图形内核路径的独立证据 | **未取得** | 本轮没有任何独立观测器；Present 成功只说明调用链完成，不证明内核侧执行细节 |
| F. 到达 NVIDIA 私有 Escape 分派 | **未取得** | 无任何观测；**不得**由 E 或 D 推出 |

### 4.1 关于诊断手段

- 前一轮已验证 `Microsoft-Windows-DxgKrnl` ETW 可采集，但**无法把事件归因到具体调用**，
  且没有 NVIDIA 自有 provider；
- 本轮**未**使用它来"证明" E，因为那会重犯"把背景活动当证据"的错；
- 因此 E/F 维持 UNKNOWN，等有独立观测手段再升级。

## 五、正常设备与 D3DKMT 设备的身份关联

| 调用 | 结果 |
|---|---|
| `OpenAdapterFromLuid(0:b33b765e)` | status 0，hAdapter `0x40000040` |
| `OpenAdapterFromHdc` | status 0，hAdapter `0x40000080` |
| 两者句柄值 | **不同** |

**这不是失败。** 每次 Open 都会分配新的 adapter 句柄；LUID 才是稳定身份。
这也解释了历史 notes 里"`hDevice` 与 `hAdapter` 相同，疑未分配设备"为何没有意义——
**句柄值在多次 Open 之间会被复用，相等纯属巧合**。

## 六、已确认与仍 UNKNOWN 的执行层级

```
已确认：用户态 API 成功（DXGI/D3D11/D3DKMT 全部 hr/status = 0）
已确认：目标适配器身份（LUID 0:b33b765e，GTX 1660）
已确认：D3D11 设备与该适配器关联（DEVICE_ADAPTER matches=yes）
UNKNOWN：内核侧是否真的执行了对应提交（无观测器）
UNKNOWN：是否存在 NVIDIA 私有 Escape 分派参与正常 Present
UNKNOWN：0xC000000D 来自哪一层
```

## 七、是否值得投入独立内核调试环境

结论：**值得，但不是现在**。

- 有了本轮基线，"合法调用"终于有了对照物；下一步可以用同一 LUID 下的
  **正常 Present** 与 **D3DKMT Escape** 做时间对齐，看能否找到相关性；
- 但相关性不是因果。要把 E 升级为"已证明"，仍然只有内核侧观测一条路
  （第二台主机 + KDNET，或在 VM 中做 GPU 直通）；
- 在那之前，任何"进入了私有分派"的说法都只能是 UNKNOWN。
- 建议顺序：先做时间对齐实验（零额外硬件），若仍无法区分，再投入独立调试环境。

## 八、边界

- 未发送任何私有 Escape，未做 Type/Flags/Size 扫描，未触发 CVE；
- 未修改驱动，未新增 CUDA/Mock 工作，未改 P11/P12 冻结基线；
- 原始程序与数据：`tools/driver/d3d11_baseline.c`、`tools/driver/abi_sizes.c`、
  `data/driver/f8s1_probe.json`、`data/driver/f8s2_baseline.json`。
