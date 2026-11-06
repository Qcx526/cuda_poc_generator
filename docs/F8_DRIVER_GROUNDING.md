# P13-4-F8：GPU 驱动约束接地

基线 `7443b88`。本轮目标是**识别真实请求需要满足哪些前置条件**，以及**能客观证明调用到达了哪一级**，
不追求触发 CVE。

> 说明：本文只写仓库里有出处的事实。工作记忆里出现过 `0x1859380`（门禁）与 `0x186bc40`
> 等地址，但**在 `docs/`、`data/driver/*.json` 里都搜不到**，故一律记为 UNKNOWN，
> 不作为事实引用。

## 一、当前驱动执行证据清单

### 1.1 目标身份（本轮实测）

| 项 | 值 |
|---|---|
| 路径 | `C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_c8bc842500fab35b\nvlddmkm.sys` |
| 大小 | 120,295,144 字节 |
| SHA256 | `31af1ce957c6065d0b4b01ba2a7ad27df386e32c15b536ce653a162e3425fa9c` |
| 版本 | 610.47（受影响侧）；610.62 为修复侧对照文件 |

### 1.2 用户态调用链（已实现并跑通）

```
OpenAdapterFromHdc / OpenAdapterFromLuid
  → CreateDevice
  → CreateContext
  → Escape(Type, Flags, pPrivateDriverData, Size)
  → DestroyContext / DestroyDevice / CloseAdapter
```

实测结果（`data/driver/p13_4f2_c|d/CVE-2026-47571/round*/run.log`）：

```
A/B/C/D 四组共 8 轮，Escape 全部返回 0xC000000D；Adapter 全部成功；
Device/Context 在 B R1、C R1 失败，D R1 未发 Escape。
```

### 1.3 按 Flags 分布的状态（`data/driver/escape-map.json`，实测记录）

| Flags | 返回 |
|---|---|
| 0 | INVALID_PARAMETER (0xC000000D) |
| 1 | ACCESS_DENIED |
| 2 | NOT_SUPPORTED |
| 0x14 | BUFFER_TOO_SMALL |
| 0x1e | BUFFER_TOO_SMALL / NOT_SUPPORTED |
| 0xd | NOT_FOUND |
| 0x41 | INVALID_PARAMETER（ACCESS_DENIED 消失） |

**这一列是本轮最重要的既有证据**：同一个 Type、同一个空缓冲区，仅改 Flags 就得到
四种不同状态，说明调用**确实进入了驱动的分派逻辑**，不是 API 层的桩式拒绝。
因此"0xC000000D 是参数非法"这一读法是**可能的**，但**尚未证明它来自哪一层**。

同文件的 notes 记录了两条反向证据：

1. `ACCESS_DENIED` 发生在任何缓冲区处理之前 → 调用者身份检查在前；
2. `CreateDevice` 返回的 `hDevice` 与 `hAdapter` **相同**，疑未真正分配设备。

## 二、现有静态事实（带出处）

| 事实 | 值 | 出处 |
|---|---|---|
| 入口点 | RVA `0x733a0e0`，42 字节，12 条指令 | `data/driver/binary/entry_610_47.json` |
| 入口调用者 | 4 个（含 `Entry Point`） | 同上 `callers` |
| 610.47 函数数 | 79,615 | `data/driver/binary/match_610_47_vs_62.json` |
| 610.62 函数数 | 79,611 | 同上 |
| 配对成功 | 75,756（identical 34,735 / relocated 41,021） | 同上 |
| 未配对 | 3,859 / 3,855 | 同上 |

**限制**：这些是 PE/.pdata 边界与字节比对结果，属于**静态事实**，
不能说明任何函数在运行时被执行到。

## 三、0xC000000D 候选约束图

按"能证明到哪一级"排列，每条给出支持证据与缺失证据。

### C1：`hDevice` 不是该客户端的真实设备（最可疑）

- **支持**：`escape-map.json` notes 记录 `hDevice == hAdapter`；`flags=1` 时返回
  `ACCESS_DENIED`（身份检查确实存在且在前）；换成真实 D3D11 设备后 `flags=1` 仍被拒。
- **缺失**：没有证据表明 `CreateDevice` 成功时内核真的分配了设备对象；
  无法读取 `hDevice` 指向的内核对象类型。
- **判定**：`HYPOTHESIS`（有间接观测，无直接证明）

### C2：私有请求体结构不合法（Size/内容）

- **支持**：`flags=0x14` 返回 `BUFFER_TOO_SMALL`，说明缓冲区尺寸确实被校验；
  `flags=0x41` 让 `ACCESS_DENIED` 变成 `INVALID_PARAMETER`，说明状态随 Flags 变。
- **缺失**：`Type=0` 对应的私有结构布局未知；没有合法样本可比对。
- **判定**：`HYPOTHESIS`

### C3：`Type=0` 不是该驱动认识的命令号

- **支持**：`flags=0x40`（DriverKnownEscape）位使 `ACCESS_DENIED` 变为
  `INVALID_PARAMETER`，但 512 个命令号**全部**返回 `INVALID_PARAMETER`。
- **缺失**：无法区分"命令号不存在"与"命令号存在但参数错"。
- **判定**：`HYPOTHESIS`（且 512 命令号全失败更像 C1 的连带结果）

### C4：分派前的通用参数校验（Size 字段、指针对齐）

- **支持**：`BUFFER_TOO_SMALL` 与 `NOT_SUPPORTED` 的存在说明有多级校验。
- **缺失**：没有任何一层校验能被定位到具体 RVA。
- **判定**：`UNKNOWN`

### C5：API 层（win32u / gdi32）直接拒绝，未进内核

- **支持**：`0xC000000D` 也可能来自用户态封装。
- **反对**：Flags 不同导致状态不同（含 `BUFFER_TOO_SMALL`），用户态封装通常不会产生这种区分。
- **判定**：`WEAKLY_REFUTED`（未能排除，但证据偏向"已进内核"）

## 四、能证明到哪一级

| 级别 | 结论 |
|---|---|
| API 被调用 | 已证明（用户态返回值 + 调用序列） |
| 对象生命周期建立 | 部分（Adapter 是；Device 可疑；Context 依赖 Device） |
| 进入内核分派 | **未直接证明**，但有强间接证据（Flags → 四种状态） |
| 到达具体分支 | 未证明 |
| 触发目标缺陷 | 未证明 |

## 五、下一步验证方案（按代价排序）

1. **确认 `hDevice` 是否真实**（低成本）：用 `D3DKMT_CreateDevice` 返回后再
   `D3DKMT_QueryAdapterInfo`/`D3DKMT_GetDeviceState` 等公共 API 探测同一句柄是否被识别；
   若一律失败，说明设备未真正创建，C1 升级为主因。
2. **建立正常业务基线**（中成本）：用 DXGI/D3D11 正常渲染路径产生 Escape 调用
   （部分驱动在 Present/Query 时会走 escape），得到一个**确定成功**的 `Type/Flags` 组合，
   作为合法样本。
3. **差分同一 Type 下的最小变化**（中成本）：固定 `hDevice/Context`，只改 Size 与
   首 16 字节，观察状态是否在 `INVALID_PARAMETER / BUFFER_TOO_SMALL / NOT_SUPPORTED`
   之间迁移，从而定位校验层顺序。
4. **内核侧观测**（高成本，未具备）：需要第二台主机 + KDNET，在 `DxgkDdiEscape`
   下断点；当前单机环境不具备。

## 六、阻塞项与能力边界

| 阻塞 | 说明 |
|---|---|
| 无私有命令格式 | `Type` 语义与私有结构布局未知，无法构造"合法"请求 |
| `hDevice` 有效性未证明 | 所有 Escape 可能都建立在一个假设备上 |
| 无内核观测 | 用户态返回值无法定位到分支；ETW（前一轮已验证）不区分 Escape |
| 单机环境 | 内核断点需要第二台主机或虚拟机直通，当前不具备 |
| 授权行为无独立 Oracle | 不能用 Mock 的 TriggerCount 代替真实驱动判定 |

## 七、交付边界

- 本轮未发起任何新的真实 CVE 尝试，未修改驱动，未在主机上做高风险请求测试。
- 未新增漏洞样本，未回到 Mock 或 CUDA 支线。
- 所有地址与哈希均可在上述文件中复核。
