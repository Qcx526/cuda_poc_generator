# P13-4-F8-Step2-R1：ABI 复验与证据收尾

基线 `4478ea5`。本轮只做最小复验，不扩大探测范围。

## 一、任务一：用修正后的 ABI 复验（本轮新数据）

在**明确选中的 LUID** `00000000:b33b765e` 上重跑，不复用 ABI 错误时期的 JSON。

```
OpenAdapterFromLuid(0:b33b765e)  status=0x0     hAdapter=0x40000040
CreateDevice                     status=0x0     hDevice=0x40000080
GetDeviceState(EXECUTION=1)      status=0x0     ExecutionState=1
GetDeviceState(0xDEAD)           status=0xC000000D
DestroyDevice                    status=0x0
GetDeviceState(已销毁的 hDevice)  status=0xC000000D
CloseAdapter                     status=0x0
```

**结构尺寸（ctypes 实测，与编译结果一致）**

```
D3DKMT_HANDLE=4  CREATEDEVICE=64  GETDEVICESTATE=56  QUERYADAPTERINFO=24
```

原始记录：`data/driver/f8s2r1_revalidation.json`（含 Windows 版本 `10.0.19045`、
目标 LUID、每条 NTSTATUS、驱动身份）。

### 1.1 过程中修掉的两个自己的错误

1. **状态错位**：最初用 `steps[-5]/[-4]/[-3]` 取值，索引偏了一位，导致
   `bogus_status` 显示为 0（其实是 CreateDevice 的状态）。改为具名变量后才是
   真实结果。**这种错位会把失败读成成功**，所以没有用负索引。
2. **`QueryAdapterInfo(DRIVERVERSION)` 的结论错了**。Step 2 我写"尺寸充足，
   失败不是长度问题"——**错**。用文档规定的 4 字节 `UINT` 缓冲重试：

   ```
   QueryAdapterInfo(DRIVERVERSION=13)  buffer_bytes=4  status=0x0  value=2700
   ```

   该类型**拒绝** 64 字节缓冲，返回 `0xC000000D`。所以此前的失败是长度问题，
   UNKNOWN 解除。

## 二、任务二：证据收尾

| 项 | 处理 |
|---|---|
| 子进程退出码 / stderr | 非 0 直接抛错，不再解析半个输出；两者都写入 JSON |
| Adapter 句柄泄漏 | `by_luid` / `by_hdc` 两条路径现在都 `CloseAdapter` |
| 驱动身份 | 磁盘文件 SHA256 `31af1ce9…`；**内核已加载模块** `nvlddmkm.sys` @ `0xfffff803c6280000`（`EnumDeviceDrivers`） |
| 两者关系 | 明确写为"两条独立线索，不能互相替代" |
| HDC 打开的 Adapter | **不再推断**与目标 LUID 相同：HDC 路径不返回 LUID，其身份记 UNKNOWN |
| 句柄相等 | 记录为"每次 Open 都会变"，不作为同一性判据 |
| 4 个 NVIDIA DXGI 条目 | 改称**逻辑适配器**，不称 4 张物理卡 |

## 三、任务三：下一阶段的研究路线与前置条件

### 3.1 如何确认"运行时"驱动身份

已有两条：磁盘文件哈希、内核模块基址。
**仍缺**：把基址映射回磁盘镜像（`GetDeviceDriverFileNameW` + 版本资源），
以及确认加载的镜像与磁盘文件**字节一致**（需要签名/版本号交叉，不能只看名字）。

### 3.2 当前能拿到的安全、文档化观测

| 观测 | 能证明 | 不能证明 |
|---|---|---|
| DXGI/D3D11 HRESULT（已有） | 用户态调用成功 | 内核执行细节 |
| `GetDeviceState`（已有） | 设备对象活着 | 任何 Escape 行为 |
| `QueryAdapterInfo(DRIVERVERSION)`（本轮打通） | 驱动版本号 2700 | 版本对应的具体构建 |
| `EnumDeviceDrivers`（本轮） | 模块已加载及基址 | 加载的代码是否等于磁盘文件 |
| ETW `Microsoft-Windows-DxgKrnl` | 有 GPU 活动、PID/TID/时间 | **无法归因到具体调用**（前轮已证） |

### 3.3 必须隔离内核调试环境才能回答的问题

1. 某个 `D3DKMTEscape` 是否真的进入 `DxgkDdiEscape`；
2. 进入后走了哪条分支、命中哪个比较；
3. 私有请求结构在内核里被如何解释；
4. `0xC000000D` 具体由哪一层的哪个返回点产生。

**结论：这些问题在用户态不可判定。** 需要第二台主机 + KDNET（或 VM + GPU 直通）。

### 3.4 如何才算"到达某个具体驱动分支"

至少需要以下之一：

- 内核断点在该函数入口命中，且**调用栈回溯到 `DxgkDdiEscape`**；
- 有带栈的 ETW/provider 事件，能把事件绑定到本次调用；
- 或用受控输入使某地址的代码字节被命中（需页表级插桩，代价更高）。

**用户态返回值不构成证据**：本轮已证明同一个 `0xC000000D` 至少对应
四种不同原因（伪造句柄、已销毁句柄、无效 StateType、错误的缓冲长度）。

### 3.5 如何把证据交给 LLM 的约束推理模块

分三类，**不得混写**：

| 类别 | 内容 | 允许模型做什么 |
|---|---|---|
| Binary Fact | RVA、字节、比较常量、函数边界（含出处与 SHA256） | 作为前提引用 |
| EvidenceRequest | "若假设 H 成立，则应能观测到 X" | 提出可验证命题 |
| Verification Result | `SUPPORTED / REFUTED / UNKNOWN` + 观测原文 | 只能引用结论，不能改写 |

硬规则：

- 静态比较**不等于**执行路径；
- `0xC000000D` 等返回值**不得**映射到内部分支；
- 模型可以提假设，但**不能自行生成验证事实**；
- 无法证明的私有语义一律 `UNKNOWN`。

## 四、BLOCKED 声明

> **路径级验证：BLOCKED。**
> 当前单机环境没有任何独立的内核执行观测手段；继续尝试未知 Type/Flags/Size
> 只能产生不可解释的返回值，不会带来新证据。
> 解除条件：具备第二台主机 + KDNET，或 VM + GPU 直通 + 内核调试。

在解除之前，本工程对"驱动内部发生了什么"的结论**一律停在 UNKNOWN**。

## 五、边界

- 未发送私有 Escape，未做 Type/Flags/Size 扫描，未触发 CVE；
- 未改驱动、未新增 CUDA/Mock 工作、未动 P11/P12 冻结基线；
- 新增/修改：`tools/driver/f8s2r1_revalidate.py`、`tools/driver/f8s2_evidence.py`、
  `tests/test_handle_validity_abi.py`、`data/driver/abi_sizes.json`、
  `data/driver/f8s2r1_revalidation.json`、`data/driver/f8s2_baseline.json`。
