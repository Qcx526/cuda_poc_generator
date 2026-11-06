# P13-4-F8-Step1：D3DKMT 句柄有效性与生命周期接地

基线 `ffe76a0`。本阶段只回答一个问题：**那个用来发 Escape 的 `hDevice` 到底有效吗？**

## 一、结论先行

| 问题 | 结论 |
|---|---|
| 历史探测器是否存在"句柄等于 adapter 即判无效"的错误逻辑 | **是**，已修 |
| `hDevice` 是否真的无效（假设 C1） | **否，C1 被推翻**：`GetDeviceState` 返回 0 |
| 0xC000000D 能否用来定位内部分支 | **不能**：四种不同原因返回同一个码 |
| escape-map.json 的原始证据 | **PROVENANCE_MISSING**：无产出脚本、无原始日志 |
| 能否建立正常业务基线 | 不能靠 `QueryAdapterInfo(DRIVERVERSION)`（同样返回 0xC000000D），需换 D3D11/DXGI 路径 |

## 二、ABI 核验（对照官方头文件）

来源：`D:\Windows Kits\10\Include\10.0.26100.0\shared\d3dkmthk.h`

### 2.1 `D3DKMT_CREATEDEVICE`（头文件 49–67 行）

```c
union { D3DKMT_HANDLE hAdapter; VOID* pAdapter; };   // 8 字节（指针宽度）
D3DKMT_CREATEDEVICEFLAGS Flags;                      // 偏移 8
D3DKMT_HANDLE            hDevice;                    // 偏移 12，out
```

实测偏移（`tests/test_handle_validity_abi.py` 断言）：

```
hAdapter @0   Flags @8   hDevice @12
```

`D3DKMT_HANDLE` 是 `UINT32`，即 **4 字节**。这与既有 `src/driver_abi.py` 的建模一致。

### 2.2 `D3DKMT_GETDEVICESTATE`（4543 行起）

```c
D3DKMT_HANDLE           hDevice;    // in
D3DKMT_DEVICESTATE_TYPE StateType;  // in，枚举
union { ... }                       // out
```

枚举取值：`D3DKMT_DEVICESTATE_EXECUTION = 1`（4525 行）。

### 2.3 `D3DKMT_QUERYADAPTERINFO`（2565 行起）

```c
D3DKMT_HANDLE hAdapter; KMTQUERYADAPTERINFOTYPE Type; VOID* pPrivateDriverData; UINT Size;
```

`KMTQAITYPE_DRIVERVERSION = 13`（2465 行）。

## 三、实际调用结果（本机实测一次）

工具：`python -m tools.driver.probe_handle_validity`
只调用文档化 API，**没有发送任何 Escape**。

| 步骤 | 句柄 | 状态 |
|---|---|---|
| QueryAdapterInfo(DRIVERVERSION) | adapter `0x40000040` | **0xC000000D** |
| CreateDevice | adapter `0x40000040` | **0x0**，hDevice `0x40000080` |
| GetDeviceState(EXECUTION) | device `0x40000080` | **0x0**，ExecutionState=1 |
| GetDeviceState(EXECUTION) | 伪造 `0xDEAD` | 0xC000000D |
| GetDeviceState(**StateType=0**) | 有效 device `0x40000080` | **0xC000000D** |
| DestroyDevice | device `0x40000080` | 0x0 |
| GetDeviceState(EXECUTION) | 已销毁 `0x40000080` | 0xC000000D |
| CloseAdapter | adapter `0x40000040` | 0x0 |

### 3.1 由此得到的三条硬结论

1. **设备句柄是有效的**：同一个 `hDevice`，`GetDeviceState` 返回 0 且给出
   `ExecutionState=1`；销毁后立刻返回 0xC000000D。这是文档化 API 的正反对照。
2. **`hDevice != hAdapter`**（`0x40000080` vs `0x40000040`）。历史 notes 里
   "hDevice 与 hAdapter 相同，疑未分配设备" **在本路径上不复现**。
3. **0xC000000D 是通用参数错误**：伪造句柄、已销毁句柄、**无效 StateType**、
   以及 `QueryAdapterInfo(DRIVERVERSION)` 四种情况都返回它。
   所以**不能**把 Escape 的 0xC000000D 读成"到达了某个内部校验分支"。

## 四、历史探测器审计

### 4.1 错误逻辑（已修）

`tools/driver/escape_probe.py:117`

```python
usable = status == 0 and device not in (0, handle)   # 旧
```

docstring 甚至把假设写成了事实："a handle equal to the adapter is the signature of
reading the wrong field"。**官方头文件没有这条约束**。

现在：

```python
def usable_device(status: int, device: int) -> bool:
    return status == 0 and device != 0
```

`same_value_as_adapter` 只作为观测字段记录，不参与判定。

### 4.2 同类逻辑的排查结果

在 `tools/driver/*.py`、`src/driver_*.py` 中搜索 `not in (0, handle)` / `!= adapter` /
`hDevice == hAdapter`，仅命中上述一处。其余调用点没有同类判定。

### 4.3 结构体偏移是对的

`escape_probe.py` 里 `D3DKMT_CREATEDEVICE` 用 `hAdapter + Reserved0 + Flags + hDevice`
模拟 union，偏移与官方一致（12）。所以"读到错误字段"这个担心，在偏移层面不成立。

## 五、escape-map.json 的来源核查

| 项 | 结果 |
|---|---|
| 产出脚本 | **未找到**：`grep -rn "status_map" tools src` 无命中 |
| 原始日志 | **未找到**：仓库内无对应 run log |
| 测试时的实际句柄 | **未知** |
| 驱动版本 | **未知**（未记录） |
| 是否证明进入内核/私有分派 | **未证明** |

**判定：PROVENANCE_MISSING。**

因此该文件里的 `status_map` 只能当作**原始观测值**，不能当作可复现实验：

- 原始观测：Flags 不同 → 状态不同（保留）；
- 人工解释："ACCESS_DENIED 是身份校验"、"BUFFER_TOO_SMALL 定位到私有缓冲区校验"
  —— **属于解释，不是事实**，本轮起在文档中标注为 `INTERPRETATION`。

## 六、假设 C1 的新状态

| 旧状态 | 新状态 | 依据 |
|---|---|---|
| HYPOTHESIS（设备可能未真正创建） | **REFUTED** | `GetDeviceState(EXECUTION)` 对该句柄返回 0，销毁后立即变为 0xC000000D |

**C1 被推翻后的含义**：Escape 的 0xC000000D 不是"设备是假的"造成的，
问题在请求体或更高层的参数校验上。这使 C2（私有请求体结构/尺寸）成为主要嫌疑，
但**仍未证明**。

## 七、能否建立正常业务调用基线

- `QueryAdapterInfo(DRIVERVERSION)` 在有效 adapter 上返回 0xC000000D，
  说明**这条查询类型在该驱动/系统上不可用**，不能拿它当"adapter 正常"的对照。
- 可行方向：用 **D3D11/DXGI 正常设备**（`D3D11CreateDevice` → 提交一次 Present），
  由 UM 驱动在内部产生正常的 Escape/提交调用，作为"合法请求"基线。
  这条路不需要私有格式，也不发送未知命令。
- 该路径尚未实现，本轮不展开。

## 八、证据与回归

- 实测脚本：`tools/driver/probe_handle_validity.py`（可复跑）
- ABI 与判定测试：`tests/test_handle_validity_abi.py`（6 条，离线）
- 探测器修复：`tools/driver/escape_probe.py`
- 未修改 P11/P12 冻结基线，未新增 CUDA/Mock 工作，未发送私有 Escape。
