# 内核驱动路径：从占位句柄到可控结构体

## 一、为什么之前所有驱动探测都被拒

不是接口不通，是**句柄门禁**：驱动在解析任何结构体之前先校验会话与 profile。
占位指针永远过不去，所以每次都停在 `NVAPI_INVALID_HANDLE` 或 `INVALID_ARGUMENT`。

## 二、可用的句柄链路

```
NvAPI_Initialize            0x0150E828 → 0
NvAPI_DRS_CreateSession     0x0694D52E → 0
NvAPI_DRS_LoadSettings      0x375DBD6B → 0
NvAPI_DRS_GetBaseProfile    0xDA8466A0 → 0     ← 真 profile 句柄
NvAPI_DRS_GetNumProfiles    0x1DAE4FBC → 0，本机 5508 个
NvAPI_DRS_EnumProfiles      0xBC371EE0 → 0
```

## 三、结构体头部：`sizeof | (version << 16)`

低 16 位必须是**精确大小**，不是"至少这么大"。猜错就是 `-9`
（`NVAPI_INCOMPATIBLE_STRUCT_VERSION`）。

标定结果：

| 结构体 | 大小 | 版本 | 关键函数 |
|---|---|---|---|
| `NVDRS_PROFILE` | **4116** | 1 | GetProfileInfo / SetProfileInfo / CreateProfile |
| `NVDRS_APPLICATION` | **16392** | 2 | CreateApplication / DeleteApplicationEx / EnumApplications |

`NVDRS_APPLICATION` 布局：

```
0      version
4      isPredefined
8      appName[2048] wchars          (4096)
4104   userFriendlyName[2048]        (4096)
8200   launcher[2048]                (4096)
12296  fileInFolder[2048]            (4096)
```

跨驱动分支稳定：551.61 与 610.47 上 `NVDRS_PROFILE` 都是 4116/v1。

## 四、两轮探测的结果

### 第一轮：profile 的四个计数字段（21 个探测）

`gpuSupport` / `isPredefined` / `numOfApps` / `numOfSettings` 各取 5 个边界值
（0 / 1 / 2 / 0x7FFFFFFF / 0xFFFFFFFF），走 `SetProfileInfo`。

**全部返回 0，无蓝屏。** 这些是**输出字段**——写入时驱动不读它们，所以改任何值都不会
改变行为。负结果，但有用：知道哪里不该看。

### 第二轮：application 写路径

`CreateApplication` 带合法名字 → **0**，写路径确认落地。

把最后一个字段 `fileInFolder` 填满 4096 字节且**不留终止符** → 仍返回 **0**，无蓝屏。
说明驱动在该边界上按字段长度而非 NUL 处理。

## 五、一个有利的副作用

不调用 `NvAPI_DRS_SaveSettings` 时，写入只停留在会话内（驱动内存），不落盘到用户配置。
探测不会污染系统配置——`DeleteApplicationEx` 随后返回 `-166`（找不到），
正是因为那条记录从未持久化。

## 六、下一步

| 目标 | 理由 |
|---|---|
| `NVDRS_SETTING` | settingId + 类型 + 值联合体，驱动**按类型分派**——越界写最可能在这里 |
| `NVDRS_APPLICATION` 的 `isPredefined` | 布尔字段若被信任，可能改变后续分支 |
| escape 路径 | CVE-2026-47571 是 `kernel-mode escape` 的授权绕过，需 D3DKMTEscape，不是 NVAPI |

## 七、工具

- `tools/driver/drs_probe.py` — 单次探测，建会话并按 `(size, version)` 调用
- `src/driver_batch.py` — 批量探测，布防标记 + 断点续跑
- `data/driver_structs.json` — 标定结果
