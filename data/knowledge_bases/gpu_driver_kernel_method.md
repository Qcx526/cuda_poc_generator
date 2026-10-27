# GPU 内核驱动 PoC：入口与判据（实测）

适用：`driver_kernel` 目标（NVIDIA 显示驱动，Windows）。全部结论来自本机实测，非文档推断。

## 何时使用本条目

- 目标漏洞位于驱动**内核态**（nvlddmkm.sys），CWE 为 787/416/190 等内存类
- 触发方式不是"喂一个文件"，而是**向驱动发一段请求**
- 判据是 **bugcheck**（事件 1001），不是进程退出码

## 入口链（按此顺序，缺一不可）

| 步骤 | 调用 | 实测要点 |
|---|---|---|
| 1 | `D3DKMTOpenAdapterFromHdc` | 只为拿 LUID；它返回的句柄**后续全部无效** |
| 2 | `D3DKMTOpenAdapterFromLuid` | 用上一步的 LUID 重新打开，得到可用句柄（实测 `0x40000040`） |
| 3 | `D3DKMTCreateDevice` | 设备句柄写在**偏移 12**，不是偏移 0 |
| 4 | `D3DKMTCreateContext` | 上下文句柄在**偏移 32** |
| 5 | `D3DKMTEscape` | `Flags` 在 `EscapeCode` **之前**（偏移 8 / 12） |

DC 必须指定显示器名：`CreateDCW("DISPLAY", "\\\\.\\DISPLAY1", ...)`；
只传 `"DISPLAY"` 得到无效句柄，驱动返回 `0xC000000D`。

## 判据：两种返回码告诉你在哪一步

同一 escape 码，只改 `Flags`：

| 结果 | 含义 | 下一步 |
|---|---|---|
| 两者都 `0xC000000D` | 卡在参数校验，**与码无关** | 先修结构体偏移，别换码 |
| `Flags=0` → `0xC000000D`，`Flags=1` → `0xC0000022` | 结构体正确，被权限拦下 | 句柄来源或客户端身份问题 |
| 出现其他码（`0`/`0xC00000BB` 等） | 已到达分发 | 记录该码，进入单字段变异 |

`0xC000000D` = STATUS_INVALID_PARAMETER；`0xC0000022` = STATUS_ACCESS_DENIED。

## 已否证的路径（不要重复尝试）

1. **NVAPI 不是入口**：替换 nvapi64 的 `DeviceIoControl` IAT 槽后调用
   `GetFullName`/`GetThermalSettings`，拦截到 **0 次**调用，但返回真实数据。
2. **`0x1000xxxx` 立即数未必是 escape 码**：`0x10001002` 与 `0x10000402`
   总成对出现在相隔约 60 字节处，是**结构体版本字**的形态。
3. **命令缓冲无关**：带 64 KB command buffer 建 device，escape 结果不变。
4. **UMD 不可钩**：`nvwgf2umx.dll` 不导入任何 D3DKMT 函数，它通过
   `D3DDI_DEVICECALLBACKS` 回调表访问内核，IAT 无位置可补。
5. **`\\.\NVIDIA` 不存在**：本机设备对象只有 `NvAdminDevice`、`DxgKrnl`、`gpuenergydrv`。

## 版本对齐（否则一切都是错的）

- 驱动文件在 `DriverStore\FileRepository`，同目录下保留**所有历史版本**
- **按版本号匹配**，不要按修改时间取最新：
  `31.0.15.3598` → NVIDIA `535.98`（取第三段的末位 + 第四段补四位）
- UMD（`nvwgf2umx.dll`）与 `nvlddmkm.sys` 同目录，版本必须一致

## 验证规则

- 句柄有效性的判据是**能否被销毁**，不是创建返回 0
- 任何"零结果"都要用第二条证据交叉验证（导出 0 个 → 换 kernel32 验证；调用点 0 个 → 检查扫描覆盖率）
- 结构体不确定时，发**全零请求并回读哪些字节发生变化**，比查头文件可靠

## 崩溃取证

- 进程会随系统一起死，结果必须**跨重启**读取：
  执行前写标记文件 → 重启后比对开机事件（6005）与 bugcheck 事件（1001）
- 快速启动（`HiberbootEnabled=1`）下 `GetTickCount64` **不归零**，uptime 不能作为重启判据

## 用户态着色器路径（CVE-2024-0107 类）

驱动附带的 `nvgpucomp64.dll` 编译 SM3 字节码，触发形态是**进程访问违例**而非蓝屏。

- 确认版本：Talos 报告给出的受影响版本是 `551.61 / 31.0.15.5161`；535.98 已修复
- 测试框架：`data/harness/shader_runner.exe bytecode <bin>`（D3D9 `CreatePixelShader`）
- 指令编码（实测）：`sincos` = `0x25`；SM2 双系数形态长度字段为 4（额外两个系数令牌）

**判定必须归因到模块**：

```
命中 = 退出码 0xC0000005 且 出错栈帧模块 == nvgpucomp64
```

截断或畸形字节码会让 `d3d9!CBaseShaderValidator` 先崩，产生大量假阳性；
仅看退出码必然误判。

**已否证的做法**（不要重复）：

1. 合法操作数变体（180 例）：全部编译通过，不进入漏洞路径
2. 令牌字段损坏（296 例）：被 D3D9 校验器拒绝，或通过但无崩溃
3. opcode 字段替换：长度不匹配，只有 `0x25` 可编译
4. 分派函数（入口约 `0x15029BD`）对像素着色器**完全不进入**，需换输入类别
