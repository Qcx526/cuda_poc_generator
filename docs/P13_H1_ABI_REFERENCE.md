# P13-H1 ABI 参考与复现说明

本文件记录 `src/driver_abi.py` 的布局依据。核心原则：**布局以编译器为准，不以手推或 LLM 推断为准。**

## 环境

| 项 | 值 |
|---|---|
| 编译器 | Microsoft (R) C/C++ Optimizing Compiler 19.29.30159 (x64) |
| 工具集目录 | `D:\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.29.30133` |
| SDK | 10.0.26100.0（`D:\Windows Kits\10`） |
| WDK | 10.0.26100.0（同根 `Include\10.0.26100.0\km`，本轮未参与用户态结构） |
| 目标架构 | x64 |
| 头文件 | `<windows.h>` + `<d3dkmthk.h>`（SDK `shared/`） |

编译命令（Git Bash，需禁用 MSYS 路径转换）：

```bash
export MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1
export INCLUDE="$MSVC\include;$K\ucrt;$K\shared;$K\um"
export LIB="$MSVC\lib\x64;$L\ucrt\x64;$L\um\x64"
cl -nologo -W3 -DUNICODE -D_UNICODE abi_reference.c -Fe:abi_reference.exe -link -NODEFAULTLIB:uuid.lib
```

两个必要处理：

- `MSYS2_ARG_CONV_EXCL='*'`：否则 Git Bash 把 `/nologo` 当路径改写。
- `-NODEFAULTLIB:uuid.lib`：SDK 26100 的 `Lib\um\x64` 不含 `uuid.lib`；本程序只取布局，不引用任何 GUID。

## 产物与哈希（SHA256）

```
e13a5f8d20cca4405ccb1c8b9e3390805ee60c1208dff2aa60171640e5824a1e  tools/driver/abi_reference.c
2a2be6449cc95e9e900a5202186dfb65805d6bf9dfbbfe9e35592690bcbd8cd6  tools/driver/abi_reference.jsonl
deb169b4e64c2dd949ede0be665c3ab4a5ae9ae77a1737e586f27cf286210967  src/driver_abi.py
ba8a2fe44f79ca440358397f50d1cca99876dd205c28ce29efa148cfc34d58f4  tests/test_driver_abi.py
0cd5cb5a6538f38a837bd92dd990b87548aea5d66ddf5baea1ddff896e343f47  data/driver/abi_compare.json
```

`abi_reference.exe` / `*.obj` / `*.pdb` / `*.ilk` 为可重建产物，已在 `.gitignore` 精确排除。

## 编译验证发现并修正的错误

| 结构 | 编译结果 | 修正前 ctypes | 原因 |
|---|---|---|---|
| `D3DKMT_OPENADAPTERFROMHDC` | sizeof 24 | 32 | `LUID` 4 字节对齐，被当成 `c_void_p`（8 字节对齐） |
| `D3DKMT_OPENADAPTERFROMLUID` | sizeof 12 | 16 | 同上 |
| `D3DKMT_CREATECONTEXT` | sizeof 96 | 88 | 漏尾部 `D3DGPU_VIRTUAL_ADDRESS CommandBuffer` |
| `D3DKMT_OPENADAPTERFROMHDC.AdapterLuid` | offset 12 | 16 | 同上 |
| `D3DKMT_OPENADAPTERFROMHDC.VidPnSourceId` | offset 20 | 24 | 同上 |

另有一次自我引入的错误：补 `CommandBuffer` 时 `str.replace` 命中两处，把 `CREATEDEVICE` 也加到 72 字节（应为 64），被第二次对照抓出。

## 当前一致性

6 个结构、27 个字段与 3 个标量，**与编译器零差异**。守卫测试：

```python
def test_ctypes_matches_the_compiler_exactly():
    """The compiler is the authority; this test fails the moment they diverge."""
```

`abi_reference.jsonl` 缺席时该测试跳过（`skipif`），所以 CI 无编译器也能跑其余 10 条。

## R0 独立验收

`python -m src.driver_abi`，不依赖任何模型输出：

```
enum_display     ok
create_dc        ok   CreateDCW("DISPLAY", 设备名)
open_adapter     ok   STATUS_SUCCESS
create_device    ok   STATUS_SUCCESS
create_context   ok   STATUS_SUCCESS
destroy_context  ok   STATUS_SUCCESS
destroy_device   ok   STATUS_SUCCESS
```

注意：`GetDC(NULL)` 得到的屏幕 DC 会被 `D3DKMTOpenAdapterFromHdc` 拒绝（`0xC000000D`）；必须用 `CreateDCW("DISPLAY", 设备名)`。

## 复现步骤

```bash
# 1. 重新生成编译期基准（可选，仓库已存 jsonl）
cd tools/driver && <上面三条 export> && cl ... abi_reference.c

# 2. 布局对照
python -m pytest tests/test_driver_abi.py -q

# 3. R0 自检（会真实打开 adapter/device/context）
python -m src.driver_abi
```
