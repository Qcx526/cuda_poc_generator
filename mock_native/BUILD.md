# 原生 Mock GPU DLL：构建与验证

## 构建

```bash
cd mock_native
export MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1
K='D:\Windows Kits\10\Include\10.0.26100.0'
L='D:\Windows Kits\10\Lib\10.0.26100.0'
MSVC='D:\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.29.30133'
export INCLUDE="$MSVC\\include;$K\\ucrt;$K\\shared;$K\\um"
export LIB="$MSVC\\lib\\x64;$L\\ucrt\\x64;$L\\um\\x64"
"$MSVC\\bin\\HostX64\\x64\\cl.exe" -nologo -W3 -O1 -LD mock_gpu.c \
    -Fe:mock_gpu.dll -link -NODEFAULTLIB:uuid.lib
```

| 项 | 值 |
|---|---|
| 编译器 | MSVC 19.29.30159 (x64)，工具集 14.29.30133 |
| SDK | 10.0.26100.0 |
| 选项 | `-O1 -LD`，x64 |
| 产物 | `mock_gpu.dll`，102,912 字节 |
| SHA256 | `9cf8b3e55df3705eacd37275f6f3802b6b10910e5169c68822e7cfadb39a6a8a` |

`.dll` / `.lib` / `.exp` / `.obj` / `.pdb` 为可重建产物，已在 `.gitignore` 排除。

## 导出

```
MockCloseAdapter 0x1008   MockCreateContext 0x1030   MockCreateDevice 0x1070
MockDestroyContext 0x10b0 MockDestroyDevice 0x10d8   MockEscape 0x1100
MockOpenAdapter 0x1240    MockReset 0x126c            MockTriggerAt 0x129c
MockTriggerCount 0x12bc
```

## 与 Python 版的一致性

`tests/test_mock_native.py` 用同一批调用脚本跑两侧，比较**状态码与触发缺陷种类**：

| 脚本 | Native | Python | 一致 |
|---|---|---|---|
| 跨 device context + PRIVILEGED | 0x0 / [AUTHZ] | 0x0 / [AUTHZ] | ✅ |
| 声明长度 = 实际 + 1 | 0x0 / [OOB] | 0x0 / [OOB] | ✅ |
| 正常 escape | 0x0 / [] | 0x0 / [] | ✅ |

不一致时测试失败——这是"两侧任一的指标都不可信"的守卫。

## 不可模仿的部分

`OOB_READ` 是**受控模拟**：越界一字节只被记录，不发生真实越界读。原生实现同样只做判定与计数，不做指针运算。
