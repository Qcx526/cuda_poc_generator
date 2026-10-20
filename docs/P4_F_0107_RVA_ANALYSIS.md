# P4-F 0107 深挖：RVA 定位与三条否证

报告语言：`zh-CN`。目标是从"负结果"推进到"能触发"。本轮用静态反汇编 + cdb 动态
断点，把 `CVE-2024-0107`（TALOS-2024-1956）的触发路径钉到了具体指令，并**否证了
现有 PoC 的三条假设**。

## 1. 定位：RVA 完全吻合

Talos 报告给出的越界调用点：`nvgpucomp64.7FF93F92315A`。
本机 DLL（551.61，`nvgpucomp64.dll 31.0.15.5161`，36,259,256 字节）中
按字节序列搜索：

```text
48 8B 4D 50        mov rcx,[rbp+50]
41 8B 50 6C        mov edx,[r8+6C]     <- 越界索引来源
48 8B 09           mov rcx,[rcx]
```

全模块**唯一命中**：文件偏移 `0x150255A` → RVA `0x150315A`（.text）。
`0x7FF93F92315A - 0x150315A = 0x7FF93E420000`，页对齐——与 Talos 的运行时基址吻合。

## 2. 反汇编结论：两层门 + 一个 24 位索引

```asm
0150310c  mov eax, [r11+0x6c]
01503110  and eax, 0x70000000
01503115  cmp eax, 0x20000000        ; 类型门 1
0150311a  je  0x1503127
0150311c  cmp eax, 0x30000000
01503121  je  0x1503127
01503123  xor al, al                 ; 类型不符 → 跳过整个路径
...
015030fa  mov eax, [r11+0x58]
015030fe  and eax, 0xFFFFCFFF
01503103  cmp eax, 0x7d              ; 指令门：token 必须（掩码后）等于 0x7D
01503106  jne 0x15031f6
...
0150315e  mov edx, [r8+0x6c]
01503165  and edx, 0xFFFFFF          ; 24 位索引，无上界
01503170  call 0x12a3720             ; 内部 [rax+rdx*4] → 越界读
```

**两层门**：

1. **类型门**：`[r11+0x6C] & 0x70000000` 必须是 `0x20000000` 或 `0x30000000`。
2. **指令门**：`[r11+0x58] & 0xFFFFCFFF == 0x7D`。

通过后，`[r11+0x6C] & 0xFFFFFF` 作为**无上界的 24 位索引**传进辅助函数，
在 `[rax+rdx*4]` 处越界读。

## 3. 否证一：原 PoC 的四个毒化值全部过不了类型门

原 PoC 的毒化值与其 bit28–30：

| 毒化值 | `& 0x70000000` | 通过类型门？ |
|---|---|---|
| `0x7FFFFFFF` | `0x70000000` | 否 |
| `0xFFFFFFFF` | `0x70000000` | 否 |
| `0x0000FFFF` | `0x00000000` | 否 |
| `0x7FFF0000` | `0x70000000` | 否 |

正确的毒化应保留类型位、拉满索引：`0x20FFFFFF` / `0x30FFFFFF`。

## 4. 否证二：改对类型位后仍不触发

把毒化值换成 `0x20FFFFFF / 0x30FFFFFF / 0x2000FFFF / 0x3000FFFF`，并对 SINCOS
token 后第 4/8/12 字节三种偏移各试一轮（12 个变体，`CVE-2024-0107_v2.py`）：
**全部 `rc=0`，无一崩溃**。原因是第二层门（指令门）没有通过。

## 5. 否证三：ps_5_0 根本没有 SINCOS 指令

用 `cdb` 在 `nvgpucomp64+0x15030f1` 下断点、跑一个正常 SINCOS 着色器：
**断点从未命中，进程直接退出**。随后解析 612 字节 DXBC 的 opcode 流：

```text
SHEX: opcode 106, 256, 515, 54(MOV), 0, 2(RET), 64, 0
```

**没有任何 SINCOS**——SM4/SM5 的 DXBC 没有 SINCOS 操作码，HLSL 的 `sin`/`cos`
被编译器内联成多项式。Talos 描述的 `sincos destSIN, destCOS, src0` 是 **SM2/SM3
的老指令**。而原 PoC 在 ps_5_0 字节流里按 `(token & 0x7FF) == 0x25` 搜"SINCOS"，
匹配到的只是操作数数据等巧合字节——**它 patch 的位置从一开始就是随机的**。

## 6. 结论与下一步

- 原 PoC 的"在 ps_5_0 里找 SINCOS token 再毒化"这条路线**在原理上不成立**。
- 触发该漏洞需要让驱动解码到 opcode `0x7D` 的指令，并让对应操作数字段
  `[+0x6C]` 带上超界的 24 位索引。
- 下一步（按序）：
  1. 确认 `0x7D` 在驱动内部 IR 对应哪条 DXBC 指令：对含不同指令的着色器逐一
     在 `+0x15030f1` 下断点，命中者即为候选；
  2. 若 `0x7D` 对应 legacy SINCOS，需要找到把 SM2/SM3 着色器送进
     `nvgpucomp64` 的入口（D3D11 不收 ps_2_0；Talos 走的是 RemoteFX/rdvgm 路径）；
  3. 找到入口后，按 `[+0x6C]` 的字段语义构造 `0x20FFFFFF` 型操作数。

## 7. 产出物

- 反汇编脚本与上下文：本轮对话记录；关键 RVA `0x150315A`。
- v2 变体：`data/reference/driver_pocs/CVE-2024-0107_v2.py`（类型位正确的 12 个变体）。
- 最小 D3D11 探针：`data/reference/driver_pocs/d3d_sincos_probe.py`。
- cdb 断点脚本：`data/reference/driver_pocs/cdb_attach.txt`。
- 调试器：`D:\Windows Kits\10\Debuggers\x64\cdb.exe`（10.0.19041.5609）。
