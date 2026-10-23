# P4-V 驱动逆向地图：CVE-2024-0107 的实际代码位置

报告语言：`zh-CN`。全部结论来自本机实测（驱动 31.0.15.5161，与 Talos 报告版本一致），
每条都标注了验证方式。

## 1. 关键地址（与本机构建对齐）

| 位置 | RVA | 验证方式 |
|---|---|---|
| 越界读助手 | **0x12A3560** | 按报告给出的机器码 `48 8B 81 00 02 00 00 48 63 D2 8B 04 90` 全模块搜索，**唯一命中** |
| 触发它的调用点 | **0x1503177** | 反汇编确认：`and edx,0FFFFFFh` → `cmp eax,8` → `call 0x12A3560` |
| 正常路径的调用点 | 0x1176D5 | 在助手下断点后取返回地址 |

> **踩过的坑**：WinDbg 显示 `nvgpucomp64!destroyFinalizer+0xab389a` 是**相对符号**的偏移，
> 不是模块偏移。`destroyFinalizer` 在 RVA 0x7EFCD0，所以真实 RVA = 0x7EFCD0 + 0xAB389A ≈ 0x12A3560。
> 之前按 0xAB3890 下断，断在完全不相干的函数上，得出过"从不命中"的错误结论。

## 2. 漏洞点的分派条件（0x15030A0–0x1503177）

```
mov   eax, r8d
mov   edx, r8d
cmp   eax, 0FFFFFFFFh      ; 哨兵值
je    ...
shr   ecx, 1Fh             ; 符号位
test  cl, cl
jne   ...
movsxd rax, edx
mov   eax, ecx
and   eax, 70000000h       ; 取源寄存器类别（bits 28-30）
cmp   eax, 10000000h       ; == 1
jne   ...
and   ecx, 0FFFFFFh        ; 取低 24 位
cmp   ecx, 3               ; < 3
...
mov   eax, [r11+58h]
and   eax, 0FFFFCFFFh
cmp   eax, 7Dh             ; 内部操作码 == 0x7D
jne   ...
and   edx, 0FFFFFFh        ; ← 索引被掩成 24 位后传给越界助手
call  0x12A3560
```

读法：要走到越界助手，需要同时满足
**源寄存器类别 == 1**、**低 24 位 < 3**、**`[r11+0x58]` 掩码后 == 0x7D**。

## 3. 已验证的"到不了"（避免重复劳动）

| 输入形态 | 是否到达 0x1503177 |
|---|---|
| ps_3_0，`sincos r0.xy, c0.x` | 否 |
| ps_3_0，`sincos r0.xy, v0.x`（输入寄存器） | 否 |
| ps_2_0，双系数常量 | 否 |
| vs_2_0，双系数常量 | 否 |
| 约 9000 例各轴变异 | 未单独验证，但均无崩溃 |

正常编译会调用同一个助手，但来自 **0x1176D5**（合法路径），不是漏洞路径。

## 3.5 分派块的语义（0x15030fa–0x1503125）

```asm
mov  eax, [r11+58h]      ; 指令描述符: 操作码
and  eax, 0FFFFCFFFh     ; 忽略 bits 12-13
cmp  eax, 7Dh            ; == 0x7D 才继续
jne  ...                 ; 否则走别的分支

mov  eax, [r11+6Ch]      ; 第一个操作数的属性字
and  eax, 70000000h      ; 寄存器类别 bits 28-30
cmp  eax, 20000000h      ; 常量
je   ...
cmp  eax, 30000000h      ; 纹理
je   ...
```

`r11` 是**每条指令的描述符**：

| 偏移 | 内容 |
|---|---|
| +0x58 | 操作码（0x7D 即本路径要的指令） |
| +0x64 | 操作数数组，每项 8 字节（`[r11+rax*8+64h]`） |
| +0x6C | 第一个操作数的属性字（类别位 + 24 位索引） |

**实测：正常 ps_3_0 的 SINCOS 根本不经过 0x15030fa**（在 `cmp eax,7Dh` 处下断，
常量源与输入寄存器源两种程序都未命中）。也就是说：该分派块属于**另一条指令路径**，
常规 SINCOS 走的是 0x1176D5 那条合法分支。

## 3.6 精确判据下的实测（29 条指令 + 200 例字节变异）

判据：`bp nvgpucomp64+0x15030FA` 是否真的 `Breakpoint hit`（不是命令回显）。

| 输入 | 到达 0x15030FA |
|---|---|
| 29 条 SM3 指令（mov/add/sub/mul/mad/dp3/dp4/min/max/rcp/rsq/lrp/frc/pow/abs/nrm/sincos/texkill/dsx/dsy/cmp…） | **全部否** |
| SINCOS 源为常量 / 输入寄存器 / 两条连续 SINCOS | **全部否** |
| base.bin 的单字段字节变异（200 例，139 例通过校验） | **全部否** |

**教训（重要）**：判定"是否命中"必须匹配 `Breakpoint \d+ hit`。曾用"输出里含 REACHED"
判定，结果匹配到了 cdb 对命令本身的回显，得出过四个连续的假阳性。

## 4. 下一步（线性，不需要猜）

1. **找 `[r11+0x58]` 的来源**：谁把内部操作码写成 0x7D。这是"哪条指令被当成 SINCOS"的关键；
2. **确认 0x7D 对应哪个 D3D 操作码**：把 SM3 的 SINCOS（0x25）与内部 0x7D 建立映射；
3. **定位 `r8d` 的来源**：它就是最终索引，来自上层结构体的某个字段；
4. 一旦三个条件可构造，直接在本地构造输入，**不需要 fuzz**。

## 5. 工具

```bash
# 反汇编任意位置
python -m tools.driver.trace_run --program data/harness/k0.bin --module nvgpucomp64 --rva 0x1503177

# 字节级观察
python -m tools.driver.byte_trace --program data/harness/k0.bin --offset 28 --second-stage
```
