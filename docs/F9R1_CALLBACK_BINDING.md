# P13-4-F9-R1：静态回调绑定尝试与事实校正

基线 `3870016`。本轮目标只有一个：尝试把 `DxgkDdiEscape` 绑定到具体 RVA。
**结果是 UNKNOWN，但失败位置是精确的。**

## 一、事实校正

| 问题 | 修正 |
|---|---|
| `text_size=91` | 镜像有**两个** `.text` 节，按名字取最后一个导致覆盖。现在按节索引逐个输出：index 0 → `vsize 13,820,405`；index 8 → `91` |
| `.pdata` 数当函数数 | 改名 `pdata_records`：这是**异常目录记录数**，一条记录表示一段有展开数据的代码区间，不等同"有效函数" |
| `0x110` 靠手工累加 | 改为**编译器证据**（见第二节） |
| `entry_610_47.json` / `match_610_47_vs_62.json` | **远程仓库里没有**（`git ls-tree origin/main` 查无）。上一轮声称"已入库"是错的，现标记为**本地文件、未入库** |

## 二、WDK 结构偏移的编译器证据

`tools/driver/km_offsetof.c`，用本机 WDK 头文件编译（不链接、只取偏移）：

```
cl -c -D_AMD64_=1 -DAMD64=1 -DWIN32=100 -D_WIN32_WINNT=0x0A00 \
   -DNTDDI_VERSION=0x0A00000C -DDBG=0 -D_KERNEL_MODE=1 km_offsetof.c
include: MSVC 19.29.30159\include; WDK 10.0.26100.0\km; \shared; \ucrt
```

结果（`data/driver/f9_offsets.json`）：

```
FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, DxgkDdiEscape) = 0x00000110
sizeof(DRIVER_INITIALIZATION_DATA)                      = 0x00000608
```

数值取自目标文件符号尺寸（`char cpg_offset_symbol[FIELD_OFFSET(...)]`），
另有 `static_assert(... == 0x110)`。

**负控制**：把断言改成 `0x111` 后编译**失败**：

```
km_offsetof.c(31): error C2338: negative control: this must not compile
```

断言真的在起作用，不是脚本自己填的数。

> 记一笔：首次自动采集时负控制因为缺 `TEMP` 变量报了 `D8037`（临时文件错误），
> 那是**假失败**。已用完整环境重跑并取回 `C2338`。

## 三、任务二：回调绑定尝试 —— 失败在第一步

目标链路：`DriverEntry → 初始化结构 → DxgkInitialize → DxgkDdiEscape 赋值 → RVA`。

### 3.1 实际发现（都可复现）

| 检查 | 结果 | 方法 |
|---|---|---|
| 导入表 DLL | `HAL.dll`、`ntoskrnl.exe`、`NETIO.SYS`、`ksecdd.sys` | 解析 Import Directory |
| 是否导入 `dxgkrnl` | **否** | 同上 |
| 镜像内 `"Dxgk"` ASCII | **0 次** | 全文扫描 |
| 镜像内 `"Dxgk"` UTF-16 | **0 次** | 全文扫描 |
| 镜像内 `"dxgkrnl"` | **1 次**（仅此一处） | 全文扫描 |
| 该字符串的 `.text` 直接 `lea` 引用 | **0 处** | Capstone 线性反汇编全 `.text` |

### 3.2 因此在哪里失去绑定证据

```
DriverEntry (0x733a0e0)
   └─ 镜像中不存在名为 Dxgk* 的任何符号
        └─ 也不导入 dxgkrnl
             └─ 只有一处 "dxgkrnl" 字符串，且无直接 lea 引用
                  └─ 绑定（若有）发生在字符串解析之后的运行期指针上
                       └─ 静态无法把任何 RVA 与 DxgkDdiEscape 关联
```

**结论：UNKNOWN。** 不能给出候选 RVA。

这意味着：`0x6912f0` 处的函数**没有**任何证据表明它是 Escape 回调，继续保持
"未命名函数"的标注。上一轮把它写成 REFUTED 也不对——**缺少证据不等于被证伪**，
应记 UNKNOWN（本报告已改）。

### 3.3 这条负结果本身的价值

它排除了一个很自然的假设："用导入表或符号名就能找到 Escape 回调"。
对 610.47 而言这条路**根本不存在**，继续在字符串/导入上打转是浪费。

## 四、SUPPORTED / REFUTED / UNKNOWN 的口径修订

| 状态 | 判据 | 本轮例子 |
|---|---|---|
| SUPPORTED | 有可复现的观测或编译证据 | 偏移 0x110、两个 `.text` 节、无 `Dxgk` 字符串 |
| REFUTED | 与已复现事实**直接矛盾** | "导入表里有 dxgkrnl"（实测无） |
| UNKNOWN | 缺证据、缺观测、只有人工标注 | "0x6912f0 是 Escape 回调"、"门禁函数地址" |

**明确废止**：把"缺证据"写成"被证伪"。F9 报告里 C-C 的 REFUTED 属误用。

## 五、escape-map.json 的定位（保持）

它是**来源缺失的历史报告**（`PROVENANCE_MISSING`）。其中 `status_map` 只能作为
"曾有观测"的线索，**不能**据此给任何私有驱动约束打 VERIFIED 分数。
F9 的 A/B 里把 `SUPPORTED/REFUTED` 当作事实验证也是错的——那是模型自评，不是验证。

## 六、下一步真正有价值的问题

既然名字路走不通，剩下两条可执行路径：

1. **从 `0x110` 的写入点反推**：在 `.text` 里找形如
   `mov qword ptr [reg+0x110], rXX` 或 `lea rXX,[rip+..]; mov [reg+0x110], rXX`
   的序列，且该 `reg` 能被证明是传给某个"外部入口"的结构体基址。
   这需要**数据流**而非符号搜索。
2. **从运行时反推**：在隔离环境里对 `DRIVER_INITIALIZATION_DATA` 实例下断点，
   读 `+0x110` 的值。这是唯一能给出确定 RVA 的方法。

### EvidenceRequest（当前主机不可执行）

| id | 命题 | 需要的观测 | 隔离条件 |
|---|---|---|---|
| ER1 | 结构体 `+0x110` 在运行期存放的是函数指针 P | 内核读内存或断点 | 第二台主机 + KDNET，或 VM + GPU 直通 |
| ER2 | P 指向的函数在 Escape 调用时被执行 | 断点命中 + 栈回溯 | 同上 |
| ER3 | 该函数内部对请求长度做校验 | 单步/条件断点 | 同上 |

以上三条**均标注为本机不可执行**，不在日常主机上尝试。

## 七、回归

```
1869 passed / 68 skipped / 0 failed
```

## 八、边界

未发送私有 Escape、未做 Type/Flags/Size 扫描、未触发 CVE；未改 CUDA/Mock；
未动 P11/P12；Ghidra 工程不入库。
