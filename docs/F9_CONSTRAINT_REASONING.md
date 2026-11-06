# P13-4-F9：有证据支撑的驱动约束推理

基线 `9dda671`。本轮不新增基础设施，只做证据盘点、最小推理链和一次 A/B 对照。

## 一、Step 1：二进制证据盘点

### 1.1 仓库内、可复现

| 产物 | 内容 | 来源 | 复现 |
|---|---|---|---|
| `data/driver/binary/version_compare.json` | 610.47 / 610.62 的路径、大小、**SHA256**、机器类型、节数、`.text` 大小、`.pdata` 条目数 | 两个驱动镜像 | 见 1.3 |
| `data/driver/binary/entry_610_47.json` | 入口 RVA `0x733a0e0`、42 字节、12 条指令、调用者列表 | Ghidra 导出 | `tools/driver/ghidra_export.py` |
| `data/driver/binary/match_610_47_vs_62.json` | 函数配对：old 79,615 / new 79,611 / pairs 75,756 / identical 34,735 / relocated 41,021 | 自研匹配 | `src/driver_match.py` |
| `data/driver/binary/handler_6912f0.asm` | RVA `0x6912f0` 起的手工反汇编 | Capstone | 本轮已逐条复验一致 |
| `data/driver/binary/recon.md` | 导入表调用点（`ProbeForWrite` @ `0x1400dd4c8` 等） | 静态侦察 | 见文档内命令 |

### 1.2 仅本地、未入库

| 项 | 体积 | 说明 |
|---|---|---|
| `data/driver/ghidra/` | **780 MB** | Ghidra 工程（`nvlddmkm_610_47`、`nvlddmkm_610_62`、`mock_gpu_native`），按约定不入库，可由镜像重建 |

### 1.3 本轮重新提取（保证可复现）

`python -m tools.driver.f9_evidence`，从磁盘镜像直接读出：

```
size        120,295,144
sha256      31af1ce957c6065d0b4b01ba2a7ad27df386e32c15b536ce653a162e3425fa9c
machine     0x8664   PE32+   image_base 0x140000000   sections 32
entry_rva   0x733a0e0   entry_va 0x14733a0e0
pdata       79,615 个函数
```

与仓库内既有产物**完全一致**（entry 与 `entry_610_47.json` 相同，79,615 与 `match` 的 `old` 相同），
RVA `0x6912f0` 的前 8 条指令与 `handler_6912f0.asm` 逐条相同。

### 1.4 仍然 UNKNOWN、禁止凭记忆恢复

- 早期提到的"门禁函数" `0x1859380`、`0x186bc40`：**仓库内无任何出处**，继续记 UNKNOWN。
- `0x6912f0` 这个函数**是做什么的**：没有证据。`recon.md` 称其为 handler 属人工标注。
- 610.47 与 610.62 的 315 处常量差异**具体改了什么**：只有计数，没有逐条映射证据。

## 二、Step 2：最小约束推理链

### 2.1 事实（每条带来源）

| id | 事实 | 来源 | 复现 |
|---|---|---|---|
| F1 | 镜像 SHA256 `31af1ce9…`，PE32+ x64，32 节 | 镜像 | `f9_evidence` |
| F2 | 入口 RVA `0x733a0e0` | PE 可选头 | `f9_evidence` |
| F3 | `.pdata` 登记 79,615 个函数 | 异常目录/12 | `f9_evidence` |
| F4 | WDK 头文件里 `DxgkDdiEscape` 在 `DRIVER_INITIALIZATION_DATA` 偏移 **0x110** | `dispmprt.h:2726`，按字段累加算出 | 见 2.2 |
| F5 | RVA `0x6912f0` 存在一个函数，前 8 条指令已知 | Capstone | `f9_evidence` |

**F4 的算法**：从 `Version`(ULONG, 4 字节) 起逐字段累加，函数指针按 8 字节、
中间出现的 `ULONG` 字段按 4 字节并按各自对齐补齐，得到 `0x110`。
（不是"33 个指针"这种估算——中间夹有非指针字段，所以必须逐字段算。）
这是**头文件布局事实**，**不证明**该驱动确实填了这个字段。

### 2.2 约束链

```
F4 ──► C-A: 若驱动支持 Escape，则初始化结构的 0x110 处必须是有效函数指针
       证据：头文件（布局）+ 需要运行时读取该结构 → UNKNOWN
       缺：没有该结构在内存中的任何观测；静态也未见写入点（未做数据流）

F2/F3 ─► C-B: 入口与函数规模已知，但"哪个函数处理 Escape"无法由边界推出
       证据：仅函数存在性 → UNKNOWN
       缺：没有调用关系证据把 0x6912f0 之类函数与 Escape 关联

F5 ────► C-C: 0x6912f0 是 Escape 处理器
       证据：无。早期文档的 "handler" 是人工命名 → REFUTED（作为事实主张）
       说明：可作为"待检验假设"，但不能当事实引用
```

### 2.3 与用户态观测的关系

`BUFFER_TOO_SMALL`、`ACCESS_DENIED` 等状态差异**只能证明"驱动对不同输入给出不同结果"**，
**不能**定位到 F4/C-A 的任何分支。本轮明确把"错误码 → 分支"的映射列为禁止推理。

## 三、Step 3：A/B 对照（真实 LLM 调用）

同一任务、同一模型、temperature=0；A 不给事实，B 给 F1–F5 全文。

| 指标 | A（无事实） | B（有事实） |
|---|---|---|
| 产出约束条数 | 3 | 3 |
| **引用可用事实数** | 0 | **0** |
| 编造地址 | 0 | 0 |
| 可被观测证伪的 EvidenceRequest | 1 / 3 | **3 / 3** |
| 未经证据支持的"命中分支"主张 | 0 | 0 |

原始输出：`data/driver/f9_llm/ab_comparison.json`。

### 3.1 关键发现：事实被忽略了

B 组**一条 F1–F5 都没引用**。原因不是模型能力，而是**我给的事实与问题无关**：
入口 RVA、函数计数、头文件偏移都不能回答"请求合法性由什么决定"。
所以 B ≈ A，唯一差别是 B 的 3 条 EvidenceRequest 都写成了可证伪形式，
并把"仅由 Type 与缓冲区决定"这条**标为 REFUTED**（用了观测到的状态差异）。

**这是负面结果，如实记录：本轮没有观察到 Binary Facts 带来的增益。**

### 3.2 为什么不编造成功率

没有客观 Ground Truth（私有分支不可观测），所以不计算"漏洞命中率""生成成功率"。
可审计的产出只有：候选约束、其引用、可证伪性，以及仍缺的证据。

## 四、Step 4：什么必须靠内核观测

| 命题 | 需要什么观测 | 为什么用户态不行 |
|---|---|---|
| 初始化结构 `0x110` 处指针是否有效 | 读内核内存（调试器）或符号 | 用户态拿不到该结构 |
| 某个 Escape 是否进入 `DxgkDdiEscape` | 内核断点 + 栈回溯 | 返回值不能证明执行 |
| 状态码对应哪个返回点 | 断点/覆盖率 | 同一码至少四种成因（F8 已证） |
| 私有请求结构如何被解释 | 内存 + 单步 | 结构布局未公开 |

结论：**路径级验证仍 BLOCKED**。解除条件不变：第二台主机 + KDNET，或 VM + GPU 直通。

## 五、SUPPORTED / REFUTED / UNKNOWN 的边界（本轮口径）

- **SUPPORTED**：有可直接复现的观测或头文件事实支撑（如 F1–F4、"Flags 影响结果"）。
- **REFUTED**：与已复现事实矛盾（如"0x6912f0 是 Escape 处理器"作为事实主张）。
- **UNKNOWN**：缺观测、缺出处、或只有人工标注（如门禁地址、私有结构语义）。

**禁止**：把静态 CFG 可达性当执行路径；把错误码当分支标识；把人工命名当事实。

## 六、回归

```
1865 passed / 68 skipped / 0 failed
```

## 七、边界

未发送私有 Escape、未做 Type/Flags/Size 扫描、未触发 CVE；未新增 CUDA/Mock；
未改 P11/P12；Ghidra 工程保持本地不入库。
