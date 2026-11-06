# P13-4-F9-R3：可见性合同加固与静态候选校验

基线 `0982819`。三个针对性任务，不扩建框架。

## 一、可见性：从"类型决定"改为"逐条决定"

**旧问题**：`EvidenceKind → Visibility` 是固定映射表，于是
`INPUT_ASSERTION` 和 `EVIDENCE_REQUEST` **天然就是 PUBLIC**——
只要字段存在，就自动进入盲测，这正是要修的东西。

**新规则**（`src/case_v2.py`）：

- `visible_in` **默认 `EVAL`**（默认拒绝）；
- 只有 `INPUT_ASSERTION` / `EVIDENCE_REQUEST` 才能被授权为 `PUBLIC`，且必须显式
  `public_reviewed=True`；
- `STATIC_FACT` **只能**是 `FACT`（不可 PUBLIC），且必须绑定 `target_identity`；
- 其余种类（观测、假设、验证结果、评测答案）一律 `EVAL`。

**这条规则当场上报了一个真问题**：驱动案例里的 R1/R2 试图以 PUBLIC 进入盲测，
而它们的正文就写着 `+0x110`——验证器直接报错拦下，现已降为 `EVAL`。

## 二、投影：字段白名单，不是透传

`src/case_projection.py` 现在按 **字段白名单** 渲染，不再把
`description` / `entry_surface` / `missing` / `contract` 整体拷过去：

| 区段 | PUBLIC_ONLY 允许 | 说明 |
|---|---|---|
| identity | case_id, cve_id, title | |
| target | vendor, component, platform, execution_tier, versions | |
| entry_surface | medium, interface, trust_boundary | `constraints` 不透传 |
| description | public_summary, cwe, impact | |
| contract | goal, backend, risk_level | `allowed_operations` 不透传 |
| missing | **不带** | 自由文本可能点出关键字段名 |
| extension | **只有 name** | payload 含镜像哈希与候选 RVA |

`FACT_ASSISTED` 在此基础上增加 `STATIC_FACT` 证据、`missing` 与 extension payload。

**不依赖关键词黑名单**：控制手段是"默认不渲染"，不是"渲染后过滤"。

测试实测：

- CUDA 公开投影不含 `sh_size` / `1..11` / `24 的倍数` / `root_cause` / `attack_vector`；
- 驱动公开投影不含 `31af1ce9`（镜像哈希）、`0x733e240`（候选 RVA）、`+0x110`；
- EVAL 证据的 id 在两种模式下都不出现。

## 三、Legacy Adapter：改为复用 normalize_input_files

旧实现直接读 JSON，自己拼摘要——"看起来无损，其实不是"。

现在 `src/case_legacy.py` 是 `normalize_input_files()` 的一个视图：

| 保留项 | 来源 |
|---|---|
| 七个文件 SHA256 / 大小 | `normalized.sources` |
| 字段级状态（VALID/UNKNOWN/CONFLICT/INVALID） | `normalized.field_states` |
| provenance 条目数 | `normalized.provenance` |
| diagnostics（前 40 条原文） | `normalized.diagnostics` |
| 冲突清单 | 由 field_states 派生 |

规则：

- 字段状态不是 `VALID` 的公开断言**不进入 PUBLIC**，并在 `adapter_notes` 里注明；
- CVE 拿不到单一值时 `cve_id=None`，`case_id` 退回 `case:<目录名>`，**不挑第一个**；
- `provenance.structural_validity_only = true`——结构有效 ≠ 漏洞事实成立。

`data/inputs/CVE-2025-23340` 实测：7 个文件哈希齐全、`conflicts=[]`、`cwe=CWE-131`。

## 四、静态候选：0x733a399 / 0x733e240 的字节级校验

`scan_table()` 已改为使用 Capstone operand detail：

- 要求 `lea` 的目的寄存器 **等于** 后续 `mov` 的源寄存器（旧版只看相邻）；
- 记录原始字节、`lea`/`store` 的 RVA、位移、目标 RVA、基址寄存器。

**校验后结果**：

```
真正成立的 lea/mov 对   57
被拒绝（寄存器不一致）   2
字段 0x110 ← 0x733e240（store @ 0x733a399，base=rbp）
表基址来源：lea rbp, [rsp - 0xe10]  @ 0x733a124   ← 结构体在栈上
```

字节：`48 c7 85 10 01 00 00 ...`（见 `data/driver/f9r2_table.json` 的 `bytes` 字段）。

### 4.1 是否已经建立"初始化结构基址"的客观证据

**没有。**

- `rbp` 被证明是**栈帧指针**（`lea rbp,[rsp-0xe10]`），不是全局结构；
- 但"这个栈帧就是 `DRIVER_INITIALIZATION_DATA`"**未证明**——
  只知道它有 57 个函数指针被连续填入，偏移 0x110 恰好与 WDK 布局一致；
- 消费该结构的调用**不在扫描窗口内**（窗口 0x700 内唯一的 `call` 在 0x733a0f0，
  早于填表），因此无法把 `rbp` 绑到任何外部入口。

**结论**：`0x733e240` 保持 **候选**，状态 **UNKNOWN**。
偏移一致是必要条件，不是证据。"没找到"也不写成 REFUTED。

## 五、口径

| 命题 | 状态 | 依据 |
|---|---|---|
| `0x733a399` 处 `mov [rbp+0x110], 0x733e240` 存在 | STATIC_FACT | 字节可复核 |
| 该表有 57 个寄存器一致的 lea/mov 对 | STATIC_FACT | operand 级校验 |
| 表基址是栈帧 `rsp-0xe10` | STATIC_FACT | `0x733a124` |
| 该结构是 `DRIVER_INITIALIZATION_DATA` | UNKNOWN | 无消费点证据 |
| `0x733e240` 是 `DxgkDdiEscape` | UNKNOWN | 同上 |

## 六、回归

```
1888 passed / 68 skipped / 0 failed
```

## 七、边界

未发私有 Escape、未扫描未知参数、未重跑 CUDA CVE、未重建 Mock、未改冻结实验；
扫描窗口限制在 Entry 起 0x700 字节，未做全驱动扫描。
