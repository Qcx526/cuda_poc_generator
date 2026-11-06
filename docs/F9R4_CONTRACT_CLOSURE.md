# P13-4-F9-R4：V2 合同收口与回调消费者接地

基线 `5e49999`。三项修复 + 一项接口合同。

## 一、Legacy Adapter：修掉一个让"盲测通过"变的 bug

审计说"PUBLIC 证据为 0 是字段状态解析错误"——**确认，确实是 bug**。

`field_states` 的键是 JSON Pointer（`/dimensions/attack_surface/entry_point`），
旧实现用点号后缀匹配（`path.endswith("." + key)`），**永远命中不到**，
于是每个字段都返回 UNKNOWN，没有一条断言能成为 PUBLIC。

修复后：

```
PUBLIC 证据：A1 A2 A3 A4 A5 A6（修复前为 0）
```

### 1.1 VALID ≠ 可公开

旧实现把 `state == VALID` 直接当成 `public_reviewed=True`。这是把"文件解析成功"
当成了"内容可以给模型看"。现已拆开：

```python
trusted  = state == FieldState.VALID      # 文件解析层面
reviewed = trusted and (dim, key) in REVIEWED_PUBLIC   # 逐条审查清单
```

`REVIEWED_PUBLIC` 是显式集合（vendor / version_range / file_format_input /
entry_point / required_permissions / cwe_id），不在集合里的一律 EVAL。

### 1.2 完整 provenance

新增 `data/cases/cve-2025-23340.raw-archive.json`（**不进入任何 Prompt**）：

| 内容 | 数量 |
|---|---|
| `raw_inputs` | 7 个文件原文 |
| `sources`（含 SHA256、大小） | 7 |
| `field_states` | **142** 条 |
| `diagnostics` | 0 条（该输入无错误） |
| `provenance_entries` | **94** 条 |

不再是"条目数量"或"前 40 条"。`provenance.json` 与 V2 Case 由**同一次转换**产出。

## 二、逐条授权：从"可见性"到"点名"

`ExperimentContract.authorized_fact_ids`：`FACT_ASSISTED` 只附加**这里列出的**
`STATIC_FACT`，空集合表示一条都不给。

`src/case_context.py::build_context` 还额外保证：调用方传入的 id **只能收窄**，
不能扩大——传一个案例从未授权的 id 不会生效。

实测：

```
CUDA  PUBLIC_ONLY   → A1..A6（6 条）
驱动  FACT_ASSISTED → S1..S7，排除 R1 R2 O1
驱动  PUBLIC_ONLY   → 0 条证据，且不含 0x110 / 0x733e240 / 31af1ce9
```

## 三、静态对象：57 组不是同一张表

按基址分类：

```
rbp 相对：51 组
rsp 相对：6 组      ← 旧结论"一张 41/57 项函数表"不成立
```

消费者追踪（填表之后 6 KB 范围，共 10 次 call）：

```
argument_from_rbp = []      ← 没有任何 call 在 8 条指令内用 rbp 设参数
```

候选目标边界：

```
RVA 0x733e240 → 节 INIT，可执行，但**不是函数起点**（.pdata 无记录）
```

**结论**：`0x733e240` 保持**候选 / UNKNOWN**，三条证据断点写清楚：

1. 51+6 组写入分属不同基址，不能当作一张表；
2. 没有调用把 `rbp` 作为参数传递，消费者未绑定；
3. 目标落在 `INIT` 节且不是函数起点——这本身与"函数指针"的预期不符，
   需要解释（可能是节属性误判，也可能 `lea` 目标算错，尚未查）。

**没有**因为偏移 0x110 吻合就认定 `DxgkDdiEscape`。

## 四、最小集成接口

`src/case_context.py`：

```
build_context(case_path, mode, authorized_fact_ids=None)
  → {case_id, platform, backend, mode, context_sha256,
     included_evidence, excluded_evidence, payload}
```

特点：

- 输出确定性（`sort_keys` + SHA256），可用哈希复现与审计；
- 返回**包含/排除清单**，不是只有 payload；
- 调用方只能收窄授权；
- 两个平台共用同一入口，各自继续用原后端（CUDA 容器 / Windows 用户态）。

下一阶段接主链的方式：在 `code_generator` 与 `driver_generator` 取上下文处，
改为调用 `build_context(case, mode)`，其余生成、执行、判定逻辑不变。

## 五、回归

```
1896 passed / 68 skipped / 0 failed
```

## 六、边界

未做私有 Escape 动态扫描、未重跑 CUDA CVE、未改 P11/P12 冻结实验、未扩建 Mock；
静态分析仍限制在 Entry 起 6 KB 窗口。
