# P4-K 七层输入的问题与优化建议

报告语言：`zh-CN`。基于 15 个工具链 CVE 的批量闭环结果，回答"输入该改哪里"。
结论先给：**瓶颈不在流水线代码，而在第 3 层与第 7 层的"可执行锚点"缺失。**

## 1. 证据：输入深度与结果强相关

用 `src/input_sufficiency.py` 对 23 个输入打分（加权覆盖 8 个关键字段，满分 17）：

| 分档 | CVE 数 | `SUPPORTED` | 成功率 |
|---|---|---|---|
| `RICH`（≥80%） | 1（仅 CVE-2025-23339，17/17） | 1 | 100% |
| `PARTIAL`（40–80%） | 13 | 4 | 31% |
| `THIN`（<40%） | 4 | 1（21821） | 25% |

`PARTIAL` 的 13 个 CVE **全部**缺同一组字段：`7_root_cause.function / file /
vulnerable_code_summary`。而唯一 17/17 的 23339，恰好是唯一一次**一轮就收敛**的。

这不是巧合。变异要打中缺陷，必须知道"哪个函数、解析循环长什么样、消费哪些字段"。
缺了它，模型只能写通用畸形输入——这正是 4 个 `NO_EFFECT` 的共同特征。

## 2. 三个具体问题

### 2.1 结构不一致（工程问题，最该先修）

同一层在数据里存在两种形状：

```json
// 23339
{"cve_id": "...", "affected_component": {"version_range": "...", ...}}
// 23340 / 21821
{"cve_id": "...", "name": "nvdisasm", "component_name": "...", ...}
```

模型能读文本，所以生成不受影响；但任何**按固定键取值**的代码都会拿到空值——
`src/pipeline.py` 的 RAG 查询就是这样（`vuln_context.get("affected_component")`）。
一旦开 RAG，`PARTIAL` 那批会静默丢组件信息。

### 2.2 缺"可执行锚点"

现在第 3 层有 `name/type/vendor/version_range`，都是**描述性**的；缺的是**可执行**的：

| 缺的字段 | 影响 |
|---|---|
| 解析入口函数（含二进制地址） | 无法定位、无法用断点验证 reached |
| 输入容器格式与魔数 | 畸形文件只能靠猜结构 |
| 合法样本的构造方法 | 每个 PoC 自己造基线，`benign exit=1` 反复出现 |
| 版本区间的机器可解析形式 | 闭环里 `version_in_range` 始终是 `None`，报告只能写"未提供" |

### 2.3 没有"可观测信号"的定义

评级器只认退出码/信号。但不同 CVE 的"成功"不同：SIGSEGV、返回码非零、
stderr 出现特定模式、HRESULT 错误。没有这个定义，评级只能退化为"崩了算成功"，
而这正是 23340 早期假阳性的来源。

## 3. 建议的 v2 字段（按优先级）

保持 7 个文件不变，**在每个文件里增加结构化子块**，不推翻现有内容（利于渐进迁移）。

### P0 — 第 7 层 `root_cause`（最高杠杆）

```json
"parser_model": {
  "entry_function": {"name": "parse_debug_abbrev", "rva": "0x00443f20"},
  "loop_pseudocode": "while(true){ code=decode_leb128(buf,&off); ... }",
  "consumed_fields": [
    {"name": "abbrev_code", "offset": 0, "size": 1, "semantics": "LEB128 变量长"},
    {"name": "section_size", "offset": 0x28, "size": 8, "bound_check": "none"}
  ]
}
```

`consumed_fields` 是把 `NO_EFFECT` 变成 `SUPPORTED` 的关键——它直接告诉模型
"改哪个字节、为什么这个字节没被检查"。

### P0 — 第 3 层 `affected_component`

```json
"executable_anchor": {
  "binary": "cuobjdump",
  "input_format": {"kind": "cubin", "magic": "0x7f454c46"},
  "baseline_recipe": "nvcc -cubin -G sample.cu -o baseline.cubin",
  "affected_versions": {"min": "11.0", "max": "12.9", "fixed_in": "13.0"}
}
```

`baseline_recipe` 能消除"良性基线自身失败"这一整类问题；
`affected_versions` 让评级器的版本门从"永远未知"变成真实判据。

### P1 — 第 4 层 `attack_surface`

```json
"invocation": {"binary": "cuobjdump", "argv": ["--dump-elf", "{artifact}"]},
"observable_signal": {"type": "exit_signal", "value": "SIGSEGV"}
```

`observable_signal` 是评级器的输入，不是文档描述。

### P2 — 每层加 `provenance`

```json
"provenance": {"source_url": "...", "retrieved_at": "2026-10-20", "confidence": 0.7}
```

论文要可复现，这一条是给评审看的。

## 4. 工程侧改进（与输入无关）

1. **分析结果缓存**：单次分析约 4 分钟，按 (CVE, 模型, 提示词哈希) 缓存，重跑只走生成；
2. **并发 3–4 路**：各 CVE 输出目录独立，15 个可从 2.5 小时压到 40 分钟；
3. **temperature 固定 0**：论文实验要可复现，0.3 的采样会让同一 CVE 每次结果不同；
4. **`NO_EFFECT` 再细分**：区分"变异未命中字段"与"字段命中但无效果"——前者加先验，
   后者说明漏洞在此配置下不成立，结论完全不同。

## 5. 不建议做的事

**不要用充分性分数做硬门禁。** 21821 只有 2/17 却成功复现，说明分数低不等于不可做。
正确用法是：低分时改变策略（保守变异 + 明确告知模型缺什么 + 报告标注
`INSUFFICIENT_INPUT`），而不是拒绝运行。

## 6. 一句话总结

现在的 7 层回答的是"这个漏洞是什么"（适合写报告），
而生成 PoC 需要的是"这个解析器吃什么字节"（适合写代码）。
v2 的任务就是把后者补进 schema——**从描述性输入升级为可执行输入**。
