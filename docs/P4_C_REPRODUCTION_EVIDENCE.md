# P4-C 复现证据合同

报告语言：`zh-CN`。本合同定义"把一次真实运行转成可复核结论"的规则：解析什么、
判定什么、拒绝什么。它不执行任何样本，也不产生 CVE 级 `VERIFIED`。

## 1. 输入与输出

- 输入：生成 PoC 自己打印的运行日志，包含
  `[CUDA_STEP:Sxx] <描述> — START|OK|FAIL` 与
  `<artifact> -> exit=<code> (crash)` 两类行。
- 附加输入：日志外记录的对照执行结果（`--controls`，JSON 数组）。
- 输出：`reproduction_evidence.json`、`reproduction_result.json`、
  `report.zh-CN.md`；全部由结构化记录确定性渲染。

入口：

```bash
python -m src.reproduction --log <run.log> --out <dir> --version-in-range yes|no|unknown
python -m src.reproduction --log <run.log> --controls <controls.json> --out <dir>
```

## 2. 判定词表（复用既有四值，不另造一套）

本模块只输出 `SUPPORTED / NOT_VERIFIED / UNKNOWN`：

| 判定 | 含义 |
|---|---|
| `SUPPORTED` | 受控样本崩溃、良性对照未崩溃、版本在受影响区间。可排除"任意输入都崩"，但仍不等于漏洞已验证 |
| `NOT_VERIFIED` | 未复现，或环境前提不满足（工具/驱动不在区间） |
| `UNKNOWN` | 证据不足或自相矛盾：缺对照、样本无标签、日志为空 |

**不输出 `VERIFIED`。** 该值属于 P3-A 的专项验证器，要求缺陷级必要条件集合与
独立复核；一次崩溃、一个退出码或模型自述都不构成它。本模块在报告"边界"一节
显式声明这一点。

## 3. 判定顺序（先命中先返回）

1. 无步骤且无样本 → `UNKNOWN`
2. `target_version_in_range == False` → `NOT_VERIFIED`（这是环境前提不满足，
   不是复现失败；这条顺序避免把"没装对版本"记成"PoC 不行"）
3. 无受控样本 → `UNKNOWN`
4. 受控样本零崩溃 → `NOT_VERIFIED`，并列出失败步骤
5. 无良性对照 → `UNKNOWN`（要求补跑 `benign.cubin` 与 `_ctrl*`）
6. 良性对照也崩溃 → `UNKNOWN`（样本不具区分力）
7. 其余 → `SUPPORTED`

第 5、6 条是本模块的核心：**没有对照的崩溃只能算"观察到崩溃"，不能算"复现了漏洞"**。
`CVE-2025-23339` 的历史日志只记录了恶意样本，因此离线判定结果是 `UNKNOWN`——
这是正确结论，不是缺陷。

## 4. 样本标签由文件名决定，调用方不能重标

`_ctrl*` / `benign*` → `BENIGN`，`malicious*` / `poc*` / `payload*` → `MALICIOUS`，
其余 `UNKNOWN`。外部附加的对照结果走同一规则，因此调用者无法把良性文件
声明成受控样本。

## 5. 崩溃判定

识别的是**故障退出码**而非任意非零：Windows NTSTATUS
（`0xC0000005` / `0xC000001D` / `0xC0000094` / `0xC00000FD` / `0xC0000409` / `0xC0000374`）
与 POSIX 信号退出（134/136/137/139/143）。`exit=1`、`exit=2` 不算崩溃。

## 6. 证据绑定与脱敏

- `source_log_sha256` 按日志**原始字节**计算，不按重新编码后的文本。
- 报告与证据 JSON 中的绝对路径统一替换为 `<path>`；日志原文不嵌入报告。
- 兼容 CRLF：Windows 日志的 `\r` 不会让步骤行被漏解析。

## 7. 已知边界

- 步骤状态来自 PoC 自身打印的 `OK/FAIL`，属于**被测程序的自我报告**；
  `S07 confirm return-address control — OK` 这类行不等于寄存器级证据，
  因此判定仅到 `SUPPORTED`。
- 真实 CVE 的根因级证据、受影响/修复差分仍未实现。
- 本模块不启动进程、不读取 `.env`、不访问网络。
