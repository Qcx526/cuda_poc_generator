# P3-C 单次生成到中文 ZIP 的交付合同

基线：`8d33ae4c16285d15c7486ce2cfda2f9658f022a4`。报告语言：zh-CN。
该接口只保存候选和研究材料，不启动候选、编译器、Memcheck 或 GPU。

## 命令与默认行为

Windows 项目根目录：

```powershell
.\.venv\Scripts\python.exe main.py --cve-id CVE-2025-23308 --no-rag --package
```

这是真正的生成命令，正常使用会访问配置的 LLM；本阶段验收只通过 Mock 调用同一
CLI 路径，没有调用实际 API。原有 `--config`、`--input-dir`、`--output-dir`、
`--target-backend` 等参数保持兼容。WSL 可以用独立 venv 的 Python 执行同样参数。

`--package` 默认关闭。无此参数时，正式 CLI 仍像 P3-B 一样生成独立研究归档，
但不自动创建 ZIP。原 Python API `CudaPipeline.run()` 默认仍仅写六份 v1 产物。
Python 调用者可以显式 `run(..., package_artifacts=True)`；它同时启用本轮归档。
新增参数置于旧参数之后，旧位置参数、原返回科学记录和 CLI 的既有调用参数不变。

## 数据流与文件

```text
原有输入归一化 → 平台前置检查 → 一次合格分析 → 一次候选生成/静态检查
  → 原六份 v1 文件与本轮 run_record
  → create_generation_run：仅复制本轮记录列出的真实文件、原始响应及输入字节
  → package_run：独立 run → ZIP → 重新打开 → 全成员字节数/SHA/绑定检查
  → 包外 index.json 记录 ZIP SHA-256
  → 独立中文 delivery 回执（不进入 ZIP，避免自引用）
```

```text
data/outputs/<CVE>/
  cuda_*_v1.*、input_manifest_v1.json       # 原兼容输出
  runs/<run_id>/
    input/ analysis/ poc/ execution/ evidence/ oracle/ reports/
    README.zh-CN.md
    artifact_manifest.json
  packages/<CVE>_<run_id>.zip
  index.json                              # ZIP 自身摘要在包外
  delivery_attempts/<run_id>/
    delivery.json
    report.zh-CN.md
```

归档及 ZIP 继续使用 P3-B 的路径、链接、成员数量、长度、哈希和跨 CVE/run 校验；
不会重写旧 run。完整性校验通过的包仍为 `GENERATION_RESEARCH_INCOMPLETE`，
因为没有真实执行、根因或差分证据。`STATIC_INVALID` 的已保存候选可以作为研究
材料打包，其静态失败状态不被提升。不存在的原始日志不会被占位文件替代。

## 可机器读取的结果

原 `run()` 返回值、`cuda_run_v1.json`、候选状态和科学对象 SHA 不增加 delivery
字段。新增 `pipeline.last_delivery` 和包外回执，格式为 `GenerationDelivery`：

```json
{
  "delivery_schema_version": "1.0",
  "report_locale": "zh-CN",
  "run_id": "<本轮32位小写十六进制ID>",
  "cve_id": "CVE-2025-23308",
  "generation_status": "COMPLETE",
  "archive_status": "ARCHIVED",
  "package_status": "INTEGRITY_VERIFIED",
  "archive_directory": "<本轮目录>",
  "package_path": "<本轮ZIP>",
  "package_sha256": "<64位包外摘要>",
  "manifest_sha256": "<64位清单摘要>",
  "candidate_execution_status": "NOT_EXECUTED",
  "real_cve_verification": "NOT_VERIFIED"
}
```

此片段仅说明字段，并非有效模型实例或真实实验。完整字段包括中文解释及错误
类别；错误类别不保存供应商响应、密钥或异常对象全文。CLI 成功时打印 ZIP 路径
和包外 SHA-256。`INTEGRITY_VERIFIED` 仅说明包完整性，不是 CVE `VERIFIED`。

## 失败处理

- 开始每次 `run()` 即清空上轮 `last_delivery`，包括参数类型错误的情况。
- `COMPLETE` 必须同时匹配有效输入、合格分析和 `GENERATED` 候选，否则拒绝自动
  交付；不靠一个字符串状态掩盖失败。
- 分析/生成失败时，可保存本轮真实存在的不完整材料，但不自动交付 ZIP；旧 v1
  残留源码不进入失败轮次。
- 归档、ZIP、身份复核或回执写入失败时退出非零；回执不携带旧 ZIP 路径或摘要。
  已写文件保留，不自动删除、覆盖、重试或回退到历史 run。
- 输入不合格时，不把疑似 CVE 当作已绑定目标；失败回执进入
  `data/outputs/unbound_generation/delivery_attempts/<run_id>/`。
- 若磁盘连失败回执也无法保存，只能在终端和 `last_delivery` 说明失败，不能承诺
  每种磁盘故障都有完整文件。原生成异常不会因打包失败变成成功。

## 离线重建与独立校验

```powershell
.\.venv\Scripts\python.exe -m src.artifact_cli verify --package <本轮ZIP> --expected-sha256 <独立核对的包外SHA>
.\.venv\Scripts\python.exe -m src.artifact_cli rebuild-report --cve CVE-2025-23308 --run-id <本轮ID>
```

`src.generation_delivery.rebuild_delivery_report(directory)` 检查回执的 CVE/run
目录绑定并逐字节重建中文交付报告。它只检查回执内部一致性；独立包复核必须
使用 `verify_package` 和包外 pin。哈希不认证操作者、提供商或主机。

回归见 [P3-C 验收](P3_C_VALIDATION.md)。未授权真实诊断的边界见
[固定诊断准备](P3_C_REAL_DIAGNOSTIC.md)。
