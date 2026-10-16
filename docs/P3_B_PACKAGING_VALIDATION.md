# P3-B 中文归档验收

日期：2026-10-16（Asia/Shanghai）。本页记录归档专项验收；全量回归和诊断能力状态见 [P3_B_VALIDATION.md](P3_B_VALIDATION.md)。所有文件系统攻击与候选源码 fixture 均为 **SYNTHETIC 离线测试**，未执行 PoC 或候选。

## 专项测试

| 检查 | Windows Python 3.12 | WSL Python 3.10 | 说明 |
|---|---|---|---|
| `pytest tests/test_artifact_packaging.py -q` | PASS：70 项，最终全量再次通过 | PASS：70 项，在最终全量中执行 | 包含 UTF-8、逐字节重建、身份与安全负例；另有 3 项跨 CVE/LLM 重新哈希绑定攻击回归 |
| 原始输入副本哈希 | PASS | 同专项回归 | 逐字节对照源文件，不重写七维 JSON |
| 中文入口与未执行声明 | PASS | 同专项回归 | `NOT_EXECUTED`、`NOT_VERIFIED` 独立固定 |
| 同 CVE 多轮、跨 CVE 隔离、同轮冲突 | PASS | 同专项回归 | 历史 run 和 ZIP 不覆盖 |
| ZIP 成员遍历、重复、链接、篡改、缺失、截断 | PASS | 同专项回归 | 安全相对路径，显式外部摘要，离线校验 |
| 本地符号链接拒绝 | PASS | 同专项回归 | Windows 账户本轮支持创建测试链接 |
| 排他锁与写入失败 | PASS | 同专项回归 | 不输出假成功；保留本次失败目录 |
| 历史英文报告字节保留 | PASS，全量及 142 个历史文件 SHA 审计 | PASS，全量及同一档案重读 | 本模块只读导入，不原地翻译 |
| 真实 CVE、生成候选或 GPU 执行 | NOT_CHECKED | NOT_CHECKED | 本阶段明确禁止 |
| 真正断电、跨主机密钥认证、恶意本机管理员 | NOT_CHECKED | NOT_CHECKED | 无此安全或持久化声明 |

## 真实公开资料归档演示

下列是本轮实际创建并重新打开校验的 **公开资料审查包**，不是漏洞实验、Synthetic Oracle 正例或 CUDA smoke。资料引用来自冻结的 P3-A 已审查目录，原始七维输入按其真实字节哈希复制。包位于 Git 忽略的 `data/outputs/`，不提交原始运行数据。

| CVE | run_id | ZIP 字节数 | 文件数（含清单） | 独立校验 |
|---|---|---:|---:|---|
| CVE-2025-23308 | `94d9b93b4f694fc3a97779b9cdab51ca` | 58,258 | 12 | INTEGRITY_VERIFIED |
| CVE-2025-23339 | `2da38c9c112645e2a4973132ed4fdc4c` | 68,806 | 12 | INTEGRITY_VERIFIED |

第一个完整资料归档目录：

```text
data/outputs/CVE-2025-23308/
  runs/94d9b93b4f694fc3a97779b9cdab51ca/
    input/                              # 七个原始 JSON 副本
    analysis/vulnerability_claim.json
    poc/                                # 空；NOT_EXECUTED
    execution/                          # 空；NOT_EXECUTED
    evidence/public_source_references.json
    oracle/                             # 空；NOT_EVALUATED
    reports/review.zh-CN.md
    README.zh-CN.md
    artifact_manifest.json
  packages/CVE-2025-23308_94d9b93b4f694fc3a97779b9cdab51ca.zip
  index.json
```

独立校验所用包外 SHA-256：

```text
CVE-2025-23308 ZIP
9146aec318374faaab3a8802d30cabe73225c2cfe2c61692dcb738f849e64177
CVE-2025-23308 artifact_manifest.json
f58aec5f7e9cd214ab84ce308895292577f3f3f5f514cf9ba379ae2c69096dbc
CVE-2025-23339 ZIP
53f1a4eb0ffe956112c0450c4fe9219143e78121b176b20d6b87b89b4841f99f
CVE-2025-23339 artifact_manifest.json
b056fac4bf2b4f6bd535c1e377f8b82350e31e4de2a17c306e3a19cdb9abff04
```

两包均为 `RESEARCH_ONLY`、`DOCUMENTED_PUBLIC_REVIEW`、`zh-CN`、`NOT_EXECUTED`、`NOT_VERIFIED`。报告中文重建逐字节一致。校验结果证明文件复制及绑定完整性，不是公告真实性签名、受影响 build 实测或真实 CVE VERIFIED。

重验第一个包：

```powershell
.\.venv\Scripts\python.exe -m src.artifact_cli verify --package data/outputs/CVE-2025-23308/packages/CVE-2025-23308_94d9b93b4f694fc3a97779b9cdab51ca.zip --expected-sha256 9146aec318374faaab3a8802d30cabe73225c2cfe2c61692dcb738f849e64177
```

这些路径是本机实际输出引用，不保证其他克隆拥有私有输出；可使用新 run_id 重新运行公开资料导入与打包。严禁覆盖本页已记录的旧 run。
