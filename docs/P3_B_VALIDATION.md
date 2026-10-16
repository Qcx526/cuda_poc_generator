# P3-B 验收记录

日期：2026-10-16，Asia/Shanghai。基线 `main@14012ae410b80bd010e714c06d49dd282e207770`，开始 fetch 后与 origin/main 同步。两个临时脚本在基线已正式删除，本轮未恢复。主机诊断及归档实现均不运行生成候选、真实 CVE、畸形 native parser 输入或 GPU kernel，不调用付费 LLM。

## 开始时的工作区与验证方法

开始时只有用户修改的 `config/default.yaml`，本轮保持原文件，不纳入提交。该 YAML 将 API base/model/key-env 写成 `CPG_*` 名称字符串；这些名称在没有环境覆盖时会被按字面值使用，不是 YAML 插值。旧离线配置测试主动隔离 `.env`，因此工作区原始基线实际为：

| 开始时原工作区，794 项、未开启两项私有历史证据测试 | PASS | SKIP | FAILED |
| --- | ---: | ---: | ---: |
| Windows Python 3.12 | 738 | 49 | 7 |
| WSL Python 3.10 | 783 | 4 | 7 |

失败均为原有默认配置/DeepSeek Mock 重试测试，发生在本轮修改前；不表示调用了模型 API。未改测试或环境隔离规则来掩盖它们，也不声称当前自定义 YAML 的直接全量检查通过。

发布代码回归在独立源码副本执行：复制当前工程文件，**只在副本**使用 `git show 14012ae:config/default.yaml` 的已提交默认配置，不复制 `.env`。副本有只读 Git 元数据指针，Git hygiene 测试仍实际执行，未通过移除 `.git` 增加 SKIP。没有创建开发分支、注册 worktree 或修改共享 Git index。最终副本的 main/src/tests 与准备提交的源码逐字节相同，只有配置是待发布版本。

## 最终完整回归

| 发布源码副本，共 1023 项 | PASS | SKIP | FAILED | 状态 |
| --- | ---: | ---: | ---: | --- |
| Windows `.venv` Python 3.12.13 | 976 | 47 | 0 | PASS，56.10 s |
| WSL 独立 venv Python 3.10.12 | 1020 | 3 | 0 | PASS，206.02 s |

794 项旧回归未修改；新增 229 项。开启了两项 P3-A 私有历史 smoke 文件读取，使用独立 manifest pin，未重新执行 CUDA 工具。Windows 的 47 SKIP 是原有 Linux native/POSIX 路径；WSL 的 3 SKIP 是两个原有 Windows 不支持分支和新增 Windows launcher 缺失分支，均为平台专用测试。

| 新增模块 | 项数 | 内容 |
| --- | ---: | --- |
| test_host_parser_evidence.py | 89 | 正常/非零/signal、无效读写、UAF/堆/栈文本不能越权分类、部分栈、XML 协议/实体/深度/截断、工具/输入/run/CVE 混淆、原始字节与离线重解析、A～F、P3-A 投影、中文报告 |
| test_host_diagnostics_probe.py | 33 | 固定注册表、nonce/目标/worker/ToolResult 绑定、版本失败与缺失、原始流和中文报告重建；WSL 有一项 Windows 专用分支 |
| test_artifact_packaging.py | 70 | 中文导航、完整原字节副本、CVE/run/父轮次、碰撞、遍历/链接/Windows 路径、ZIP 重复/NUL/损坏/缺失、外部 pin、磁盘失败、候选生成研究归档 |
| test_artifact_binding_extra.py | 3 | 全部重新计算哈希仍拒绝跨 CVE 原始输入、LLM 冒充公开审查、错 CVE 合格分析 |
| test_report_locale.py | 34 | UTF-8/LF、旧英文保持、科学 SHA 不变、固定翻译核心、非法来源路径/篡改/未知 locale、失败中文、CLI、新旧生成 API、独立执行中文视图与多 run |

开发中已修复的实际问题：报告渲染顺序不稳定、Windows CLI 编码和换行、同编号套用错误中文事实、跨 CVE 重新哈希材料、旧 v1 布局被新目录破坏。保留负例；未修改原测试分母、fixture 或通过标准。Windows 旧 P2-C 的 MAX_PATH 行为仍保留，新跨环境报告测试使用受控短临时路径，不改系统长路径设置。

## 其他实际检查

| 检查 | Windows | WSL |
| --- | --- | --- |
| Ruff main.py/src/tests | PASS | PASS |
| pip check | PASS，无依赖升级 | PASS，无依赖升级 |
| main.py --help / 原 CLI 参数 | PASS | PASS |
| 新 artifact/report CLI | PASS，含独立 ZIP 与中文重建 | PASS，完整回归及本机真实两 ZIP/三个视图重新读取 |
| Python 语法 | PASS，120 个 main/src/tests Python 文件 AST | PASS，同 120 文件 AST |
| 新 Valgrind/ASan/GDB 内存诊断实测 | NOT_CHECKED | NOT_CHECKED |
| 真实 CVE / 生成候选 / GPU 执行 | NOT_CHECKED | NOT_CHECKED |
| 付费 LLM、在线 RAG/Tavily | NOT_CHECKED | NOT_CHECKED |

保留已有 Prompt 的 `\d` SyntaxWarning/DeprecationWarning；不是语法失败。ZIP 重复成员负例会由 Python zipfile 给出预期 UserWarning，随后验证器拒绝该包，没有把警告当成成功证据。

## 真实只读诊断能力

Windows Python 发起 WSL 固定 worker，实际只调用受检工具 `--version`；完整记录见 [可行性矩阵](P3_B_FEASIBILITY.md)。

- 通用探测目录：`data/outputs/diagnostic_probes/c00c0fa1bf3a4263bca2362da4318c28/`，状态 PARTIAL。
- 活跃 nvdisasm、cuobjdump 均为 12.8.90；已测实际文件 SHA 和完整原始版本流。
- Valgrind/GDB 在固定 `/usr/bin` 检查路径未发现：UNKNOWN，不能泛化为系统任何位置都不存在。
- 诊断效果、目标符号、可信受影响/修复构建、root-cause 绑定：UNKNOWN/NOT_CHECKED。
- 真实 CVE 隔离与实验准备：UNSUPPORTED。没有安装工具、改变 ptrace/cgroup、驱动、网络或系统权限。
- 原始 worker packet 与 ToolResult 重新关联、流哈希、代码身份及中文报告离线重建通过。

较早独立诊断目录曾因报告排序校验失败，原件保留未覆盖；修复后新 run 校验通过，失败未算成功。固定版本查询不是诊断 fixture 实验，更不是 CVE 复现。

## 合成诊断与生产边界

`docs/examples/p3_b/host/` 的两个 CVE 例子均为 SYNTHETIC。每例保留 XML、采集记录、解析结果、A～F、P3-A plan/result 和中文报告。无效写只支持普通访问异常；堆/栈、UAF 生命周期、访问大小、精确根因不从描述猜测。A/B/E/F 保持 UNKNOWN/UNIMPLEMENTED；生产专项 collector 和生产 Oracle 投影仍 UNSUPPORTED，真实 NOT_VERIFIED 固定。

未认证导入 XML 不得升级为客观 CVE_TRIGGER。报告重建可内部重放解析以检查派生字段一致性，但没有独立的新来源信任；独立重评估需要另行固定原始 collection/plan/manifest 并重跑 parser/Oracle。二者都不是重新采集或真实实验。

## 中文正式报告与统一归档

见 [语言合同](REPORT_LOCALE_CONTRACT.md)、[归档合同](CVE_ARTIFACT_PACKAGING.md)、[归档专项验收](P3_B_PACKAGING_VALIDATION.md)。

正式 CLI 默认中文，冻结 v1 英文 reader/renderer 留作兼容完整性载体，另生成中文视图，不原地改历史文件。新视图清单有 report_locale 和 source_domain。旧 Python 生成 API 默认仍保持六文件布局；正式 main.py 默认启用按 CVE/run 归档，额外调用参数保持兼容。

已实际生成 23308、23339 两个中文公开资料审查目录与 ZIP，独立重新打开并核对每个成员及包外 SHA。包只含真实公开资料审查产物及原始七维副本，标为 RESEARCH_ONLY、NOT_EXECUTED、NOT_VERIFIED，不是完整实验包；详细目录、run、ZIP/manifest SHA 在专项验收中。空 execution/oracle 等目录用明确类别状态说明，不制造占位日志。

固定 smoke、平台探测和通用 Synthetic 保留独立通用目录；不冒充 CVE 试验。既有 P2-C/P3-A 私有原件只读导入/核验，不移动或覆盖。候选生成仍只生成与静态检查；本轮没有真正编译/运行候选。

## 工程和安全审计

最终提交前核对 main HEAD/origin、限定变更文件、diff whitespace、链接、ignore、跟踪凭证和原始私有日志。`config/default.yaml` 保持用户修改且不暂存。原 42 JSON、生成 Prompt、冻结报告/Oracle 结果、safe_smoke.cu 和旧测试均不修改。P3-A 两个已删除临时脚本不恢复。

实际交付审计：Windows/WSL 均通过两 ZIP 独立校验、原能力探测档案重读、三个中文独立视图逐字节重建；本次纳入核验的 142 个 P2-C/P3-A 历史文件 SHA 全部保持。42 个原输入未改；用户 YAML 的开始/结束 SHA 相同。35 个本地文档链接有效，Ruff、双环境 pip check、whitespace 检查通过；提交前另核对暂存字节及实际本地凭证值，无密钥或私有主机路径进入交付文件。独立视图包含两个 SYNTHETIC 主机诊断和一个历史 Oracle 中文副本，均在忽略目录，原件没有修改。

本地原始证据、ZIP、源码测试副本、下载网页和审计日志均在忽略目录。源码/文档只保留受控合成例子、公开来源引用和非秘密哈希；不提交 API Key、原始私有日志、GPU UUID 或主机绝对路径。哈希不提供出版者/管理员认证，没有恶意本机沙箱、真实断电耐久或跨主机签名承诺。

## 审查后的下一步

首次真实实验仍被阻断：明确授权、可信准确受影响/修复工具、输入来源与格式、适用诊断工具及无害验证、独立可丢弃隔离、资源/回收、CVE 专项 E/F 标准缺一不可。完整准备清单在可行性文档；本阶段不执行该清单，不开放生产 VERIFIED。

关键发布回归通过后正常 commit/push main，不创建 PR、不 force push、不重写历史。最终 SHA、同步状态和保留的工作区改动由交付回执给出。完成后停止等待审查。
