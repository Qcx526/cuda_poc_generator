# P3-C 验收记录

日期：2026-10-16；报告语言：zh-CN；开发基线：
`main@8d33ae4c16285d15c7486ce2cfda2f9658f022a4`。
开始时 HEAD、origin/main、远端 main 一致；仅 `config/default.yaml` 有既有修改。
两份已删除临时脚本没有恢复。本轮没有分支、PR、历史重写或 force push。

## 配置差异与修复

用户随后明确允许将 config 中的 LLM 信息提交 GitHub。实际差异只有三项不含密钥
的 `CPG_*` 裸占位符；文件原始字节保持，SHA-256 仍为
`15ea1f636e9f2846b45a6769a1d3accc0a2f1d9fdc9916ae2f8e1546d556e119`。
API Key、实际 `.env` 和自定义服务环境值没有提交。

修改前在 Windows 实际工作区运行旧 `tests/test_baseline.py`：**19 PASS / 7 FAILED**。
一个测试直接比较 API 地址字面量，其余六个因密钥选择器被误作变量名而在 Mock
请求前失败。不是网络、模型、余额或 CUDA 失败。本阶段修改前没有额外重跑 WSL
全量基线；不将 P3-B 的旧默认配置结果冒充当前用户配置基线。

仅对三项精确同名占位兼容已发布默认值并给出中文警告；推荐显式 `{env, default}`，
普通字符串保持原样，另支持 `{literal}` 逃逸。既有环境覆盖优先级、密钥隔离及
公开接口不变；缺失/空白/错误引用明确失败。未改旧测试，未调用真实模型。
完整字段差异、七个旧测试 ID、迁移和限制见
[配置兼容合同](P3_C_CONFIG_COMPATIBILITY.md)。

## 最终源码回归

当前配置回归在实际工作区执行，不替换 YAML。测试按原有规则隔离 `.env` 和
进程凭证；另独立执行真实用户 `.env` 加载加 Mock 构造验证，二者不混同。

| 检查 | Windows Python 3.12.13 `.venv` | WSL Python 3.10.12 独立 venv |
|---|---|---|
| 最终工作区全量，共 1160 项 | PASS：1112 PASS / 48 SKIP / 0 FAILED，91.10 s | PASS：1157 PASS / 3 SKIP / 0 FAILED，269.90 s |
| 七项旧失败逐项复测 | PASS：7 PASS | PASS：7 PASS |
| 旧配置测试加新增兼容测试 | PASS：63 PASS / 0 FAILED | PASS：63 PASS / 0 FAILED |
| 历史字面默认配置兼容 | PASS：独立副本全量 1112 PASS / 48 SKIP / 0 FAILED，89.65 s | PASS：旧配置加新增兼容专项 63 PASS / 0 FAILED，3.71 s |
| 实际用户 `.env` 与配置、密钥选择器的 Mock 构造 | PASS；没有请求、没有打印配置值 | PASS；相同只读/Mock 边界，没有请求 |
| Ruff、pip check、CLI help、Python 语法 | PASS；126 个 Python 文件 AST | PASS；126 个 Python 文件 AST |

历史配置副本只在忽略的临时目录用 `git show 8d33ae4:config/default.yaml` 恢复旧
**字面默认值**，没有改用户工作区；源文件与最终工程相同，不复制 `.env`。
只读 Git 元数据指针保留原 Git hygiene 检查，不创建分支或注册 worktree。
Windows 对该副本完整回归；WSL 针对唯一差异执行配置专项，未声称 WSL 该副本
全量再次通过。

原 P0～P3-B 的 1023 项测试保持不变，新增 137 项：

| 新测试 | 数量 | 实际覆盖 |
|---|---:|---|
| test_config_compatibility.py | 37 | 普通字符串/精确兼容/显式引用/默认/类型/空值/覆盖优先级/Mock |
| test_generation_delivery.py | 27 | CLI 到 ZIP、六 v1 兼容、多轮/多 CVE、部分失败、磁盘失败、错误身份、回执重建 |
| test_harmless_diagnostic.py | 73 | 固定注册表/源码替换/缺工具与版本失败/授权和资源阻断、无 CVE、XML/三流/身份/篡改/中文/归档 |

Windows 的 48 SKIP 为原 47 项 Linux/POSIX 专用检查，加一个新增 POSIX FIFO
拒绝测试；WSL 的 3 SKIP 为两个旧 Windows 不支持分支和 Windows 缺失 launcher
专用检查；新增 FIFO 拒绝测试在 WSL 通过。跳过不计作 PASS。
ZIP 重复成员负例有预期 UserWarning；原 Prompt 中 `\d` 的旧语法警告不在本阶段
修改，不计作新的 CUDA 或模型实验。

开发中一次新 Mock 诊断能力测试曾因构造的内容摘要漏掉模型默认字段而失败；
修正为先按严格模型生成完整 Synthetic 记录，再计算摘要，未改生产身份校验。
最终归档审查补上序列化长度上限负例后重新运行最终源码回归；早先结果不冒充
新增该负例后的最终结果。

## 真实只读观察与待授权实验

本轮真实 Windows→WSL 版本查询为 **PARTIAL**，目录与记录身份：

- `data/outputs/diagnostic_probes/b220f1fb9edd4556ad937e92972af07b/`
- 内容 SHA-256：`7d3cad3358f429bb960b3a45149e73dcfa9eb159cede1796a19b65f91e59ca43`

固定 `/usr/bin` 未发现可测量 Valgrind/GDB，不能扩大为“全系统没有安装”；
cuobjdump/nvdisasm 为 OBSERVED 12.8.90，仅 `--version`。没有安装、改设置或提权。
真实诊断程序、XML v4 实测、隔离与资源效果均 **NOT_CHECKED**；P2 专项动作
和 Memcheck 资源适配为 **UNSUPPORTED**。当前执行准备始终 **REJECTED**。

已实际保存当前源码的中文阻断报告：

- `data/outputs/host_diagnostic_preparations/a73ad37c88fd4080a76e036f356ed365/`
- preparation.json 原始字节 SHA-256：`e7f8685bc4013c9288b17845bc46e2e0246d9644565984cb9156c72b8a34d4b8`
- 中文报告 SHA-256：`af7164c5dfd675c66ca5e14bc79298a2cfee6ff645b4aa4bd72882887aa0b526`

这是真实能力观察下的准备记录，没有启动诊断进程，因此没有 PID/XML/退出码/
回收结果；没有伪造占位日志。早期开发准备目录保留，不用于最终重建通过声明。

另一个明确 **SYNTHETIC** 的无 CVE 离线解析示例独立保存为：

- `data/outputs/synthetic_diagnostics/cce689388f3a407bb0ad8881f195f05a/`
- manifest.json 原始字节 SHA-256：`5e86a08d32f15bf2608392a239201df06f0a86d208f645241feaa94cddd489d4`

示例只检验格式、绑定、中文重建和原始字节重新解析，不是 Memcheck 实测或 CVE
复现。`UNVERIFIED_IMPORT` 也不能改标成认证真实采集；两者均不进入真实 CVE Oracle。
接口、fixture 哈希、资源限制和后续授权清单见
[真实诊断准备](P3_C_REAL_DIAGNOSTIC.md)。

## 中文交付与科学边界

新增 `--package` 已由无网络 Mock 测试贯通实际 `main()` 到单轮生成、中文归档、
ZIP、重新打开逐成员校验、包外 SHA 输出。未启动候选。原六份 v1 及 Python API
保留；原科学 run_record 不增加交付字段。回执独立于 ZIP，避免自引用摘要。
失败时不引用旧 run；磁盘完全不可写时不能承诺有完整文件，仍返回失败。

包继续为 `GENERATION_RESEARCH_INCOMPLETE`，`INTEGRITY_VERIFIED` 不代表 CVE。
诊断、交付及准备报告均 zh-CN/UTF-8，支持确定性重建；原始三流从不翻译。
无 CVE 的通用诊断拒绝 CVE 目录读写，Synthetic、导入及真实只读探测分别标注。
详见 [一键交付合同](P3_C_PACKAGING.md)。

真实 API 鉴权/模型可用性、在线 RAG/Tavily、真实 Memcheck/ASan/GDB 实验、C fixture
编译执行、真实 CVE、生成候选、CUDA 工具新 smoke、GPU kernel 均为 **NOT_CHECKED**。
本阶段没有真实 CVE 验证，始终 **NOT_EXECUTED / NOT_VERIFIED**。

## 历史与提交审计

Windows/WSL 均实际通过新准备报告和无 CVE Synthetic 档案的中文重建/独立重解析，
旧两个资料 ZIP 独立重读、三个 P3-B 中文视图逐字节重建、新只读探测报告重读。
开始时固定的 1342 个既有输出文件均只读且双环境 SHA 复核相同；42 个七维 JSON、旧测试、生成 Prompt、
P2/P3 冻结报告及 safe_smoke.cu 未修改。当前用户 YAML 原字节保留，经后续明确
授权纳入提交；`.env`、密钥、原始私有证据、测试输出、ZIP 和临时副本不提交。
实际本地凭证值及私钥模式扫描、20 个限定交付文件、UTF-8、ignore、41 个文档链接、
whitespace 和已测试副本的源码字节对照均 PASS。提交前再核对暂存区与 main 同步；
最终 Git SHA 和推送状态随交付回执给出。没有依赖升级或工具安装。

后续真实诊断仍需明确批准安装及执行、独立隔离、可信工具/构建、适配资源和
P2 专项动作审查。离线部分通过不取消这些阻断；完成本轮后停止等待独立审查。
