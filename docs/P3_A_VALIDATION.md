# P3-A 验收记录

日期：2026-10-16。基线为 `main@f1e3bc98322b23f87830e229a912acb8ff0bda17`；开始时 fetch 后 HEAD 与 origin/main 一致。工作区只有 `_diag.py`、`_check_rel.py` 未暂存删除；维护者随后明确表示不再需要两文件，本轮按此最新指令纳入删除。

## 测试环境与分母

Windows 使用项目 `.venv` CPython **3.12.13**，WSL Ubuntu-22.04 使用独立 venv CPython **3.10.12**。没有安装/升级依赖、改驱动、CUDA Toolkit、WSL 网络或系统权限。

| 检查 | Windows | WSL |
| --- | --- | --- |
| 修改前全量 601 项 | PASS：554 passed / 47 skipped / 0 failed | PASS：599 passed / 2 skipped / 0 failed |
| 最终全量 794 项 | PASS：747 passed / 47 skipped / 0 failed，27.24s | PASS：792 passed / 2 skipped / 0 failed，142.48s |
| 新增 193 项 | PASS：193/193；两个可选历史证据读取均开启，无新 SKIP | PASS：193/193；两个可选历史证据读取均开启，无新 SKIP |
| main.py --help | PASS，原 CLI 参数保留 | PASS，原 CLI 参数保留 |
| ruff check main.py src tests | PASS | PASS |
| pip check | PASS，无 broken requirements | PASS，无 broken requirements |
| Python 语法 | PASS：103 个 main/src/tests Python 文件 AST parse | PASS：103 个 main/src/tests Python 文件 AST parse |
| 历史真实 P2-C 原始证据读取 | PASS，独立 manifest pin、所有关联/原件/角色与哈希 | PASS，同一档案经 Linux 路径读取、重建六份报告；未启动工具 |
| 新 CUDA 工具、GPU/kernel、真实 CVE/生成候选运行 | NOT_CHECKED（本阶段未执行） | NOT_CHECKED（本阶段未执行） |
| 付费模型、在线 RAG、Tavily | NOT_CHECKED（未调用） | NOT_CHECKED（未调用） |

Windows 的 47 SKIP 全是原有 Linux 路径、/proc、ptrace、进程组、POSIX 权限/symlink 等平台用例。WSL 原有 2 SKIP 是专测 Windows 不支持适配器的测试，Linux 使用真实受支持路径。不改变旧测试、分母或 skip 条件制造 PASS。未设置历史证据目录/pin 时，P3 另有两项按设计 SKIP，不能将其报告为通过。

源码中已有 `src/code_generator.py:84` Prompt 字符串 `\d` SyntaxWarning 保留，未改 Prompt；它不是本轮语法错误或执行验证。

## 新增离线回归

| 文件 | 数量 | 实际覆盖 |
| --- | ---: | --- |
| tests/test_oracle.py | 96 | 合成正反未知；缺证据、CVE/身份/source/collector/scope 变更、版本不匹配、布尔与数值区分、不同必要谓词冲突、可选冲突、不得豁免必要完整性、crash/exit0/Sanitizer 不能代替根因、差分不足、严格模型与 LLM 断言边界 |
| tests/test_oracle_evidence.py | 45 | 合成/客观域分离、不可变字节、原始哈希、严格/畸形 JSON、Pointer、Markdown 拒绝、独立 pin、部分采集、actual step 工具角色、nvcc 专属字段、限定版本 banner、release 不一致、可选历史真实读取 |
| tests/test_oracle_report.py | 31 | 状态原样渲染、claim/plan/目标/条件关联、篡改与未知文件、重复键、大小界限、磁盘失败、不覆盖历史、链接/路径拒绝、Markdown 注入转义、离线重建 |
| tests/test_oracle_catalog_cli.py | 21 | 六套 42 JSON 哈希/字段来源复用、CWE 冲突保留、未知案例、全部新 CLI help/claim、4 份冻结合成输入的重新计算、合成 CLI/rebuild、目标 parser 版本未知不借用 Toolkit 排除、六例历史 smoke 判定及重建 |

开发过程中发现并修复：计划缺少完整工具哈希映射校验；必要条件可用 completeness_required=false 豁免；不同工具的字段可误绑另一个合法工具；仅有 Toolkit 版本便可能排除 parser 漏洞。保留对应负例。初次 catalog 测试的来源相对路径不能定位原文件，已修正为带案例目录的来源路径；未修改原输入或削弱断言。

## 历史真实证据兼容性

此处是**读取 P2-C 已有无害真实执行档案**，不是新实验或新 Windows→WSL 执行。原记录为固定 CUDA 编译/检查，无 kernel、无候选执行。保留原 `NOT_EXECUTED / NOT_VERIFIED`。

独立固定原始 manifest SHA-256：

```text
d7e3d701873566666aa0b8f7adba8259af3612bede1eaaa6ba1527d8eda2b58c
```

原采集器 p2c-1.1；native 原件索引/采集/回收状态合格；6 个原工具步骤退出 0。原始版本精确 banner 测得 nvcc 12.8.93、cuobjdump/nvdisasm 12.8.90，Toolkit release 12.8。独立 reader 核验全部关联，52 个原文件在新审查前后逐字节 SHA 相同。没有改写旧报告结论或以当前文件替换原证据。

本地私有 `data/outputs/oracle_runs/p3a-archive-review-<unique-id>/` 新建六份完整 plan/result/claim/report/index bundle；可离线重建，未纳入 Git。摘要不公开主机 ID、驱动路径、GPU UUID 或授权私有信息。

| CVE | 资格 | Oracle verdict | 真实 CVE | 新报告 SHA-256 |
| --- | --- | --- | --- | --- |
| 2022-21821 | INELIGIBLE | NOT_VERIFIED | NOT_VERIFIED | d7fce24f5cca279ea365207bdf0553a5361fe6e87ebb0b0a1a533b212aaf1e19 |
| 2023-0196 | INELIGIBLE | NOT_VERIFIED | NOT_VERIFIED | 0faf70d0f5192c95019adc8abdf23dab218d772302e99cfd4e7277720d974bea |
| 2024-0076 | INELIGIBLE | NOT_VERIFIED | NOT_VERIFIED | 4882289b9db413fc55623dd1cd2d1913c4705b8b787ecb60c8f4f2142d3d3324 |
| 2024-0124 | INELIGIBLE | NOT_VERIFIED | NOT_VERIFIED | c2437f97ed81715a56f72a205cb990082dc24f23099056398827c3bd82cf6df2 |
| 2025-23308 | UNKNOWN | NOT_VERIFIED | NOT_VERIFIED | 861c6f701d28cde2db1d306fc59ac388f9e0afc6d478fb44605526c5f4b48e37 |
| 2025-23339 | UNKNOWN | NOT_VERIFIED | NOT_VERIFIED | de497739feda035b908441ed41dd6a3b83ae3b76c2e353e67319702ab9a742ab |

该表只适用于这些被身份绑定的历史工具字节。不能推导本机所有同名可执行文件均未受影响；也不能称前四项“复现失败”。2025 两项范围匹配只是必要前提，非充分验证资格。

## 公开来源审查

六个 CVE 均逐项比对原七维 JSON、厂商公告及 NVIDIA CNA；2025 另核对 Talos 原技术报告与受测 build。详见 [资格总表](P3_A_CVE_ELIGIBILITY.md)、[审查 A](P3_A_CVE_REVIEW_A.md)、[审查 B](P3_A_CVE_REVIEW_B.md)。保留 CWE/CVSS/build/机密性影响及输入补丁推测的差异；不将模型/输入的根因升级为事实。

厂商/CNA 检索 PASS；CVE API 直接访问和部分仅 JS 页面未取得有效正文，使用已实际读取的官方 CVEProject/cvelistV5 CNA raw JSON 替代，未把失败访问标 PASS。机器摘要中未测原始响应字节的来源哈希明确 null。未检查厂商补丁实现、受影响二进制、根因调用栈、恶意输入字节、真实差分或 WSL 漏洞路径；这些均 UNKNOWN/NOT_CHECKED。

## 工程与敏感信息审计

基线 177 个跟踪文件中，旧文件改动仅 README 和维护者授权删除的两个临时脚本。旧生成算法、Prompt、辅助工具、42 输入、已有 tests、依赖、平台/执行合同和历史文档全部不改。新增接口位于独立 oracle 模块，未接入自动生成/自动执行主流程。

| 项目 | 状态 |
| --- | --- |
| 42 个原输入逐源 SHA 与路径 | PASS |
| 原有生成 Mock / 配置 / 平台 / 执行回归 | PASS，双环境最终全量执行，未修改旧测试 |
| .env、.venv、tmp、私有 oracle 输出 ignore | PASS，git check-ignore 已实际核对 |
| .env 跟踪检查 | PASS，仅 .env.example 跟踪，未打印本地值 |
| 本地实际凭证值与新文件比对、key/private-key 模式检查 | PASS；仅扫描结果，未公开值；不声称完整历史密钥审计 |
| 新文件无本机用户绝对路径、GPU UUID/原始私有日志 | PASS，私有输出留在忽略目录 |
| git diff --check / staged diff、Markdown 链接 | PASS，33 文件逐项限定；36 个本地 Markdown 链接有效 |

扫描区分 `CPG_LLM_API_KEY_ENV` 这种公开环境变量名称指针与实际凭证内容；既没有提交 .env，也没有通过打印密钥定位匹配。哈希索引不是签名，不对恶意宿主、管理员、伪造厂商标签或一致重写全套无签名材料提供认证。

## 可复现检查

Windows 常规离线检查：

```powershell
.\.venv\Scripts\python.exe -m pytest -q -rs
.\.venv\Scripts\python.exe -m ruff check main.py src tests
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m src.oracle_cli --help
git diff --check
```

WSL 用独立 Python，运行同一套源码/测试：

```bash
cd /mnt/f/qcx/code/cuda_poc_generator
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pytest -q -rs
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m ruff check main.py src tests
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pip check
```

开启两项历史原始证据检查前，在相应环境自行设置 `P3A_P2C_EVIDENCE_DIR` 和独立可信 `P3A_P2C_MANIFEST_SHA256`。路径分别使用 Windows/Linux 形式，不复用 Windows Python/DLL。两项仅读取文件，不启动 WSL worker、nvcc、cuobjdump 或 GPU。库外用户没有该私有档案时保持 SKIP。

## 交付及限制

新增模型/确定性评估器/固定证据 adapter/六例审查导入/报告与独立 CLI；新增 4 测试模块、公开资料审查及 4 组标注 SYNTHETIC 的输入/输出/报告。README 如实说明已实现与未实现。新增 OraclePlan/OracleResult/OracleReportManifest 均为版本 1.0；原 P2-C EvidenceManifest/ExecutionRecord 仍按既有 1.1 schema 读取，未改变旧语义。

真实生产 root-cause/differential assessor **UNSUPPORTED**。本阶段生产真实 VERIFIED 不开放；SYNTHETIC VERIFIED 只能证明规则行为。当前无生成候选执行准入、GPU 安全隔离、完整网络隔离、真实受影响/修复版本实验或反馈迭代。报告 bundle 的离线重建只证明本地结构/渲染一致；科学复核必须重新核验独立固定的原始证据并运行 Oracle。

Git 在 main 正常提交/推送，禁止 force/history rewrite/PR；最终 SHA 和 origin 同步状态由交付回执提供，避免提交内容自引用 commit SHA。关键验收失败则不提交失败版本。完成后停止，等待独立审查。
