# P3-D-R3 验收与实测记录

报告语言：`zh-CN`。开发基线：`main@81443b0f8f013003ab26fe538aa1dc5bac74cd85`。本文件只记录已执行检查和客观结果；最后修订时必须核对每项原始证据和实际 Git 状态。

## 1. 当前验收范围

| 项目 | 验收要求 | 当前记录 |
|---|---|---|
| A：接收文件实际运行 | Windows 发起固定 `p2b-normal-v1` 传输和独立授权执行；WSL 进程确实读取该落盘文件，保存 PID、FD 身份、原始输出、退出和回收证据 | 第三轮 `COMPLETED`，FD、PID、原始流、独立回收和离线中文报告均已核验；前两轮失败原件保留 |
| B：良性目标诊断 | 本轮固定 `safe_smoke.cu` 编译产物进入精确侧载 cuobjdump 的受控 Memcheck，并保存原始 XML | **BLOCKED / NOT_CHECKED**：自动安全审查拒绝诊断子任务；无本轮目标进程或 XML 结果 |
| C：真实候选预检 | 只读核对已归档生成 run 的 CVE、源码、模型/静态状态和平台工具身份；缺少可加载候选源码时明确阻断 | 资料审查 run 被 `preflight` 按身份拒绝；当前无可加载候选源码，真实生成候选的目标观测未检查 |
| Windows 入口 | 固定动作 CLI 的参数和退出状态与实际行为一致；无授权或身份失败不启动远端文件 | `execute` 固定动作和 `evaluate` 离线重建实测 PASS，未知模式/缺授权离线负例 PASS |
| 双环境回归 | Windows Python 3.12 与 WSL Python 3.10 全量离线测试；新拒绝场景和原 P0～P3-D-R2 回归 | Windows 1225 passed / 66 skipped / 0 failed；WSL 1285 passed / 6 skipped / 0 failed |
| Git 交付 | 审查工作区、敏感信息、diff 和远端同步，仅对验收通过的工程文件正常提交推送 | PASS：实现提交 `0e045fe` 已推送 `origin/main`；历史草稿和私有证据未提交 |

上述“待”状态表示**尚未检查**，并非 PASS。若实际 preflight 拒绝或执行端无法证实资源、身份和回收，应保存阻断记录并保持对应项失败或未检查。

只读盘点 `data/outputs` 中的 CVE 归档清单：CVE-2025-23308 与 CVE-2025-23339 的现有轮次是 `DOCUMENTED_PUBLIC_REVIEW`；CVE-2024-0124 有两个 `GENERATED_CANDIDATE_RESEARCH` 轮次，但清单均没有 `poc/cuda_poc_v1.py`。对 CVE-2025-23339 的资料审查轮次实际调用只读 `preflight`，按域身份被拒绝，未进入候选执行。这个负例证明资料审查不能冒充生成轮次；尚未对带真实候选源码的归档进行目标观测或执行。私有轮次标识保留在本地原件中。

## 2. 身份、资源与拒绝测试

离线测试应分别覆盖：接收文件哈希变化、receipt 替换、跨 transfer/run 或环境混淆、符号链接和文件替换、路径与硬链接异常、授权缺失/过期、工具替换、`/proc` FD 与回执不符、资源未实施、超时与日志截断、进程组回收失败。测试必须确认这些情形不会退回执行注册表中的另一份同字节源码。

目标解析器诊断入口本轮未实现和运行。不能用尚未验收的草稿测试、R2 的独立 CUDA smoke、R1 的固定 CPU XML 或历史证据为本轮 B 填写 PASS。未来另行审查该路径时，应覆盖输入来源、工具 build/哈希、资源隔离、XML 完整性及跨 run 绑定。

## 3. Windows→WSL 实测证据

以下数值来自本轮三个独立 WSL run；前两轮的阻断与缺失证据保留原状。安全诊断 B 没有本轮执行。任何字段不得从 Mock/Synthetic 数据、模型描述或历史无关 run 推断。

| 任务 | Windows 请求 / WSL run | 身份与过程 | 原始证据、独立复核 | 状态 |
|---|---|---|---|---|
| A：首次门禁拒绝 | request `7258eccf79f94297b821a25bfae1f0bd`；run `b38bac689ed04c56a4a1d29333700e6c` | `REJECTED`：`PYTHON_EXECUTABLE_IDENTITY_CHANGED`；`process=null`，无子进程；回收 `CONFIRMED` | `evaluate` 离线完整性 `VERIFIED`，固定源码 `NOT_EXECUTED` | 阻断原件保留 |
| A：第二轮记录失败 | request `3c464cdc8ead4d0ab8954a628659ee5d`；run `dc70398ec60d4a34bab8cba7d8e45432` | WSL worker journal 有接收文件 FD 证明、PID `517`、门禁放行和回收事件；记录模型错误导致执行记录未保存 | controller `UNKNOWN`、回收 `CONFIRMED`；没有完整 stdout/stderr 归档，不计成功 | 不完整原件保留 |
| A：完整固定执行 | request `0ec29dcb33734db89870f27b0763170a`；run `50905545cd6a4ad69219702b8b247294`；transfer `4f9c641285904f0eae2ec7172c163086` | WSL worker PID `528`、固定文件进程 PID `529`；实际 FD `device=2096`、`inode=86964`，退出码 `0`、signal 空；回收 `CONFIRMED`（worker 已退出、进程组为空） | stdout `26` B / `e92e8dfe5ad14678c86a6b7ac5131edd026da2dcf17c89f5d20cf446e2a4bcf1`；stderr `0` B / `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`；独立 `evaluate` 完整性 `VERIFIED` | 固定文件 `COMPLETED`；候选 `NOT_EXECUTED`、CVE `NOT_VERIFIED` |
| B：固定良性 cubin 与目标诊断 | 无本轮执行 | 无本轮进程 | 无本轮 XML | BLOCKED / NOT_CHECKED |

首次拒绝轮次的 transfer ID 为 `fb8af77d8975487caef89b5a04f73f56`，固定源码 SHA-256 为 `a69c83e61b0fc66ed5b776e2c7ac45d801578be2ed6ebc189f21455f9dcf1bf5`。本地 `evidence_manifest.json` SHA-256 为 `61508121314a5480256a370a52532a5f12c6e8e07e5fc96dcfc2be57232e458b`，中文报告 SHA-256 为 `cd81324b153da355ddfd0af9b914fe5453b69ce6986901821a93235dcabb516c`。Windows `.venv` 离线重读清单、身份记录与报告后返回 `integrity_status=VERIFIED`，该词仅说明**拒绝记录的保存完整性**；原始执行流与目标进程不存在，不能据此填写执行成功。

完整固定执行的源码 SHA-256 为 `a69c83e61b0fc66ed5b776e2c7ac45d801578be2ed6ebc189f21455f9dcf1bf5`，收据原始字节 SHA-256 为 `ab6e3ae9f2a218bfbaec5f1874aac931856e26572e22174367eb6eabdf3c5217`，Python 工具文件 SHA-256 为 `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae`。本地证据目录为 `data/outputs/p3d_r3_staged_fixture/50905545cd6a4ad69219702b8b247294/`，清单 SHA-256 `b5027e3b999cb6dc03d75d7c58a6c83db6ce44d6c66ab6c9ac06ce9b3171ee53`，中文报告 SHA-256 `178c518b294d2d547f0e5a984d7d73e52f90745dc12f23a945997a0628cdc498`。Windows 重新打开原始文件，比较执行与 STATUS 的记录、原始流、清单和中文报告；`integrity_status=VERIFIED` 不代表 CVE 验证。

无论安全输入上的工具退出或 Memcheck 结果如何，固定任务不属于指定 CVE 的漏洞触发证据。当前生成候选状态与 CVE 验证状态仍须分别报告 `NOT_EXECUTED` 和 `NOT_VERIFIED`。

## 4. 双环境、CLI 与 Git 结果

| 检查 | Windows Python 3.12 | WSL Python 3.10 | 说明 |
|---|---|---|---|
| P0～R2 全量回归及 R3 新测试 | PASS：1225 passed / 66 skipped / 0 failed | PASS：1285 passed / 6 skipped / 0 failed | `python -B -m pytest -q -p no:cacheprovider`；总收集数相同，平台相关用例的 skip 分布不同 |
| Python 语法检查 | PASS：86 个 Python 源文件 AST 解析 | PASS：86 个 Python 源文件 AST 解析 | AST 检查不写缓存；Windows `compileall` 曾因既有 pycache 写入 WinError 5 未完成 |
| `src.cve_lab` CLI 参数/拒绝路径 | PASS | 不适用 | `--help`、未知模式/缺授权离线负例、真实固定 `execute` 与独立 `evaluate` |
| 证据清单重读、报告逐字节重建 | PASS：拒绝轮次与完整固定轮次 | NOT_CHECKED | `src.cve_lab evaluate --archive <本地 run 目录>` 返回完整性 `VERIFIED`，同时保留各自执行状态 |
| Git diff、敏感信息、远端同步 | PASS：15 个本轮工程文件通过 diff/凭证模式检查；推送成功 | 不适用 | 提交前 `HEAD` 与 `origin/main` 均为基线 `81443b0f8f013003ab26fe538aa1dc5bac74cd85`；实现提交 `0e045fe` 已正常推送 |

实现提交为 `0e045fe`（`feat: add fixed staged fixture execution contract`），正常推送 `origin/main` 成功。提交范围为本轮 15 个工程文件；两份既有未跟踪历史草稿 `docs/P3_D_EXECUTION.md`、`docs/P3_D_REAL_VALIDATION.md` 和私有原始证据均未纳入提交。

## 5. 仍未实施或未获授权的工作

- 通用 LLM 候选传输和执行：`UNSUPPORTED`。固定无害 fixture 的动作与授权不能迁移到未知候选。自动安全审查已拒绝通用真实 PoC 候选传输子任务；本轮不重试该入口。
- 良性 cubin → 目标 cuobjdump → Memcheck 自动诊断：`BLOCKED / NOT_CHECKED`。自动安全审查拒绝该子任务，本轮没有可归属的新 XML 或目标进程结果。
- 真实付费模型调用：`NOT_EXECUTED`；须单独确认模型、范围、调用次数和费用。
- 真实 CVE 触发输入及生成候选执行：`NOT_EXECUTED`；须提交具体字节身份、目标、风险和隔离方案，取得新的明确授权。
- GPU kernel 和真实漏洞 Oracle `VERIFIED`：`NOT_CHECKED` / `NOT_VERIFIED`；安全 smoke 或普通 Memcheck 结果不能替代专项根因证据。

验收 A、B、C 逐项依据实测填写；若缺少任何实际证据，不把代码存在或离线测试通过写成真实联调成功。
