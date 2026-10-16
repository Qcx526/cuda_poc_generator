# P3-C 真实无害主机诊断准备与离线证据接口

日期：2026-10-16；报告语言：zh-CN。基线：`8d33ae4c16285d15c7486ce2cfda2f9658f022a4`。

**真实 Memcheck 实验：NOT_CHECKED，待独立授权。** 本阶段没有安装工具、变更
WSL 设置、申请权限、编译或执行新增 CPU 测试程序，也没有运行 CVE、生成候选
或 GPU kernel。下面的只读版本查询、Synthetic 解析和实验准备分别记录。

## 本机只读能力观察

Windows Python 发起 P3-B 原有固定 WSL worker，只查询注册工具 `--version`：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostics_probe --backend wsl
```

本轮通用目录：`data/outputs/diagnostic_probes/b220f1fb9edd4556ad937e92972af07b/`。
原始 packet、stdout/stderr、实际工具身份和中文报告保存在此目录，不放进任何 CVE
实验。结构化记录内容 SHA-256：
`7d3cad3358f429bb960b3a45149e73dcfa9eb159cede1796a19b65f91e59ca43`。

| 项目 | 实际状态 | 含义 |
|---|---|---|
| Windows→WSL 只读通信 | PASS | 复用固定 worker、nonce/source/目标身份及原始包校验 |
| Valgrind / GDB | UNKNOWN | 固定 `/usr/bin` 位置没有可测量工具；没有遍历所有位置，也不宣称全系统未安装 |
| cuobjdump / nvdisasm | OBSERVED，12.8.90 | 仅版本查询；没有编译、解析诊断目标或 GPU 执行 |
| Memcheck XML v4 与诊断效果 | NOT_CHECKED | 没有实际诊断进程或原始 XML |
| 无害异常 fixture 隔离与资源适配 | NOT_CHECKED / UNSUPPORTED | 尚未验证 Memcheck 资源配置和专项回收协议 |
| 真实 CVE 实验 | UNSUPPORTED | 当前能力不提供真实漏洞隔离或专项根因判定 |

能力档案可用原 `host_diagnostics_probe --rebuild <目录>` 只读复核。版本查询不证明
安装适用性或诊断效果。旧 P2/P3 证据没有修改。

## 固定任务注册表

`src.host_diagnostic_tasks.DIAGNOSTIC_TASKS` 是只读映射，元素为冻结 dataclass。
不接受 shell、自由 argv、任意源码、二进制或 LLM 授权字段。源文件必须与下面的
固定 SHA-256 匹配；`.gitattributes` 保证 C fixture 使用 LF，跨环境不改身份。

| task_id | 源文件 | 设计用途（不是实测结果） | SHA-256 |
|---|---|---|---|
| p3c-normal-v1 | normal.c | 正常分配、访问和释放 | 430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107 |
| p3c-invalid-read-v1 | invalid_read.c | 单字节受控越界读的诊断准备 | ee94debc4196dfdca03988288ebfc62e58bc7f4aaaa14977d8644bc5ed745d1c |
| p3c-invalid-write-v1 | invalid_write.c | 单字节受控越界写的诊断准备 | d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c |
| p3c-freed-read-v1 | freed_read.c | 已释放对象读的诊断准备 | 7dd07a5103c6308e83e01728a1f0c15bed903ba58dc1490a4c29cc8380e57e05 |

路径为 `tests/fixtures/host_diagnostics/`。程序不访问网络、用户文件、CUDA 或子进程，
但异常程序存在刻意的 C 未定义行为，因此没有授权、限制和隔离时仍不得执行。
源码意图不能被当作已发生的诊断；编译器优化也可能改变观测，后续必须实测。

拟议构建固定为已测量系统 C 编译器、`-std=c11 -g -O0 -Wall -Wextra`、注册源码与
独立输出目录；本阶段不实施该构建。诊断的固定形状是 Valgrind、`--tool=memcheck`、
`--xml=yes`、`--xml-file=<本轮文件>`、无参数固定目标；没有任意 argv 入口。
后续必须另行审核编译器/目标二进制身份、依赖、文件访问和进程回收。

## 只准备、不启动的前置接口

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks prepare --probe-dir data/outputs/diagnostic_probes/b220f1fb9edd4556ad937e92972af07b --probe-sha256 7d3cad3358f429bb960b3a45149e73dcfa9eb159cede1796a19b65f91e59ca43 --task p3c-normal-v1
```

返回 `REJECTED`，CLI 退出 2；这是预期的阻断，不是实验失败或测试失败。保存新的
`data/outputs/host_diagnostic_preparations/<run_id>/preparation.json` 与中文报告，
没有 XML、进程 PID、退出码或占位运行日志。每次独立 request/run，不覆盖历史。

`DiagnosticPreparation` 复用 `ExecutionResourceLimits` 的严格资源字段，但它只
表达待审核的 wall-clock/CPU/地址空间/输出要求，**并未实施**。既有 P2 的
Preflight、OperatorAuthorization、ExecutionRecord 和执行注册表保持冻结，
没有冒用旧 Python/CUDA fixture 授权去运行 Memcheck。

当前阻断包括：缺少操作者授权、隔离未确认、Memcheck 资源适配未验证、P2 专项
动作未注册，以及工具身份未知或版本失败。即使 Mock 工具显示已安装，准备仍
`REJECTED`，不会因一个 `--version` 成功绕过其他条件。

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks rebuild --directory <准备目录> --expected-sha256 <preparation.json原始字节SHA>
```

该命令离线核对独立摘要、run 目录和中文文本，不再次探测或执行。

## 无 CVE 的原始证据合同与解析

P3-B `HostParserCollection` 固定绑定两个真实 CVE 与 NVIDIA 组件，不能伪造其中一个
目标来容纳普通 CPU 测试。新增 `HarmlessDiagnosticCollection` 作为无 CVE 适配层，
复用 P3-B 的同一 XML v4 核心、`HostRawArtifact`、精确 XML 节点及内存观察模型；
不改旧模型、解析规则或 Oracle。

必需字段包括 collection/request/run、固定 task/source SHA、声明的构建记录 SHA、
目标和 Valgrind 文件身份、版本记录 SHA、平台/probe/snapshot SHA、`ToolResult`、
PID、原始 XML/stdout/stderr 身份、完整性和回收状态。实际 Linux argv 必须采用
绝对 POSIX 路径，拒绝 Windows drive、NUL、遍历及额外参数。

只支持两个数据域：

- `SYNTHETIC` / `p3c-synthetic-xml4/1.0`：纯合成格式与规则测试。
- `UNVERIFIED_IMPORT` / `p3c-unverified-import-xml4/1.0`：只读导入字节，未认证采集来源。

两者 `cve_id=null`、`execution_authorized=false`、`authenticated_real_capture=false`。
不接受 `REAL_CAPTURE`、真实 CVE 目标或授权为 true 的导入声明。**仅靠 XML 字节
无法认证它由真实进程产生**；需要可信执行端采集器和已审核生命周期绑定，当前
尚未实现，不能通过修改标签伪装完成真实闭环。

```python
parse_harmless_diagnostic(collection, diagnostic_bytes=xml,
    stdout_bytes=stdout, stderr_bytes=stderr,
    expected_collection_sha256=operator_pinned_collection_sha256)
reassess_harmless_diagnostic(evidence,
    expected_collection_sha256=operator_pinned_collection_sha256)
```

格式/版本、PID、argv、三个流的 SHA、采集完整性或回收不满足时拒绝解析或返回
`REJECTED`。支持的观察仍仅为无效读/写等结构化类别；栈/堆、UAF 生命周期、访问
大小、故障地址及 CVE 根因保持 UNKNOWN。普通 exit 0、非零和 SIGSEGV 不变成
漏洞证据。未知 XML 协议严格拒绝；不能改写原始日志以适配解析器。

Valgrind 官方说明 XML 输出使用明确选项，并提示 Memcheck 对部分栈/静态边界的
覆盖局限，见[核心输出手册](https://valgrind.org/docs/manual/manual-core.html)、
[Memcheck 手册](https://valgrind.org/docs/manual/mc-manual.html)。这里不宣称当前
发行版一定输出协议 4；真实协议及平台效果为 NOT_CHECKED。

## 独立归档、中文报告和复核

`save_harmless_evidence()` 只创建独立通用档案：

```text
data/outputs/host_diagnostic_evidence/<run_id>/
  collection.json
  parsed.json
  raw/<原始XML、stdout、stderr文件>
  report.zh-CN.md
  manifest.json
```

也可把 Synthetic 示例显式放入通用 `synthetic_diagnostics/`，但禁止保存或从 CVE
祖先目录读取这类档案。读取拒绝路径遍历、链接、特殊文件、Windows 保留名称、
大小写别名、清单外文件及跨 run 替换；写入异常不宣称成功。报告 UTF-8、中文，
动态字段转义，原始三流字节不翻译、不改写。正文展示来源域、平台/工具/输入身份、
进程状态、解析/回收、原文件 SHA、XML 节点、缺失条件及不能证明 CVE 的原因。

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks reparse --collection <无CVE采集JSON> --collection-sha256 <独立规范摘要> --xml <原始XML> --stdout <原始stdout> --stderr <原始stderr>
.\.venv\Scripts\python.exe -m src.host_diagnostic_tasks verify --directory <通用档案目录> --manifest-sha256 <包外清单原始字节SHA>
```

`verify` 固定外部清单摘要、核对六个文件，再用磁盘中的原始三流独立重新解析，
比较解析对象与中文文本。`render_harmless_report()` 则只是同一对象内部重建；
不能把自带摘要的渲染叫作独立来源认证。两者均不启动程序。

## 后续真实实验的准入清单

1. 明确批准固定任务、工具/构建身份、诊断方法、目标环境和资源策略；安装工具
   与执行异常程序需分别获准，当前用户任务不是自动安装/执行许可。
2. 核验隔离、目录/网络/凭证访问、权限及进程回收；不把 WSL 本身当作完整沙箱。
3. 取得可测量工具，核对实际 XML 协议、CPU 诊断适配、地址空间需求及输出上限，
   不能降低原约束来制造成功；RLIMIT_AS 不是 GPU VRAM 限额。
4. 增量接入 P2 严格动作、Preflight、授权、worker/launcher 生命周期和独立回收；
   启动后观察真实 PID/时间、工具及构建字节身份，保存真实原始三流。
5. 经可信采集路径产生新的认证数据域，再独立重新解析；先以正常 fixture 确认
   方法，再在获准隔离范围内实施受控异常。当前没有该域，不能通过导入字段替代。

任何一步未知都阻断。即使未来无害诊断成功，仍不绑定真实 CVE，也不提供根因
Oracle 或真实 VERIFIED。双环境实际结果见 [P3-C 验收](P3_C_VALIDATION.md)。
