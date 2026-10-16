# CUDA 主机侧解析漏洞的专项证据可行性

审查日期：2026-10-16。阶段：P3-B。报告语言：zh-CN。结论：两个目标的真实验证均为 **NOT_VERIFIED**；后续真实实验准备资格为 **UNSUPPORTED**。本文没有执行 CVE 输入、生成候选或 GPU kernel；公开技术观察与本机只读版本查询分别标注。

## 来源、版本与事实边界

[NVIDIA 公告 5661](https://nvidia.custhelp.com/app/answers/detail/a_id/5661) 将两例列为 Windows/Linux CUDA Toolkit 13.0 之前的发布受影响，更新发布为 13.0；CNA 分别记录 [CVE-2025-23308](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/23xxx/CVE-2025-23308.json) 与 [CVE-2025-23339](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/23xxx/CVE-2025-23339.json)。这是 **DOCUMENTED 的产品发布范围**，不能说明任一 12.8 工具 build 已在本机触发，也不能把 Toolkit、nvcc、驱动、nvdisasm 和 cuobjdump 的版本号互换。

Talos 主报告 [2204](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2204) 记录 nvdisasm 12.9.88 的 REL 路径与堆越界写，使用 ELF32 结构说明该路径，并展示第三方 Valgrind 内存写诊断。报告 [2155](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2155) 记录 cuobjdump 12.8.55 的 DWARF `.debug_abbrev` 解析问题，描述 fatbin 内 cubin 的调试信息及 `--dump-elf` 路径，展示含 64bit ELF 的上下文和 GDB 终止观察。这些是 **DOCUMENTED 的第三方观察**，没有本工程 request/run、原始输入哈希和工具哈希绑定。P3-A 另记 Talos 汇总文章曾列 nvdisasm 12.8.90；本阶段不以汇总文章替代主报告的确认版本，也不声称两个 build 等价。

## CVE Evidence Feasibility Matrix

| 审查项目 | CVE-2025-23308 | CVE-2025-23339 |
| --- | --- | --- |
| 组件与公开分类 | nvdisasm；CWE-122；主机侧堆缓冲区越界写，DOCUMENTED | cuobjdump；CWE-121；主机侧栈缓冲区越界写，DOCUMENTED |
| 厂商受影响发布 / 更新发布 | CUDA Toolkit <13.0 / 13.0；不是逐个工具 build 的实测列表 | CUDA Toolkit <13.0 / 13.0；不是逐个工具 build 的实测列表 |
| 主技术报告确认 build | nvdisasm 12.9.88；该 build 的来源、完整二进制哈希本机尚未确认 | cuobjdump 12.8.55；该 build 的来源、完整二进制哈希本机尚未确认 |
| 本轮 OBSERVED build | 活跃 Linux nvdisasm 12.8.90；仅 `--version` | 活跃 Linux cuobjdump 12.8.90；仅 `--version` |
| 本轮 OBSERVED 工具 SHA-256 | `250ebe97dd86617574a30daf8d8ee433e6c5d9d10bafff922078779d1ba36073` | `9d515ac6f60c246ef63fe87b0a95d209b00ff3e25b716f8f263520010760e8f8` |
| 输入格式与入口差异 | 公开研究涉及 ELF32 的 REL 解析；必须单独确认目标输入 ELF class、endianness、REL 类型及实际入口覆盖；不得套用 P2-C ELF64 profile | 公开研究涉及 fatbin 容器、其中的 cubin 与 DWARF abbreviation 数据；需要分别绑定容器及内含对象，不能将单个 ELF64 cubin 当作所有 fatbin 的代表 |
| 可公开支持的异常观察 | 第三方记录 invalid write、访问大小、调用栈和分配边界；不能将其地址直接套用到当前 build | 第三方反汇编分析与 GDB 终止观察相结合；单独 SIGSEGV 不能证明栈越界写或指定根因 |
| 必要但 UNKNOWN 的根因信息 | 当前 build 对应解析函数/模块偏移、实际 REL 处理路径、错误写与分配对象的关联、修复映射 | 当前 build 对应 DWARF 解码与写入位置、栈对象边界、同一解析根因的符号/模块偏移映射、修复映射 |
| CPU 侧诊断工具 | Memcheck XML 可承载无效访问与调用栈；栈/堆归属须有明确边界上下文，不能凭工具名推断 | GDB 可提供进程、信号和栈观察；Memcheck 未必能识别栈内对象边界；需要独立、适用的诊断方法 |
| 客观证据支持上限 | 合格、绑定完整的诊断最多支持对应访问异常条件；没有根因绑定只能支持局部观察 | 合格、绑定完整的诊断最多支持对应异常/控制流观察；没有栈边界及根因证据不能提升为完整 CVE 证明 |
| 受影响 / 修复版本对照要求 | 可信来源的精确受影响二进制及 13.0 修复二进制；独立哈希、固定同一输入、等价诊断与资源条件；必须排除不同解析路径或诊断覆盖造成差异 | 同左，并确认 fatbin/cubin/DWARF 入口在两版都被实际解析；“旧版 crash、新版不 crash”不足以证明同一根因已修复 |
| 当前平台适用资格 | 保留 P3-A UNKNOWN；发布系列匹配不等于当前 build、输入路径和根因均已确认 | 保留 P3-A UNKNOWN；12.8.55 的第三方观察不等于本机 12.8.90 的实验结果 |
| 实验安全与准备资格 | UNSUPPORTED：本阶段只读桥接，不具备真实漏洞所需隔离；没有受影响/修复对照、输入审核及完整专项 Oracle | UNSUPPORTED：同左；宿主解析器风险不因“不运行 GPU kernel”自动消失 |

## 格式范围不能合并

[NVIDIA Binary Utilities 文档](https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html) 区分 cubin、fatbin，以及 cuobjdump/nvdisasm 的输入能力。cubin 是包含面向特定 CUDA 架构代码的 ELF 对象；fatbin 是可包含多个对象或 PTX 的容器。**ELF32/ELF64 是对象布局类别，不是容器名称；REL/RELA 是重定位数据类别，不等于 DWARF 调试数据。** 实际采集必须保存每一层的文件字节和 SHA-256，并记录所验证的 class、endianness、section 或容器成员；未知项仍为 UNKNOWN。

P2-C 的固定无害 `safe_smoke.cu` 仅产生已观察的 ELF64 CUDA profile。历史编译、cuobjdump 和 nvdisasm 正常退出是 TOOLCHAIN_SMOKE，不能提供本表目标的 ELF32 REL 入口或 fatbin/DWARF 根因证据。不得为扩大支持范围而修改该冻结 profile 或执行畸形文件。

## 诊断工具能力与可实施范围

[Valgrind Memcheck 文档](https://valgrind.org/docs/manual/mc-manual.html) 和[核心输出文档](https://valgrind.org/docs/manual/manual-core.html) 描述无效访问及 XML 输出。XML 是可定位的记录格式，不是 CVE Oracle。必须核对 collector、XML 协议、目标进程、工具身份、run 和完整性；只有可用上下文才能建立访问方向、大小或分配对象归属。部分栈、未知符号、丢失分配边界不能补写为根因。

[Clang ASan 文档](https://clang.llvm.org/docs/AddressSanitizer.html) 要求编译插桩和运行库；不能因为机器有 Clang 或 ASan 库，就宣称闭源 NVIDIA 工具已受到 ASan 保护。UBSan 同样需要适用构建与对应诊断合同。本轮未取得目标源码或经认证的插桩工具，ASan/UBSan 对两工具的适用性为 **UNKNOWN/NOT_CHECKED**，没有尝试 LD_PRELOAD 等猜测性注入。

GDB 的版本查询不证明可 ptrace 目标、可展开栈或已有符号。Compute Sanitizer 的 GPU 相关诊断不能代替本表主机侧内存解析根因。安装诊断工具不等于已验证适用；本阶段没有安装软件、修改 ptrace/cgroup/网络设置或申请额外权限。

## A～F 初步客观证据要求

| 条件组 | 必须具备的对象与观测 | 当前支持与阻断 |
| --- | --- | --- |
| A 精确版本和身份 | 工具可信来源、完整字节 SHA-256、精确 build、平台快照、request/run；区分 DOCUMENTED 范围和 OBSERVED 身份 | 当前仅版本查询和本机工具身份 OBSERVED；精确受影响根因与修复工具来源 UNKNOWN |
| B 输入身份及格式 | 原始输入 SHA-256；容器和成员绑定；目标专项 ELF class/调试或重定位类型 | 本阶段没有目标漏洞输入；UNKNOWN；不借用无害 smoke 身份 |
| C 执行入口 | 真实生命周期、argv、目标进程身份及诊断目标绑定；目标解析路径的合格覆盖证据 | 未执行目标；NOT_EXECUTED；仅 `--version` 不满足 |
| D 内存异常类型 | 合格原始诊断中确定性节点/字段，绑定方向、大小、地址和栈中真实存在的信息 | 仅 Synthetic 测试解析；没有实际宿主诊断；UNKNOWN |
| E 机制关联 | 精确 build 下的模块偏移/函数、输入结构与错误对象的对应关系 | 两例均缺生产专项检测器；UNIMPLEMENTED/UNKNOWN；不能由一次 memory error 自动满足 |
| F 根因或修复差分 | 预先审查的方法、同一输入/入口/诊断覆盖、可信受影响与修复二进制，以及充分独立根因证据 | 尚未建立；UNIMPLEMENTED/UNKNOWN；真实 VERIFIED 继续禁用 |

这些组是必要条件的组织方式，不授予执行权限，也不降低 P3-A 必要条件。公开异常类型可帮助提出证据请求，不能生成客观实测 EvidenceReference。

## Windows→WSL 本轮只读联调

命令在 Windows Python 3.12 发起：

```powershell
.\.venv\Scripts\python.exe -m src.host_diagnostics_probe --backend wsl
.\.venv\Scripts\python.exe -m src.host_diagnostics_probe --rebuild data/outputs/diagnostic_probes/c00c0fa1bf3a4263bca2362da4318c28
```

首条命令只运行固定注册表中的四项 `--version`。请求没有 argv、输入文件或脚本字段；目标必须与选定 WSL distribution 标签及实际内核观察一致。真实记录保存在忽略的通用目录，不伪装为 CVE 实验：

`data/outputs/diagnostic_probes/c00c0fa1bf3a4263bca2362da4318c28/`

| 实际检查 | 状态 | 观测与边界 |
| --- | --- | --- |
| Windows→WSL 固定 worker 通信及 nonce/source/目标校验 | PASS | 得到经过结构校验的当前目标响应；不作为 PlatformSnapshot 替代身份 |
| cuobjdump / nvdisasm 版本查询与身份前后测量 | PASS | 两者 12.8.90，NORMAL_EXIT；只证明版本查询和测得字节身份 |
| Valgrind / GDB 发现 | UNKNOWN | 固定 `/usr/bin` 位置未发现可测量可执行文件；没有遍历任意 PATH，不能宣称整台系统不存在其他副本 |
| 原始字节保存、SHA-256、离线重新读取和中文逐字节重建 | PASS | 保存 launcher 与工具 stdout/stderr；读取器重解析原始 worker packet 并核对结果 |
| 诊断效果、ptrace、栈边界检测与目标符号 | NOT_CHECKED | 没有运行任何诊断目标 |
| 真实 CVE 隔离与实验准备 | UNSUPPORTED | 当前只读协议不提供不可信程序沙箱、完整网络隔离或 GPU/驱动隔离 |

记录内容 SHA-256：`aefc5e453d1286256ab8661862b3e7c192754d7d5ff8e20cd3dbc03c07a921f4`。

原始 worker packet SHA-256：`207936796e851c4c65419409da461b876cf38e1e8245c018f61ac79c958e189c`。

中文报告 SHA-256：`8b676be93ceb13e464b741b2a8524db1a5f457c7f6aa70f835bffc7223e468f6`。

清单文件 SHA-256：`79ed281b31c4d4184aba5d004eb0efb7a95911ba767b43cc961e6f9da2bb19b4`。

一次较早只读版本查询产生的独立目录 `2b14d0b1f69e404ba21bda8b5896b53d` 在交付前的中文报告重建校验中失败，原因是字典遍历顺序；记录保留，未覆盖。修复为排序渲染后，上述新编号完整重跑与校验通过。该失败不改变工具原始输出，也没有被算作成功归档。

本轮专项测试：Windows **33 PASS / 0 SKIP / 0 FAILED**；WSL **32 PASS / 1 SKIP / 0 FAILED**，SKIP 为仅 Windows 的缺失 launcher 分支；全量回归以 [P3_B_VALIDATION.md](P3_B_VALIDATION.md) 最终记录为准。没有实际 Valgrind/ASan/GDB 内存诊断 smoke，也没有 CUDA 编译或真实 CVE 实验。

## 首次真实实验的阻断条件与准备清单

当前每项阻断都必须由后续独立审查消除，不能以 LLM 声明、文档描述或版本查询代替。

1. 操作者批准明确目标、精确工具身份、固定已审核输入、诊断方法和允许动作；通用 EXECUTE_CANDIDATE 继续不开放。
2. 准备独立可丢弃的受限环境，核验网络、文件、凭证、权限、进程回收及资源限制。当前 WSL 只读桥接不满足真实漏洞隔离。
3. 获取可信受影响构建与修复构建，分别记录来源、完整哈希、依赖和精确版本，不将整个 12.8 系列当作公开受测 build。
4. 在独立审核后准备格式明确、来源可追溯的目标输入；绑定容器、成员、class 与专项入口；本阶段不产生或运行漏洞输入。
5. 确认实际 CPU 诊断工具可用，并先通过固定无害、受限诊断实验验证其适用性、输出协议、截断检测和回收；安装仍需独立授权。
6. 制定经审查的 E/F 根因与差分方法，明确每条必要条件如何由客观字段证明，以及哪些情况必须 UNKNOWN/CONFLICT。
7. 完成执行端原始证据采集、平台/工具/输入/run 绑定和跨环境离线独立核验；报告不能更改 Oracle 结果。
8. 只有完整 CVE 专项标准通过后续审查，才可讨论解除生产 VERIFIED 禁令。本阶段始终 NOT_VERIFIED。

## 公开来源原始响应字节身份

浏览器取得上述一手页面；另用只读 HTTPS 取得原始响应字节，保存在忽略的 `tmp/p3b-source-review/`。整篇版权网页和私有日志不提交。下列 SHA-256 只标识本次取得的响应，不替代来源认证或证明断言正确。CNA-23339 首次字节下载遇到 URLError，单次重试成功；初次失败与成功记录分别保留。

| 来源 | 取得日期 | 字节数 | SHA-256 |
| --- | --- | ---: | --- |
| NVIDIA 5661 | 2026-10-16 | 39632 | `78e565ea983df98cda155b093299ec871943e877751621728aec377e09168b05` |
| Talos 2204 | 2026-10-16 | 85294 | `2f7a6c07462a0a62e649e9c64a979dd64678dfaf39019137ff03f3e5761aea07` |
| Talos 2155 | 2026-10-16 | 85680 | `bfef7aad2beb0fd24e0c0960605edb37262165d4150e34654a3503d2a27bce5e` |
| NVIDIA CNA CVE-2025-23308 | 2026-10-16 | 6411 | `bc1e3dd76da98a3b4c66de6976219ba68b9aa4747c1f3d7940d2f4529e099b6e` |
| NVIDIA CNA CVE-2025-23339 | 2026-10-16 | 6426 | `9011f4af57c107a502ce912d143d12a407d7c940ce9998f937169e2100297f9f` |
