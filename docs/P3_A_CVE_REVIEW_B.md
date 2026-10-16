# P3-A 公开资料审查 B：三个 CUDA 工具 CVE

审查日期：2026-10-16。仅进行输入与公开资料比对，没有运行漏洞、畸形解析输入或模型请求。此文的公开研究结论不是本机实测证据；原始七维 JSON 保持不变。

| CVE | 可追溯组件与类型 | 厂商受影响发布范围 / 修复发布 | 当前 WSL Toolkit 12.8 初步资格 |
| --- | --- | --- | --- |
| CVE-2024-0124 | nvdisasm，CWE-416，读取已释放内存 | Toolkit 至 12.6U1（含）；12.6U2 修复 | INELIGIBLE：12.8 不在该发布范围内。不得将未复现解释成 CVE 失败。 |
| CVE-2025-23308 | nvdisasm，CWE-122，堆内存越界写 | Toolkit <13.0；13.0 修复 | UNKNOWN：厂商发布范围匹配；本机 build 的具体根因、触发前提和 WSL 适用细节尚未独立确认。 |
| CVE-2025-23339 | cuobjdump，CWE-121，栈缓冲区溢出 | Toolkit <13.0；13.0 修复 | UNKNOWN：厂商发布范围匹配；本机 build 的具体根因、触发前提和 WSL 适用细节尚未独立确认。 |

受影响发布、组件与 CWE 分别见 [NVIDIA 5577](https://nvidia.custhelp.com/app/answers/detail/a_id/5577) 和 [NVIDIA 5661](https://nvidia.custhelp.com/app/answers/detail/a_id/5661)。表中资格是保守审查结论，不授予执行权限，不等同于 Oracle 已验证任何触发条件。CUDA Toolkit、单个工具 build 和 GPU 驱动版本属于不同版本空间；不能用 `nvidia-smi` 的 CUDA 能力版本或 nvcc build 替换目标解析工具的身份。

## CVE-2024-0124

厂商描述的入口是 nvdisasm 读取异常 ELF；预期客观现象须绑定读取已释放内存及对应解析路径，而不是任意退出非零或 crash。[CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/0xxx/CVE-2024-0124.json) 与公告一致。公告中的 `nvdisam` 是原始拼写；组件名称依据同一句中出现的 nvdisasm 归一化，并保留来源原文位置。

原输入 `3_affected_component.json` 和 `7_root_cause.json` 的大类及版本范围有公告支持。`7_root_cause.json#/root_cause/technical_details` 对重复 section、sh_link/sh_info、调试信息的具体解释，没有在本次取得的厂商/CNA 资料中找到对应公开验证；`fix_description` 中的置空指针推测也不能升级为修复事实。原输入的旧 Windows 11.2 环境仅是输入声明，不能代表当前 WSL 测量。

修复发布名 `12.6U2` 与归档 `12.6.2` 的对应关系可由 [CUDA 12.6 Update 2 发行说明](https://docs.nvidia.com/cuda/archive/12.6.2/cuda-toolkit-release-notes/index.html) 核对。该说明同时指出组件独立版本化，因此不能将 12.6.2 当作 nvdisasm 二进制 build 号。精确符号、失效对象生命周期与修复代码仍 UNKNOWN。

## CVE-2025-23308

[Talos TALOS-2025-2204](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2204) 报告 REL 节解析中的堆越界写，列出的确认版本为 nvdisasm 12.9.88；其公开技术观察不能作为当前机器执行记录。公告覆盖的产品发布范围比这一确认 build 更宽，二者不能互相替代。[CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/23xxx/CVE-2025-23308.json) 也记录 Toolkit <13.0。

原输入 `2_cuda_environment.json#/cuda_toolkit_version` 和 `3_affected_component.json#/version_range` 将组件 build `12.9.88` 写成整个 Toolkit 的通用上限，不应直接用作机器版本范围。原输入详细根因与 Talos 的研究主题相符，但地址、偏移及条件属于该报告所分析 build 的上下文；没有本机根因绑定与原始工具证据，不能自动套用到 12.8.90 或旧 Windows 11.2。`7_root_cause.json#/root_cause/patch_analysis` 对补丁实现使用推测措辞，不是公开修复差分。

[Talos 汇总文章](https://blog.talosintelligence.com/nvidia-and-adobe-vulnerabilities/) 写 nvdisasm 12.8.90，主报告写 12.9.88。保留来源与不同 build，不擅自合并为唯一实测版本；两个版本也可能同时受影响，不能仅据数字差异认定来源互斥。Talos 的 CVSS 是 7.8，厂商/CNA 是 3.3；原输入的 7.8 有公开技术来源支持，不能覆盖厂商评分。评分不参与验证 Oracle。

## CVE-2025-23339

[Talos TALOS-2025-2155](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2155) 报告 cuobjdump 的 DWARF 调试缩写解析缺少写入边界约束，确认版本为 cuobjdump 12.8.55，入口涉及含调试信息的 CUDA 文件。其研究展示的异常仍属于第三方公开资料，不是本工程的本机实测。[CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/23xxx/CVE-2025-23339.json) 与厂商发布范围一致。

原输入在 `3_affected_component.json` 与 `7_root_cause.json` 中包含 Talos 分析的详细 build 上下文，应标为公开技术分析的转述，不能宣称本机 12.8.90 已得到同样观察。`fixed_code_summary`、`fix_mechanism` 声称具体补丁方式，但本次取得的资料未提供可供独立校验的修复前后代码；该项 UNKNOWN。原输入对最早引入版本的描述没有取得公开证明，仍 UNKNOWN。原输入 CVSS 7.8 来自 Talos，而厂商/CNA 给 3.3，必须分别保留。

## 取得状态和字节身份

以上所有页面均由浏览器实际取得正文；三份 CNA JSON 另经只读 HTTPS 下载得到原始字节。哈希只是本次内容身份，不能替代来源认证或证明其中所有断言为真。公开来源快照保存在忽略的 `tmp/p3_source_review_b/`，不提交整篇公告、私有运行日志或任何凭证。版本化的机器审查摘要位于 [cve_review_b.json](examples/p3_a/cve_review_b.json)。

| CNA 记录 | 字节数 | SHA-256 |
| --- | ---: | --- |
| CVE-2024-0124 | 5714 | `0e4742db914df8761951a53f8de6fa027d622ed7047df4f4a648d74abdbf52c4` |
| CVE-2025-23308 | 6411 | `bc1e3dd76da98a3b4c66de6976219ba68b9aa4747c1f3d7940d2f4529e099b6e` |
| CVE-2025-23339 | 6426 | `9011f4af57c107a502ce912d143d12a407d7c940ce9998f937169e2100297f9f` |

浏览器访问 `https://cveawg.mitre.org/api/cve/<CVE-ID>` 三次均不可达，因此未宣称该 API 检查通过；官方 CVEProject `cvelistV5` 的 NVIDIA CNA 容器是本次成功取得的替代来源。公告、Talos 和发行说明没有测量原始响应字节，因此其机器摘要 `content_sha256` 为 null。没有实施真实受影响/修复版本差分；当前三个案例的真实漏洞验证均为 NOT_VERIFIED。
