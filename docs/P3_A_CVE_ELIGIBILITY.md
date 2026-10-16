# 六个 CVE 的验证资格初步审查

资料检索日期：2026-10-16。范围只包括已有六套输入和 P2-C 历史证据绑定的 12.8 系列 host-side utilities，不代表当前所有安装副本。未执行任何 CVE。来源分类、逐字段差异及检索失败见 [审查 A](P3_A_CVE_REVIEW_A.md)、[审查 B](P3_A_CVE_REVIEW_B.md)。

| CVE | 组件 / 资料根因 | 厂商受影响 Toolkit / 更新版本 | 对已绑定 12.8 目标的资格 | 必要未知项 |
| --- | --- | --- | --- | --- |
| CVE-2022-21821 | cuobjdump；整数溢出；输入 CWE-190 与 CNA CWE-1285 分类冲突 | <11.6 Update 2 / 11.6 Update 2 | INELIGIBLE | 精确输入、函数、分配/写入链与补丁均未客观确认 |
| CVE-2023-0196 | cuobjdump；NULL 解引用 / CWE-476 | <12.1 / 12.1 | INELIGIBLE | 精确畸形字段、指针来源、补丁与根因方法未知 |
| CVE-2024-0076 | cuobjdump / nvdisasm；越界读 / CWE-125 | 公告列 <12.4；updated 列 12.4U1 | INELIGIBLE | 12.4/12.4U1 边界不擅自消解；输入所述信息泄露无已审查主源支持 |
| CVE-2024-0124 | nvdisasm；释放后读取 / CWE-416 | ≤12.6U1 / 12.6U2 | INELIGIBLE | 对象生命周期、重复 section/patch 推测没有实测依据 |
| CVE-2025-23308 | nvdisasm；heap overflow / CWE-122；公开分析关联 REL 处理 | <13.0 / 13.0 | UNKNOWN | 厂商发布范围匹配；当前 WSL 路径、输入、根因未确认；Talos 主文测 12.9.88，汇总另提 12.8.90 |
| CVE-2025-23339 | cuobjdump；stack overflow / CWE-121；公开分析关联 DWARF abbreviation | <13.0 / 13.0 | UNKNOWN | 厂商发布范围匹配；Talos 实测 12.8.55，不等于当前 12.8.90 的本机实测；WSL 与补丁方法未知 |

来源：[NVIDIA 5334](https://nvidia.custhelp.com/app/answers/detail/a_id/5334)、[5446](https://nvidia.custhelp.com/app/answers/detail/a_id/5446)、[5517](https://nvidia.custhelp.com/app/answers/detail/a_id/5517)、[5577](https://nvidia.custhelp.com/app/answers/detail/a_id/5577)、[5661](https://nvidia.custhelp.com/app/answers/detail/a_id/5661)；2025 技术资料：[Talos 2204](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2204)、[Talos 2155](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2155)。官方 CNA 原始 JSON URL、测得 SHA 或明确 null 见 [机器审查 A](examples/p3_a/cve_review_a.json)、[机器审查 B](examples/p3_a/cve_review_b.json)。

这里的 INELIGIBLE 是源资料与已绑定发布系列的排除结论，不是复现失败。UNKNOWN 不能改写为未受影响、已修复或已验证，也不授权实验。四个旧 CVE 的 exact Update/build 方法仍是 UNKNOWN；必要排除条件足以排除当前 12.8，并不能证明任意旧版本有资格。

历史观测：Toolkit release 12.8、nvcc 12.8.93、cuobjdump/nvdisasm 12.8.90。driver release 是 WSL 宿主驱动观测，不替代 Toolkit/build。六个案例主要是 host binary parser 工具，不从 GTX 1660/CC7.5 推导 parser 漏洞存在或不存在。

原 42 JSON 原样保留。CWE、CVSS、公开受测 build、旧 Windows 环境和修复假设都有各自来源；厂商与 Talos 评分并列不合并。未收集本机漏洞触发、根因、修复前后差分证据；六例真实 CVE 状态全部 **NOT_VERIFIED**。
