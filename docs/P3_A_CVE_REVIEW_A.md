# P3-A 公开来源初审：2022-21821、2023-0196、2024-0076

审查日期：2026-10-16。范围：只读比对各案例的七个原始输入 JSON、NVIDIA 公告及 NVIDIA CNA 的 CVE 记录；未运行样本、未验证根因、未检查补丁二进制。原始输入保持不变。

本文中的“来源支持”只表示资料支持该陈述，不表示当前环境已触发漏洞。公开资料未提供的字段、偏移、调用栈和触发字节一律保持 UNKNOWN。现有输入中“确定性触发”“无需堆整理”等断言没有通过本次资料审查获得支持。

## 初步资格表

| CVE | 公告支持的组件、入口和漏洞类型 | 公告受影响范围 / 公告更新版本 | 当前 P2-C 绑定的 12.8 工具的初步资格 | 仍未知的必要条件 |
| --- | --- | --- | --- | --- |
| CVE-2022-21821 | Toolkit 中独立 `cuobjdump`；本地用户对攻击者提供的损坏文件运行工具；整数溢出 | Windows、Linux，早于 Toolkit 11.6 Update 2 / 11.6 Update 2 | INELIGIBLE：12.8 系列不在该公告的版本范围内；不是复现失败 | 精确函数、触发字段、算术及分配链、补丁对应位置、目标输入与根因绑定 |
| CVE-2023-0196 | Toolkit `cuobjdump`；本地解析损坏二进制；空指针解引用、有限 DoS；CWE-476 | Windows、Linux，早于 Toolkit 12.1 / 12.1 | INELIGIBLE：12.8 系列不在该公告的版本范围内；不是复现失败 | 具体文件格式子路径、触发字段、NULL 来源、补丁位置和根因绑定 |
| CVE-2024-0076 | Toolkit `cuobjdump` 和 `nvdisasm`；用户读取损坏 ELF；越界读、部分 DoS；CWE-125 | 公告写早于 Toolkit 12.4；更新列为 **12.4U1** | INELIGIBLE：12.8 系列超出已公告范围；**12.4 边界不能由这张表直接推定** | 12.4 与 12.4U1 的组件修复映射、具体越界读路径、根因与补丁绑定 |

依据：[NVIDIA 5334](https://nvidia.custhelp.com/app/answers/detail/a_id/5334)、[NVIDIA 5446](https://nvidia.custhelp.com/app/answers/detail/a_id/5446)、[NVIDIA 5517](https://nvidia.custhelp.com/app/answers/detail/a_id/5517)。资格仅针对已绑定、已测量的工具副本；不能推断其他 PATH 副本或历史安装版本的资格。平台与工具身份仍须经 P2 证据核验，本文不能替代该核验。

这三项都是主机开发工具问题，不是仅凭 GPU 驱动版本判定的漏洞。NVIDIA 5334 明确区分独立开发工具与正常 CUDA runtime；不能将 `nvidia-smi` 的 CUDA compatibility 字段当成受影响 Toolkit 版本，也不能用 `nvcc` 版本代替 `cuobjdump` / `nvdisasm` 的文件身份与组件版本。Toolkit 的 Update 号也不能与组件独立 build 号直接等同。

## CVE-2022-21821

[NVIDIA 公告 5334](https://nvidia.custhelp.com/app/answers/detail/a_id/5334)（页面更新 2022-04-07）支持整数溢出描述、工具入口、受影响发行范围及用户交互要求。公告未披露输入必须为 ELF64/cubin、哪一个 section 字段造成溢出、是否先发生小块堆分配，或可复现的根因栈。因此，输入中的 `4_attack_surface.json#/trigger_mechanism`、`7_root_cause.json#/root_cause/technical_details` 的具体堆损坏机制仍是未经复核的输入断言。

[CVEProject 中 NVIDIA CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2022/21xxx/CVE-2022-21821.json) 的 `/containers/cna/problemTypes/0/descriptions/0/cweId` 为 **CWE-1285**，而原输入 `5_vulnerability_type.json#/vulnerability_type/cwe_id` 为 **CWE-190**。CNA 描述同时使用整数溢出概念。必须保留分类来源差异，不能静默覆盖原输入或宣称两者等价；缺少进一步根因资料时相关分类一致性为 CONFLICT。公告并未把 Linux kernel 列为受影响组件，原输入 `1_os_environment.json#/notes` 对“Linux kernel”的表述应保留为不受该来源支持的断言。

## CVE-2023-0196

[NVIDIA 公告 5446](https://nvidia.custhelp.com/app/answers/detail/a_id/5446) 与 [NVIDIA CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2023/0xxx/CVE-2023-0196.json) 一致支持 `cuobjdump` 空指针解引用、CWE-476、受影响范围早于 12.1，以及有限 DoS。CNA 来源路径包括 `/containers/cna/affected/0/versions/0`、`/containers/cna/problemTypes/0/descriptions/0` 和 `/containers/cna/metrics/0/cvssV3_1`。

原输入 `5_vulnerability_type.json#/vulnerability_type/cvss_vector` 声称机密性低影响，官方向量该项为 `C:N`；原输入根因段自身又称没有机密性影响。应报告此冲突。`4_attack_surface.json#/trigger_mechanism` 提到 `sh_offset` 越界及不存在的 section 数据，本次一手资料没有证明这些特定触发条件。一般 access violation / SIGSEGV 也不能证明是本 CVE 的空指针路径。

## CVE-2024-0076

[NVIDIA 公告 5517](https://nvidia.custhelp.com/app/answers/detail/a_id/5517) 与 [NVIDIA CNA 记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/0xxx/CVE-2024-0076.json) 支持两个二进制工具、损坏 ELF 入口、CWE-125 及部分 DoS。CNA 的受影响范围与公告相同，但没有解释公告“受影响早于 12.4 / 更新为 12.4U1”的边界。12.4 具体组件版本须补充审核发行说明、更新包和工具身份映射，未补充前保持 UNKNOWN，不能猜测其是否已修复。

原输入 `5_vulnerability_type.json#/vulnerability_type/cvss_vector`、`6_impact_controllability.json#/impact`、`7_root_cause.json#/root_cause/summary` 声称机密性或堆数据泄露；本次一手资料只支持 DoS，官方机密性影响为 `C:N`。越界读不自动证明可利用信息泄露，原输入的泄露与特定 section 字段触发叙述仍是未经复核的断言。`cuobjdump + nvdisasm` 是两个工具的组合描述，不是合法的单个可执行文件名或可直接信任的命令。

## 实际取得的来源与字节身份

下列 SHA-256 来自 2026-10-16 的独立 HTTPS 字节读取；页面内容同时经浏览器工具读取并人工审查。散列用于标识本次读取内容，不是来源真实性、事实正确性或漏洞触发证明。HTML 包含动态页面内容，后续抓取可能产生不同散列；原始网页不作为运行证据写入 Git。

| 来源 | 原始字节数 | SHA-256 |
| --- | ---: | --- |
| [NVIDIA 5334](https://nvidia.custhelp.com/app/answers/detail/a_id/5334) | 33377 | `23cc2d0bab533f2deb27dea616b51cbea81d25ee186304a3afffdc6f432aa709` |
| [NVIDIA 5446](https://nvidia.custhelp.com/app/answers/detail/a_id/5446) | 32915 | `acd42bd2c326cbccc4b3f8d447294ffd09d265f4e1bfe9877e7927613af4225f` |
| [NVIDIA 5517](https://nvidia.custhelp.com/app/answers/detail/a_id/5517) | 34469 | `d5317534498e0eb600b33ce85e87a0040ba6799208fe397f6e5a5d34b5b7d517` |
| [CNA 2022-21821](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2022/21xxx/CVE-2022-21821.json) | 7034 | `20f72d762dbf466fa94016804f145694080b05b66b81e8d62f47bc00f3901170` |
| [CNA 2023-0196](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2023/0xxx/CVE-2023-0196.json) | 6178 | `3483e07a7c6f81b884cbbf97e609a6e1d8060cbf9aa8a9c5faa4496d18c56261` |
| [CNA 2024-0076](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/0xxx/CVE-2024-0076.json) | 6101 | `fa9f693a0f986132c773b35e0744713eebcc3ed95f1805a5176677f9347a7ab2` |

未取得的访问：浏览器对 `https://cveawg.mitre.org/api/cve/` 下这三个 CVE 的读取均失败；`cve.org` 的 2024-0076 页面仅返回 JavaScript 提示，未作为事实依据。已改用 CVEProject 官方仓库中的 CNA JSON，不采用搜索摘要、第三方镜像或模型记忆补齐细节。本阶段没有取得经复核的专项技术分析、补丁差分或真实 CVE 实测。
