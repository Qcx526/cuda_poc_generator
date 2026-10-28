# 复现与新发现：当前状态

判定口径：公告给出的组件、现象、受影响版本；在其中一个版本上复现该现象即为成功。
后续版本不再崩溃说明修复生效，不构成复现失败。

## 一、CVE 复现

| CVE | 组件 | 受影响版本 | 修复版本 | 最近一次闭环 | 判定 |
|---|---|---|---|---|---|
| CVE-2024-0076 | NVIDIA CUDA cuobjdump + nvdi | all versions prior to CUDA Toolkit 12.4 | 12.4 (12.4U1) | data\loop\v4\CVE-2024-0076 | `SUPPORTED` |
| CVE-2024-0091 | NVIDIA GPU Display Driver -  |  |  | — | `未跑` |
| CVE-2024-0107 | NVIDIA GPU Display Driver us |  |  | data\loop\driver0107b\CVE-2024-0107 | `NOT_VERIFIED` |
| CVE-2025-23247 | cuobjdump .nv_debug_source p |  |  | data\loop\s5g_lint\CVE-2025-23247 | `NOT_VERIFIED` |
| CVE-2025-23339 | NVIDIA CUDA cuobjdump (DWARF |  |  | data\loop\v5_23339\CVE-2025-23339 | `SUPPORTED` |
| CVE-2025-23340 | NVIDIA CUDA nvdisasm (SHT_RE | all versions prior to CUDA Toolkit 13.0 | 13.0 | data\loop\c3_B\CVE-2025-23340 | `SUPPORTED` |
| CVE-2026-24193 | NVIDIA GPU Display Driver (n |  |  | — | `未跑` |

## 二、变异发现的新崩溃

### CVE-2024-0076

| 样本 | 崩溃点 | 访问类型 | 实测版本 | 查重结论 |
|---|---|---|---|---|
| structure_e_shnum_1.cubin | `cuobjdump+0x12000` | null-read | 12.4.1 不崩 → 非新漏洞 | UNTRIAGED |
| structure_e_shnum_4096.cubin | `libc.so.6+0x183000` | null-read | 12.4.1 不崩 → 非新漏洞 | UNTRIAGED |
| sec3.sh_type_sec3.sh_type_0.cubin | `nvdisasm+0x10000` | null-read | 12.4.1 崩; 13.0.0 不崩 → 非新漏洞 | 已有人上报（KNOWN） |
| sec8.sh_offset_sec8.sh_offset_0.cubin | `nvdisasm+0x49000` | null-read | 12.4.1 崩; 13.0.0 不崩 → 非新漏洞 | 已有人上报（KNOWN） |

### CVE-2025-23340

| 样本 | 崩溃点 | 访问类型 | 实测版本 | 查重结论 |
|---|---|---|---|---|
| poc_sh_size_0.cubin | `` | — | 未测 | UNTRIAGED |

## 三、说明

- 新发现只在判断“是否为新漏洞”时才需要跑修复版本；仍崩即为候选新漏洞。
- 样本与证据存放于 `data/findings/novel/`，含 sha256、崩溃点与 memcheck 记录。
