# P13-4-F7：真实 CVE 上的 LLM 自主生成验证

基线：`89bb4f5`。本轮只做 CVE-2024-0076，不扩展到 23340。

## 一、Step 0：历史证据核查（结论先写）

### 1.1 三个 SUPPORTED 的内部判定存在

`demo/CVE-2024-0076/out/status.zh-CN.md` 记录：0076 / 23339 / 23340 为 `SUPPORTED`，
各自有 `data/loop/<批次>/` 目录。这是**框架内部判定**，不是外部验证。

### 1.2 "两个新崩溃点归属 CVE-2024-53877" 缺证据

README 第 9 行写"查重后归属为 CVE-2024-53877"，但仓库内证据不支持：

| 来源 | 说法 |
|---|---|
| `README.md` | 2 个独立崩溃点，归属 CVE-2024-53877 |
| `demo/.../status.zh-CN.md` | 这些崩溃点：`非新漏洞` / `已有人上报（KNOWN）` / `UNTRIAGED` |
| `docs/P5_C_POC_MUTATION_METHOD.md` | 23340 与 0076 两条知识条目"未通过归属判定，已移入 pending" |
| `docs/P5_E_CUDA124_SWEEP.md` | CUDA 13.0（23340 修复版）**不崩** → 更像 23340 家族 |
| `docs/P10_ATTRIBUTION.md` | 按访问类型排除 23339（写 vs 读） |
| `data/findings/novel/CVE-2024-53877/` | **空目录**，无归档证据 |

**结论：CVE-2024-53877 的归属不可确认，README 该句应视为未证陈述。**
不得因为"组件相同 + 版本范围内崩溃"就认定属于某条 CVE。

### 1.3 23339 / 23340 的 CWE 无法从仓库核实

`data/cve_catalog.json` 中多条记录的 `cwe` / `advisory` / `fixed_in` 为空（来源标 `inputs`）。
官方 CWE 与内部机制分析的差异**无法在仓库内核对**，记为 UNKNOWN，不作断言。

### 1.4 LLM 生成 vs 预先配置

`data/loop/v4/CVE-2024-0076/` 只有 observation 与 report，**没有生成脚本留档**；
无法从该批次区分"模型生成"与"预置样本"。这是历史留档的缺口，如实记录。

## 二、Step 1–2：本轮真实运行（CVE-2024-0076）

命令：

```bash
docker（Docker Desktop CLI，PATH 未含，用绝对路径）
python -m src.batch_loop --cve CVE-2024-0076 --iterations 2 \
  --workdir data/loop/f7 --image cpg/cuda112-py3:1.0 \
  --tier userland_toolchain --freeze-history
```

`--freeze-history` 忽略规格里的 observed 知识，等价于最小合同（公告 + 工具调用方式 +
输入格式），不含历史 PoC、触发偏移与 Ground Truth。

结果：`SUPPORTED`，it=1，1/1，612s。**首轮即通过，第二轮未发生**（闭环在成功时停止）。

### 2.1 五级事实分离

| 级别 | 结论 | 证据 |
|---|---|---|
| GENERATED | 是（`--freeze-history`，产出 4 个 artifact 与完整 harness） | `iteration_1_candidate.txt` |
| EXECUTED | 是（CUDA 11.2.2 容器内，4 样本 × 2 工具） | `[CPG_RUN]` 行 |
| CRASH_OBSERVED | **部分**：`cuobjdump` exit=139 两次；`nvdisasm` exit=1（非崩溃） | 同上 |
| SUPPORTED | 是，按框架规则"受控样本 1/4 产生崩溃退出码" | `batch_summary.json` |
| CVE_ATTRIBUTED | **未达成** | 见 2.2 |

### 2.2 必须记录的矛盾

生成程序自己的判据写的是：

```
[CUDA_DIFF] single_field_differential=False
[CUDA_VERDICT] NOT_REPRODUCED — crafted sh_size did not fault under nvdisasm
HARNESS_RC=1
```

即：**候选自评未复现；框架判 SUPPORTED**。原因是框架只要求"1/4 受控样本崩溃"，
而崩溃的是 `cuobjdump`，目标 CVE 描述的是 `nvdisasm`/`cuobjdump` 解析器。
两者不一致时，SUPPORTED 的含义应理解为"观察到一个崩溃"，**不等于"复现了该 CVE 机制"**。

良性基线与对照确实干净：

```
benign_baseline  nvdisasm=0  cuobjdump=0
ctrl_sh_size_restored_0x10  nvdisasm=0  cuobjdump=0
poc_sec8_sh_size_u32max     nvdisasm=1  cuobjdump=139
poc_sec8_sh_size_huge       nvdisasm=1  cuobjdump=139
```

所以差分条件成立（恶意崩、基线净、对照净），但 **`single_field_differential=False`**
说明对照组与恶意样本不止差一个字段，机制归因被削弱。

### 2.3 反馈驱动

本轮首轮成功，**没有第二轮可评估**。要求 6（第二轮修改是否由客观反馈驱动）在 0076 上
无法验证，必须换一个首轮失败的目标才能回答。

## 三、下一步的前提条件

1. 想要"两轮闭环"，需要一个首轮会被判 `NOT_VERIFIED` 的目标（23340 历史上有 NO_EFFECT 记录）；
2. 想要"CVE_ATTRIBUTED"，需要把判据从"任一受控样本崩溃"收紧到"目标工具 + 单字段差分"；
3. README 的 53877 归属句应改为"待证"，或补归档证据；
4. 历史批次缺生成脚本留档，后续每轮必须落 `poc.py`/prompt/response。
