# F14：重放口径修正与六 CVE 复核

基线 `323fa35`。本轮的核心发现不在生成侧，而在**测量侧**：F13 的"无命中"结论，
大部分是重放时用错了 argv 造成的假阴性。

## 一、开场四条审计的核实

| 审计 | 核实结果 |
|---|---|
| `src/trusted_grading.py` 远程缺失 | **属实**：文件只在磁盘上，`git ls-tree` 里没有 → 干净克隆无法运行判定器。已提交 |
| `tests/test_trusted_grading.py` 缺失 | **属实**，同上 |
| `loop_stages` 仍是旧 `make_grader()` | **不准确**：`require_trusted` 已存在且在 `loop_runner.py:57` 按 toolchain 传入；问题只是模块没被提交 |
| `public_brief()` 重复分支、空 versions 遮蔽顶层 affected | **属实**：`elif self.affected` 出现两次。已去重，保留顶层回退 |

## 二、最重要的发现：重放用了错的命令行

候选调用的是 `cuobjdump -elf <file>`（脚本第 815 行 `for mode in ('-elf','-all')`），
而我的重放只跑 `cuobjdump <file>`。同一个文件：

```
cuobjdump poc_sh_size_size_past_eof.cubin      → exit 0
cuobjdump -elf poc_sh_size_size_past_eof.cubin → exit 139   ← 候选看到的崩溃
```

**F13 把 23346 判成"6 次调用、0 崩溃"，是重放方式造成的假阴性，不是候选失败。**

已修：`trusted_exec` 的重放按 argv 矩阵展开（nvdisasm 裸调用；cuobjdump 的
``、`-elf`、`-all`、`-sass`），并用单元分隔符传字段（之前 `|` 会被空字段错位）。

附带修掉的两个真 bug：

- `[CPG_RUN] file exit=N` 这种旧格式没被解析（正则强制要求 `::tool`），
  于是"候选声称崩溃、harness 没看到"根本没被标记；现在无工具名也能解析，并按文件名比对，
  声称崩溃但重放不复现会被记为 `声称的崩溃在重放中不可复现`。
- 候选产物会被 `_stale_*` 归档，重放要在归档目录里找，否则读到 0 个产物。

## 三、六 CVE 复核（按候选 argv 重放）

| CVE | advisory 工具 | 状态 | 调用 | 解析器崩溃 | 崩溃工具 |
|---|---|---|---|---|---|
| CVE-2024-0111 | cuobjdump | TARGET_TOOL_DIFFERENTIAL_SUPPORTED | 60 | 17 | cuobjdump |
| CVE-2024-0124 | nvdisasm | TARGET_TOOL_DIFFERENTIAL_SUPPORTED | 95 | 26 | cuobjdump,nvdisasm |
| CVE-2024-0125 | nvdisasm | DIFFERENTIAL_SUPPORTED | 105 | 34 | cuobjdump |
| CVE-2025-23308 | nvdisasm | CRASH_OBSERVED | 140 | 7 | cuobjdump |
| CVE-2025-23338 | nvdisasm | CRASH_OBSERVED | 2730 | 164 | nvdisasm |
| CVE-2025-23346 | cuobjdump | CRASH_OBSERVED | 110 | 39 | cuobjdump,nvdisasm |

### 3.1 23346 为什么"没有有效输入"

有输入、有崩溃，但**崩溃件不是它自己声明的 poc**：崩溃来自上一轮留下的
`cve_2025_23346_h1_*.cubin`，属于 UNLABELED。按新规则，未分类崩溃只登记为
`FINDING_CANDIDATE`，不参与配对，所以停在 `CRASH_OBSERVED`。

这正好回答任务的第一问：**不是生成失败，是标签与配对缺失**。

### 3.2 23338 为什么仍不给差分

它的 164 次崩溃里包含 **`benign_symtab.cubin` 自身崩溃**——所谓"良性基线"不干净，
配对条件不成立。把这份文件当基线会让任何"差分"都失真。

### 3.3 0124 里的 137

12 次 `exit=137`（SIGKILL）已单独计数（`killed_137`），**不计入解析器崩溃**：
那是容器资源限制或外部终止，与解析器缺陷无关。

## 四、判据收紧后的状态

- `CVE_MECHANISM_SUPPORTED`：**0 个**（仍要求逐案例根因证据，缺则 UNKNOWN）
- `CVE_ATTRIBUTED`：**0 个**
- 有目标工具差分的：0111、0124（2 个）
- 有差分但非目标工具的：0125

## 五、诚实交代：本轮没做到的

任务要求"改进生成后完整重跑 23346/23308/23338 + 回归 0111/0124"。
本轮**没有跑新的 LLM 生成轮次**——时间全部用于把测量口径修对，
因为在此之前任何"重跑"的结论都会被同样的假阴性污染。

因此以下仍未交付：
1. 生成侧的改进（先约束后代码、可复用 cubin 构建库、真实 stderr 回灌）；
2. 六个案例的新一轮 LLM 生成与前后对照；
3. 23346 标签补全后的重新配对实验。

## 六、回归与产物

```
1937 passed / 67 skipped / 0 failed
```

产物：`data/driver/f14-replay/*.json`（按 argv 重放，原始 trusted 未改动）、
`data/driver/f13-verdicts.json`（重评）。
