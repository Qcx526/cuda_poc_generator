# P5-B 第一次自己跑：完整流程手把手

目标：用一条命令跑完 `CVE-2025-23340`，看清每个阶段发生了什么、结果落在哪里。

## 0. 为什么选这个 CVE

| 条件 | 情况 |
|---|---|
| 规格现成 | `specs/CVE-2025-23340/spec.json`，含精确 oracle |
| 策略 | `MUTATE_DIRECTED`（定点变异，不是盲搜） |
| 触发条件 | `sh_type == SHT_RELA(4)` 且 `0 <= sh_size <= 11` |
| 崩溃形态 | `SIGSEGV` / `0xC0000005`，判定干脆 |
| 之前是否跑过 | **从未执行**（`history.attempts` 为空） |

oracle 明确意味着模型不需要猜"改哪个字段"——它知道要改 `sh_size`，只需要构造出合法的 ELF 外壳。

## 1. 前置检查（三条，缺一不可）

```powershell
# ① Docker Desktop 必须已启动（工具链阶段在容器里跑）
docker ps

# ② 镜像存在
docker images cpg/cuda112-py3:1.0

# ③ 规格能被解析
.venv\Scripts\python.exe -c "from pathlib import Path; from src.spec_model import load; print(load(Path('specs/CVE-2025-23340/spec.json')).cve_id)"
```

若 ② 不存在，先构建（Dockerfile 在仓库里）：

```powershell
docker build -t cpg/cuda112-py3:1.0 -f docker/Dockerfile .
```

## 2. 一条命令跑完

```powershell
.venv\Scripts\python.exe -u -m src.batch_loop --cve CVE-2025-23340 --iterations 2 --repeat 1 --workdir data/loop/first
```

参数含义：

| 参数 | 含义 |
|---|---|
| `--cve` | 只跑这一个 |
| `--iterations 2` | 最多两轮（第一轮失败会带反馈再来一次） |
| `--repeat 1` | 只跑一遍（想估成功率再用 `--repeat 3`） |
| `--workdir` | 本轮所有产物落在这里 |

## 3. 你会看到什么

按阶段顺序，每个阶段都有 `[stage]` 标记：

```
[generate]  → 模型读规格，写出 cuda_poc_v1.py
[execute]   → 容器里跑该脚本；随后判分器用 nvdisasm / cuobjdump 自己跑产物
[verdict]   → 三条件判定：baseline 干净 + crafted 崩 + control 干净
```

判分器**不听候选的自述**：它自己把 `artifacts.json` 里声明的文件逐个喂给工具。
这是 2026-10-27 那轮改造的核心（详见 `P4_Z`）。

## 4. 结果在哪

| 文件 | 内容 |
|---|---|
| `data/loop/first/CVE-2025-23340/loop_report.zh-CN.md` | 人读的报告：判定、证据、每轮观察 |
| `data/loop/first/CVE-2025-23340/iteration_1_observation.txt` | 原始执行输出（含 `[CPG_RUN]` 行与清单信息） |
| `data/outputs/CVE-2025-23340/` | 候选脚本与它产出的 ELF |
| 终端最后一行 | `[batch] CVE-... SUPPORTED/NOT_VERIFIED ... 耗时` |

判定含义：

| 判定 | 含义 |
|---|---|
| `SUPPORTED` | 三条件同时成立，视为复现 |
| `NOT_VERIFIED` | 有崩溃但对照不干净，或没有崩溃 |
| `EXHAUSTED` | 迭代用尽仍未满足 |
| `ERROR` | 阶段失败（生成失败、超时、容器问题） |

## 5. 第一次运行大概率会遇到的两件事

**① 生成阶段超时或失败**
模型服务抖动会让 `[generate]` 直接报 `STAGE_ERROR`。重跑即可，不需要改任何东西。

**② 判定 `NOT_VERIFIED` 但看到了崩溃**
先看 `iteration_1_observation.txt`：

- 有 `[CPG_MANIFEST] N artifacts declared` → 清单被读到，判分器按声明跑
- 只有 `[CPG_MANIFEST] missing` → 候选没声明，判分退回按文件名兜底（最多 12 个）

## 6. 想验证"流程真的是对的"

跑完后做一次交叉检查：手动用容器跑一遍它产出的文件。

```powershell
docker run --rm -v "${PWD}/data/outputs/CVE-2025-23340:/work" cpg/cuda112-py3:1.0 `
  bash -c "cd /work && for f in *.elf; do nvdisasm \$f >/dev/null 2>&1; echo \"\$f exit=\$?\"; done"
```

如果手工结果与报告里的 `[CPG_RUN]` 行一致，说明整条链没有撒谎。

## 7. 下一步可选

| 想做什么 | 命令 |
|---|---|
| 估成功率 | `--repeat 3` |
| 换目标 | 见 `specs/` 下其它目录（0076 / 23247 / 23339 / 23340） |
| 看某轮细节 | 直接读 `iteration_N_observation.txt` |
| 加新目标 | 在 `specs/<CVE>/spec.json` 写规格，重启即可被识别 |
