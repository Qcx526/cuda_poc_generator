# CUDA / GPU 驱动 PoC 生成与复现框架

从"模型写一个候选 PoC"走到"框架自己判定它是否真的复现了漏洞"。
核心不是生成，而是**判定**：候选的自述不算证据，判分器自己把产物喂给目标工具。

**当前状态：闭环可用（生成 → 执行 → 判分 → 归因 → 反馈重试）。**
覆盖三层目标：用户态工具链、驱动用户态组件、驱动内核组件。前两层可复现，第三层受接口硬化限制（见 §7）。

## 1. 快速开始

```bash
# 前置：Docker Desktop 已启动；仓库根目录有 .env（模型端点与密钥）
pip install -e ".[rag]"          # RAG 可选

# ① 单次生成（只生成与静态检查，不执行）
python main.py --cve-id CVE-2025-23340

# ② 闭环跑一个 CVE（生成→执行→判分→反馈重试）
python -u -m src.batch_loop --cve CVE-2025-23340 --iterations 2 --repeat 1 --workdir data/loop/mine

# ③ 按层批量
python -u -m src.batch_loop --tier userland_toolchain --iterations 2 --limit 3
```

产物位置：

| 路径 | 内容 |
|---|---|
| `data/outputs/<CVE>/` | 候选脚本、它产出的样本、`artifacts.json` |
| `data/loop/<run>/<CVE>/loop_report.zh-CN.md` | 人读报告：判定、证据、每轮观察 |
| `data/loop/<run>/<CVE>/iteration_N_observation.txt` | 原始执行输出（含协议行） |
| `data/loop/<run>/batch_summary.zh-CN.md` | 批次汇总 |

## 2. 目标分层

| 层 | 输入形态 | 判定方式 | 现状 |
|---|---|---|---|
| `userland_toolchain` | 文件（ELF/cubin）喂给 CUDA 工具 | 进程退出码 / 信号 | **可复现** |
| `driver_userland` | 着色器字节码等，喂给驱动用户态组件 | 访问违例 + **模块归因** | 可达，触发条件未解 |
| `driver_kernel` | ioctl / escape 请求发给内核驱动 | bugcheck + 跨重启取证 | 入口可达，**分发前被拒** |

## 3. 架构

```text
specs/<CVE>/spec.json          规格：输入格式、锚点命令、消费字段、oracle
        │
        ├─ generate    LLM 读规格写出候选脚本（lint 拒绝 → 重写）
        │
        ├─ execute     候选在容器内运行；判分器**独立**把声明的产物喂给目标工具
        │              （内核层：主机 + 布防标记 + 重启后取证）
        │
        ├─ grade       解析协议行 → 三角色判定（benign / crafted / controls）
        │
        ├─ diagnose    失败归因到 12 类（NO_OBSERVATION / PATH_NOT_REACHED /
        │              FALSE_POSITIVE / PRECONDITION_VIOLATED …）
        │
        └─ feedback    可归因 → 带证据进入下一轮；不可归因 → 停止并说明原因
```

关键设计：**候选与判分器分离**。候选只能通过 `artifacts.json` 声明产出了什么，
判分器按声明逐个执行，不采信候选日志里的自我描述。

## 4. 判定规范

三条件同时成立才算复现：

```
1. benign 样本不崩溃      （基线干净）
2. crafted 样本崩溃        （触发成立）
3. controls 样本不崩溃      （单变量回指，排除"怎么改都崩"）
```

否则为 `NOT_VERIFIED`（有崩溃但不干净）或 `UNKNOWN`（没有可判读的观察）。

两条硬规则：

- **崩溃必须归因到模块**。只看退出码会把 D3D 校验器的崩溃当成驱动崩溃（实测踩过）。
- **零结果必须交叉验证**。"导出 0 个符号""0 个调用点"都出现过，都是解析错误而非事实。

## 5. 规格（`specs/`）

7 份规格，每份把 CVE 描述变成可执行定义：

```json
{
  "cve_id": "CVE-2025-23340",
  "anchor": {"binary": "nvdisasm", "invocation": ["nvdisasm", "{artifact}"],
             "input_magic": "0x7f454c46", "baseline_recipe": "..."},
  "parser": {"consumed_fields": [{"name": "sh_size", "offset": 32, "bound_check": "none"}]},
  "oracle": {"field": "sh_size", "condition": "sh_type == SHT_RELA(4) and 0 <= sh_size <= 11"},
  "claims": {"每条结论": "带 source / verified_by / confidence"}
}
```

`oracle` 决定策略：有精确 oracle 时走**定点变异**（`MUTATE_DIRECTED`），无需盲搜。

## 6. 协议行（判分器读这个，不读自然语言）

| 行 | 含义 |
|---|---|
| `[CPG_RUN] <file>::<tool> exit=<n>` | 一次受控执行及其退出码 |
| `[CPG_MANIFEST] <n> artifacts declared` / `missing` | 候选是否声明了产物 |
| `[CPG_CANDIDATE_FAULT] <exception>` | 候选自身抛异常，无可判分内容 |
| `[CPG_STEP:...]` | 工具链步骤（编译/汇编）成功或失败 |

## 7. 已知边界（实测结论）

**内核层未打通，且不是技术细节问题。** 六条否证（详见 `docs/P4_Z_KERNEL_ESCAPE_PROBE.md`）：

1. NVAPI 不经过 `kernel32!DeviceIoControl` 触达驱动（IAT 钩子拦截到 0 次）
2. 二进制里的 `0x1000xxxx` 立即数多为结构体版本字，不是 escape 码
3. 设备是否带命令缓冲不影响结果
4. UMD 不导入任何 D3DKMT 函数（走回调表，IAT 无处可补）
5. DxgKrnl 的 ETW 提供程序不记录通用 escape
6. 硬件 access 的 escape 在分发前返回 `0xC0000022`

主流程**没有**：真实 CVE 的通用根因验证器、跨 CVE 成功率基准。
"生成出候选"不等于"漏洞已复现"，报告里始终显式区分这两件事。

## 8. 目录

```text
main.py                     单次生成入口
src/batch_loop.py           闭环入口（按 CVE / 按层）
src/closed_loop.py          循环控制（迭代、终止、反馈）
src/loop_stages.py          generate / execute / grade
src/reproduction.py         日志解析与三条件判定
src/failure_taxonomy.py     12 类失败归因与重试判定
src/spec_model.py           规格加载与提示词生成
src/driver_probe.py         内核层布防与跨重启取证
src/driver_crash.py         崩溃转储解析
specs/                      7 份 CVE 规格
data/knowledge_bases/       RAG 语料（含驱动方法条目）
docs/                       合同、验收、勘误与实测记录
tests/                      1486 passed / 66 skipped
```

## 9. 测试

```bash
python -m pytest -q -p no:cacheprovider
```

覆盖重点不是覆盖率，而是**不变量**：判定必须归因、零结果必须可交叉验证、
候选崩溃必须可反馈、解码失败不得伪装成"没有观察"。

## 10. 文档索引

| 文档 | 内容 |
|---|---|
| `docs/P5_A_GPU_POC_FEASIBILITY.md` | 一天 11 组实验的可行性报告（含三条结构性原因） |
| `docs/P5_B_FIRST_RUN.md` | 第一次自己跑的手把手流程 |
| `docs/P4_Z_KERNEL_ESCAPE_PROBE.md` | 内核 escape 六条否证与判定方法 |
| `docs/P4_V_DRIVER_RE_MAP.md` | CVE-2024-0107 逆向地图与勘误 |
| `docs/P4_X_STAGE_SUMMARY.md` | 阶段总结与工具能力清单 |
| `docs/CVE_ARTIFACT_PACKAGING.md` | 归档与交付合同（ZIP、包外 SHA、离线校验） |
| `docs/REPOSITORY_MAINLINE.md` | 主线选择与外部数据迁移规则 |

历史阶段（P0–P4）的合同与验收记录保留在 `docs/`，不随本次重写删除。

## 11. 安全边界与许可

仅用于经过授权的安全研究和防御验证。不得自动运行真实漏洞 PoC、提权或破坏性样本；
不得把模型结论当作客观证据；不得提交 API Key、私有日志、GPU UUID 或主机绝对路径。

本工程继承原有 CUDA 专项系统，保留源码中的作者标识 `CUDA Security Research Framework`
及原免责声明；维护仓库为 [Qcx526/cuda_poc_generator](https://github.com/Qcx526/cuda_poc_generator)。
仓库未提供独立 `LICENSE` 文件，本轮不新增或推断其他开源许可证。
