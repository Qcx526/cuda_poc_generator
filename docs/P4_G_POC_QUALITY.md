# P4-G 生成质量提升：失败模式 → 工程对策

报告语言：`zh-CN`。本文件把四轮实测中暴露的生成缺陷逐一映射到工程对策，
并记录本轮已经落地的部分。

## 1. 诊断：不是模型不行，是约束从未闭环

生成的 PoC 质量问题有明确的系统性根因：**模型只在"语法/导入"层面被校验，
领域正确性从未被检查**；而动态结果（对照崩溃、探测空转）也没有回流到生成端。
五个真实案例：

| 案例 | 失败模式 | 暴露的问题 |
|---|---|---|
| 0090 | 版本分类器把 `551` 判成"不在受影响分支"→ 假 PATCHED | 分支表不完备时被当作"未受影响" |
| 0091 | 35 次探测全部 `CUDA_ERROR_NOT_INITIALIZED` | 探测前没有建 CUDA 上下文，测量了空气 |
| 0107 | ps_5_0 里搜 SINCOS token、patch 随机位置 | SM4/SM5 没有 SINCOS 指令 |
| 0107 | 四个毒化值全部过不了类型位门 | 不知道驱动有 `& 0x70000000` 校验 |
| 23340 | PoC 自身崩溃，但 5 个对照也全崩 | 因果假设未经对照检验 |

## 2. 本轮落地：领域 lint + 提示词硬约束

### 2.1 `src/quality_lints.py`（新增，接入 `_validate_code`）

| lint | 捕捉的真实失败 | 实现要点 |
|---|---|---|
| `version-classifier-unknown-major` | 0090 | AST 识别 `x not in y` / `not (x in y)` 两种写法（两者 AST 不同），分支体内 `return False` 或 `(False, ...)` 即报 |
| `driver-probe-without-context` | 0091 | 对名字含 probe 的函数做**可达调用闭包**，闭包内无 `cuInit`/`cuCtxCreate`/`D3D11CreateDevice` 即报；只看本函数体会被公共 helper 骗过 |
| `legacy-token-search-on-modern-profile` | 0107 | 同时出现 `ps_5_0` 类 profile 与 `D3DSIO_*` 常量即报 |

lint 报错进入现有的**修正循环**：`_validate_code` 返回的 `err_msg` 会拼进下一轮
生成的 correction prompt，模型收到的是具体罪名而不是笼统的"质量差"。

### 2.2 代码生成系统提示词新增三条硬约束（7/8/9 条）

1. 版本分类：未映射的 branch 必须判 UNKNOWN，禁止 NOT-AFFECTED；
2. 驱动 API 前置：probe 之前必须 `cuInit` + 真实上下文，且**每个** probe 函数都要满足；
3. 指令 token：搜索前必须确认目标 profile 确实含该指令（D3DSIO_* 只在 SM2/SM3）。

提示词原有序号本身是乱的（三个 8、两个 11），已全部重排为 1–19。

### 2.3 测试

`tests/test_quality_lints.py` 9 个用例，每个 lint 都有一个"从真实失败复刻"的
反例和一个干净正例；`_validate_code` 集成路径也有直接断言。
全量回归 1282 passed / 66 skipped。

## 3. 后续路线（按收益排序）

1. **端到端自动评级**：`main.py --package` 之后自动接容器执行 + `reproduction decide`，
   一次命令产出 `GENERATED / EXECUTED / SUPPORTED|UNKNOWN` 的完整链路。现在三段是手动串的。
2. **动态结果回流**：对照全崩时（如 23340），把"对照也崩"的事实和失败原因写进
   下一轮迭代的 correction prompt——现在迭代只对静态失败生效，动态失败不回流。
3. **证据包增强**：input_manifest 目前只有公告文本。把 Talos/CVE 参考的技术细节
   （如 TALOS-2024-1956 的汇编片段、受影响组件精确版本）结构化进 manifest，
   模型就不用从"公告没写"变成"猜"。
4. **RAG 知识库**：沉淀本轮发现的领域事实（DXBC 无 SINCOS、D3D11 拒收 ps_2_0、
   CUDA 探测必须先建上下文、驱动分支表不完备），生成时按 CVE 类型注入。
5. **version_eligibility 独立模块**：受影响区间判定与 PoC 自述解耦，冲突显式列出。

## 4. 一个诚实的边界

lint 只能拦"已知形状的错误"。0107 的类型位门（`& 0x70000000`）这种**驱动内部
细节**，除非知识库里有对应条目，lint 与提示词都救不了——这正是证据包/RAG 的价值：
把我们逆向得到的事实喂回去，下一轮生成就站在本轮的肩膀上。

## 5. lint 对真实 PoC 的验证（2026-10-20）

拿三份历史上真实出问题的 PoC 直接跑 lint：

| PoC | 结果 | 判定 |
|---|---|---|
| `CVE-2024-0107.py` | `legacy-token-search-on-modern-profile` | ✅ 真阳性——正是逆向发现的病根 |
| `CVE-2024-0090.py` | `version-classifier-unknown-major` | ✅ 真阳性——正是假 PATCHED 的原因 |
| `CVE-2024-0091.py` | clean | ⚠️ **漏报**，见下 |

### 5.1 一个误报，已修

0090 一开始还报了 `driver-probe-without-context`。查下来是 `probe_nvapi_initialize`
只做指针解析（`nvapi_QueryInterface` 返回函数地址），并没有消费攻击者数据。已把
`nvapi_QueryInterface` 从探测 API 列表移除——解析器不是探测器。

### 5.2 一个漏报，如实记录

0091 的 `run_single_probe` 通过 `for name, fn in build_probe_targets(...)` 间接调用，
AST 只能看到 `fn(value)`，看不到 `fn` 就是 `cuModuleLoadData`。这是静态分析的固有边界。

处理方式：**不引入更"聪明"的启发式**（容易误伤），而是承认它、并依赖动态层——
该 PoC 在无上下文时返回 `CUDA_ERROR_NOT_INITIALIZED`，闭环会判
`PRECONDITION_VIOLATED`，诊断指令与静态 lint 完全一致。

**这条边界写进论文反而加分**：静态通道负责快速拦截可直接识别的形状，
动态通道负责语义级判断，两者互补而不是互相替代。
