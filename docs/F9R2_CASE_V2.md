# P13-4-F9-R2：GPU Vulnerability Case v2 与定向静态接地

基线 `7412e6a`。

## 一、先纠正 R1 的一条推断

R1 写"绑定只能发生在运行期解析的指针上"——**这是过度推断**。
没有 `Dxgk` 字符串、没有 dxgkrnl 导入、没有直接 LEA，只能证明**这几种识别方式失败**，
不能证明静态数据流追踪不可能成功。

本轮用数据流试了一次，**有结果**（见第五节）。回调 RVA 在此之前确实是 UNKNOWN。

## 二、Schema：六模块 + 有类型扩展

`src/case_v2.py`，`gpu-vulnerability-case/v2`：

| 模块 | 内容 |
|---|---|
| `CaseIdentity` | case_id、**可选** cve_id、标题、资料来源 |
| `TargetProfile` | 厂商、组件、平台、执行层级、版本 |
| `EntrySurface` | 介质、接口、信任边界、入口约束 |
| `VulnerabilityDescription` | 公开描述、CWE、影响、**根因状态**（默认 UNKNOWN） |
| `ConstraintKnowledge` | 证据列表 + 缺失知识 |
| `ExperimentContract` | 目标、后端、允许操作、风险、是否需独立验证 |
| `PlatformExtension` | `name` + `version` + `payload`，平台特有字段只放这里 |

没有 CVE、没有公开根因、没有触发参数的案例都能表达（驱动案例就没有 CVE）。

## 三、证据分层：七类，可见性由类型决定

| kind | 可见性 | 说明 |
|---|---|---|
| INPUT_ASSERTION | PUBLIC | 外部文档声明，**不代表已证实** |
| STATIC_FACT | FACT | 必须绑定 `target_identity`（模型层强制） |
| RUNTIME_OBSERVATION | EVAL | 实测观测，不进生成 Prompt |
| LLM_HYPOTHESIS | EVAL | 模型推理，永不回流公开事实 |
| EVIDENCE_REQUEST | PUBLIC | 待验证命题 |
| VERIFICATION_RESULT | EVAL | 独立验证器结论 |
| EVALUATION_ONLY | EVAL | 隐藏答案 |

模型层用 `model_validator` 强制 kind 与 visible_in 一致：
`STATIC_FACT` 写成 PUBLIC 直接报错，`EVALUATION_ONLY` 写成 PUBLIC 也报错。

**"信息为真"与"允许模型看到"是两个独立判断**：23340 的公告文本是公开的，
但里面的 `attack_vector` 写着完整配方，所以它在 v2 里是 `EVALUATION_ONLY`。

## 四、可见性投影

`src/case_projection.py`：

- `PUBLIC_ONLY`：只保留 PUBLIC 证据；**extension 只给平台名与版本，不给 payload**
  （payload 含镜像 SHA256 与候选 RVA，属事实）。
- `FACT_ASSISTED`：额外给 FACT 级静态事实。
- EVAL 级（含 VerificationResult、Hypothesis、Observation）在两种模式下都不出现。

测试覆盖：CUDA 公开投影不含 `sh_size` / `1..11` / `24 的倍数` / `root_cause` / `attack_vector`；
驱动公开投影不含镜像哈希与候选 RVA；EVAL 证据 id 在两个模式下都不出现。

## 五、定向静态分析：找到一张函数表

范围限制在 Entry 窗口（`0x733a0e0` 起 1 KB），只找 `lea rax,[rip+X]` + `mov [rbp+off],rax` 对。

**结果**：窗口内 41 条此类写入，形成一张连续填充结构体的表：

```
字段 0xc0  ← 0x733e190
字段 0xb8  ← 0x136df10
...
字段 0x100 ← 0x136df31
字段 0x110 ← 0x733e240     ← store 位于 RVA 0x733a399
字段 0x118 ← 0x13a5703
...
```

判断与保留：

| 项 | 状态 |
|---|---|
| "RVA `0x733a399` 处存在 `mov [rbp+0x110], 0x733e240`" | **STATIC_FACT**（可复核字节） |
| "该结构体是 `DRIVER_INITIALIZATION_DATA`" | **UNKNOWN**（未证明 rbp 是结构基址） |
| "`0x733e240` 是 `DxgkDdiEscape`" | **UNKNOWN**（偏移吻合只是必要条件） |

**为什么不能算命中**：偏移与 WDK 布局一致（0x110）只说明"某个 0x110 偏移被写入"；
还没有证明 `rbp` 指向初始化结构，也没有证明这张表交给了 dxgkrnl。

这两条正是 `EVALUATION_ONLY` 里的 O1，投影时不会出现。

## 六、两个真实案例

| | 案例 A | 案例 B |
|---|---|---|
| 文件 | `data/cases/cve-2025-23340.v2.json` | `data/cases/nvlddmkm-610-47-escape.v2.json` |
| 来源 | 七维输入经 Legacy Adapter | F8/F9 静态事实 |
| CVE | CVE-2025-23340 | **无** |
| 平台 | linux / userland_toolchain | windows / kernel_driver |
| 扩展 | `cuda_toolchain` | `windows_gpu_driver` |
| 后端 | `cuda_container` | `windows_userland` |
| 证据 | 6 条 PUBLIC + 7 条 EVAL | 6 条 FACT + 2 条 EVIDENCE_REQUEST + 1 条 EVAL |

同一个 `GPUCase.model_validate` 解析两者；CUDA 案例不含驱动字段，驱动案例不含 CUDA 字段。

## 七、旧七维兼容

`src/case_legacy.py`：

- 保留 7 个文件的 SHA256、`field_states`、`diagnostics`；
- 缺失字段**不补全**；`missing_files` 如实记录；
- 受限字段（attack_vector / attack_complexity / surface_type / subtype /
  controllable_fields / exploitation_difficulty / root_cause）降为 EVALUATION_ONLY，
  并在 diagnostics 里逐条注明；
- 所有证据 `status=UNKNOWN`——**结构有效 ≠ 事实成立**。

旧 CUDA Pipeline 未改动，仍按七文件运行。

## 八、边界

- 未发起真实内核 Escape、未扫描私有参数、未重跑 CUDA CVE、未改 Mock 与冻结基线；
- 未新增漏洞样本；
- 静态分析范围限制在 Entry 窗口 1 KB，未做全驱动扫描。

## 九、下一步

`0x733e240` 是目前唯一有字节级出处的候选。要把它变成事实，只差一步：
**证明 `rbp` 指向的结构被交给了 dxgkrnl**。这需要跨函数数据流（找到那次调用的实参来源），
比本轮范围大，但仍在静态能力内——如果下一轮继续，应先做这件事，而不是再扫描字符串。

运行期确认仍是 BLOCKED（需第二台主机 + KDNET 或 VM 直通）。
