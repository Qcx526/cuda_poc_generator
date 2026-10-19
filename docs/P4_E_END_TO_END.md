# P4-E 端到端验收：生成新 PoC 并在隔离环境测试

报告语言：`zh-CN`。本文件记录一次完整链路：真实模型生成 → 归档交付 → 容器内执行 →
判定。所有数值来自本轮实际运行。

## 1. 生成阶段

| 项 | 值 |
|---|---|
| 目标 | `CVE-2025-23340`（nvdisasm SHT_RELA 堆越界写） |
| 模型 | `deepseek-v4.1-flash`（OpenAI 兼容中转站） |
| 温度 / 上限 | 0.3 / 32768 tokens |
| 分析结果 | 9 个步骤，置信度 0.78，CWE-131 |
| 候选 | `cuda_poc_v1.py`，679 行，`GENERATED / STATIC_VALID` |
| 交付 | `packages/CVE-2025-23340_a7567ed3….zip`，包外 SHA-256 `b8f5c98a…43cf`，`INTEGRITY_VERIFIED` |

### 1.1 两次失败与根因：推理 token 吃掉了输出预算

前两次运行都以 `ANALYSIS_PARSE_ERROR` / "生成模型没有返回非空候选源码" 结束，
`diagnostics` 只有 `{"path": [], "code": "empty_response"}`，没有更多线索。

直接探测端点后确认：该模型返回 **`content` 与 `reasoning_content` 两个字段**，
推理过程先消耗 `max_tokens`。当预算不足时 `content` 为空、`finish_reason=length`，
但 `LLMClient.chat()` **不检查 `finish_reason`**，于是被误报成"空响应"。

- 4096 tokens：分析阶段即失败（简单请求实测推理占 37/43 tokens，长提示下比例更高）。
- 16384 tokens：分析通过，代码生成仍为空。
- 32768 tokens：分析与生成均通过。

**已知缺陷**：`src/llm_client.py` 未把 `finish_reason=length` 与"模型返回空"区分开，
错误信息无法指向"调大预算"。当前规避方式：`CPG_LLM_MAX_TOKENS=32768`。

## 2. 执行阶段

容器镜像在 `nvidia/cuda:11.2.2-devel-ubuntu20.04` 基础上加装 `python3`（构建时联网，
运行时断网），镜像 `cpg/cuda112-py3:1.0`。运行参数：

```text
--network none --cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /tmp:size=512m --pids-limit 256 --memory 2g --cpus 2
-v <outputs>/CVE-2025-23340:/work:rw
```

未挂 GPU（用户态工具不需要）。

## 3. 结果

PoC 自建骨架并扫描 `sh_size`：

| 组 | 数量 | 结果 |
|---|---|---|
| 触发区 `sh_size` 0–11 | 12 | **全部 SIGSEGV（rc=-11）** |
| 差分区（对照）12、23、24、36、48 | 5 | **全部 SIGSEGV（rc=-11）** |
| 未修改骨架 `poc_skeleton.cubin` | 1 | exit=0 |

PoC 自己的 `S06` 步骤报告 `FAIL: control samples unexpectedly triggered`，退出码 4。

## 4. 判定

`NOT_VERIFIED` → 实际输出为 `UNKNOWN`，理由：

> 机制对照 5/5 全部崩溃；所声称的触发条件未得到支持，崩溃不可归因于受控变量。

也就是说：**PoC 能崩，但它声称的"小 sh_size 才触发"被自己的对照否证了**。
把 `.text` 节改成 `SHT_RELA` 之后，任何 `sh_size` 都崩——这说明崩溃来自"节类型被改"
这件事本身，而不是被断言的对齐计算缺陷。

## 5. 本轮发现并修复的问题

1. **负信号未识别**：`subprocess` 用 `-11` 表示 SIGSEGV，而 `is_crash_exit` 只认 shell 的
   `139`，导致 12 个崩溃样本全被当成"未崩溃"，判定一度是 `NOT_VERIFIED`。
   现已同时支持两种约定（`-signal` 与 `128+signal`）。
2. **缺少"对照全崩"档**：此前只要基线不崩就给 `SUPPORTED`。现在若机制对照
   **全部**崩溃，直接判 `UNKNOWN`，因为所声称的触发条件不成立。
3. **显式标签**：`poc_shsize_12.cubin` 这类文件名不带 `malicious`/`ctrl` 语义，
   允许调用方在名称本身无法判定时显式给标签；已能识别的名称仍禁止改写。

## 6. 结论

- 生成链、归档链、交付链在真实模型下可用，产物结构完整。
- 执行链可在断网容器内跑通 LLM 生成的 Python PoC。
- **"生成成功"与"漏洞复现"之间仍有巨大距离**：本次候选静态检查通过、也能让工具崩溃，
  但对照实验证明其因果假设不成立。这正是本系统坚持 `NOT_EXECUTED / NOT_VERIFIED`
  分离、并要求差分对照的原因。

## 7. 下一步

1. 修复 `finish_reason` 诊断，让"预算不足"可被直接识别。
2. 把容器运行固化为 `src/container_runner.py`，避免每次手工拼 docker 命令。
3. 针对 `23340` 重新设计对照：只改 `sh_size`、不改 `sh_type`，或保留原 `.text` 类型，
   以区分"节类型篡改"与"尺寸对齐缺陷"两条路径。
