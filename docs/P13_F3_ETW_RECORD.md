# F3 ETW 采集记录与局限

结论（统一表述）：

> 当前 ETW 采集和解析配置未发现能够可靠区分目标 Escape 调用的事件。

这条结论**只针对当前配置**：`Microsoft-Windows-DxgKrnl`、默认关键字、tracerpt 文本解析。它不声称 ETW 永远无法观测 Escape。

## 采集配置

| 项 | 值 |
|---|---|
| 工具 | `logman`（启动/停止）、`tracerpt`（解析） |
| Provider | `Microsoft-Windows-DxgKrnl` `{802EC45A-1E99-4B83-9920-87C98277BA9D}` |
| 会话名 | `cpg_dxg`（`-ets`，不落盘为服务） |
| 输出 | `.etl`，随后 `tracerpt -of CSV` |
| 关键字 / 级别 | 默认（未显式设置 `-matchanykw` 或 `-p ... -ct` 细分） |
| 场景 | `python -m src.driver_abi`（R0 生命周期），以及同场景 + 一次 `D3DKMTEscape` |

解析命令：

```bash
tracerpt base.etl -o base.csv -of CSV -y
```

## 归档与校验

原始 ETL 不入 Git，保存在 `data/driver/etw/archive/`（13 MB）：

```
d42c5cdd5d3e605aa93681e3d4d130f04f060f798bfca7632afef03fb1ada7ab  base.etl   （R0，无 escape）
962fdbe64ee9e9e17be69a386d8a6c01bcb47e884ab7a0e7e4c873d41007d0c2  esc.etl    （R0 + 1 次 escape）
a5e593ffd8c750c20520f6a2e799814896fe4becb27e794c300025db0be0b406  dxg.etl    （首次长时间采集，4 秒窗口，119,377 事件）
```

`.gitignore` 只排除 `data/driver/etw/*.etl` 与 `data/driver/etw/*.csv`，不影响其他数据文件。

## 采集结果

`dxg.etl` 窗口内共 119,377 条 DxgKrnl 事件：

```
Info  45,707    Start 36,849    Stop 36,819
PID 58 个；主要 PID 0x111E0（约 7 万条）
```

字段可用：`PID`、`TID`、`Processor Number`、`Activity ID`、`Clock Time`、`Task`、`Opcode`。

## 判别实验

同场景两次采集，唯一差别是有没有发一次 `D3DKMTEscape`（返回 `0xC000000D`）：

| task | 基线（无 escape） | 带 escape | 差 |
|---|---|---|---|
| 68 | 773 | 733 | −40 |
| 74 | 167 | 169 | +2 |
| 9 | 132 | 136 | +4 |
| 263 | 68 | 71 | +3 |
| 总事件 | 1,904 | 1,818 | **−86** |

**没有任何 task 出现与 escape 对应的单向增量**；最大差异（−40）方向还是负的，属窗口内背景活动波动。

## 三条硬限制

1. **只有数字 task id**。tracerpt 文本输出不含 manifest 名称，`task 68` 无法被确认为 "Present" 或其它语义。
2. **没有 NVIDIA 自有 provider**。`logman query providers` 里无 nvlddmkm 相关条目，escape 路径在 ETW 中无专属事件。
3. **无法把事件绑定到具体调用**。事件有 PID/TID，但一次 escape 与同进程的其它 D3DKMT 调用在时间上重叠，无法区分。

## 因此可以/不可以声称什么

可以：

- GPU 活动确实发生，且带有进程、线程、时间信息；
- 资源创建/销毁期间有事件产生。

不可以：

- 「escape 处理函数被执行」；
- 「授权分支被走到」；
- 「某个 task 就对应 Escape」。

## 复现

```bash
python -m tools.driver.etw_probe                      # 基线，无 escape
python -m tools.driver.etw_probe --escape             # 带一次 escape
# 聚合结果写在 data/driver/etw/*_summary.json
```
