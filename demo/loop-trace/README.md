# 一次真实的闭环生成记录

生成阶段需要模型端点，无法离线复跑。这里放的是一次**实际运行**的完整痕迹，
用来在没有 API key 的情况下检查闭环的行为是否符合预期。

## 这次运行

| 项 | 值 |
|---|---|
| CVE | CVE-2025-23340（nvdisasm 畸形 ELF → 越界读） |
| 迭代 | 2 轮 |
| 结果 | 第 1 轮 `NOT_VERIFIED` → 第 2 轮 `SUPPORTED` |

## 三个文件

| 文件 | 内容 |
|---|---|
| `loop_report.zh-CN.md` | 人读报告：判定、逐轮诊断、结束原因 |
| `iteration_1_observation.txt` | 第 1 轮的原始执行输出（含 `[CPG_*]` 协议行） |
| `iteration_2_observation.txt` | 第 2 轮同上 |

## 该看什么

**① 第 1 轮为什么失败**

```
| 1 | `NOT_VERIFIED` | `NO_EFFECT` | No observable effect occurred. Verify the input
   actually reaches the parser ... |
```

`NO_EFFECT` 表示候选脚本跑起来了，但受控样本没有崩——输入没打到解析器。

**② 第 2 轮为什么成功**

```
| 2 | `SUPPORTED` | `—` |
```

同一条轨迹里能看到三条件逐条成立：

```
受控样本 3/3 个产生崩溃退出码
良性基线 3 个全部未崩溃
机制对照 3 个全部未崩溃
```

**③ 反馈是怎么生效的**

第 1 轮的诊断（`NO_EFFECT` + 具体指令）会写回第 2 轮的生成提示，
所以第 2 轮换了做法而不是重跑同一个脚本。两轮的观察文件对比即可看出差异。

## 判定仍然不采信候选自述

两轮的样本都是框架在容器里跑出来的，`[CPG_CRASH]` 行记录了模块、偏移、故障地址与出错指令。
候选脚本自己没有资格声明"已复现"。

## 想看自己的运行

```bash
cp .env.example .env          # 填模型端点与密钥
python -m src.batch_loop --cve CVE-2024-0076 --iterations 2 --workdir data/loop/mine
```

产物落在 `data/loop/mine/CVE-2024-0076/`，结构与本目录一致。
