# 闭环复现记录：SMOKE-001

| 项 | 值 |
|---|---|
| CVE | `SMOKE-001` |
| 状态 | `EXHAUSTED` |
| 迭代次数 | 1 |
| 最终判定 | `NOT_VERIFIED` |

## 迭代轨迹

| # | 判定 | 诊断 | 处置指令（截断） |
|---|---|---|---|
| 1 | `NOT_VERIFIED` | `UNCLASSIFIED` | The failure does not match a known pattern. Add instrumentation that distinguishes 'did no… |

## 结束原因

- 未观察到任何样本退出码；输入可能未到达解析器

## 边界说明

`SUPPORTED` 只表示受控样本崩溃、良性基线干净、机制对照未全崩，
且目标版本处于受影响区间；它不等于 CVE 级 `VERIFIED`。
