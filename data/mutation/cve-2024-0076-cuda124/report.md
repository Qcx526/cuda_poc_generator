# CVE-2024-0076 变异战役

种子基线指纹：`（未记录）`

| 类别 | 数量 | 含义 |
|---|---|---|
| `SAME_SITE` | 0 | 与种子同一处崩溃 |
| `CLEAN` | 4 | 不崩溃 |
| `NOVEL_SITE` | 0 | **崩溃在别处，候选新发现** |
| `NO_SIGNAL` | 6 | 非零退出但无崩溃点（多为工具拒绝），或无结果 |

## 结论

- 本轮没有产生可判读的差异。

## 明细

| 轴 | 字段 | 取值 | 退出码 | 指纹 | 访问 | 判定 |
|---|---|---|---|---|---|---|
| seed | (unchanged) | 0 | 0 | `-` | - | `` |
| boundary | sh_size | 16 | 0 | `-` | - | `CLEAN` |
| boundary | sh_size | 4294967295 | 1 | `-` | - | `NO_SIGNAL` |
| boundary | sh_size | 18446744073709551600 | 0 | `-` | - | `CLEAN` |
| structure | e_shnum | 11 | 0 | `-` | - | `CLEAN` |
| structure | e_shnum | 1 | 1 | `-` | - | `NO_SIGNAL` |
| structure | e_shnum | 4096 | 1 | `-` | - | `NO_SIGNAL` |
| structure_shstrndx | e_shstrndx | 9 | 1 | `-` | - | `NO_SIGNAL` |
| structure_shstrndx | e_shstrndx | 99 | 1 | `-` | - | `NO_SIGNAL` |
| mechanism_offset | sh_offset | 1024 | 0 | `-` | - | `CLEAN` |
| mechanism_offset | sh_offset | 100000 | 1 | `-` | - | `NO_SIGNAL` |
