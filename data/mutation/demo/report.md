# CVE-2025-23340 变异战役

种子基线指纹：`nvdisasm+0x28000`

| 类别 | 数量 | 含义 |
|---|---|---|
| `SAME_SITE` | 4 | 与种子同一处崩溃 |
| `CLEAN` | 3 | 不崩溃 |
| `NOVEL_SITE` | 0 | **崩溃在别处，候选新发现** |
| `NO_SIGNAL` | 0 | 无可用信号 |

## 结论

- 机制轴全部落在同一崩溃点：把 `sh_type` 改成 [4, 3, 1] 都不改变崩溃位置，说明崩溃与声明机制无关——按当前证据它**不是**该 CVE。
- 边界轴：[0] 崩溃，[11, 12, 24] 不崩溃。
- 注意：公告声称 0..11 都应触发，但实测只有 0 触发——该构建的有效窗口比文档更窄。

## 明细

| 轴 | 字段 | 取值 | 退出码 | 指纹 | 访问 | 判定 |
|---|---|---|---|---|---|---|
| seed | (unchanged) | 0 | 139 | `nvdisasm+0x28000` | null-read | `` |
| boundary | sh_size | 0 | 139 | `nvdisasm+0x28000` | null-read | `SAME_SITE` |
| boundary | sh_size | 11 | 0 | `-` | - | `CLEAN` |
| boundary | sh_size | 12 | 0 | `-` | - | `CLEAN` |
| boundary | sh_size | 24 | 0 | `-` | - | `CLEAN` |
| mechanism | sh_type | 4 | 139 | `nvdisasm+0x28000` | null-read | `SAME_SITE` |
| mechanism | sh_type | 3 | 139 | `nvdisasm+0x28000` | null-read | `SAME_SITE` |
| mechanism | sh_type | 1 | 139 | `nvdisasm+0x28000` | null-read | `SAME_SITE` |
