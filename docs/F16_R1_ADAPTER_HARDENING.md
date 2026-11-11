# F16-R1：JPEG 适配器工程化

起点 `bec891e`。本轮不新增 CVE 实验，只把适配器从实验代码提升为可测试、可复现的组件。

## 一、修掉的缺陷

### 1.1 SOF 字段偏移错误（审计确认）

`set_sof_size` 把 height 写在 `start+6`、width 写在 `start+8`。按 T.81 B.2.2，
从 `0xFF` 起算的实际布局是：

```
0 FF | 1 marker | 2-3 length | 4 precision | 5-6 height | 7-8 width | 9 Nf | ...
```

所以每次改尺寸都会**多写一个字节到前一个字段上**：height 的高位移到 precision，
width 的高位移到 height 的低位。现已改为 `+5` / `+7`，并加了针对性的回归测试：
断言改完后 `Nf`（分量数）与 `precision` 不变，且相邻分量的采样字节不变。

### 1.2 control 由"猜原始值"改为"逆序回放 journal"

旧实现用固定值恢复（sampling→1×1、DRI→64），插入的段不撤销、删除的段不恢复。
现在每个操作在执行时记录它替换了什么：

| 操作 | journal 记录 | 撤销方式 |
|---|---|---|
| `set_sof_size` | 原 width/height | 写回原值 |
| `set_component_sampling` | 原 h/v 与字节偏移 | 写回原字节 |
| `set_dri`（替换） | 原 interval | 写回原值 |
| `set_dri`（插入） | 插入偏移 | 删除该 6 字节段 |
| `insert_segment` | 偏移与块长 | 删除该块 |
| `strip_segment` | 偏移与原始字节 | 原位插回 |

撤销按**逆序**执行，因此偏移在撤销过程中自然复位。最后强制校验
`control == baseline`（逐字节），不相等就抛错——不会再产出"看起来像对照、实际不同"的文件。

### 1.3 fail-closed

| 输入 | 行为 |
|---|---|
| 宽/高 0、负数、>65535 | 抛 `AdapterError`（以前用 `& 0xFFFF` 静默截断） |
| 分量索引负数或 ≥ Nf | 抛错 |
| 采样因子不在 1–4 | 抛错 |
| DRI interval 不在 0–65535 | 抛错 |
| 插入 marker 非 APP/COM | 抛错 |
| payload > 65533 | 抛错 |
| progressive（SOF2）、无损、算术编码 | 抛错（`require_editable`） |
| 多 scan（sos_count > 1） | 抛错 |
| 重复 `set_dri` | 第二次按替换处理，保证文件里只有一个 DRI 段 |

### 1.4 依赖声明

`pyproject.toml` 增加 `jpeg` extra（`Pillow>=10,<14`），另加 `requirements-jpeg.txt`。
实测版本 **Pillow 13.0.0**。Pillow 只在 JPEG 适配器与参考解码中使用，ELF/cubin 链路不依赖它。

## 二、专项测试（`tests/test_jpeg_adapter.py`，15 项）

| # | 覆盖点 | 测试 |
|---|---|---|
| 1 | RGB / 灰度基线 | `test_baseline_rgb_and_gray_decode` |
| 2 | SOF 尺寸修改用真实偏移 | `test_sof_size_edit_uses_real_offsets` |
| 3 | SOF 精确恢复 | `test_sof_size_restores_exactly` |
| 4 | 采样修改与恢复 | `test_component_sampling_edit_and_restore` |
| 5 | 非法索引/范围 | `test_sampling_rejects_bad_index_and_range` |
| 6 | 尺寸越界不掩码 | `test_sof_size_rejects_out_of_range_instead_of_masking` |
| 7 | DRI 插入/替换/恢复 | `test_dri_insert_replace_and_restore` |
| 8 | DRI 范围 | `test_dri_interval_range_and_duplicate_dri_refused` |
| 9 | 段插入/删除与恢复 | `test_segment_insert_and_strip` |
| 10 | 非法 marker / 超长 payload | `test_segment_rejects_bad_marker_and_long_payload` |
| 11 | 多操作逆序恢复 | `test_multiple_operations_restore_in_reverse` |
| 12 | SHA256 确定性 | `test_sha256_is_deterministic` |
| 13 | progressive 拒绝 | `test_progressive_and_multiscan_refused` |
| 14 | bundle provenance | `test_write_bundle_provenance` |
| 15 | control 不一致必须报错 | `test_control_mismatch_is_detected` |

**全部使用真实 Pillow 解码**，没有任何 mock 替换解码判定。
结果：`15 passed`。

## 三、干净克隆验证

```
git clone --depth 1 → tests/test_jpeg_adapter.py → 15 passed in 0.16s
smoke: build_baseline → write_bundle(plan=[set_sof_size 48x32, set_dri 0])
       control_equals_baseline: True
       poc_vs_control: same_length=False (left=1518, right=1512)
       ref: BENIGN ok / MALICIOUS ok / CONTROL ok，poc 段含 DRI(0)
```

## 四、F16 指标的降格与更正

F16 曾写"67% → 100%"，本轮按审计要求降格为**探索性观察**，并重算分层指标：

| 层 | A（F15 历史） | B（F16 三轮） |
|---|---|---|
| 模型 POC 数 | 6 | 3 |
| POC 参考解码接受 | 2/6 | 3/3 |
| benign 接受 | 5/6 | 3/3 |
| **control == baseline** | 未定义 | **0/3** |
| **严格配对样本** | 0 | **0** |

**0/3 的原因**：F16 的 `build_control` 用固定值恢复。实测 run1/run2 的 control 带 `DRI(64)`，
run3 的 control 带 `DRI(64)` + `DRI(0)`（即审计指出的重复段）。原始实验文件未修改，
登记为历史缺陷（见 `docs/F16_JPEG_ADAPTER.md` §3.4），并在严格配对统计中排除全部三轮。

因此本轮不宣称"适配器带来确定因果提升"。可以说的是：**结构合法成为默认结果**，
且**严格 control 合同现在由代码强制**，而不是靠约定。

## 五、长期接口（已实现的部分）

统一合同，不引入框架：

| 合同 | 现状 |
|---|---|
| mutation plan（数据，不是代码） | `apply_plan(baseline, plan) -> (bytes, journal)` |
| artifact provenance | `write_bundle` 写 `plan.json`：journal、`control_equals_baseline`、差范围 |
| reference validation | `reference_decode`（JPEG=Pillow；ELF 对应 readelf 待接） |
| control restoration | journal 逆序 + 逐字节校验 |
| execution feedback | 探针逐阶段输出，适配器不参与判定 |

ELF/cubin、C/CUDA、IOCTL、API_SEQUENCE 只保留这四个合同的形状，**未建空壳**。
IOCTL 未来需要区分：设备身份、控制码、输入/输出缓冲区布局、运行权限。

## 六、未解决

1. 历史三轮 control 不严格，无法追溯修复（原始文件保留，已在统计中排除）；
2. 适配器不支持 SOS 参数、progressive、无损、算术编码——这些会改变熵流语义；
3. 尚未用新的严格 control 重跑 B 臂实验（本轮范围限定为工程化，未跑新实验）；
4. 仍未证明真实越界写（需要 PageHeap/ASan）。
