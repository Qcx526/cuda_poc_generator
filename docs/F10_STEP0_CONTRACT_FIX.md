# P13-4-F9-R4-R1 / F10-Step0：合同修复与 V2 集成预检

基线 `64af220`。修两项真实错误、纠正一条错误报告、复核静态负结果、跑集成预检。

## 一、修掉公开字段的旁路

**问题**：`vendor` 类型错误时，Normalizer 已标 `INVALID`、`A1` 也不进 PUBLIC evidence，
但 `_value()` 会把原始对象 `str()` 化，照样写进 `TargetProfile.vendor`，
再从 `PUBLIC_ONLY` 的 `target.vendor` 漏出去。

**修法**：新增 `_trusted()`，只有字段状态为 `VALID` 才取值，否则回落 `"unknown"`。
`target / description / entry_surface` 全部改用 `_trusted()`。

回归测试 `test_untrusted_vendor_cannot_reenter_through_target_profile`：
把 `vendor` 改成 `{"nested": "leaked"}`，断言公开投影里没有 `leaked`，且 `target.vendor == "unknown"`。

**验证范围已改为检查完整 PUBLIC_ONLY payload**，不再只看 evidence IDs。

## 二、FACT_ASSISTED 服从授权

新增 `shared_payload_keys` 与 `share_missing`：

- `extension.payload` 只输出被点名的键，未授权的一律不出现；
- `missing` 默认不输出，需要 `share_missing=True`。

这样授权为空时，镜像 SHA256、候选 RVA、缺失提示都不会从旁路获得。

## 三、纠正"重复键无防护"的错误结论

上一轮我写"重复键由 json 静默取最后一个、完全没有防护"——**这是错的**。
`normalized_input.py` 已经用 `object_pairs_hook` 处理：

| 输入 | 实际行为 |
|---|---|
| `"vendor":"NVIDIA","vendor":"OtherCorp"` | `DUPLICATE_KEY_CONFLICT`，字段 `CONFLICT` |
| `"vendor":"NVIDIA","vendor":"NVIDIA"` | 无诊断，字段 `VALID`（值相同，等价） |

已补两条测试锁定行为，并确认 `CONFLICT` 值不会进入 PUBLIC（经 `_trusted` 拦截）。

## 四、静态负结果的可靠性复核

### 4.1 `function_bounds` 之前是无效证据

旧实现调用 `PEImage.function_at()`——**该方法不存在**（`function_at` 在另一个 dataclass 上），
所以 `function_at_rva=False` 什么也证明不了。审计这条是对的。

现在改用 `image.functions()`（`.pdata` 记录）做二分查找，输出：

```
rva 0x733e240 · section INIT · executable True
inside_pdata_record False · is_record_start False
```

即：**不在任何 .pdata 记录范围内**。

### 4.2 读到真实字节后，假设被推翻

```
0x733e240: 45 00 6e 00 61 00 62 00 6c 00 65 00 44 00 69 00
UTF-16LE : "EnableDirectFlip"
```

这是**配置字符串**，不是代码。而且不是孤例：

```
57 组 lea 目标分类：utf16-string 30 · unmapped 27 · code 0
```

**结论：`0x733e240` 不是 `DxgkDdiEscape`，此前的"回调候选"假设已证伪**（REFUTED，有字节证据）。

这不是"没找到证据"，而是**证据指向相反方向**——与 R1 那次"缺证据写成 REFUTED"是两回事：
那次是无据可依，这次是字节本身否定了假设。

### 4.3 两点限定

- `block_copies=0` 与 `argument_from_rbp=[]` 只是**当前窗口、当前指令模式**的负结果，
  不能断言对象绝对没被复制或传递；
- `INIT` 节 `executable=True`，不能把 `INIT` 当非代码——但本节的字节确实是字符串，
  这两件事不矛盾；
- **`.pdata` 未覆盖不等于绝对不是代码**：当前分类器只判断"是否落在记录内 + 首字节是否像
  UTF-16"，不是对执行语义的穷尽证明；`code=0` 也只覆盖本窗口的 57 个 lea 目标。

## 五、集成预检

`tools/driver/f10_preflight.py`，三个上下文全部经 `build_context()`：

| 上下文 | 证据 | SHA256 前 8 位 |
|---|---|---|
| `cuda_public`（PUBLIC_ONLY） | A1–A6 | `0cbec98c` |
| `driver_public`（PUBLIC_ONLY） | 无 | `133042e6` |
| `driver_facts`（FACT_ASSISTED） | S1–S7 | `1c59b66c` |

### 5.1 真实模型调用（两次，temperature=0）

| 上下文 | 引用 | 无效引用 | 无据 FACT | 编造地址 |
|---|---|---|---|---|
| cuda_public | A2 A3 A4 A5 A6 | 0 | 0 | 0 |
| driver_facts | S3 S5 S6 S7 | 0 | 0 | 0 |

模型只引用了给它的 id，没有编造地址，也没有把 FACT 写成无引用的断言。
原始输出：`data/driver/f10/llm_outputs.json`；上下文摘要：`prompt_contexts.json`。

**不计算任何成功率**——没有 Ground Truth，算了就是编造。

## 六、回归

```
1906 passed / 68 skipped / 0 failed
```

## 七、边界

未发私有 Escape、未重跑 CUDA CVE、未改 P11/P12、未新增 Mock 或 Agent；
静态范围仍在 Entry 起 6 KB；模型调用仅两次，只消费投影后的上下文。
