# F16-R2：JPEG 解析器契约加固、Manifest 与严格 A/B

起点 `3113995`（工作区中另有未提交的 `require_trusted` 接线，已先单独提交为 `0d0686d`）。

**实验对象统一命名为**：nvJPEG JPEG Input Generation and Differential Behavior Experiment。
本轮不把它表述为已确认的 NVIDIA CVE 复现。

## 一、解析器加固

### 1.1 旧实现的缺陷

`walk()` 在第一个 SOS 处 `break`，因此：

- 无法统计真实扫描数，多扫描 JPEG 会被当成单扫描；
- SOS 之后的合法段完全没读到；
- 熵区内的 `FF 00`、`FF D0-D7` 从未被正确处理。

### 1.2 新解析器（`src/jpeg_parser.py`）

状态机按 T.81 遍历，熵区规则：

| 字节 | 处理 |
|---|---|
| `FF 00` | 熵数据里的填充字节，继续当前扫描 |
| `FF D0-D7` | 重启标记，属于扫描，继续 |
| `FF FF` | 标记前填充，跳过 |
| 其他 `FF xx` | 当前扫描结束，回到标记解析 |

其它规则：段长 < 2 拒绝；段长越界（截断）拒绝；EI 前无 EOI 拒绝；`FF 00` 出现在扫描外拒绝；
RST 出现在扫描外拒绝。

### 1.3 Marker 策略表（fail-closed）

| 类别 | 标记 | 行为 |
|---|---|---|
| 支持 | SOI EOI DQT DHT SOF0 SOF1 SOS DRI | 解析并允许编辑 |
| 透传 | APP0–APP15、COM | 解析、允许存在、可插入/删除 |
| 已知但拒绝 | SOF2/3/5/6/7/9/10/11/13/14/15、DAC、DNL、DHP、EXP、TEM | 抛 `ParserError`，附原因 |
| 未知 | 其余一切 | 抛 `ParserError`，不静默跳过 |

### 1.4 重复 DRI

- 解析阶段统计 `dri_count` 与全部 `dri_values`；
- **基线存在多个 DRI 直接拒绝编辑**（没有唯一可恢复的原值，control 无法逐字节还原）；
- 单个 DRI 的替换记录原 interval；
- 无 DRI 时允许插入，journal 记录插入偏移，撤销时删除该 6 字节段；
- 重复 `set_dri` 确定性处理：第二次为替换，文件里始终只有一个 DRI 段。

### 1.5 明确边界

只支持 Baseline / Extended Sequential 单扫描。Progressive、无损、算术编码、多扫描一律拒绝。
**结构解析成功 ≠ 熵流合法**：可解码性仍由 Pillow 判定，两条结论分开记录。

## 二、Manifest 与离线核验

`write_bundle()` 现在同时产出 `manifest.json`（schema `jpeg-bundle-manifest/v1`）：

| 段 | 内容 |
|---|---|
| `adapter` | 适配器版本、**源码 SHA256**（adapter+parser 字节合并）、参考解码器与版本、Python 版本 |
| `artifacts.{baseline,candidate,control}` | 文件名、SHA256、字节数、结构摘要（SOF/SOS/DRI/熵字节）、参考解码结果 |
| `pairing` | control 是否与 baseline 逐字节相同、candidate 是否不同于 baseline、两处差异范围 |
| `provenance` | canonical plan + `plan_sha256`、journal + `journal_sha256` |
| `manifest_sha256` | 除自身外全字段的 canonical 哈希 |

**确定性**：`json.dumps(sort_keys=True, separators=(",",":"))`，不含时间戳、绝对路径、UUID。
运行环境信息只放 `adapter` 的固定字段（版本号），不参与内容身份的可变因素。

`verify_bundle(directory)` 会重算：manifest 哈希、plan/journal 哈希、三文件 SHA256 与字节数、
`control == baseline`、以及（可选）重新执行参考解码并比较判定。任何不一致直接抛 `BundleError`，
**不自动修复**。

## 三、严格 A/B 实验

### 3.1 设计

| 项 | A 臂 | B 臂 |
|---|---|---|
| 模型输入 | 相同 baseline（SHA 一致）+ 相同假设文本 | 同左 |
| 模型输出 | 完整 JPEG 的 Base64 | 结构化 Mutation Plan |
| Harness 处理 | 自解码 → 校验 → 结构解析 → 参考解码 → 探针 | 适配器构造 → journal → manifest → 探针 |
| 执行模型代码 | **不执行** | **不执行** |
| Control | baseline 副本，比较 SHA/字节 | journal 逆序恢复，强制 `== baseline` |

模型、温度(0)、每格 1 次调用、无重试、无筛选；两臂各自独立反馈，未互相污染。
5 组为探索性样本，不做统计显著性声明。

### 3.2 版本冻结

| 版本 | DLL | SHA256 |
|---|---|---|
| 13.2.2 | `D:\cuda1341_extract\libnvjpeg\nvjpeg\bin\x64\nvjpeg64_13.dll` | 见 `summary.json` |
| 11.4.0 | `C:\...\CUDA\v11.2\bin\nvjpeg64_11.dll` | 见 `summary.json` |

探针 `nvjpeg_probe.exe` 未改动，STAGE1/4/5/6/7 语义与 F15-R3 一致，仅 STAGE7 全通过才记完整解码。

### 3.3 结果（全部原始输出在 `data/driver/f16r2/ab/`）

| 组 | 假设类别 | A 输出 | A 参考解码 | A STAGE4/7 | B 输出 | B 参考解码 | B STAGE4/7 | B 严格配对 |
|---|---|---|---|---|---|---|---|---|
| H1 | restart-interval | 有效 base64 | ✗ broken stream | 2/2 | 构建成功 | ✓ 64x64 | 2/2 | ✓ |
| H2 | scan-structure | 有效 base64 | ✗ broken stream | 2/0 | 构建成功 | ✓ 64x64 | 2/2 | ✓ |
| H3 | app-metadata | **base64 缺 padding** | — | 0/0 | 构建成功 | ✓ 64x64 | 2/2 | ✓ |
| H4 | sampling-geometry | **base64 缺 padding** | — | 0/0 | 构建成功 | ✗ broken stream | 2/0 | ✓ |
| H5 | sof-geometry | **无 base64 块** | — | 0/0 | 构建成功 | ✗ broken stream | 2/2 | ✓ |

崩溃：**A 0 / B 0**。

### 3.4 分层指标

| 指标 | A | B |
|---|---|---|
| Model Output Success | 2/5 | **5/5** |
| Candidate Count | 2 | 5 |
| Structural Acceptance | 2/2 | 5/5 |
| Reference Acceptance（候选） | **0/2** | **3/5** |
| Native STAGE4（通过/总运行） | 4/4 | 10/10 |
| Native STAGE7 | 2/4 | 8/10 |
| Crash Count | 0 | 0 |
| Strict Pair Count | 2/5 | **5/5** |
| Unique Mutation Families | —（失败为主） | **5/5**（五类各不相同） |
| Bundle Verified | 不适用 | 5/5 |
| Duplicate Candidate | 0 | 0 |

**Token 消耗**：LLM 客户端未返回 usage，只能记录响应字符数（A: 380/716/251/285/193；
B: 149/306/350/258/204），不能作为 token 统计，如实标注为不可得。

### 3.5 关键观察

1. **A 臂的主要失败不是"构造错了"，而是输出合同违约**：3/5 是 base64 缺 padding 或干脆没有代码块。
   这些是格式层失败，与 JPEG 语义无关。
2. **A 臂两次有效 base64 都被参考解码器拒绝**（`broken data stream`），与 F15 第七轮同一失效模式。
3. **B 臂五类假设全部落地为不同变异族**，且全部通过 manifest 离线核验。
4. **nvJPEG 与 Pillow 判定不一致的样本存在**：H5 B 的候选 Pillow 拒绝、nvJPEG 却走完 STAGE7；
   H1/H2 A 的候选 nvJPEG 通过头解析说明它也接受部分 Pillow 拒绝的流。
   这只能说明两个解码器宽容度不同，**不构成漏洞证据**。
5. 没有一次异常终止，因此不存在可归因的崩溃。

## 四、工程验收

| 项 | 结果 |
|---|---|
| JPEG 适配器测试 | 15 passed |
| 解析器测试 | 13 passed（含真实 progressive 多扫描识别、FF00、RST、截断、非法段长、重复 DRI、未知 marker、算术编码拒绝） |
| Manifest / 离线核验测试 | 8 passed（篡改候选、删文件、改 plan、control 不等于 baseline 全部报错） |
| 全量回归 | **1988 passed / 67 skipped / 0 failed** |
| `compileall` | 通过 |
| `git diff --check` | 通过 |
| 干净克隆 | 见下 |

干净克隆验证：`git clone --depth 1` → 安装 `.[jpeg]` 等价依赖 → 36 项 JPEG 测试全过 →
`verify_bundle` 通过 → smoke（baseline+plan→三件套）通过。

## 五、局限

1. 5 组样本，仅作探索；不能据此宣称普遍提升或统计显著。
2. Token 统计缺失（客户端无 usage 返回）。
3. 只有两个 DLL 版本，版本集合虽已冻结但不足以覆盖 13.4 U1。
4. A 臂失败中含格式违约，说明该对照组同时受"输出纪律"影响，比较的是"完整链路可用性"而非纯构造能力。
5. 没有内存安全证据（无 PageHeap/ASan），不宣称越界写。

## 六、结论

**能宣称的**：结构化变异把"模型输出合同违约"与"熵流非法"两类失败都消除了——
B 臂 5/5 输出合规、5/5 严格配对、5/5 manifest 可离线核验；A 臂 2/5 输出合规、0/2 可解码。

**不能宣称的**：没有异常、没有漏洞机制证据、没有版本差分归因。
本阶段验证的是**输入生成与证据验证方法**，不是某个漏洞的可复现性。
