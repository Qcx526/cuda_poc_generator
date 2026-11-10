# F15：2026 年 NVIDIA 新漏洞筛选与 CVE-2026-65160 nvJPEG 实验

起点 `c9397c3`。目标：验证现有方法能否迁移到一个**全新的库型漏洞**，而不是继续做工具链解析器。

## 一、2026 年 NVIDIA 公告筛选

官方索引共 **80 条** 2026 年公告。与 CUDA 直接相关的只有 2 条：

| 公告 | 日期 | CVE | 组件 | CWE | 能否用现有后端测试 |
|---|---|---|---|---|---|
| **5910** | 2026-11-03 | CVE-2026-65160 | **nvJPEG**（CUDA Toolkit 内） | CWE-369 除零 | **能**，库调用后端 |
| 5755 | 2026-01-20 | CVE-2025-33228/33229/33230/33231 | Nsight Systems / Nsight VS（CUDA Toolkit 内） | CWE-78 命令注入、CWE-427 搜索路径 | **不能**：需安装器/脚本注入/DLL 劫持 |

另有两条 CUDA 生态但不属 Toolkit：5820（CUDA-Q，CVE-2026-24189）、5738（Nsight Graphics，CVE-2025-33206）。

**口径提醒**：CVE-2025-33228~33231 编号是 2025，公告发布于 2026——"编号年份"与"公开年份"不是一回事。本轮只用 5910。

## 二、CVE-2026-65160 官方身份

| 项 | 值 |
|---|---|
| 公告 | 5910，2026-11-03 |
| 组件 | nvJPEG |
| CWE | CWE-369 Divide By Zero |
| CVSS | 5.5 MEDIUM，AV:L/AC:L/PR:N/UI:R |
| 受影响 | nvJPEG 0 – 26.06；CUDA Toolkit 0 – 13.4.1 |
| 修复 | nvJPEG 26.07；CUDA Toolkit 13.4 U1 |
| 公开描述内容 | 只有一句"可导致除零，进而拒绝服务"，**无函数、无字段、无尺寸、无配方** |

## 三、本机环境（实测，不靠标签推断）

| 项 | 值 |
|---|---|
| nvJPEG | **11.4.0**（`nvjpegGetProperty`，不是从容器标签推的） |
| 库文件 | `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\nvjpeg64_11.dll`，3,424,256 字节，SHA256 `f53e8d5d1940e6ca…` |
| Toolkit | CUDA 11.2 |
| 驱动 | 发行版本 **610.47**（`nvidia-smi`，与 `cuDriverGetVersion=13030` 区分） |
| GPU | GTX 1660，sm_75 |
| 版本适用性 | 11.4 < 26.06 → 落在官方受影响区间 |
| 修复版本 | 26.07 / 13.4 U1 **本机没有** → 无法做版本差分 |

## 四、正常基线（真实执行）

`data/driver/f15/baseline_nvjpeg.cu`（harness 自带，nvcc 编译，sm_75）：

```
nvjpegCreateSimple=SUCCESS
nvjpegJpegStateCreate=SUCCESS
nvjpegGetImageInfo=SUCCESS components=3 64x64
cudaMalloc=no error
nvjpegDecode=SUCCESS
cudaMemcpy=no error
PIXELS=12288 CHECKSUM=1356454264
BASELINE=DONE
```

证明：合法 JPEG 能走通真实 nvJPEG 解码路径，且有可复现的像素校验和。

## 五、LLM 生成与三轮反馈（全部留档）

候选只允许**构造输入**；解码由固定的 harness 二进制执行，候选无法伪造崩溃。

| 轮 | 假设（模型自述） | 构造 | 结果 |
|---|---|---|---|
| 1 | H 采样因子置 0 使 MCU 尺寸为 0 | `poc_nvjpeg_hsamp_zero.jpg` | `nvjpegGetImageInfo=BAD_JPEG components=1 0x0`，exit 1，**无崩溃** |
| 2 | 高度置 0 使行数除法除零 | `poc_h0_sampling_8x8_rgb.jpg` | 同上，`components=3 0x0`，exit 1 |
| 3 | 保持 SOF 合法但采样因子为 0 | `poc_sof_sampling_zero.jpg` | 同上，exit 1 |

每轮的 benign 与 control 都**正常解码**（exit 0，像素数一致），说明文件构造本身是合法的。

**判据修正（重要）**：我最初的分类把"非零退出"当作崩溃，于是第一轮被算成
`crafted_crashed: true`——那会把一次正常拒绝变成假阳性。现在只有
Windows 结构化异常（如 `0xC0000094` 除零、`0xC0000005` 访问冲突）或负退出码才算崩溃，
`exit=1` 一律记为**库正常拒绝**。

## 六、可信证据

| 项 | 值 |
|---|---|
| 解码器 | `baseline_nvjpeg.exe`，SHA256 已记入 `result.json` |
| 库身份 | nvjpeg64_11.dll SHA256 已记入 |
| 输入 | 每个 jpg 的 SHA256 与字节数 |
| 候选 | `candidate.py` SHA256 + 运行日志 |
| 观测 | 每个文件的 stdout/exit，由 harness 直接采集 |
| 判定来源 | 只来自 harness 执行，**不采信候选打印** |

## 七、十条问题的回答

1. **是否针对 2026 新披露漏洞做真实实验？** 是，CVE-2026-65160（公告 2026-11-03）。
2. **哪个组件与版本？** nvJPEG 11.4.0（CUDA 11.2 自带），驱动 610.47，GTX 1660。
3. **LLM 是否生成可运行的有效候选？** 是：三轮各生成 3 个合法 JPEG，benign/control 均能被 nvJPEG 成功解码。
4. **是否到达 nvJPEG 实际处理路径？** 到达**头解析**路径（`nvjpegGetImageInfo`），三轮都被它拒绝；未进入熵解码。
5. **是否观察到独立确认的异常？** **没有**。9 个文件、3 轮执行，无任何异常终止。
6. **能否证明除零机制？** 不能。没有任何崩溃，更没有根因证据。
7. **能否归属 CVE-2026-65160？** 不能，`CVE_ATTRIBUTED = 0`，机制状态 UNKNOWN。
8. **既有能力复用了多少？** Case V2、PUBLIC_ONLY 投影、LLM 客户端、候选/证据目录约定、SHA256 记录——**复用**；FILE_INPUT 后端**不适用**（nvJPEG 是库不是 CLI）；API_SEQUENCE 的"生成 C 程序"模式**部分复用**（本题改成生成输入构造脚本，解码器固定）。
9. **主要阻塞属于哪一类？** **公开信息不足 + 输入构造**。官方只给"除零"一句，没有字段；
   模型三轮都选了被前置校验拦下的零值字段。环境版本不是阻塞（11.4 在受影响区间），
   可信验证也不是阻塞（harness 能观察到异常终止，只是确实没有异常）。
10. **下一步更该加强什么？** 输入适配器——具体是让候选能探测"校验通过但派生量为零"的输入类，
    并给 nvJPEG 增加可观测的分阶段回调（解码哪一步失败）；其次是约束推理，最后才是生成速度。

## 八、结论

```
CVE-2026-65160
  TOOL_EXECUTED             ✓（9 次真实解码调用）
  CRASH_OBSERVED            ✗
  DIFFERENTIAL_SUPPORTED    ✗
  CVE_MECHANISM_SUPPORTED   ✗ (UNKNOWN)
  CVE_ATTRIBUTED            ✗
```

**NOT_VERIFIED**，原因：官方披露不含触发细节；三轮假设均被库的前置校验拒绝；
本机无 26.07 修复版本，无法做版本差分。

## 九、未做 / 明确延后

- 未安装 CUDA 13.4 / 26.07（会覆盖主机稳定环境，任务明确禁止）；
- 未做 5755 的 Nsight 案例（需要安装器/脚本注入，属高风险，仅做静态分析）；
- 未做 cpgkit 重构、提示词压缩、并行调度（本轮优先级在实验）。
