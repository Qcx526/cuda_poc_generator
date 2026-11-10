# F15 补充：历史归档重评、多版本 nvJPEG 环境与跨版本对照

起点 `746a5df`。本补充完成三件事：改正历史判定、建立新版 nvJPEG 环境、给出跨版本对照。

## 一、历史归档重评（不动原始证据）

`run1/result.json` 是旧分类器写的，把 `exit=1`（库返回 BAD_JPEG）算成了崩溃，于是
`crafted_crashed=true`、`differential=true`。那是**假阳性**。

处理方式：原文件字节未改，另存 `result.corrected.json` 与汇总 `verdicts.corrected.json`。

| 轮次 | 原始判定 | 更正后 | 被拒文件 |
|---|---|---|---|
| run1 | crafted_crashed=true, differential=true | **false / false** | poc_nvjpeg_hsamp_zero.jpg |
| run2 | false / false | false / false | poc_h0_sampling_8x8_rgb.jpg |
| run3 | false / false | false / false | poc_sof_sampling_zero.jpg |

`run1/result.json` 的 SHA256 保持 `5b48e861d0e464d8…`，可对比证明未篡改。
更正规则：**只有异常终止（负退出码或 Windows 结构化异常）才算崩溃**；
`exit=1` 是库返回错误状态，记为正常拒绝。

## 二、建立新版本环境（隔离，不动系统）

按"自主安装独立版本"的授权：

1. 下载 `cuda_13.4.1_windows_x86_64.exe`（3,750,931,600 字节）到 `D:\cuda_installers`；
2. **不安装**，用 7zr 只解出 nvJPEG 组件到 `D:\cuda1341_extract`；
3. 得到 `nvjpeg64_13.dll`（4,523,120 字节，SHA256 `957bb73818e62883ac4bfc0aa15204b…`），
   `nvjpegGetProperty` 报 **13.2.2**；
4. 写了一个**只走 driver API** 的解码器（`baseline_nvjpeg_drv.cpp`），用 cl.exe 直接编译，
   链接 13.x 的 `nvjpeg.lib` + 11.2 的 `cuda.lib`——避开 cudart 13 的版本耦合；
5. 正常基线通过：`nvjpegGetImageInfo=SUCCESS 3 64x64`、`nvjpegDecode=SUCCESS`、
   `PIXELS=12288`。

系统 CUDA 11.2/12.4、驱动 610.47 均未被修改。

## 三、跨版本对照：9 个输入 × 3 个库版本

| 轮 | 文件 | 11.4.0 | 12.3.1 | 13.2.2 |
|---|---|---|---|---|
| run1 | benign_nvjpeg_sampling_11.jpg | 0 | 0 | 0 |
| run1 | ctrl_nvjpeg_sampling_11_restored.jpg | 0 | 0 | 0 |
| run1 | poc_nvjpeg_hsamp_zero.jpg | 1 | 1 | 1 |
| run2 | benign_sampling11_8x8_rgb.jpg | 0 | 0 | 0 |
| run2 | ctrl_restored_sampling11_8x8_rgb.jpg | 0 | 0 | 0 |
| run2 | poc_h0_sampling_8x8_rgb.jpg | 1 | 1 | 1 |
| run3 | benign_color_64x64_samp_11.jpg | 0 | 0 | 0 |
| run3 | ctrl_sof_sampling_11.jpg | 0 | 0 | 0 |
| run3 | poc_sof_sampling_zero.jpg | 1 | 1 | 1 |

**27 次执行，行为完全一致**：良性与对照永远成功，三个候选永远被拒，没有一次异常终止。

顺带一个可观测差异：同一张 64×64 JPEG 在 13.2.2 上解出的校验和与 11.4.0 不同
（`1160047537` vs `1356454264`）。说明三版实现确有差异，但**差异不在崩溃面上**。

## 四、版本对照的客观限制

官方口径是"受影响 0–13.4.1，修复 13.4 U1"。本机拿到的 13.4.1 里的 nvJPEG 是 13.2.2，
它是否等于"13.4 U1"无法从公开信息判定——NVIDIA 的 U1 命名与 13.4.x 点版本号的对应关系
没有官方说明。因此：

- 我们能确认：**三个不同版本的 nvJPEG 对同一批输入行为一致**；
- 我们不能声称：**做过"受影响 vs 已修复"的差分**。

这一条如实记为 `VERSION_DIFFERENTIAL = NOT_ESTABLISHED`。

## 五、结论（未变）

```
CVE-2026-65160
  TOOL_EXECUTED             ✓（36 次真实解码：9 输入 × 4 次，含基线）
  CRASH_OBSERVED            ✗
  DIFFERENTIAL_SUPPORTED    ✗
  CVE_MECHANISM_SUPPORTED   ✗ UNKNOWN
  CVE_ATTRIBUTED            ✗
```

阻塞仍在**输入构造**：模型的三个假设（H 采样=0、高度=0、SOF 采样=0）都被前置校验拒绝，
一个都没走到算术阶段。环境已不再是阻塞——13.x 已隔离就位，可随时复跑。

## 六、产物

```
data/driver/f15/run{1,2,3}/result.corrected.json   更正判定
data/driver/f15/verdicts.corrected.json            三轮汇总
data/driver/f15/cross_version.json                 9 输入 × 3 版本
data/driver/f15/baseline_nvjpeg_drv.cpp            13.x 解码器源码
data/driver/f15/nvjpeg13_decoder.exe               编译产物
D:\cuda1341_extract\…\nvjpeg64_13.dll              13.2.2（4.5 MB，不入库）
```
