# F11-L：WSL Linux 侧接入与跨平台复用验证

基线 `0aa8cd2`。起因：放开系统级工具后 WSL 可用，验证 Linux 侧能否承担 Driver API 实验。

## 一、WSL 可用性与 GPU 栈的真实故障

| 检查 | 结果 |
|---|---|
| `wsl -l -v` | Ubuntu-22.04（Stopped）/ docker-desktop |
| `/dev/dxg` | 存在（`crw-rw-rw- 10,125`）→ GPU 直通设备在位 |
| `nvidia-smi` | **崩溃**：`ld.so: dl-setup_hash.c:36 Assertion '(bitmask_nwords & (bitmask_nwords-1)) == 0' failed` |
| `ctypes.CDLL('/usr/lib/wsl/lib/libcuda.so.1')` | **失败**：`l": cannot open shared object file` |
| 该库的 `.gnu.hash` | `bloom_size=64`，**是 2 的幂**，结构合法 |
| 与 Windows `lxss/lib` 对比 | **SHA256 完全相同**（`158e0c4e…`） |

库本身没坏、和 Windows 侧逐字节一致，却加载失败——所以问题不在文件内容。

### 1.1 根因：9p 挂载点

把**同一个文件**拷到 ext4 后立即正常：

```
cp /usr/lib/wsl/lib/libcuda.so.1 /tmp/ && dlopen("/tmp/libcuda.so.1")
→ loaded from ext4 · cuInit 0 · cuDriverGetVersion 13030
```

**结论**：`/usr/lib/wsl/lib` 这个 9p/drvfs 镜像挂载点在当前内核（6.6.87.2）与 glibc 2.35 组合下
无法 dlopen，属于**挂载层问题**，不是驱动或库的问题。

### 1.2 固化修复

```bash
mkdir -p ~/cuda-wsl-libs && cp -f /usr/lib/wsl/lib/*.so* ~/cuda-wsl-libs/
export LD_LIBRARY_PATH=$HOME/cuda-wsl-libs:$LD_LIBRARY_PATH
```

验证（20 个库已复制）：

```
cuInit: 0 · cuDeviceGet: 0 → device 0
name: NVIDIA GeForce GTX 1660
cc: 7.5
driver_api: 13030
```

与 Windows 侧身份完全一致（同一张卡、同一驱动 API 版本）。

## 二、跨平台复用：同一份生成代码两边跑

拿 Windows 轮次生成的 **原封不动** 的候选源码，在 WSL 用 gcc 编译执行：

| 候选 | Windows（nvcc + nvcuda.dll） | Linux（gcc + libcuda） |
|---|---|---|
| `normal/candidate1.c` | BUILD 0 / RUN 0 / `DATA=OK` | **BUILD 0 / RUN 0 / `DATA=OK`**（8 个 API 全 0） |
| `boundary/candidate1.c` | BUILD 0 / RUN 0 / `BOUNDARY=DONE` | **BUILD 1**：`fatal error: windows.h: No such file or directory` |

### 2.1 这暴露了我 F11 设计里的一个真缺陷

`boundary` 候选含 `#include <windows.h>`——**我的提示词从没声明目标平台**，
模型自然按 Windows 写（前一轮跑在 Windows 上，看起来"没问题"）。

这不是模型的错，是任务规格缺失。修复：提示词显式声明 "Linux x86-64、禁止 windows.h、
用 gcc 可编译"，并由 case 的 `target.platform` 驱动。

修复后 Linux 侧重新生成并执行（`tools/cuda/f11_wsl.py`）：

```
BUILD_RC=0
API cuInit = 0 … cuCtxDestroy = 0   （8 条全 0）
DATA=OK
RUN_RC=0
```

**同一套 Case V2 → build_context → LLM → C 代码 → 编译 → 真实 GPU**，
在 Windows 与 Linux 两侧都跑通。

## 三、必须说清的边界

**WSL 的 `libcuda` 不是原生 Linux 驱动**：它是经 DXCore 转发到 **Windows 驱动** 的兼容层。
因此：

- 能验证：Linux 用户态下 API 语义、参数校验、生命周期；
- **不能**验证：Linux 内核驱动代码路径、Linux 特有的驱动行为。

把 WSL 结果当作"Linux 驱动行为"是错的。要做真正的平台对照，仍需原生 Linux + GPU 主机。

## 四、产物

```
data/driver/f11-linux/{prompt.txt,response.txt,candidate.c,run.log}
tools/cuda/f11_wsl.py           Linux 侧生成 + 编译 + 执行
```

## 五、回归

```
1912 passed / 68 skipped / 0 failed
```

## 六、下一步建议

1. 把 `f11_wsl.py` 的编译/执行部分抽成 `cuda_api_backend` 的第二个 transport，
   让 `build_context` 之后的流程完全平台无关（目前是两份脚本）；
2. `ToolInvocation` 仍未接入 FILE_INPUT 执行器——这是测量基础设施里最欠的一环。
