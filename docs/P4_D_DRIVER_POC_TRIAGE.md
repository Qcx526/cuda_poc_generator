# P4-D 驱动 PoC 分诊记录

报告语言：`zh-CN`。本文件记录对三个驱动类 CVE 的 PoC 做**静态审查与一次良性执行**的结果。
驱动缺陷触发成功是蓝屏级故障，不是进程崩溃，因此执行策略与工具链 CVE 完全不同。

## 1. 三个目标的触发性质

| CVE | 组件 | 触发路径 | 本机可否安全执行 |
|---|---|---|---|
| 2024-0090 | NVIDIA 显示驱动（内核态 + 用户态组件） | 公告未披露具体入口 | PoC 无利用步骤，仅良性探测 → 可执行 |
| 2024-0091 | NVIDIA 显示驱动 | 通过驱动 API 传入不可信指针 | **不可**：会真的把非法指针交给内核驱动 |
| 2024-0107 | `nvgpucomp64.dll`（用户态着色器编译器） | 提交篡改的着色器字节码 | PoC 存在代码缺陷，未到达触发点 |
| 2026-24191 | 显示驱动（仅 Maxwell/Volta/Pascal） | 竞态 | 硬件不匹配（GTX 1660 为 Turing） |

## 2. CVE-2024-0090 的实执行结果：一个假阴性

在驱动 **551.61**、`CUDA 11.2` 下执行 PoC（副本放在 `data/reference/driver_pocs/`，
原目录未改动）。PoC 全程只做 `NvAPI_Initialize`、打开/关闭显示驱动控制设备、GPU 健康快照，
**没有任何利用代码**，因此执行本身无风险。输出：

```text
installed_driver: [551, 61]
classify_reason:  driver major 551 is outside the affected branches (470/535/550/555)
affected: false
conclusion: PATCHED / NOT EXPLOITABLE in this environment
```

**这个结论是错的。** 原因在 PoC 自身的版本模型：

```python
FIXED_BRANCHES = {"470": (470,256,2), "535": (535,183,1),
                  "550": (550,90,7), "555": (555,52,4)}

def classify_driver_version(installed):
    key = str(installed[0])
    if key not in FIXED_BRANCHES:
        return False, "driver major %d is outside the affected branches"
```

它假定"主版本号必须等于表中某个分支才算受影响"。但 NVIDIA 公告对 **Windows GeForce**
的表述是"R555 分支 `555.99` 之前的所有版本受影响"——`551.61` 属于 R550 分支的 Windows
构建，数值上低于 555.99，**仍然受影响**。PoC 用一个错误的规则得出了恰好正确的旧结论
（当时驱动是 617.42，确实已修复），这是典型的"结论对、理由错"。

由此得到一条必须写进合同的规则：

> **生成 PoC 自述的版本判定不可信。** 受影响区间必须由独立实现判定，
> 不能引用 PoC 内部的分支表。

## 3. CVE-2024-0091：未执行，风险明确

PoC 在 `S04` 构造参数变异矩阵，把 `0xdeadbeef`、`0xffffffffffffffff` 等值传给
`cuModuleLoadData`、`nvmlDeviceGetHandleByIndex_v2`、`nvapi_QueryInterface` 等入口。
日志记录 7 个目标、35 次探测、0 次崩溃——但那是在驱动 617.42（已修复）上。

当前驱动 551.61 落在该 CVE 的受影响区间内，这些调用会真正进入缺陷路径。
探测虽在子进程中执行，但缺陷位于内核驱动，**子进程隔离挡不住蓝屏**。

结论：**不在唯一的工作机上执行**。需要第二台机器或可回滚的宿主快照。

## 4. CVE-2024-0107：已修复缺陷并执行，未触发

`nvgpucomp64.dll` 是**用户态**组件（着色器编译器），崩溃只影响编译进程，不会蓝屏，
因此是本组里唯一可以在单机上安全尝试的目标。当前驱动 551.61 携带的
`nvgpucomp64.dll` 文件版本为 **31.0.15.5161**，与 Talos 对 0107 记录的实测版本一致。

原 PoC 在 `S03` 抛出 `TypeError`（`dxbc.find(chunk)`，`chunk` 是 `str`、`dxbc` 是 `bytes`）。
在 `data/reference/driver_pocs/` 的副本中把 `("SHEX", "SHDR")` 改为 `(b"SHEX", b"SHDR")`
后，完整执行：

```text
[ENV] driver=551.61 vulnerable_branch=True
[ENV] nvgpucomp64.dll version=None            # 指纹未取到
[S02] baseline bytecode 612 bytes
[S03] SINCOS token offsets: ['0x138']
[S04] generated 4 variants
[SUBMIT] off0x138_val0x7fffffff: rc=0 crashed=False
[SUBMIT] off0x138_val0xffffffff: rc=0 crashed=False
[SUBMIT] off0x138_val0x0000ffff: rc=0 crashed=False
[SUBMIT] off0x138_val0x7fff0000: rc=0 crashed=False
S05 FAIL: no access violation observed on any variant
S07 FAIL: host in vulnerable range but no OOB read observed
```

**结论：负结果，不是复现。** 驱动在受影响区间，但当前变异策略没有触发缺陷。
可能原因（未验证，按优先级）：

1. 变异只改了 SINCOS 指令后的第一个 dword，未必命中 Talos 描述的
   "着色器编译器的 SINCOS 操作数处理"具体字段；
2. 基线 DXBC 由微软 `d3dcompiler_47.dll` 生成，指令编码可能已被折叠或改写；
3. 该缺陷可能需要特定寄存器类型/立即数组合，而不是任意毒化值。

另外 PoC 的 `nvgpucomp64.dll version=None` 说明它自己的指纹步骤没有取到版本，
本次"vulnerable_branch=True"来自驱动号而非组件版本，证据强度不足。

## 5. 内核路径（0091）的前置条件

`CVE-2024-0091` 的缺陷在内核驱动，触发成功可能直接蓝屏。**本机不执行**，除非满足：

1. 有第二台可丢弃机器，或当前机器可接受重启；
2. 已建系统还原点，并准备好安全模式恢复步骤；
3. 记录触发前的驱动版本、GPU 健康状态与基线 `nvidia-smi` 输出；
4. 单次运行、限时、可中止；触发后立即复位而不是连续重试。

在满足这些条件前，该 CVE 保持 `UNSUPPORTED_ENVIRONMENT`，不进入自动闭环。

## 6. 本轮未做的事

- 未执行 0091（内核路径，风险明确）与 24191（硬件不匹配）。
- 0107 只在宿主以子进程方式提交着色器，未做寄存器级或内核级观测。
- 未修改原工程目录中的任何 PoC；只在本仓库 `data/reference/driver_pocs/` 放了副本。
- 未对 0090 的结果做"修正后重跑"：它本身没有利用步骤，改分类器也只会输出
  "AFFECTED — validate on an isolated host"，不产生新的漏洞证据。

## 7. 下一步

1. 把"受影响区间判定"独立实现为 `version_eligibility`，与 PoC 自述解耦；
   任何与 PoC 判定冲突的情况必须在报告里显式列出。
2. 0107：先从 Talos 报告取回 SINCOS 操作数的精确编码与偏移，再重做变异；
   当前毒化策略只改指令后的第一个 dword，命中率不足。
3. 0091：需要可回滚宿主；结论以"是否蓝屏 + 是否可复位"为观测，而不是进程退出码。
