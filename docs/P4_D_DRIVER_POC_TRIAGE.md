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

## 4. CVE-2024-0107：PoC 到不了触发点

在 `S03` 直接抛异常，未执行到着色器提交：

```text
File "...cuda_poc_v1.py", line 301, in find_sincos_offsets
    position = dxbc.find(chunk)
TypeError: argument should be integer or bytes-like object, not 'str'
```

`dxbc` 是 `bytes`，`chunk` 是 `str`。这是一个真实的代码缺陷，说明"生成成功"
不等于"可执行"。该组件是用户态 DLL，理论上触发只影响编译进程，但仍是驱动组件，
需在隔离环境验证后再考虑。

## 5. 本轮未做的事

- 未执行 0091（风险明确）、0107（代码缺陷未修）、24191（硬件不匹配）。
- 未修改原工程目录中的任何 PoC；只在本仓库 `data/reference/driver_pocs/` 放了副本。
- 未对 0090 的结果做"修正后重跑"：它本身没有利用步骤，改分类器也只会输出
  "AFFECTED — validate on an isolated host"，不产生新的漏洞证据。

## 6. 下一步

1. 把"受影响区间判定"独立实现为 `version_eligibility`，与 PoC 自述解耦；
   任何与 PoC 判定冲突的情况必须在报告里显式列出。
2. 0091 需要可回滚宿主；结论以"是否蓝屏 + 是否可复位"为观测，而不是进程退出码。
3. 0107 先修 `str/bytes` 缺陷，再在隔离环境编译恶意着色器，观察编译器是否崩溃。
