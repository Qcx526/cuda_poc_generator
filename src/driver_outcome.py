# -*- coding: utf-8 -*-
"""Turn a driver probe run into one of ten states the LLM can act on.

An exit code alone cannot tell "the call was refused" from "the code never got
there", and those two demand opposite next moves: fix the argument, or fix the
path. So a candidate is required to print a single ``CPG_RESULT`` JSON line
describing what it did; this module reads that line, falls back to the process
exit status when it is missing, and returns a state plus the one sentence that
should go back into the next prompt.

The contract for the candidate's last line::

    CPG_RESULT {"stage": "escape", "status": -1073741790, "reached": false,
                "calls": [{"api": "D3DKMTCreateDevice", "status": 0}],
                "notes": "..."}
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BUILD_FAILED = "BUILD_FAILED"
API_CALL_FAILED = "API_CALL_FAILED"
API_REJECTED = "API_REJECTED"
INPUT_REJECTED = "INPUT_REJECTED"
TARGET_NOT_REACHED = "TARGET_NOT_REACHED"
TARGET_REACHED = "TARGET_REACHED"
USERMODE_FAULT = "USERMODE_FAULT"
KERNEL_BUGCHECK = "KERNEL_BUGCHECK"
TIMEOUT = "TIMEOUT"
ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"

ALL_STATES = (BUILD_FAILED, API_CALL_FAILED, API_REJECTED, INPUT_REJECTED,
              TARGET_NOT_REACHED, TARGET_REACHED, USERMODE_FAULT,
              KERNEL_BUGCHECK, TIMEOUT, ENVIRONMENT_MISMATCH)

# What the next round should try, per state. This is the text the analyst sees,
# not a decision the loop makes on its own.
NEXT_MOVE = {
    BUILD_FAILED: "先修构建：缺头文件/结构体定义或编译命令错误；不要改触发逻辑",
    API_CALL_FAILED: "调用本身失败（不存在/参数错/句柄无效）：核对接口签名与句柄来源",
    API_REJECTED: "驱动拒绝了请求：检查参数取值、对象状态与调用顺序，而不是随机改 payload",
    INPUT_REJECTED: "输入在进入目标前被拒：放宽/校准结构体字段，使其通过前置校验",
    TARGET_NOT_REACHED: "没有到达目标代码：优先调整入口路径或调用序列，暂不改触发字段",
    TARGET_REACHED: "已到达目标：保持入口不变，只微调触发字段与取值",
    USERMODE_FAULT: "用户态崩溃：先判断是调用约定/结构体错，还是目标缺陷初现",
    KERNEL_BUGCHECK: "内核崩溃：停止本批，保留现场，等待环境恢复后再单次重试",
    TIMEOUT: "超时：缩小输入规模或降低等待，先确认进程是否卡在驱动",
    ENVIRONMENT_MISMATCH: "环境不符：驱动版本/架构/设备不在受影响范围，先换环境",
}

_RESULT_MARK = "CPG_RESULT"

# Status codes that mean "the platform is not there", not "the driver said no".
_ENV_CODES = {
    -1073741275,   # STATUS_NOT_FOUND
    -1073741515,   # STATUS_DLL_NOT_FOUND
    -1073741701,   # STATUS_INVALID_IMAGE_FORMAT
}
# A Win32 call that returns BOOL/HANDLE signals failure with -1 or NULL, not with
# an NTSTATUS. Treating that as "the driver refused" sends the next round looking
# at parameter values when the actual problem is the call itself.
_WIN32_FAILURE = (-1, 0xFFFFFFFF)
# Windows reports a crashed process as an unsigned exception code, not a negative
# number, so a bare `returncode < 0` check misses it entirely.
_USERMODE_EXCEPTIONS = (0xC0000005, 0xC0000409, 0xC00000FD, 0xC0000135, 0xC0000374)
_ACCESS_DENIED = -1073741790
_INVALID_PARAMETER = -1073741811


@dataclass
class Outcome:
    state: str
    reason: str
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def next_move(self) -> str:
        return NEXT_MOVE.get(self.state, "")

    def as_dict(self) -> Dict[str, Any]:
        return {"state": self.state, "reason": self.reason,
                "next_move": self.next_move, "detail": self.detail}


def parse_result(output: str) -> Optional[Dict[str, Any]]:
    """The candidate's own account of the run, if it printed one."""
    for line in reversed(output.splitlines()):
        if _RESULT_MARK not in line:
            continue
        payload = line.split(_RESULT_MARK, 1)[1].strip()
        try:
            return json.loads(payload)
        except ValueError:
            match = re.search(r"\{.*\}", payload)
            if match:
                try:
                    return json.loads(match.group(0))
                except ValueError:
                    return None
    return None


def _looks_like_build_error(output: str) -> bool:
    marks = ("SyntaxError", "ModuleNotFoundError", "ImportError",
             "NameError", "IndentationError", "command not found")
    return any(mark in output for mark in marks)


def classify(*, returncode: Optional[int], output: str = "",
             timed_out: bool = False, bugcheck: Optional[dict] = None,
             expected_reached: bool = False,
             external_evidence: Optional[List[dict]] = None) -> Outcome:
    """Decide what happened, in the order that cannot be argued with.

    A bugcheck outranks everything: whatever the candidate printed, the machine
    went down. A missing result line means the candidate never got to say what it
    did, which is itself information.
    """
    if bugcheck:
        return Outcome(KERNEL_BUGCHECK,
                       "系统发生 bugcheck：%s" % (bugcheck.get("code") or "unknown"),
                       {"bugcheck": bugcheck})
    if timed_out:
        return Outcome(TIMEOUT, "进程在超时时间内未结束")
    if _looks_like_build_error(output):
        return Outcome(BUILD_FAILED, "出现构建/导入类错误，代码未能运行")

    result = parse_result(output)
    if result is None:
        if returncode in _USERMODE_EXCEPTIONS:
            return Outcome(USERMODE_FAULT,
                           "候选以异常码 0x%08X 退出，未留下结果行" % returncode,
                           {"returncode": returncode})
        if returncode in (None, 0):
            return Outcome(TARGET_NOT_REACHED, "候选没有输出 CPG_RESULT，无法证明到达任何阶段")
        if returncode is not None and returncode < 0:
            return Outcome(USERMODE_FAULT,
                           "候选在报告结果前终止（退出码 %d）" % returncode,
                           {"returncode": returncode})
        return Outcome(API_CALL_FAILED, "退出码 %d，且无结果行" % returncode,
                       {"returncode": returncode})

    calls: List[Dict[str, Any]] = result.get("calls") or []
    status = result.get("status")
    reached = bool(result.get("reached"))
    stage = result.get("stage") or ""

    for call in calls:
        code = call.get("status")
        if code in _ENV_CODES:
            return Outcome(ENVIRONMENT_MISMATCH,
                           "%s 返回 %s：平台/镜像不符" % (call.get("api"), code),
                           {"call": call})
    if result.get("environment"):
        return Outcome(ENVIRONMENT_MISMATCH, str(result["environment"]), {"result": result})

    if status in _WIN32_FAILURE:
        failing = next((c for c in calls if c.get("status") in _WIN32_FAILURE), {})
        return Outcome(API_CALL_FAILED,
                       "%s 调用失败（返回 -1/NULL），尚未接触到驱动"
                       % (failing.get("api") or stage or "call"),
                       {"result": result})
    if status == _ACCESS_DENIED:
        return Outcome(API_REJECTED,
                       "%s 被拒绝（ACCESS_DENIED）；层级未定，需调用路径证据" % (stage or "call"),
                       {"result": result})
    if status == _INVALID_PARAMETER:
        return Outcome(INPUT_REJECTED,
                       "%s 参数被拒（INVALID_PARAMETER）：结构体/字段与接口不符" % (stage or "call"),
                       {"result": result})
    # Arrival is the one thing a candidate cannot certify about itself. Its
    # "reached" flag, its own evidence blob and a zero status are all claims or
    # return values; only an outside observer that watched the code run counts.
    hit = [item for item in (external_evidence or []) if item.get("hit")]
    if hit:
        first = hit[0]
        return Outcome(TARGET_REACHED,
                       "外部观测命中（%s）：%s"
                       % (first.get("producer", "unknown"),
                          first.get("where") or first.get("module") or "probe"),
                       {"external": hit, "result": result})
    if reached:
        return Outcome(TARGET_NOT_REACHED,
                       "候选自称到达 %s，但没有外部命中证据" % (stage or "?"),
                       {"result": result})
    if status is None:
        return Outcome(TARGET_NOT_REACHED, "候选未报告状态码", {"result": result})
    if status == 0 and not reached:
        return Outcome(TARGET_NOT_REACHED,
                       "%s 调用成功，但候选未报告到达目标" % (stage or "call"),
                       {"result": result})
    if status == 0 and expected_reached:
        return Outcome(TARGET_NOT_REACHED,
                       "%s 调用成功但没有出现目标现象" % (stage or "call"),
                       {"result": result})
    return Outcome(API_REJECTED, "%s 返回 %s" % (stage or "call", status),
                   {"result": result})
