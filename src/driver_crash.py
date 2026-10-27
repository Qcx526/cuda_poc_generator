# -*- coding: utf-8 -*-
"""Did the machine bugcheck, and if so, with what.

A kernel-tier probe does not end with an exit code: it ends with a reboot, or
with nothing at all. The only reliable evidence is the crash record the OS
leaves behind, so this module reads that record rather than trusting the
process, which may not have survived to report anything.

Windows is the current target because the operator's GPU is there. The same
shape applies to Linux - uptime resets and the kernel log replace the event
log - and the functions below keep that in one place.
"""

import datetime as _dt
import re
import subprocess
from typing import Dict, List, Optional

BUGCHECK_EVENT_ID = 1001

# https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2
BUGCHECK_NAMES = {
    "0x0000000a": "IRQL_NOT_LESS_OR_EQUAL",
    "0x0000001e": "KMODE_EXCEPTION_NOT_HANDLED",
    "0x0000003b": "SYSTEM_SERVICE_EXCEPTION",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA",
    "0x0000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "0x0000008e": "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    "0x0000009f": "DRIVER_POWER_STATE_FAILURE",
    "0x000000d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "0x000000ea": "THREAD_STUCK_IN_DEVICE_DRIVER",
    "0x000000ef": "CRITICAL_PROCESS_DIED",
    "0x00000133": "DPC_WATCHDOG_VIOLATION",
    "0x00000139": "KERNEL_SECURITY_CHECK_FAILURE",
    "0x0000013a": "KERNEL_MODE_HEAP_CORRUPTION",
    "0x00000154": "UNEXPECTED_STORE_EXCEPTION",
    "0x00000162": "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
    "0x000001c8": "ASSERT_FAILED",
    "0x000001d5": "DRIVER_PNP_WATCHDOG",
    "0x000001e9": "VIDEO_DXGKRNL_FATAL_ERROR",
    "0x000001ea": "VIDEO_TDR_FAILURE",
    "0x000001eb": "VIDEO_TDR_ERROR",
    "0x0000021a": "STATUS_SYSTEM_PROCESS_TERMINATED",
}


def normalise_code(raw: str) -> str:
    """`0xa`, `0x0000000A`, `10` all mean the same bugcheck."""
    text = str(raw).strip().lower()
    value = int(text, 16) if text.startswith("0x") else int(text)
    return "0x%08x" % value


def bugcheck_name(code: str) -> str:
    return BUGCHECK_NAMES.get(normalise_code(code), "UNKNOWN_BUGCHECK")


_PARAM = re.compile(r"0x[0-9a-fA-F]+")


def parse_bugcheck_record(text: str) -> Optional[Dict[str, object]]:
    """Read a BugCheck event, in either the rendered or the XML shape.

    Rendered records start with "The computer has rebooted from a bugcheck ...
    A bugcheck was: 0x000000d1 (0x..., 0x..., 0x..., 0x...)". XML keeps the same
    facts in attributes. Both are accepted because the caller should not care
    which form the query returned.
    """
    if not text:
        return None
    lowered = text.lower()
    if "bugcheck was" in lowered:
        tail = text[lowered.index("bugcheck was") + len("bugcheck was"):]
        codes = _PARAM.findall(tail)
        if not codes:
            return None
        code = normalise_code(codes[0])
        return {"code": code, "name": bugcheck_name(code),
                "params": [normalise_code(item) for item in codes[1:5]]}
    match = re.search(r'BugcheckCode"?\s*>?\s*(?:&quot;)?(0x[0-9a-fA-F]+|\d+)', text)
    if match:
        code = normalise_code(match.group(1))
        params = re.findall(
            r'BugcheckParameter\d"?\s*>?\s*(?:&quot;)?(0x[0-9a-fA-F]+|\d+)', text)
        return {"code": code, "name": bugcheck_name(code),
                "params": [normalise_code(item) for item in params[:4]]}
    return None


def _run(command: List[str], timeout: int = 30) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


def last_bugcheck(timeout: int = 30) -> Optional[Dict[str, object]]:
    """The most recent BugCheck this machine recorded, if it can be read."""
    query = "*[System[(EventID=%d)]]" % BUGCHECK_EVENT_ID
    text = _run(["wevtutil", "qe", "System", "/q:%s" % query,
                 "/c:1", "/rd:true", "/f:text"], timeout=timeout)
    return parse_bugcheck_record(text)


def uptime_seconds() -> Optional[float]:
    """Seconds since boot; a reset between two samples means a crash."""
    import os
    if os.name == "nt":
        # GetTickCount64 wraps after 584 million years; fine.
        try:
            import ctypes
            return ctypes.windll.kernel32.GetTickCount64() / 1000.0
        except Exception:  # noqa: BLE001
            return None
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as handle:
            return float(handle.read().split()[0])
    except OSError:
        return None


def booted_after(moment: _dt.datetime) -> bool:
    """Whether the machine booted after a given wall-clock moment."""
    age = uptime_seconds()
    if age is None:
        return False
    booted_at = _dt.datetime.now() - _dt.timedelta(seconds=age)
    return booted_at > moment
