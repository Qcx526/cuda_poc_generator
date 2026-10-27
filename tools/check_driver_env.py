# -*- coding: utf-8 -*-
"""Check whether this machine can host kernel-tier GPU probes.

A driver probe that bugchecks destroys the evidence unless the machine is
configured to keep it: no dump means no attribution, and no auto-restart means
the run stops at the first crash and never resumes. This reports each
requirement with the exact command that fixes it, so the operator configures
once instead of discovering gaps after a crash.

  python -m tools.check_driver_env
"""

import os
import platform
import subprocess
from typing import List, Tuple

CRASH_CONTROL = r"SYSTEM\CurrentControlSet\Control\CrashControl"
MEMORY_MANAGEMENT = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

# 0 none, 1 complete, 2 kernel, 3 small (minidump), 7 automatic
DUMP_MODES = {0: "none", 1: "complete", 2: "kernel", 3: "small (minidump)",
              7: "automatic"}


def _run(command: str, timeout: int = 20) -> str:
    try:
        completed = subprocess.run(command, shell=True, capture_output=True,
                                   text=True, timeout=timeout,
                                   encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    return (completed.stdout or "").strip()


def read_registry_value(name: str, path: str = CRASH_CONTROL) -> str:
    """Read through winreg: no external binary, so locked-down shells still work."""
    try:
        import winreg
    except ImportError:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
    except OSError:
        return ""


Check = Tuple[str, bool, str, str]


def checks() -> List[Check]:
    """(name, ok, detail, how to fix)."""
    results: List[Check] = []

    gpu = _run('nvidia-smi --query-gpu=name,driver_version --format=csv,noheader')
    results.append(("GPU and driver visible", bool(gpu), gpu or "nvidia-smi failed",
                    "install an NVIDIA driver from the branch the target CVE affects"))

    dump = read_registry_value("CrashDumpEnabled")
    ok_dump = dump in {"1", "2", "3", "7"}
    results.append(("Crash dump enabled", ok_dump,
                    "CrashDumpEnabled=%s (%s)" % (
                        dump or "unreadable",
                        DUMP_MODES.get(int(dump), "?") if dump.isdigit() else "?"),
                    "wmic recoveros set DebugInfoType = 3"))

    auto_reboot = read_registry_value("AutoReboot")
    # Unattended probing needs the machine to come back on its own; the dump,
    # not the blue screen, is the record.
    results.append(("Auto restart after bugcheck", auto_reboot in {"1", "0x1"},
                    "AutoReboot=%s" % (auto_reboot or "unreadable"),
                    'reg add "HKLM\\%s" /v AutoReboot /t REG_DWORD /d 1 /f' % CRASH_CONTROL))

    minidump = os.path.isdir(r"C:\Windows\Minidump")
    results.append(("Minidump directory", minidump,
                    r"C:\Windows\Minidump",
                    "created by the first dump; check its permissions"))

    pagefile = read_registry_value("PagingFiles", MEMORY_MANAGEMENT)
    results.append(("Pagefile configured", bool(pagefile),
                    pagefile or "none",
                    "a small dump needs a pagefile on the system drive"))

    event = _run('wevtutil qe System /q:*[System[(EventID=1001)]] /c:1 /rd:true /f:text')
    can_read = bool(event) or bool(_run("wevtutil gl System"))
    results.append(("BugCheck events readable", can_read,
                    "event 1001 %s" % ("returned a record" if event else "returned nothing"),
                    "run the terminal as administrator"))

    verifier = _run("verifier /query")
    active = bool(verifier) and "no drivers are currently verified" not in verifier.lower()
    results.append(("Driver Verifier", not active,
                    "active" if active else "off",
                    "verifier /reset  (keep it off for reproduction runs)"))

    return results


def main() -> int:
    if platform.system() != "Windows":
        print("This checker targets Windows hosts; on Linux read dmesg and kdump instead.")
        return 0
    if os.name != "nt":
        print("Run from Windows PowerShell.")
        return 0

    print("kernel-tier host check")
    print("=" * 62)
    failures = 0
    for name, ok, detail, fix in checks():
        print("%s %-30s %s" % ("[ok]  " if ok else "[FAIL]", name, detail))
        if not ok:
            print("       fix: %s" % fix)
            failures += 1
    print("=" * 62)
    print("%d check(s) need attention" % failures if failures
          else "ready for kernel-tier probes")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
