# -*- coding: utf-8 -*-
"""Arm, launch, and harvest a probe that may take the machine down with it.

A kernel probe cannot report its own result: the process dies with the system.
So the protocol is a marker on disk and a reading taken later - on the next run,
after the machine has come back. Three outcomes are distinguishable:

  * exited          the probe returned; its exit code is the result
  * rebooted        the machine went down while armed; the dump holds the reason
  * still_running   neither happened within the window

Keeping the marker separate from the result is what makes this survivable: the
marker is written before the risk, and the verdict is computed afterwards from
evidence that outlives the crash.
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

MARKER_NAME = "probe_armed.json"


def arm(workdir: Path, candidate: Path, note: str = "") -> Path:
    """Record that a probe is about to run, before it can hurt anything."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    payload = {
        "candidate": str(candidate),
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "host": os.environ.get("COMPUTERNAME", ""),
        "platform": sys.platform,
        "note": note,
    }
    path = workdir / MARKER_NAME
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


def read_marker(workdir: Path) -> Optional[Dict[str, object]]:
    path = Path(workdir) / MARKER_NAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def launch(candidate: Path, timeout: int = 600) -> int:
    """Start the probe detached and wait for it, but not for the machine.

    A child sharing this console dies with it, and a bugcheck kills both; the
    return code is only meaningful when the machine survives.
    """
    creation = 0
    if os.name == "nt":
        # Own process group: a Ctrl-C must not take the probe with it, and the
        # probe must not take this shell down before it writes its result.
        creation = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    completed = subprocess.run([sys.executable, str(candidate)],
                               capture_output=True, text=True, timeout=timeout,
                               creationflags=creation)
    return completed.returncode


def harvest(workdir: Path, *, uptime_seconds: Optional[float] = None,
            bugcheck: Optional[Dict[str, object]] = None,
            exit_code: Optional[int] = None) -> Dict[str, object]:
    """Decide what happened, from the marker plus what the OS recorded.

    ``uptime_seconds`` and ``bugcheck`` are injectable so the logic can be
    tested without actually crashing a machine.
    """
    marker = read_marker(workdir)
    if marker is None:
        return {"outcome": "no_marker", "detail": "no probe was armed here"}

    started = datetime.fromisoformat(str(marker["started_at"]))
    if uptime_seconds is None:
        from .driver_crash import uptime_seconds as _uptime
        uptime_seconds = _uptime()

    rebooted = False
    if uptime_seconds is not None:
        booted_at = datetime.fromtimestamp(datetime.now().timestamp() - uptime_seconds)
        rebooted = booted_at > started

    if rebooted:
        if bugcheck is None:
            from .driver_crash import last_bugcheck
            bugcheck = last_bugcheck()
        return {
            "outcome": "crashed",
            "rebooted": True,
            "bugcheck": bugcheck or {"code": "unknown", "name": "BUGCHECK_NOT_READABLE"},
            "candidate": marker.get("candidate"),
            "started_at": marker.get("started_at"),
        }

    if exit_code is not None:
        return {"outcome": "exited", "exit_code": exit_code,
                "candidate": marker.get("candidate"),
                "started_at": marker.get("started_at")}

    return {"outcome": "still_running", "candidate": marker.get("candidate"),
            "started_at": marker.get("started_at")}


def summarise(result: Dict[str, object]) -> str:
    """One line a reader can act on."""
    outcome = result.get("outcome")
    if outcome == "crashed":
        bug = result.get("bugcheck") or {}
        return "machine went down: %s (%s)" % (bug.get("name"), bug.get("code"))
    if outcome == "exited":
        return "probe exited with %s; no restart" % result.get("exit_code")
    if outcome == "still_running":
        return "probe neither exited nor crashed within the window"
    return "no armed probe found in this workdir"
