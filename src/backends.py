# -*- coding: utf-8 -*-
"""Pluggable execution backends and a backend-neutral observation.

The loop used to assume one executor: a hardened Linux container running a
bash matrix. That assumption is what made driver targets unreachable - a
Windows DLL cannot be loaded there - and it is what limits the framework to
one class of vulnerability.

A backend answers a single question: *given a candidate, run it where its
target actually lives and report what was observed*. Everything the grader
needs is in :class:`ExecutionObservation`, so adding a platform never changes
grading logic.

Supported axes today:

===========  ======================  ==============================
platform     privilege               backend
===========  ======================  ==============================
linux        user                    ``container`` (docker matrix)
windows      user                    ``windows_native`` (subprocess)
any          kernel                  ``vm_snapshot`` (not built yet)
===========  ======================  ==============================

A profile that no available backend satisfies is reported as
``NEEDS_BACKEND`` rather than silently graded as a failure.
"""

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol


@dataclass(frozen=True)
class TargetProfile:
    """What a candidate needs in order to run at all."""

    platform: str = "linux"      # linux | windows | any
    privilege: str = "user"      # user | kernel
    medium: str = "file"         # file | api_sequence | ioctl | packet
    device: str = "none"         # none | gpu

    @classmethod
    def for_tier(cls, tier: str) -> "TargetProfile":
        if tier == "driver_userland":
            return cls(platform="windows", privilege="user",
                       medium="api_sequence", device="gpu")
        if tier == "driver_kernel":
            return cls(platform="windows", privilege="kernel",
                       medium="ioctl", device="gpu")
        return cls()


@dataclass(frozen=True)
class ExecutionObservation:
    """A backend-neutral record of one run."""

    backend: str
    exit_code: Optional[int] = None
    fault_module: Optional[str] = None
    reached: Optional[bool] = None
    stdout: str = ""
    stderr: str = ""
    artifacts: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def crashed(self) -> bool:
        from .reproduction import is_crash_exit
        return self.exit_code is not None and is_crash_exit(self.exit_code)


class ExecutionBackend(Protocol):
    """Minimal contract every backend must satisfy."""

    name: str
    platform: str
    privilege: str

    def available(self) -> bool: ...
    def run(self, candidate: Path, *, timeout: int) -> ExecutionObservation: ...


class ContainerBackend:
    """Linux userspace, file input, hardened docker matrix."""

    name = "container"
    platform = "linux"
    privilege = "user"

    def available(self) -> bool:
        try:
            probe = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                                   capture_output=True, text=True, timeout=20)
            return probe.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def run(self, candidate: Path, *, timeout: int,
            image: str = "cpg/cuda112-py3:1.0") -> ExecutionObservation:
        command = ["docker", "run", "--rm", "--network", "none",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--read-only", "--tmpfs", "/tmp:size=512m",
                   "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
                   "-v", "%s:/work:rw" % Path(candidate).parent.resolve(),
                   image, "python3", Path(candidate).name]
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout)
        return ExecutionObservation(
            backend=self.name, exit_code=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr)


class WindowsNativeBackend:
    """Windows userspace: run the candidate natively, where driver DLLs live.

    Only userspace: a kernel-tier probe must never run on the operator's
    workstation, because a bugcheck takes the machine with it.
    """

    name = "windows_native"
    platform = "windows"
    privilege = "user"

    def available(self) -> bool:
        return os.name == "nt"

    def run(self, candidate: Path, *, timeout: int) -> ExecutionObservation:
        if not self.available():
            raise RuntimeError("windows_native backend requires Windows")
        completed = subprocess.run([sys.executable, str(candidate)],
                                   capture_output=True, text=True, timeout=timeout)
        return ExecutionObservation(
            backend=self.name, exit_code=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr,
            note="userspace probe; kernel targets require a VM snapshot")


class BackendRegistry:
    """Select the cheapest available backend that satisfies a profile."""

    def __init__(self, backends: Optional[List[object]] = None) -> None:
        self._backends = list(backends) if backends is not None else [
            ContainerBackend(), WindowsNativeBackend()]

    def register(self, backend: object) -> None:
        self._backends.append(backend)

    def candidates(self, profile: TargetProfile) -> List[object]:
        return [b for b in self._backends
                if getattr(b, "platform", "any") == profile.platform
                and getattr(b, "privilege", "user") == profile.privilege]

    def select(self, profile: TargetProfile) -> Optional[object]:
        """Return an available backend, or None when the capability is missing.

        Kernel targets deliberately have no backend yet: pretending to run them
        on the operator's machine would risk the only workstation available.
        """
        if profile.privilege == "kernel":
            return None
        for backend in self.candidates(profile):
            if backend.available():
                return backend
        return None

    def describe(self, profile: TargetProfile) -> str:
        chosen = self.select(profile)
        if chosen is not None:
            return chosen.name
        return ("NEEDS_BACKEND: platform=%s privilege=%s medium=%s device=%s "
                "is not served by any available backend"
                % (profile.platform, profile.privilege, profile.medium,
                   profile.device))
