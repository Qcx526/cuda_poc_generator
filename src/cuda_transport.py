# -*- coding: utf-8 -*-
"""One compile/run contract, two platforms.

Everything above this layer - the case, the context, the prompt, the candidate, the
evidence model - is shared. A transport only knows how to build a C file and how to
run the resulting binary, and each reports its own exit codes.

Windows: nvcc + MSVC environment, executable on the host, CUDA via nvcuda.dll.
WSL:     gcc against the CUDA headers, binary under a per-run directory, CUDA via the
         DXCore shim. WSL is not a native Linux driver and must not be presented as one.
"""

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .cuda_api_backend import TOOLKIT, compile_source
from .exec_evidence import ToolInvocation

DISTRO = "Ubuntu-22.04"
WSL_LIBS = "$HOME/cuda-wsl-libs"


@dataclass
class BuildResult:
    ok: bool
    returncode: int
    log: str
    artifact: Optional[str]
    artifact_sha256: Optional[str]
    source_sha256: str
    transport: str


class Transport:
    name = "abstract"

    def build(self, source_path: Path, workdir: Path) -> BuildResult:  # pragma: no cover
        raise NotImplementedError

    def run(self, artifact: str, run_id: str, timeout: int = 120) -> ToolInvocation:
        raise NotImplementedError


class WindowsTransport(Transport):
    name = "windows_nvcc"

    def build(self, source_path: Path, workdir: Path) -> BuildResult:
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        result = compile_source(source_path, workdir / "candidate", workdir)
        return BuildResult(ok=result["returncode"] == 0,
                           returncode=result["returncode"],
                           log=(result["stdout"] or "") + (result["stderr"] or ""),
                           artifact=result["binary"],
                           artifact_sha256=result["binary_sha256"],
                           source_sha256=digest, transport=self.name)

    def run(self, artifact: str, run_id: str, timeout: int = 120) -> ToolInvocation:
        from .cuda_api_backend import run_program
        return run_program(Path(artifact), run_id, timeout)


class WslTransport(Transport):
    """gcc inside WSL. Every run gets its own directory so a stale binary cannot be
    picked up, and both hashes are checked on the way in and out."""

    name = "wsl_gcc"

    def _wsl(self, script: str, timeout: int = 300,
             stdin: Optional[bytes] = None) -> subprocess.CompletedProcess:
        return subprocess.run(["wsl.exe", "-d", DISTRO, "--", "bash", "-lc", script],
                              input=stdin, capture_output=True, timeout=timeout)

    def build(self, source_path: Path, workdir: Path) -> BuildResult:
        raw = source_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        remote = "~/f12/%s" % digest[:16]
        # New directory per source hash: no leftover binary, no stale object.
        prep = self._wsl("rm -rf %s && mkdir -p %s && cat > %s/candidate.c"
                         % (remote, remote, remote), stdin=raw)
        if prep.returncode != 0:
            return BuildResult(False, prep.returncode, prep.stderr.decode("utf-8", "replace"),
                               None, None, digest, self.name)

        check = self._wsl("sha256sum %s/candidate.c | cut -d' ' -f1" % remote)
        transferred = check.stdout.decode("utf-8", "replace").strip()
        if transferred != digest:
            return BuildResult(False, -1, "transfer hash mismatch: %s != %s"
                               % (transferred, digest), None, None, digest, self.name)

        build = self._wsl(
            "export LD_LIBRARY_PATH=%s; cd %s && gcc candidate.c -o candidate "
            "-I/usr/local/cuda/include -L$HOME/cuda-wsl-libs -lcuda 2>&1; echo __RC__$?"
            % (WSL_LIBS, remote))
        out = build.stdout.decode("utf-8", "replace")
        rc = int(out.rsplit("__RC__", 1)[-1].strip()) if "__RC__" in out else -1
        log = out.rsplit("__RC__", 1)[0]
        if rc != 0:
            return BuildResult(False, rc, log, None, None, digest, self.name)

        binary_sha = self._wsl("sha256sum %s/candidate | cut -d' ' -f1" % remote)
        return BuildResult(True, 0, log, remote + "/candidate",
                           binary_sha.stdout.decode("utf-8", "replace").strip(),
                           digest, self.name)

    def run(self, artifact: str, run_id: str, timeout: int = 120) -> ToolInvocation:
        proc = self._wsl("export LD_LIBRARY_PATH=%s; %s 2>/tmp/f12.err; echo __RC__$?; "
                         "echo __ERR__; cat /tmp/f12.err" % (WSL_LIBS, artifact),
                         timeout=timeout)
        out = proc.stdout.decode("utf-8", "replace")
        rc, _, tail = out.partition("__RC__")
        code_line, _, err = tail.partition("__ERR__")
        try:
            code = int(code_line.strip().splitlines()[0])
        except (ValueError, IndexError):
            code = None
        return ToolInvocation(run_id=run_id, tool="cuda_driver_api_program",
                              tool_version="gcc + libcuda (WSL shim)",
                              input_sha256=None, exit_code=code,
                              stdout=rc[-8000:], stderr=err[-4000:],
                              signal=None)


def transport_for(platform: str) -> Transport:
    if platform == "windows":
        return WindowsTransport()
    if platform == "linux":
        return WslTransport()
    raise ValueError("未知平台: %s" % platform)


def record_path(workdir: Path) -> Path:
    return workdir / "transport_record.json"


def save_record(workdir: Path, build: BuildResult, invocation: ToolInvocation) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    record_path(workdir).write_text(json.dumps({
        "transport": build.transport,
        "build": {"ok": build.ok, "returncode": build.returncode,
                  "source_sha256": build.source_sha256,
                  "artifact": build.artifact, "artifact_sha256": build.artifact_sha256,
                  "log_tail": build.log[-3000:]},
        "run": {"run_id": invocation.run_id, "tool": invocation.tool,
                "tool_version": invocation.tool_version,
                "exit_code": invocation.exit_code, "signal": invocation.signal,
                "timed_out": invocation.timed_out,
                "stdout": invocation.stdout[-8000:], "stderr": invocation.stderr[-4000:]},
        "note": "编译与运行退出码均由 transport 直接取得，未经过管道",
    }, ensure_ascii=False, indent=1), encoding="utf-8")


__all__ = ["BuildResult", "Transport", "WindowsTransport", "WslTransport",
           "transport_for", "save_record", "TOOLKIT"]
