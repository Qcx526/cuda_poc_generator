# -*- coding: utf-8 -*-
"""CUDA Driver API backend: real compilation and real GPU execution on this host.

The file-input backend treats the artifact as the payload; here the payload is a
sequence of API calls. Both share the same execution ladder: a plain API error is a
rejection, never a crash, and never evidence of a vulnerability.
"""

import ctypes
import hashlib
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .exec_evidence import RunRecord, ToolInvocation

TOOLKIT = Path("C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.2")
NVCC = TOOLKIT / "bin" / "nvcc.exe"
MSVC = Path("D:/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/14.29.30133")
WINSDK = Path("D:/Windows Kits/10")


def _msvc_env() -> dict:
    """nvcc shells out to cl.exe; without these paths it dies with 'Cannot find
    compiler cl.exe', which the first run hit three times because the harness
    never set them."""
    import os
    env = dict(os.environ)
    cl_dir = str(MSVC / "bin" / "HostX64" / "x64")
    env["PATH"] = cl_dir + os.pathsep + env.get("PATH", "")
    env["INCLUDE"] = ";".join([
        str(MSVC / "include"),
        str(WINSDK / "Include/10.0.26100.0/ucrt"),
        str(WINSDK / "Include/10.0.26100.0/shared"),
        str(WINSDK / "Include/10.0.26100.0/um"),
        str(TOOLKIT / "include"),
    ])
    env["LIB"] = ";".join([
        str(MSVC / "lib" / "x64"),
        str(WINSDK / "Lib/10.0.26100.0/ucrt/x64"),
        str(WINSDK / "Lib/10.0.26100.0/um/x64"),
        str(TOOLKIT / "lib" / "x64"),
    ])
    return env

CUDA_ERROR_STRINGS = {
    0: "CUDA_SUCCESS",
    1: "CUDA_ERROR_INVALID_VALUE",
    2: "CUDA_ERROR_OUT_OF_MEMORY",
    3: "CUDA_ERROR_NOT_INITIALIZED",
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    201: "CUDA_ERROR_INVALID_CONTEXT",
    400: "CUDA_ERROR_INVALID_HANDLE",
}


@dataclass
class Environment:
    cuinit: int
    driver_api_version: int
    device_name: str
    compute_capability: str
    nvcc_version: str
    note: str = ("cuDriverGetVersion 是 CUDA Driver API 兼容版本号，"
                 "不是 NVIDIA 驱动发行版本")


def probe() -> Environment:
    cu = ctypes.CDLL("nvcuda.dll")
    version = ctypes.c_int(0)
    result = cu.cuDriverGetVersion(ctypes.byref(version))
    device = ctypes.c_int(-1)
    cu.cuInit(0)
    init = cu.cuInit(0)
    cu.cuDeviceGet(ctypes.byref(device), 0)
    name = ctypes.create_string_buffer(256)
    cu.cuDeviceGetName(name, 256, device)
    major, minor = ctypes.c_int(0), ctypes.c_int(0)
    cu.cuDeviceComputeCapability(ctypes.byref(major), ctypes.byref(minor), device)
    nvcc_out = subprocess.run([str(NVCC), "--version"], capture_output=True,
                              text=True, errors="replace").stdout
    nvcc_line = next((line for line in nvcc_out.splitlines()
                      if "release" in line), "").strip()
    return Environment(cuinit=init, driver_api_version=version.value if result == 0 else -1,
                       device_name=name.value.decode(errors="replace"),
                       compute_capability="%d.%d" % (major.value, minor.value),
                       nvcc_version=nvcc_line)


def compile_source(source: Path, output: Path, workdir: Path) -> dict:
    """nvcc, with the full log kept - a missing header or a link error is a build
    failure, not a runtime one, and the ladder must be able to tell them apart."""
    output = output.with_suffix(".exe")
    command = [str(NVCC), str(source.name), "-o", str(output.name),
               "-I", str(TOOLKIT / "include"), "-L", str(TOOLKIT / "lib" / "x64"),
               "-lcuda"]
    proc = subprocess.run(command, cwd=workdir, capture_output=True, text=True,
                          errors="replace", timeout=600, env=_msvc_env())
    return {"command": " ".join(command), "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:],
            "binary": str(output) if proc.returncode == 0 else None,
            "binary_sha256": (hashlib.sha256(Path(output).read_bytes()).hexdigest()
                              if proc.returncode == 0 and Path(output).exists() else None)}


def run_program(binary: Path, run_id: str, timeout: int = 120) -> ToolInvocation:
    started = time.time()
    try:
        proc = subprocess.run([str(binary)], capture_output=True, text=True,
                              errors="replace", timeout=timeout)
        exit_code, stdout, stderr, timed_out = (proc.returncode, proc.stdout,
                                                proc.stderr, False)
    except subprocess.TimeoutExpired as exc:
        exit_code, stdout, stderr, timed_out = (None, exc.stdout or "",
                                                "TIMED OUT after %ds" % timeout, True)
    return ToolInvocation(run_id=run_id, tool="cuda_driver_api_program",
                         tool_version="nvcc 11.2.152 / nvcuda.dll",
                         input_sha256=None, exit_code=exit_code,
                         stdout=str(stdout)[-8000:], stderr=str(stderr)[-4000:],
                         timed_out=timed_out)


def parse_api_lines(stdout: str) -> List[dict]:
    """Programs print one line per API call: API <name> = <code>."""
    rows = []
    for line in stdout.splitlines():
        if line.startswith("API "):
            parts = line.split("=", 1)
            name = parts[0].strip().removeprefix("API").strip()
            code = int(parts[1].strip()) if len(parts) > 1 else None
            rows.append({"name": name, "code": code,
                         "meaning": CUDA_ERROR_STRINGS.get(code, "UNKNOWN"),
                         "is_error": code is not None and code != 0})
    return rows


def build_record(compile_result: dict, invocation: Optional[ToolInvocation],
                 source: Path) -> RunRecord:
    record = RunRecord(candidate_generated=bool(source.read_text(encoding="utf-8",
                                                                 errors="replace").strip()),
                      candidate_started=compile_result["returncode"] == 0)
    if invocation is not None:
        record.invocations.append(invocation)
    return record
