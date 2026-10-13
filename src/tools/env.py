"""Environment query tools — detect GPU, CUDA version, and toolchain paths.

Importable by PoC scripts to avoid hardcoding paths and compute capabilities.
All functions are pure stdlib — no langchain, no LLM dependencies.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List


def find_cuda_tool(name: str) -> str:
    """Locate a CUDA Toolkit binary by name (e.g. 'nvcc', 'cuobjdump').

    Searches in order: CUDA_PATH env var → PATH → Program Files glob.
    Returns the full path or raises FileNotFoundError.
    """
    is_win = os.name == "nt"
    exe_name = f"{name}.exe" if is_win else name

    # 1. CUDA_PATH environment variable
    cuda_path = os.environ.get("CUDA_PATH", "") or os.environ.get("CUDA_ROOT", "")
    if cuda_path:
        candidate = os.path.join(cuda_path, "bin", exe_name)
        if os.path.isfile(candidate):
            return candidate

    # 2. PATH search
    found = shutil.which(name)
    if found:
        return found

    # 3. Filesystem glob
    if is_win:
        import glob
        for p in glob.glob(
            r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*\bin\\" + exe_name
        ):
            if os.path.isfile(p):
                return p
        for p in glob.glob(r"D:\NVIDIA GPU Computing Toolkit\CUDA\v*\bin\\" + exe_name):
            if os.path.isfile(p):
                return p
    else:
        for p in ["/usr/local/cuda/bin/" + name] + [
            f"/usr/local/cuda-{v}/bin/{name}" for v in "12 11 10".split()
        ]:
            if os.path.isfile(p):
                return p

    raise FileNotFoundError(f"CUDA tool '{name}' not found. Set CUDA_PATH or add to PATH.")


def find_msvc_vcvarsall() -> str:
    """Locate vcvarsall.bat for MSVC environment setup. Windows only.

    Returns the full path or empty string if not found.
    """
    if os.name != "nt":
        return ""
    # try vswhere first
    for prog in [
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
    ]:
        vswhere = os.path.join(prog, "Microsoft Visual Studio", "Installer", "vswhere.exe")
        if os.path.isfile(vswhere):
            try:
                vs_root = subprocess.check_output(
                    [vswhere, "-latest", "-property", "installationPath"],
                    text=True, timeout=10,
                ).strip()
                candidate = os.path.join(vs_root, "VC", "Auxiliary", "Build", "vcvarsall.bat")
                if os.path.isfile(candidate):
                    return candidate
            except Exception:
                pass
    # fallback: search common paths
    for base in [
        os.environ.get("ProgramFiles", "C:\\Program Files"),
        os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        "D:\\Microsoft Visual Studio",
    ]:
        import glob as _g
        for p in _g.glob(os.path.join(base, "*", "*", "VC", "Auxiliary", "Build", "vcvarsall.bat")):
            if os.path.isfile(p):
                return p
    return ""


def get_cuda_toolkit_version() -> str:
    """Return CUDA Toolkit version string (e.g. '11.2'), or 'unknown'."""
    nvcc = find_cuda_tool("nvcc")
    try:
        out = subprocess.check_output([nvcc, "--version"], text=True, timeout=10)
        m = re.search(r"release\s+(\d+\.\d+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def get_cuda_driver_version() -> int:
    """Return CUDA Driver version as integer (e.g. 11020 for 11.2), or 0."""
    if os.name == "nt":
        try:
            import ctypes
            lib = ctypes.CDLL("nvcuda.dll")
            ver = ctypes.c_int()
            if hasattr(lib, "cuDriverGetVersion"):
                lib.cuDriverGetVersion(ctypes.byref(ver))
                return ver.value
        except Exception:
            pass
    # fallback: nvidia-smi
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            out = subprocess.check_output(
                [nvidia_smi, "--query-gpu=driver_version", "--format=csv,noheader"],
                text=True, timeout=10,
            )
            return int(out.strip().split(".")[0]) * 1000 + int(out.strip().split(".")[1].split(".")[0])
        except Exception:
            pass
    return 0


def get_gpu_compute_capability() -> str:
    """Return primary GPU compute capability (e.g. 'sm_75'), or 'sm_52' fallback."""
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return "sm_52"
    try:
        out = subprocess.check_output(
            [nvidia_smi, "--query-gpu=compute_cap", "--format=csv,noheader"],
            text=True, timeout=10,
        )
        cap = out.strip().split("\n")[0].strip().replace(".", "")
        if cap and cap.isdigit():
            return f"sm_{cap}"
    except Exception:
        pass
    return "sm_52"


def setup_msvc_env(msvc_version: str = "") -> Dict[str, str]:
    """Return environment dict with MSVC + Windows SDK paths for nvcc.

    On Windows, calls vcvarsall.bat and captures INCLUDE/LIB/PATH.
    On Linux, returns os.environ unchanged.
    Returns empty dict on failure (caller should fall back to os.environ).
    """
    if os.name != "nt":
        return dict(os.environ)
    vcvars = find_msvc_vcvarsall()
    if not vcvars:
        return {}
    try:
        ver_arg = f" -vcvars_ver={msvc_version}" if msvc_version else ""
        result = subprocess.run(
            f'cmd /c ""{vcvars}" x64{ver_arg} >nul && set"',
            capture_output=True, text=True, timeout=30, shell=True,
        )
        if result.returncode != 0:
            return {}
        env = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                env[k] = v
        if "INCLUDE" in env:
            return {**os.environ, **env}
        return {}
    except Exception:
        return {}


def get_compiler_info() -> Dict[str, str]:
    """Return {'name': 'MSVC'|'GCC', 'path': ..., 'version': ...}."""
    if os.name == "nt":
        cl = shutil.which("cl.exe") or ""
        return {"name": "MSVC", "path": cl, "version": ""}
    gcc = shutil.which("gcc") or ""
    return {"name": "GCC", "path": gcc, "version": ""}
