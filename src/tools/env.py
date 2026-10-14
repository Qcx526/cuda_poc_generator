"""Environment query tools — detect GPU, CUDA version, and toolchain paths.

Importable by PoC scripts to avoid hardcoding paths and compute capabilities.
All functions are pure stdlib — no langchain, no LLM dependencies.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional


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
    try:
        nvcc = find_cuda_tool("nvcc")
        out = subprocess.check_output([nvcc, "--version"], text=True, timeout=10)
        m = re.search(r"release\s+(\d+\.\d+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def get_cuda_driver_version() -> Optional[int]:
    """Read this OS's cuDriverGetVersion, or None; never convert driver release.

    The standard probe intentionally does not call this optional library helper.
    It does not initialize a CUDA context or load another OS's dynamic library.
    """
    try:
        import ctypes
        lib = ctypes.WinDLL("nvcuda.dll") if os.name == "nt" else ctypes.CDLL("libcuda.so.1")
        ver = ctypes.c_int()
        query = lib.cuDriverGetVersion
        query.argtypes = [ctypes.POINTER(ctypes.c_int)]
        query.restype = ctypes.c_int
        return ver.value if query(ctypes.byref(ver)) == 0 and ver.value > 0 else None
    except (OSError, AttributeError):
        return None


def get_gpu_compute_capability() -> Optional[str]:
    """Return sm notation derived from an actual compute_cap query, or None."""
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return None
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
    return None


def setup_msvc_env(msvc_version: str = "") -> Dict[str, str]:
    """Compatibility adapter for a separately prepared developer environment.

    Open a Visual Studio developer terminal before calling this on Windows.
    No batch files or shell command strings are executed here. A requested MSVC
    toolset must match VCToolsVersion; an unknown selection returns {}.
    """
    if not isinstance(msvc_version, str) or (msvc_version and not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", msvc_version)):
        raise ValueError("msvc_version must be a numeric toolset version")
    if os.name != "nt":
        return dict(os.environ)
    env = dict(os.environ)
    lookup = {key.upper(): value for key, value in env.items()}
    if not lookup.get("INCLUDE") or not lookup.get("LIB") or not shutil.which("cl.exe", path=lookup.get("PATH", "")):
        return {}
    if msvc_version and not re.fullmatch(re.escape(msvc_version) + r"(?:\.[0-9]+)*", lookup.get("VCTOOLSVERSION", "")):
        return {}
    return env


def get_compiler_info() -> Dict[str, str]:
    """Return {'name': 'MSVC'|'GCC', 'path': ..., 'version': ...}."""
    if os.name == "nt":
        cl = shutil.which("cl.exe") or ""
        return {"name": "MSVC", "path": cl, "version": ""}
    gcc = shutil.which("gcc") or ""
    return {"name": "GCC", "path": gcc, "version": ""}
