"""nvcc compilation tool — build CUDA cubin files with MSVC environment support.

Usage:
    from src.tools.compile import compile_cubin

    cubin_path = compile_cubin(source_path, "output.cubin", arch="sm_75")
"""

import os
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple

from .env import find_cuda_tool, find_msvc_vcvarsall


def compile_cubin(
    source_path: str,
    output_path: str,
    arch: str = "sm_75",
    extra_flags: str = "",
    use_msvc: bool = True,
) -> str:
    """Compile a .cu source file to a cubin binary.

    Args:
        source_path: Path to .cu source file.
        output_path: Desired path for the output .cubin file.
        arch: Compute capability target (e.g. 'sm_75').
        extra_flags: Additional nvcc flags (e.g. '-G' for debug, '-lineinfo').
        use_msvc: If True, set up MSVC environment before compiling (Windows only).

    Returns:
        Path to the compiled cubin file (same as output_path).

    Raises:
        RuntimeError: If compilation fails.
        FileNotFoundError: If nvcc is not found.
    """
    nvcc = find_cuda_tool("nvcc")
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    cmd = f'"{nvcc}" {extra_flags} -arch={arch} -cubin -o "{output_path}" "{source_path}"'

    # MSVC environment setup (Windows only)
    env = dict(os.environ)
    if use_msvc and os.name == "nt":
        vcvars = find_msvc_vcvarsall()
        if vcvars:
            # Get CUDA version to choose compatible MSVC
            from .env import get_cuda_toolkit_version
            cuda_ver = get_cuda_toolkit_version()
            msvc_ver = _cuda_to_msvc_version(cuda_ver)
            ver_arg = f" -vcvars_ver={msvc_ver}" if msvc_ver else ""
            cmd = f'cmd /c ""{vcvars}" x64{ver_arg} >nul && ' + cmd

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(
            f"nvcc compilation failed (rc={result.returncode}):\n"
            f"Command: {cmd[:500]}\n"
            f"STDERR: {result.stderr[-500:]}\n"
            f"STDOUT: {result.stdout[-500:]}"
        )
    _validate_cubin(output_path)
    return output_path


def compile_kernel_source(kernel_source: str, arch: str = "sm_75", extra_flags: str = "",
                         work_dir: Optional[str] = None) -> Tuple[str, str]:
    """Compile a kernel source string to a cubin. Returns (cubin_path, source_path).
    Creates temporary files that are cleaned up. If work_dir is provided, keeps the files.
    """
    if work_dir:
        os.makedirs(work_dir, exist_ok=True)
        src = os.path.join(work_dir, "_kernel.cu")
        out = os.path.join(work_dir, "_kernel.cubin")
    else:
        src_fd, src = tempfile.mkstemp(suffix=".cu")
        os.close(src_fd)
        out = src.replace(".cu", ".cubin")
    try:
        with open(src, "w") as f:
            f.write(kernel_source)
        compile_cubin(src, out, arch=arch, extra_flags=extra_flags)
        if not work_dir:
            os.unlink(src)
        return out, src
    except Exception:
        for p in [src, out]:
            if os.path.exists(p) and not work_dir:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        raise


def _cuda_to_msvc_version(cuda_version: str) -> str:
    """Map CUDA toolkit version to compatible MSVC toolchain version."""
    compat = {
        "11.0": "14.28", "11.1": "14.28", "11.2": "14.29",
        "11.3": "14.29", "11.4": "14.29", "11.5": "14.29",
        "11.6": "14.29", "11.7": "14.29", "11.8": "14.29",
        "12.0": "14.36", "12.1": "14.36", "12.2": "14.36",
        "12.3": "14.36", "12.4": "14.36", "12.5": "14.40",
        "12.6": "14.40", "12.7": "14.40", "12.8": "14.40",
    }
    return compat.get(cuda_version[:4], "")


def _validate_cubin(path: str) -> None:
    """Check that a file is a valid ELF cubin. Raises ValueError if not."""
    if not os.path.isfile(path):
        raise ValueError(f"Cubin file not found: {path}")
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic != b"\x7fELF":
        raise ValueError(f"Invalid cubin (not an ELF file): {path} ({magic.hex()})")
