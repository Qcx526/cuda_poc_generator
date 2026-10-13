"""Toolchain inspection tools — cuobjdump and nvdisasm wrappers.

Usage:
    from src.tools.inspect import cuobjdump_elf, nvdisasm_run

    sections = cuobjdump_elf("file.cubin")  # returns parsed dict
    ok, stdout, stderr, rc = nvdisasm_run("file.cubin")
"""

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from .env import find_cuda_tool


def cuobjdump_elf(cubin_path: str) -> Dict:
    """Run cuobjdump --dump-elf on a cubin and return parsed results.

    Returns dict with keys: 'raw' (full output), 'sections' (list of section
    names), 'symbols' (list of symbol names). Returns empty dict on failure.
    """
    try:
        cuobjdump = find_cuda_tool("cuobjdump")
    except FileNotFoundError:
        return {}
    if not os.path.isfile(cubin_path):
        return {}

    result = subprocess.run(
        [cuobjdump, "--dump-elf", cubin_path],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return {"raw": "", "sections": [], "symbols": [], "error": result.stderr}
    out = result.stdout
    return {
        "raw": out,
        "sections": _extract_section_names(out),
        "symbols": _extract_symbols(out),
    }


def nvdisasm_run(
    cubin_path: str, timeout: int = 10
) -> Tuple[bool, str, str, int]:
    """Run nvdisasm on a cubin file.

    Returns (ok, stdout, stderr, exit_code).
    ok=False means the process crashed, timed out, or nvdisasm not found.
    """
    try:
        nvdisasm = find_cuda_tool("nvdisasm")
    except FileNotFoundError:
        return False, "", "nvdisasm not found", -1
    if not os.path.isfile(cubin_path):
        return False, "", f"cubin not found: {cubin_path}", -1
    try:
        result = subprocess.run(
            [nvdisasm, cubin_path],
            capture_output=True, text=True, timeout=timeout,
        )
        return True, result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return False, "", "nvdisasm timed out", -1
    except Exception as e:
        return False, "", str(e), -1


def nvdisasm_has_relocation_sections(cubin_path: str) -> bool:
    """Check if a cubin has relocation sections that nvdisasm processes."""
    info = cuobjdump_elf(cubin_path)
    out = info.get("raw", "")
    return "REL" in out or "rel" in out


def get_nvdisasm_version() -> str:
    """Return nvdisasm version string, or 'unknown'."""
    try:
        nvdisasm = find_cuda_tool("nvdisasm")
    except FileNotFoundError:
        return "unknown"
    try:
        result = subprocess.run([nvdisasm, "--version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"release\s+(\d+\.\d+\.?\d*)", result.stdout)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def is_access_violation(exit_code: int) -> bool:
    """Check if an exit code indicates an access violation (crash)."""
    # 0xC0000005 on Windows, or negative signal on Linux
    return exit_code in (3221225477, -1073741819, 3221226356, -1073740940) or exit_code < -1000


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _extract_section_names(output: str) -> List[str]:
    """Extract section names from cuobjdump --dump-elf output."""
    names = []
    for match in re.finditer(r"\.section\s+\.(\S+)", output):
        names.append(f".{match.group(1)}")
    return names


def _extract_symbols(output: str) -> List[str]:
    """Extract symbol names from cuobjdump output."""
    return re.findall(r"\.global\s+\.(\w+)", output)
