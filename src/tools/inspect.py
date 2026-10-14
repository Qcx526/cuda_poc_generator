"""Binary inspection evidence, independent of any target CVE verdict."""

import os
from pathlib import Path
import re
from typing import Dict, List, Tuple

from .compile import _local_path, _validate_cubin
from .env import find_cuda_tool
from .elf_ops import find_sections_by_type, SHT_REL, SHT_RELA
from .process import run_tool


def _tool_path(name: str):
    try:
        return find_cuda_tool(name), None
    except FileNotFoundError as error:
        return (name + ".exe" if os.name == "nt" else name), error


def _run_inspector(name: str, arguments: list[str], *, timeout_seconds=10,
                   max_output_bytes=1048576, artifact_root=None):
    tool_path, discovery_error = _tool_path(name)
    return run_tool([tool_path, *arguments], cwd=str(Path.cwd()),
                    target_environment="local", timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes, artifact_root=artifact_root,
                    command_source="src.tools.inspect: fixed " + name + " adapter",
                    tool_source="CUDA tool discovery: filesystem/PATH", _startup_error=discovery_error)


def cuobjdump_result(cubin_path: str, *, timeout_seconds=10, max_output_bytes=1048576,
                     artifact_root=None):
    """Return unmodified process semantics and persisted raw inspection output."""
    path = _local_path(cubin_path)
    if not path.is_file():
        raise FileNotFoundError("cubin input does not exist")
    _validate_cubin(path)
    return _run_inspector("cuobjdump", ["--dump-elf", str(path)], timeout_seconds=timeout_seconds,
                          max_output_bytes=max_output_bytes, artifact_root=artifact_root)


def cuobjdump_elf(cubin_path: str, **kwargs) -> Dict:
    """Legacy parsed output, with explicit status and the new full ToolResult."""
    try:
        result = cuobjdump_result(cubin_path, **kwargs)
    except (FileNotFoundError, ValueError) as error:
        return {"raw": "", "sections": [], "symbols": [], "ok": False,
                "error": "INPUT_REJECTED", "diagnostics": [str(error)], "tool_result": None,
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    out = result.stdout_bytes().decode("utf-8", errors="replace")
    success = result.end_status == "NORMAL_EXIT"
    return {"raw": out, "sections": _extract_section_names(out) if success else [],
            "symbols": _extract_symbols(out) if success else [], "ok": success,
            "error": "" if success else result.end_status,
            "tool_result": result.model_dump(mode="json"),
            "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}


def nvdisasm_result(cubin_path: str, *, timeout_seconds=10, max_output_bytes=1048576,
                    artifact_root=None):
    path = _local_path(cubin_path)
    if not path.is_file():
        raise FileNotFoundError("cubin input does not exist")
    _validate_cubin(path)
    return _run_inspector("nvdisasm", [str(path)], timeout_seconds=timeout_seconds,
                          max_output_bytes=max_output_bytes, artifact_root=artifact_root)


def nvdisasm_run(cubin_path: str, timeout: int = 10, **kwargs) -> Tuple[bool, str, str, int]:
    """Legacy tuple. True means normal exit 0, even if stderr has a warning.

    New callers should use nvdisasm_result for statuses, raw bytes and evidence.
    A legacy -1 denotes no exit code and must not be interpreted as a signal.
    """
    try:
        result = nvdisasm_result(cubin_path, timeout_seconds=timeout, **kwargs)
    except (FileNotFoundError, ValueError) as error:
        return False, "", str(error), -1
    return (result.end_status == "NORMAL_EXIT", result.stdout_bytes().decode("utf-8", "replace"),
            result.stderr_bytes().decode("utf-8", "replace"),
            result.returncode if result.returncode is not None else -1)


def nvdisasm_has_relocation_sections(cubin_path: str) -> bool:
    """Read validated ELF sh_type; relocation presence makes no CVE claim."""
    data = _validate_cubin(_local_path(cubin_path))
    return bool(find_sections_by_type(data, SHT_REL) or find_sections_by_type(data, SHT_RELA))


def get_nvdisasm_version(**kwargs) -> str:
    result = _run_inspector("nvdisasm", ["--version"], timeout_seconds=5, **kwargs)
    if result.end_status != "NORMAL_EXIT":
        return "unknown"
    match = re.search(r"release\s+(\d+\.\d+\.?\d*)", result.stdout_bytes().decode("utf-8", "replace"))
    return match.group(1) if match else "unknown"


def is_access_violation(exit_code: int, *, platform_type: str | None = None) -> bool:
    """Only Windows STATUS_ACCESS_VIOLATION; SIGSEGV is a distinct Linux signal."""
    platform_type = platform_type or ("windows" if os.name == "nt" else "linux")
    if platform_type not in {"windows", "linux", "wsl"}:
        raise ValueError("unsupported platform_type")
    if type(exit_code) is not int:
        raise ValueError("exit_code must be an integer")
    return platform_type == "windows" and exit_code in (0xC0000005, -1073741819)


def _extract_section_names(output: str) -> List[str]:
    return ["." + match.group(1) for match in re.finditer(r"\.section\s+\.(\S+)", output)]


def _extract_symbols(output: str) -> List[str]:
    return re.findall(r"\.global\s+\.(\w+)", output)
