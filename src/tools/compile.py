"""Bounded nvcc adapters. Compilation never attests candidate execution or CVEs."""

from dataclasses import dataclass, replace
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import tempfile
import warnings
from typing import Mapping, Sequence

from ..models.platform import PlatformSnapshot
from ..models.tool_result import ToolResult
from .env import find_cuda_tool
from .elf_ops import validate_elf_structure
from .process import run_tool, current_platform_type


_BOOLEAN_FLAGS = {
    "-G", "--device-debug", "-lineinfo", "--generate-line-info", "-g", "--debug",
    "--use_fast_math", "--expt-relaxed-constexpr", "--expt-extended-lambda",
}


@dataclass(frozen=True)
class CompileResult:
    """Process evidence and the separate structural artifact check."""

    tool_result: ToolResult
    source_path: str
    output_path: str | None
    artifact_status: str
    diagnostics: tuple[str, ...] = ()
    candidate_execution_status: str = "NOT_EXECUTED"
    verification_status: str = "NOT_VERIFIED"

    @property
    def ok(self):
        return self.artifact_status == "COMPILED_ELF_CUDA" and self.tool_result.end_status == "NORMAL_EXIT"

    def to_dict(self):
        return {"tool_result": self.tool_result.model_dump(mode="json"),
                "source_path": self.source_path, "output_path": self.output_path,
                "artifact_status": self.artifact_status, "diagnostics": list(self.diagnostics),
                "candidate_execution_status": self.candidate_execution_status,
                "verification_status": self.verification_status}


class CompileError(RuntimeError):
    """Legacy failure adapter retaining structured evidence for the caller."""

    def __init__(self, result: CompileResult):
        self.result = result
        super().__init__(f"nvcc compilation failed: {result.tool_result.end_status}; "
                         f"artifact={result.artifact_status}; evidence={result.tool_result.evidence_directory}")


def _cleanup_owned_directory(path: Path, expected_parent: Path) -> str | None:
    """Refuse redirected targets, and preserve primary failures on cleanup errors."""
    try:
        resolved = path.resolve()
        if resolved != path.absolute() or resolved.parent != expected_parent.resolve():
            return "CLEANUP_FAILED: temporary directory no longer resolves to its owned location"
        shutil.rmtree(resolved)
    except OSError as error:
        return "CLEANUP_FAILED: " + str(error)
    return None


def _attach_cleanup_failure(error: BaseException, diagnostic: str | None):
    if diagnostic:
        if isinstance(error, CompileError):
            error.result = replace(error.result, diagnostics=error.result.diagnostics + (diagnostic,))
        else:
            error.cleanup_diagnostic = diagnostic


def validate_compile_flags(extra_flags: str | Sequence[str]) -> list[str]:
    """Accept a deliberately small flag set; never forward arbitrary nvcc options."""
    if isinstance(extra_flags, str):
        flags = shlex.split(extra_flags, posix=True)
    elif isinstance(extra_flags, (list, tuple)):
        flags = list(extra_flags)
    else:
        raise ValueError("extra_flags must be a string or a list/tuple of flag tokens")
    for flag in flags:
        if not isinstance(flag, str) or not (
            flag in _BOOLEAN_FLAGS or re.fullmatch(r"-O[0-3]", flag)
            or re.fullmatch(r"(?:--std|-std)=c\+\+(?:11|14|17|20)", flag)
            or re.fullmatch(r"--maxrregcount=(?:0|[1-9][0-9]{0,2})", flag)
        ):
            raise ValueError(f"unsupported compile flag: {flag!r}")
        if flag.startswith("--maxrregcount=") and int(flag.split("=", 1)[1]) > 255:
            raise ValueError("maxrregcount must be between 0 and 255")
    if len(flags) > 32:
        raise ValueError("too many compile flags")
    return flags


def resolve_compile_arch(arch: str | None, snapshot: PlatformSnapshot | dict | None = None) -> str:
    """Select an explicit architecture, or a single observed and supported GPU target."""
    model = PlatformSnapshot.model_validate(snapshot.model_dump(mode="json") if
                                             isinstance(snapshot, PlatformSnapshot) else snapshot) if snapshot is not None else None
    if arch is None:
        if model is None or model.gpu_devices.status != "OBSERVED" or not model.gpu_devices.value:
            raise ValueError("arch is required without observed target GPU capabilities")
        choices = set()
        for device in model.gpu_devices.value:
            capability, inferred = device["compute_capability"], device["sm_arch"]
            if capability["status"] != "OBSERVED" or inferred["status"] != "INFERRED":
                raise ValueError("target GPU capabilities are not observed")
            choices.add(inferred["value"])
        if len(choices) != 1:
            raise ValueError("multiple GPU architectures require an explicit arch")
        arch = choices.pop()
    if not isinstance(arch, str) or not re.fullmatch(r"sm_[1-9][0-9]{1,2}[a-z]?", arch):
        raise ValueError("arch must be an sm_<number>[suffix] architecture token")
    if model is not None:
        if model.supported_architectures.status != "OBSERVED" or arch not in (model.supported_architectures.value or []):
            raise ValueError("architecture is not in the target's observed nvcc supported architectures")
        if model.platform_type != current_platform_type():
            raise ValueError("snapshot belongs to another platform; this helper executes only in its current OS")
    return arch


def _local_path(value: str | Path, *, source: bool = False) -> Path:
    text = os.fspath(value)
    if not text or any(char in text for char in ("\x00", "\r", "\n")):
        raise ValueError("path must be nonblank and contain no NUL or newline")
    if os.name != "nt" and (re.match(r"^[A-Za-z]:", text) or "\\" in text):
        raise ValueError("Windows paths cannot be used by the Linux compiler helper")
    if os.name == "nt":
        if text.startswith("/"):
            raise ValueError("Linux paths cannot be used by the Windows compiler helper")
        if ":" in text[2:] or (":" in text and not re.match(r"^[A-Za-z]:", text)):
            raise ValueError("Windows alternate stream paths are not supported")
    path = Path(text).resolve()
    if source and (not path.is_file() or path.suffix.lower() != ".cu"):
        raise ValueError("source_path must identify an existing .cu file")
    return path


def prepare_msvc_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Validate a separately prepared MSVC environment; no shell/batch compilation.

    Open a Visual Studio developer terminal or explicitly supply its environment.
    This function does not execute vcvarsall or guess a CUDA/MSVC version pairing.
    """
    result = dict(os.environ if env is None else env)
    if any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in k + v for k, v in result.items()):
        raise ValueError("environment keys and values must be NUL-free strings")
    if os.name == "nt":
        lookup = {key.upper(): value for key, value in result.items()}
        if not lookup.get("INCLUDE") or not lookup.get("LIB") or not shutil.which("cl.exe", path=lookup.get("PATH", "")):
            raise ValueError("MSVC environment is not prepared; use a Visual Studio developer terminal "
                             "or supply prepared env; nvcc was not started")
    return result


def _validate_cubin(path: str | Path, max_cubin_bytes: int = 67108864) -> bytes:
    if Path(path).stat().st_size > max_cubin_bytes:
        raise ValueError("compiler output exceeds the cubin file-size limit")
    with Path(path).open("rb") as stream:
        data = stream.read(max_cubin_bytes + 1)
    if len(data) > max_cubin_bytes:
        raise ValueError("compiler output exceeds the cubin file-size limit")
    problems = validate_elf_structure(data)
    if problems:
        raise ValueError("invalid cubin structure: " + "; ".join(problems))
    if len(data) < 20 or struct.unpack_from("<H", data, 18)[0] != 190:
        raise ValueError("ELF machine must be EM_CUDA (190)")
    return data


def compile_cubin_result(
    source_path: str, output_path: str, arch: str | None = None,
    extra_flags: str | Sequence[str] = "", use_msvc: bool = True, *,
    snapshot: PlatformSnapshot | dict | None = None, env: Mapping[str, str] | None = None,
    timeout_seconds: float = 120, max_output_bytes: int = 1048576,
    artifact_root: str | Path | None = None, overwrite: bool = False,
    max_cubin_bytes: int = 67108864,
) -> CompileResult:
    """Run only nvcc with argv; persist evidence and inspect output without executing it."""
    selected_arch = resolve_compile_arch(arch, snapshot)
    flags = validate_compile_flags(extra_flags)
    if type(max_cubin_bytes) is not int or not 64 <= max_cubin_bytes <= 268435456:
        raise ValueError("max_cubin_bytes must be between 64 and 268435456")
    source, output = _local_path(source_path, source=True), _local_path(output_path)
    if source == output or (output.exists() and not overwrite):
        raise ValueError("output already exists or overlaps source; explicit overwrite is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    discovery_error = None
    try:
        nvcc = find_cuda_tool("nvcc")
    except FileNotFoundError as error:
        discovery_error = error
        nvcc = "nvcc.exe" if os.name == "nt" else "nvcc"
    if snapshot is not None:
        model = PlatformSnapshot.model_validate(snapshot.model_dump(mode="json") if isinstance(snapshot, PlatformSnapshot) else snapshot)
        if model.nvcc_path.status != "OBSERVED" or not model.nvcc_path.value:
            raise ValueError("snapshot must contain an observed nvcc_path to bind compiler capabilities")
        if _local_path(model.nvcc_path.value) != _local_path(nvcc):
            raise ValueError("selected nvcc differs from the platform snapshot's observed nvcc")
    effective_env = dict(os.environ if env is None else env)
    if use_msvc and os.name == "nt" and Path(nvcc).is_file():
        effective_env = prepare_msvc_environment(effective_env)
    temporary = Path(tempfile.mkdtemp(prefix=".cuda_compile_", dir=output.parent))
    built = temporary / "candidate.cubin"

    def perform_compile():
        result = run_tool(
            [nvcc, *flags, "-arch=" + selected_arch, "-cubin", "-o", str(built), str(source)],
            cwd=str(source.parent), target_environment="local", timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes, env=effective_env, artifact_root=artifact_root,
            command_source="src.tools.compile: fixed nvcc cubin adapter",
            tool_source="CUDA tool discovery: filesystem/PATH",
            _startup_error=discovery_error,
        )
        if result.end_status != "NORMAL_EXIT":
            return CompileResult(result, str(source), None, "NOT_COMPILED")
        try:
            _validate_cubin(built, max_cubin_bytes)
        except (OSError, ValueError) as error:
            return CompileResult(result, str(source), None, "INVALID_COMPILER_OUTPUT", (str(error),))
        try:
            if overwrite:
                os.replace(built, output)
            else:
                # Same-filesystem hard link publishes a complete artifact atomically
                # and fails if another caller created the requested output meanwhile.
                os.link(built, output)
        except OSError as error:
            return CompileResult(result, str(source), None, "ARTIFACT_PUBLICATION_FAILED", (str(error),))
        return CompileResult(result, str(source), str(output), "COMPILED_ELF_CUDA")
    try:
        operation = perform_compile()
    except BaseException as error:
        _attach_cleanup_failure(error, _cleanup_owned_directory(temporary, output.parent))
        raise
    diagnostic = _cleanup_owned_directory(temporary, output.parent)
    return replace(operation, diagnostics=operation.diagnostics + (diagnostic,)) if diagnostic else operation


def compile_cubin(source_path: str, output_path: str, arch: str | None = None,
                  extra_flags: str | Sequence[str] = "", use_msvc: bool = True, **kwargs) -> str:
    """Legacy path adapter; failures retain ``CompileError.result`` and raw evidence."""
    result = compile_cubin_result(source_path, output_path, arch, extra_flags, use_msvc, **kwargs)
    if not result.ok:
        raise CompileError(result)
    if result.diagnostics:
        warnings.warn("; ".join(result.diagnostics), RuntimeWarning, stacklevel=2)
    return result.output_path


def compile_kernel_source(kernel_source: str, arch: str | None = None,
                          extra_flags: str | Sequence[str] = "", work_dir: str | None = None,
                          **kwargs) -> tuple[str, str]:
    """Retain both returned files in a unique directory; caller owns success cleanup.

    Only the directory created by this call is removed on failure. Process evidence
    lives separately and is not removed with temporary source files.
    """
    if not isinstance(kernel_source, str) or not kernel_source.strip():
        raise ValueError("kernel_source must be a nonblank string")
    base = _local_path(work_dir) if work_dir is not None else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    task_dir = Path(tempfile.mkdtemp(prefix="cuda_kernel_", dir=base))
    source, output = task_dir / "kernel.cu", task_dir / "kernel.cubin"
    try:
        source.write_text(kernel_source, encoding="utf-8")
        compile_cubin(str(source), str(output), arch, extra_flags, **kwargs)
        return str(output), str(source)
    except BaseException as error:
        _attach_cleanup_failure(error, _cleanup_owned_directory(task_dir, task_dir.parent))
        raise
