"""Fixed device-only CUDA smoke input and pure command/artifact checks.

This module never starts a tool, loads a CUDA driver or launches a kernel. The
execution worker separately authorizes each task and measures tool identities.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import struct

from .models.platform import PlatformSnapshot
from .models.tool_result import ToolIdentity
from .tools.compile import resolve_compile_arch
from .tools.elf_ops import parse_all_sections, validate_elf_structure, find_section, CUDA_12_8_PROFILE


CUDA_SMOKE_ID = "p2c-cuda-smoke-v1"
CUDA_SMOKE_SOURCE = b'''// Fixed P2-C device-only compilation fixture. Never launch this kernel.
// No host entry point, CUDA API call, memory access, filesystem or networking.
extern "C" __global__ void cuda_poc_safe_smoke() {}
'''
CUDA_SMOKE_SHA256 = hashlib.sha256(CUDA_SMOKE_SOURCE).hexdigest()
CUDA_SMOKE_RELATIVE_PATH = "tests/fixtures/cuda/safe_smoke.cu"
CUDA_SMOKE_KERNEL = "cuda_poc_safe_smoke"
CUDA_SMOKE_KERNEL_SECTION = ".text." + CUDA_SMOKE_KERNEL
CUDA_SMOKE_SOURCE_NAME = "safe_smoke.cu"
CUDA_SMOKE_OUTPUT_RELATIVE_PATH = "out/safe_smoke.cubin"


@dataclass(frozen=True)
class RegisteredCudaSmoke:
    fixture_id: str = CUDA_SMOKE_ID
    source: bytes = CUDA_SMOKE_SOURCE
    sha256: str = CUDA_SMOKE_SHA256
    relative_path: str = CUDA_SMOKE_RELATIVE_PATH
    description: str = "Fixed empty CUDA kernel; compile and inspect only, never execute"


_ACTION = RegisteredCudaSmoke()


def get_cuda_smoke_action() -> RegisteredCudaSmoke:
    return _ACTION


def _posix_absolute(value, label):
    if not isinstance(value, (str, PurePosixPath)):
        raise ValueError(label + " must be an absolute target POSIX path")
    text = str(value)
    path = PurePosixPath(text)
    if (not text or any(character in text for character in "\0\r\n\\")
            or PureWindowsPath(text).drive or not path.is_absolute()
            or text.startswith("//") or ".." in path.parts or str(path) != text):
        raise ValueError(label + " must be a canonical absolute target POSIX path")
    return text


def _arch_token(arch):
    if not isinstance(arch, str) or not re.fullmatch(r"sm_[1-9][0-9]{1,2}[a-z]?", arch):
        raise ValueError("CUDA target must be one explicit sm_<number>[suffix] token")
    return arch


def _equivalent_tool_paths(left, right):
    if left == right:
        return True
    # Resolve a CUDA installation symlink only in the actual target filesystem.
    # Windows must never reinterpret a Linux path as a local drive path.
    if os.name == "nt":
        return False
    try:
        return Path(left).resolve(strict=True) == Path(right).resolve(strict=True)
    except OSError:
        return False


def select_cuda_arch(arch, snapshot, *, expected_nvcc_path):
    """Require observed GPU capabilities and that exact nvcc's supported target.

    This runs in the target OS, like resolve_compile_arch. A snapshot remains a
    record, not a freshness or authorization grant; the worker handles those.
    """
    model = PlatformSnapshot.model_validate(snapshot.model_dump(mode="python")
                                            if isinstance(snapshot, PlatformSnapshot) else snapshot)
    expected = _posix_absolute(expected_nvcc_path, "expected nvcc executable")
    if model.platform_type != "wsl" or model.execution_backend != "wsl":
        raise ValueError("CUDA smoke requires an observed WSL target snapshot")
    for name in ("nvcc_path", "nvcc_version", "cuda_toolkit_version", "supported_architectures"):
        if getattr(model, name).status != "OBSERVED":
            raise ValueError("CUDA smoke requires observed " + name)
    if not _equivalent_tool_paths(_posix_absolute(model.nvcc_path.value, "snapshot nvcc executable"), expected):
        raise ValueError("compiler executable differs from the snapshot nvcc")
    if model.gpu_devices.status != "OBSERVED" or not model.gpu_devices.value:
        raise ValueError("CUDA smoke requires an observed target GPU")
    gpu_architectures = set()
    for device in model.gpu_devices.value:
        if device["compute_capability"]["status"] != "OBSERVED" or device["sm_arch"]["status"] != "INFERRED":
            raise ValueError("GPU architecture must derive from an observed compute capability")
        gpu_architectures.add(device["sm_arch"]["value"])
    selected = resolve_compile_arch(arch, model)
    if selected not in gpu_architectures:
        raise ValueError("explicit architecture does not match any observed target GPU")
    return selected


def _tool(tools, role):
    if not isinstance(tools, dict) or set(tools).difference({"nvcc", "cuobjdump", "nvdisasm", "guard_python", "host_compiler"}):
        raise ValueError("CUDA tools must use the fixed role registry")
    if role not in tools:
        raise ValueError("CUDA tool role is missing: " + role)
    value = tools[role]
    identity = ToolIdentity.model_validate(value.model_dump(mode="python") if isinstance(value, ToolIdentity) else value)
    if identity.status != "OBSERVED":
        raise ValueError("CUDA tool identity is unmeasured: " + role)
    path = _posix_absolute(identity.resolved_path, role + " executable")
    if role in {"nvcc", "cuobjdump", "nvdisasm"} and PurePosixPath(path).name != role:
        raise ValueError("CUDA executable basename disagrees with its registered role")
    return path


def build_nvcc_argv(tool, arch, source, output, *, host_compiler):
    """Fixed device-only compile flags; no caller flags or response files."""
    return [_posix_absolute(tool, "nvcc"), "--cubin", "--gpu-architecture=" + _arch_token(arch),
            "--std=c++14", "--compiler-bindir=" + _posix_absolute(host_compiler, "host compiler"),
            "--output-file", _posix_absolute(output, "cubin output"), _posix_absolute(source, "CUDA source")]


def build_cuda_step_argv(step_id, tools, arch, workspace):
    """Construct one fixed tool step; requests cannot supply argv or filenames."""
    root = _posix_absolute(workspace, "task workspace")
    source = str(PurePosixPath(root) / CUDA_SMOKE_SOURCE_NAME)
    output = str(PurePosixPath(root) / CUDA_SMOKE_OUTPUT_RELATIVE_PATH)
    if step_id in {"nvcc_version", "cuobjdump_version", "nvdisasm_version"}:
        return [_tool(tools, step_id.removesuffix("_version")), "--version"]
    if step_id == "compile":
        return build_nvcc_argv(_tool(tools, "nvcc"), arch, source, output,
                               host_compiler=_tool(tools, "host_compiler"))
    if step_id == "cuobjdump":
        return [_tool(tools, "cuobjdump"), "--dump-elf", output]
    if step_id == "nvdisasm":
        return [_tool(tools, "nvdisasm"), "--no-dataflow", output]
    raise ValueError("unregistered CUDA smoke tool step")


def validate_smoke_cubin_bytes(data, *, expected_sha256=None, max_cubin_bytes=67108864):
    """Describe the supported ELF subset; this does not establish file origin.

    Only a successful, authorized compile of the registered source can make this
    file eligible for native inspection. The worker verifies that provenance and
    repeats the exact byte hash immediately before each native-tool launch.
    """
    if type(max_cubin_bytes) is not int or not 64 <= max_cubin_bytes <= 268435456:
        raise ValueError("unsupported cubin byte limit")
    if not isinstance(data, bytes) or not 64 <= len(data) <= max_cubin_bytes:
        raise ValueError("cubin must be nonempty bounded ELF64 bytes")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or digest != expected_sha256):
        raise ValueError("cubin SHA-256 differs from the compiler artifact record")
    # Keep original bytes. Unknown vendor version tuples remain rejected; this
    # opt-in profile is supported only for this workflow's measured CUDA 12.8.
    profile = CUDA_12_8_PROFILE if struct.unpack_from("<I", data, 20)[0] != 1 else None
    problems = validate_elf_structure(data, profile=profile)
    if problems:
        raise ValueError("unsupported or invalid cubin structure: " + "; ".join(problems))
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_machine != 190:
        raise ValueError("cubin machine must be EM_CUDA (190)")
    if e_type != 2:
        raise ValueError("fixed smoke cubin must use ET_EXEC")
    sections = parse_all_sections(data, profile=profile)
    kernel = find_section(data, CUDA_SMOKE_KERNEL_SECTION, profile=profile)
    if kernel is None or kernel[1][1] != 1 or kernel[1][5] == 0:
        raise ValueError("fixed CUDA kernel text is absent, empty or not SHT_PROGBITS")
    return {"size_bytes": len(data), "sha256": digest, "elf_class": "ELF64",
            "byte_order": "little", "e_machine": e_machine, "e_type": e_type,
            "section_count": len(sections), "kernel_name": CUDA_SMOKE_KERNEL,
            "kernel_section": CUDA_SMOKE_KERNEL_SECTION, "kernel_section_size_bytes": kernel[1][5],
            "structure_status": "SUPPORTED_ELF_SUBSET", "structural_profile": profile or "SYSTEM_V_ELF64",
            "elf_version_raw": struct.unpack_from("<I", data, 20)[0], "osabi_raw": data[7], "abi_version_raw": data[8],
            "candidate_execution_status": "NOT_EXECUTED",
            "verification_status": "NOT_VERIFIED"}


def observe_smoke_cubin(path, *, expected_sha256=None, max_cubin_bytes=67108864):
    """Read bounded regular bytes only; never execute or repair the artifact."""
    selected = Path(path)
    if not selected.is_absolute() or any(item.is_symlink() for item in (selected, *selected.parents)):
        raise ValueError("compiler artifact must use an absolute, unlinked task path")
    if not selected.is_file():
        raise ValueError("compiler cubin output is missing or not a regular file")
    if type(max_cubin_bytes) is not int or not 64 <= max_cubin_bytes <= 268435456:
        raise ValueError("unsupported cubin byte limit")
    with selected.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > max_cubin_bytes:
            raise ValueError("compiler cubin exceeds the file-size limit")
        data = stream.read(max_cubin_bytes + 1)
        after = os.fstat(stream.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("compiler artifact changed during measurement")
    result = validate_smoke_cubin_bytes(data, expected_sha256=expected_sha256, max_cubin_bytes=max_cubin_bytes)
    return {"path": str(selected), **result}
