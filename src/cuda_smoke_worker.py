"""Fixed safe CUDA description/workflow, dispatched only by lifecycle_worker.

No arbitrary command, source or candidate execution interface exists here.
"""

from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import sys
import time

from pydantic import Field

from .cuda_registry import (CUDA_SMOKE_ID, CUDA_SMOKE_SOURCE, CUDA_SMOKE_SHA256,
                            CUDA_SMOKE_RELATIVE_PATH, select_cuda_arch, observe_smoke_cubin)
from .execution_worker import _snapshot, resource_capabilities
from .execution_preflight import target_boot_id
from .models.execution import StrictContract, CudaToolchainScope, ResourceSupport
from .models.lifecycle import CudaSmokeObservation, CudaSmokeStep, CudaBinaryArtifact
from .models.platform import PlatformSnapshot
from .tools.process import canonical_target_environment, measure_tool_identity, run_tool


@contextmanager
def cuda_probe_environment():
    """Remove compiler option injection while running the fixed read-only probe.

    This scoped WSL worker is single-task; original values are restored afterwards.
    Native compile/inspect steps separately use a minimal explicit environment.
    """
    names = ("NVCC_PREPEND_FLAGS", "NVCC_APPEND_FLAGS", "NVCC_CCBIN", "CC", "CXX", "CFLAGS", "CXXFLAGS",
             "CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH",
             "LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT")
    previous = {name: os.environ.pop(name) for name in names if name in os.environ}
    try:
        yield
    finally:
        for name in names:
            os.environ.pop(name, None)
        os.environ.update(previous)


def cuda_snapshot(target):
    with cuda_probe_environment():
        return _snapshot(target)


class CudaSmokeDescription(StrictContract):
    description_schema_version: str = Field(pattern=r"^1\.0$")
    status: str = Field(pattern=r"^(DESCRIBED|UNKNOWN|UNSUPPORTED|REJECTED)$")
    snapshot: PlatformSnapshot | None
    scope: CudaToolchainScope | None
    native_task_root: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resource_support: ResourceSupport
    diagnostics: list[str]


def validate_cuda_versions(scope, snapshot):
    """This first integration deliberately supports the measured 12.8 family."""
    for role, record in scope.version_records.items():
        text = (record.stdout_bytes() + record.stderr_bytes()).decode("utf-8", errors="replace")
        found = re.search(r"release\s+(\d+)\.(\d+)", text)
        if found is None or found.groups() != ("12", "8"):
            raise ValueError("unsupported or unrecognized CUDA 12.8 tool version: " + role)
        if record.target_environment != canonical_target_environment():
            raise ValueError("CUDA version observation belongs to another target")
    if (snapshot.cuda_toolkit_version.status != "OBSERVED"
            or re.fullmatch(r"12\.8(?:\.[0-9]+)?", str(snapshot.cuda_toolkit_version.value)) is None):
        raise ValueError("toolkit observation does not establish CUDA 12.8")


def describe_cuda_smoke(root, native_root):
    """Only fixed read-only snapshot/version queries; no compiler input supplied."""
    data = {"description_schema_version": "1.0", "status": "UNKNOWN", "snapshot": None,
            "scope": None, "native_task_root": str(native_root), "source_sha256": CUDA_SMOKE_SHA256,
            "resource_support": resource_capabilities(), "diagnostics": []}
    try:
        source = root / CUDA_SMOKE_RELATIVE_PATH
        if source.is_symlink() or source.read_bytes() != CUDA_SMOKE_SOURCE:
            raise ValueError("registered CUDA source file identity mismatch")
        snapshot_started_ns = time.monotonic_ns()
        boot_id = target_boot_id()
        snapshot = cuda_snapshot(canonical_target_environment())
        data["snapshot"] = snapshot.model_dump(mode="json")
        if snapshot.nvcc_path.status != "OBSERVED":
            data.update(status="UNSUPPORTED", diagnostics=["NVCC_NOT_OBSERVED"])
            return CudaSmokeDescription.model_validate(data).model_dump(mode="json")
        nvcc = measure_tool_identity(snapshot.nvcc_path.value, source="fixed CUDA describe nvcc bytes")
        if nvcc.status != "OBSERVED":
            raise ValueError("nvcc identity unknown")
        tools = {"nvcc": nvcc, "guard_python": measure_tool_identity(sys.executable, source="fixed CUDA guard interpreter")}
        for role in ("cuobjdump", "nvdisasm"):
            tools[role] = measure_tool_identity(str(Path(nvcc.resolved_path).parent / role),
                                                source="fixed CUDA toolkit sibling executable")
        compiler = shutil.which("g++", path="/usr/bin:/bin")
        if compiler is None:
            data.update(status="UNSUPPORTED", diagnostics=["HOST_COMPILER_MISSING"])
            return CudaSmokeDescription.model_validate(data).model_dump(mode="json")
        tools["host_compiler"] = measure_tool_identity(compiler, source="fixed system host compiler bytes")
        if any(tool.status != "OBSERVED" for tool in tools.values()):
            data.update(status="UNSUPPORTED", diagnostics=["REQUIRED_CUDA_TOOL_IDENTITY_UNAVAILABLE"])
            return CudaSmokeDescription.model_validate(data).model_dump(mode="json")
        versions = {}
        for role in ("nvcc", "cuobjdump", "nvdisasm"):
            tool = tools[role]
            versions[role] = run_tool([tool.resolved_path, "--version"], cwd=root, timeout_seconds=5,
                max_output_bytes=32768, command_source="fixed CUDA read-only tool version describe",
                tool_source=tool.source,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                allowed_tool_identities={tool.resolved_path: tool.file_sha256})
            observed = versions[role].tool_identity
            if (observed.status != "OBSERVED" or (observed.resolved_path, observed.file_sha256)
                    != (tool.resolved_path, tool.file_sha256)):
                raise ValueError("tool identity changed during the fixed version observation: " + role)
            # Preserve the original run_tool provenance/requested spelling. A
            # symlink spelling or measurement description is not a file identity;
            # path and byte hash were compared before accepting this observation.
            tools[role] = observed
        arch = select_cuda_arch(None, snapshot, expected_nvcc_path=nvcc.resolved_path)
        scope = CudaToolchainScope(arch=arch, tools=tools, version_records=versions, target_boot_id=boot_id,
                                   snapshot_started_monotonic_ns=snapshot_started_ns, observed_monotonic_ns=time.monotonic_ns())
        validate_cuda_versions(scope, snapshot)
        data.update(status="DESCRIBED", scope=scope.model_dump(mode="json"))
    except FileNotFoundError:
        data.update(status="UNSUPPORTED", diagnostics=["REGISTERED_SOURCE_OR_REQUIRED_TOOL_MISSING"])
    except (OSError, ValueError) as exc:
        data.update(status="UNKNOWN", diagnostics=["CUDA_DESCRIPTION_FAILED:" + str(exc)])
    return CudaSmokeDescription.model_validate(data).model_dump(mode="json")


@dataclass(frozen=True)
class CudaWorkflowOutcome:
    state: str
    smoke: CudaSmokeObservation
    diagnostics: list[str]

    @property
    def process(self):
        return self.smoke.steps[-1].process if self.smoke.steps else None


def run_cuda_workflow(request, authorization, snapshot, folder, *, nonce, on_event, save_json):
    """Run the exact six registered tool steps after the parent strict preflight."""
    from .cuda_process import run_registered_cuda_tool
    scope = request.cuda_toolchain
    steps = []
    artifact = None
    workspace = Path(request.cwd)

    def outcome(state, diagnostics):
        if state in {"REJECTED", "UNSUPPORTED", "START_FAILED"} and any(step.process.action_started for step in steps):
            diagnostics = ["LATER_TOOL_STEP_NOT_STARTED:" + state, *diagnostics]
            state = "UNKNOWN"
        return CudaWorkflowOutcome(state, CudaSmokeObservation(
            source_sha256=CUDA_SMOKE_SHA256, arch=scope.arch, tool_versions=scope.version_records,
            steps=steps, artifact=artifact), diagnostics)

    for step_id in ("nvcc_version", "cuobjdump_version", "nvdisasm_version", "compile", "cuobjdump", "nvdisasm"):
        from .execution_preflight import authorization_active
        if not authorization_active(authorization):
            return outcome("UNKNOWN" if steps else "REJECTED", ["AUTHORIZATION_EXPIRED_BETWEEN_CUDA_STEPS"])
        # Check the same exact source before every step. Inspection consumes only
        # the byte-identical output produced by this run's successful compiler.
        source = workspace / "safe_smoke.cu"
        try:
            source_ok = not source.is_symlink() and source.read_bytes() == CUDA_SMOKE_SOURCE
        except OSError:
            source_ok = False
        if not source_ok:
            return outcome("UNKNOWN" if steps else "REJECTED", ["REGISTERED_CUDA_SOURCE_CHANGED"])
        if step_id == "compile" and (workspace / "out" / "safe_smoke.cubin").exists():
            return outcome("UNKNOWN", ["CUBIN_OUTPUT_ALREADY_EXISTS"])
        if step_id in {"cuobjdump", "nvdisasm"}:
            try:
                observe_smoke_cubin(workspace / "out" / "safe_smoke.cubin", expected_sha256=artifact.sha256)
            except (OSError, ValueError):
                return outcome("UNKNOWN", ["COMPILED_ARTIFACT_CHANGED_OR_MISSING"])
        current_step = folder / "steps" / step_id
        current_step.mkdir(parents=True, mode=0o700, exist_ok=False)
        def observed(kind, detail):
            on_event(kind, {**detail, "cuda_step_id": step_id})
        try:
            result = run_registered_cuda_tool(step_id, tools=scope.tools, arch=scope.arch,
                workspace=workspace, limits=request.resource_limits, target_environment=request.binding.target_environment,
                request_id=request.request_id, run_id=folder.name, nonce=nonce,
                cancellation_file=folder / "cancel.json", on_event=observed,
                expected_artifact_sha256=None if artifact is None else artifact.sha256)
        except (OSError, ValueError) as exc:
            return outcome("UNKNOWN" if steps else getattr(exc, "execution_state", "UNKNOWN"),
                           ["CUDA_STEP_NOT_STARTED:" + step_id, type(exc).__name__ + ":" + str(exc)])
        steps.append(CudaSmokeStep(step_id=step_id, state=result.state, process=result.process))
        try:
            for name, raw in (("stdout.bin", result.process.stdout_bytes()), ("stderr.bin", result.process.stderr_bytes())):
                fd = os.open(current_step / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            save_json(current_step / "process_result.json", result.process.model_dump(mode="json"))
        except OSError as exc:
            return outcome("UNKNOWN", ["NATIVE_STEP_EVIDENCE_INCOMPLETE:" + step_id, type(exc).__name__])
        if result.state != "COMPLETED":
            return outcome(result.state, ["CUDA_STEP_FAILED:" + step_id, *result.process.diagnostics])
        if step_id.endswith("_version"):
            text = (result.process.stdout_bytes() + result.process.stderr_bytes()).decode("utf-8", errors="replace")
            version = re.search(r"release\s+(\d+)\.(\d+)", text)
            if version is None or version.groups() != ("12", "8"):
                return outcome("UNKNOWN", ["ACTUAL_CUDA_TOOL_VERSION_UNSUPPORTED:" + step_id])
        if step_id == "compile":
            try:
                measured = observe_smoke_cubin(workspace / "out" / "safe_smoke.cubin")
                artifact = CudaBinaryArtifact(**{key: measured[key] for key in (
                    "size_bytes", "sha256", "structural_profile", "elf_version_raw", "osabi_raw", "abi_version_raw",
                    "section_count", "kernel_section_size_bytes")})
            except (OSError, ValueError) as exc:
                return outcome("UNKNOWN", ["COMPILED_ELF_REJECTED:" + str(exc)])
    return outcome("COMPLETED", [])
