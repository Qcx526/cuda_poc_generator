from types import SimpleNamespace
from pathlib import PurePosixPath
from unittest.mock import patch

import pytest

from src.cuda_smoke_worker import (CUOBJDUMP_12_8_55_1_SHA256, CudaSmokeDescription,
    infer_cuobjdump_profile, registered_sidecar_cuobjdump_identity_matches, validate_cuda_versions)


def _scope(nvcc, cuobjdump, version_text="Cuda compilation tools, release 12.8, V12.8.90"):
    from src.models.tool_result import ToolIdentity

    tools = {
        "nvcc": ToolIdentity(status="OBSERVED", requested_executable=str(nvcc), resolved_path=str(nvcc),
            file_sha256="a" * 64, source="test"),
        "cuobjdump": ToolIdentity(status="OBSERVED", requested_executable=str(cuobjdump), resolved_path=str(cuobjdump),
            file_sha256="b" * 64, source="test"),
    }
    return SimpleNamespace(tools=tools, version_records={"cuobjdump": SimpleNamespace(
        stdout_bytes=lambda: version_text.encode(), stderr_bytes=lambda: b"",
        target_environment="wsl:Ubuntu-22.04")})


def test_default_cuda_description_serialization_keeps_legacy_shape():
    description = CudaSmokeDescription(
        description_schema_version="1.0", status="UNKNOWN", snapshot=None, scope=None,
        native_task_root="/tmp/tasks", source_sha256="a" * 64,
        resource_support={"status": "UNKNOWN", "mechanisms": [], "source": "offline test"}, diagnostics=[])
    dumped = description.model_dump(mode="json")
    assert dumped["description_schema_version"] == "1.0"
    assert "tool_profile" not in dumped


def test_sidecar_profile_requires_its_versioned_description_schema():
    with pytest.raises(ValueError):
        CudaSmokeDescription(
            description_schema_version="1.0", tool_profile="cuobjdump-12.8.55-1", status="UNKNOWN",
            snapshot=None, scope=None, native_task_root="/tmp/tasks", source_sha256="a" * 64,
            resource_support={"status": "UNKNOWN", "mechanisms": [], "source": "offline test"}, diagnostics=[])
    sidecar = CudaSmokeDescription(
        description_schema_version="1.1", tool_profile="cuobjdump-12.8.55-1", status="UNKNOWN",
        snapshot=None, scope=None, native_task_root="/tmp/tasks", source_sha256="a" * 64,
        resource_support={"status": "UNKNOWN", "mechanisms": [], "source": "offline test"}, diagnostics=[])
    assert sidecar.model_dump(mode="json")["tool_profile"] == "cuobjdump-12.8.55-1"


def test_only_system_sibling_or_fixed_sidecar_path_is_registered():
    bindir = PurePosixPath("/opt/cuda/bin")
    nvcc, system = bindir / "nvcc", bindir / "cuobjdump"
    sidecar = PurePosixPath("/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump")
    with patch("src.cuda_smoke_worker._sidecar_cuobjdump_path", return_value=sidecar):
        assert infer_cuobjdump_profile(_scope(nvcc, system)) == "system-toolkit"
        assert infer_cuobjdump_profile(_scope(nvcc, sidecar)) == "cuobjdump-12.8.55-1"
        with pytest.raises(ValueError, match="outside registered"):
            infer_cuobjdump_profile(_scope(nvcc, PurePosixPath("/tmp/unknown-cuobjump")))


def test_sidecar_profile_rejects_wrong_build_identity():
    nvcc = PurePosixPath("/opt/cuda/bin/nvcc")
    sidecar = PurePosixPath("/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump")
    scope = _scope(nvcc, sidecar, version_text="Cuda compilation tools, release 12.8, V12.8.90")
    snapshot = SimpleNamespace(cuda_toolkit_version=SimpleNamespace(status="OBSERVED", value="12.8.90"))
    with patch("src.cuda_smoke_worker._sidecar_cuobjdump_path", return_value=sidecar):
        with patch("src.cuda_smoke_worker.canonical_target_environment", return_value="wsl:Ubuntu-22.04"):
            with pytest.raises(ValueError, match="registered CUDA 12.8.55"):
                validate_cuda_versions(scope, snapshot, tool_profile="cuobjdump-12.8.55-1")


def test_sidecar_identity_requires_measured_executable_sha256():
    nvcc = PurePosixPath("/opt/cuda/bin/nvcc")
    sidecar = PurePosixPath("/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump")
    version = ("Cuda compilation tools, release 12.8, V12.8.55\n"
               "Build cuda_12.8.r12.8/compiler.35351055_0\n")
    scope = _scope(nvcc, sidecar, version_text=version)
    snapshot = SimpleNamespace(cuda_toolkit_version=SimpleNamespace(status="OBSERVED", value="12.8.90"))
    scope.tools["cuobjdump"] = scope.tools["cuobjdump"].model_copy(
        update={"file_sha256": CUOBJDUMP_12_8_55_1_SHA256})
    with patch("src.cuda_smoke_worker._sidecar_cuobjdump_path", return_value=sidecar):
        with patch("src.cuda_smoke_worker.canonical_target_environment", return_value="wsl:Ubuntu-22.04"):
            validate_cuda_versions(scope, snapshot, tool_profile="cuobjdump-12.8.55-1")
            assert registered_sidecar_cuobjdump_identity_matches(scope.tools["cuobjdump"], version)
            scope.tools["cuobjdump"] = scope.tools["cuobjdump"].model_copy(update={"file_sha256": "b" * 64})
            assert not registered_sidecar_cuobjdump_identity_matches(scope.tools["cuobjdump"], version)
            with pytest.raises(ValueError, match="registered CUDA 12.8.55"):
                validate_cuda_versions(scope, snapshot, tool_profile="cuobjdump-12.8.55-1")


@pytest.mark.parametrize("target_root,expected", [
    ("/home/pocdev/.local/state/cuda-poc-generator/lifecycle_tasks", True),
    ("/home/other/.local/state/cuda-poc-generator/lifecycle_tasks", False),
    ("/home/pocdev/.local/state/cuda-poc-generator/other_tasks", False),
    ("/home/pocdev/../pocdev/.local/state/cuda-poc-generator/lifecycle_tasks", False),
    ("C:\\Users\\Administrator\\.local\\state\\cuda-poc-generator\\lifecycle_tasks", False),
])
def test_remote_sidecar_identity_uses_bound_posix_root_not_controller_home(target_root, expected):
    sidecar = PurePosixPath("/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump")
    tool = _scope(PurePosixPath("/opt/cuda/bin/nvcc"), sidecar).tools["cuobjdump"].model_copy(
        update={"file_sha256": CUOBJDUMP_12_8_55_1_SHA256})
    version = "Cuda compilation tools, release 12.8, V12.8.55\nBuild cuda_12.8.r12.8/compiler.35351055_0\n"
    with patch("src.cuda_smoke_worker._sidecar_cuobjdump_path", side_effect=AssertionError("controller HOME must not be used")):
        assert registered_sidecar_cuobjdump_identity_matches(tool, version, target_task_root=target_root) is expected
