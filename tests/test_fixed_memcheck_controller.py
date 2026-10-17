"""SYNTHETIC Windows transport regressions; no fixture or native tool runs."""

import base64
from copy import deepcopy
import json
from unittest.mock import patch

import pytest

from src import fixed_memcheck as controller
from src.models.lifecycle import canonical_sha256
from src.models.memcheck import MemcheckDescription
from src.models.tool_result import digest_argv, digest_bytes, seal_tool_result
from tests.test_execution_bridge import fixed_request
from tests.test_lifecycle_bridge import worker_identity
from tests.test_memcheck_evidence import synthetic_memcheck_case
from tests.test_p1c_integration import synthetic_tool_record


def synthetic_description():
    """SYNTHETIC only: dictionary observations do not authenticate a host."""
    _, snapshot, _ = fixed_request()
    tools = {role: {"requested_executable": "/synthetic/" + role, "resolved_path": "/synthetic/" + role,
        "status": "OBSERVED", "file_sha256": "1" * 64, "source": "SYNTHETIC_NOT_REAL_CAPTURE"}
        for role in ("compiler", "valgrind", "valgrind_launcher", "memcheck", "bwrap", "guard_python")}
    versions = {}
    for role in ("compiler", "valgrind", "bwrap"):
        value = synthetic_tool_record().model_dump(mode="python")
        argv = [tools[role]["resolved_path"], "--version"]
        value.update(argv=argv, cwd="/synthetic", target_environment="wsl:Ubuntu-22.04", platform_type="wsl",
                     tool_identity=tools[role], command_identity={"source": "SYNTHETIC_VERSION_ONLY", "argv_sha256": digest_argv(argv)})
        value["resource_limits"]["termination_scope"] = "POSIX_PROCESS_GROUP"
        versions[role] = seal_tool_result(value)
    return MemcheckDescription(description_id="d" * 32, status="DESCRIBED", target_environment="wsl:Ubuntu-22.04",
        snapshot=snapshot, native_task_root="/home/pocdev/.local/state/cuda-poc-generator/memcheck_tasks",
        tools=tools, helper_images={}, collector_sha256=controller._collector_sha256(), versions=versions,
        target_boot_id="11111111-1111-1111-1111-111111111111", observed_monotonic_ns=1000, diagnostics=[])


def describe_packet(desc, **updates):
    result = {"schema_version": "1.0", "operation": "DESCRIBE", "nonce": "e" * 32,
        "request_id": "a" * 32, "run_id": "b" * 32, "target_environment": "wsl:Ubuntu-22.04",
        "worker_identity": worker_identity(100), "status": desc.status,
        "description": desc.model_dump(mode="json"), "record": None, "recovery": None,
        "raw_files": {}, "diagnostics": []}
    result.update(updates)
    return result


def parse_packet(value, **kwargs):
    return controller.parse_memcheck_packet(json.dumps(value).encode(), operation=value["operation"],
        nonce="e" * 32, request_id="a" * 32, run_id="b" * 32,
        target_environment=value["target_environment"], **kwargs)


def test_explicit_operator_boundary_pins_complete_request_and_target_boot():
    desc = synthetic_description()
    request, auth, policy = controller.build_fixed_memcheck_context(desc, "p3c-normal-v1",
        authorize_fixed_memcheck=True, operator_id="SYNTHETIC_OPERATOR", authorization_reference="SYNTHETIC_SCOPE")
    assert auth.request_sha256 == policy.request_sha256 == canonical_sha256(request)
    assert request.description_sha256 == canonical_sha256(desc)
    assert request.collector_sha256 == desc.collector_sha256
    assert auth.target_boot_id == desc.target_boot_id
    assert auth.expires_monotonic_ns - auth.not_before_monotonic_ns == 300000000000
    assert policy.resource_limits.memory_bytes == 4294967296
    assert policy.allowed_images == {item.resolved_path: item.file_sha256 for item in desc.tools.values()}


@pytest.mark.parametrize("granted", [False, None, "true", 1])
def test_untrusted_truthy_values_cannot_authorize(granted):
    with pytest.raises(ValueError, match="明确授权"):
        controller.build_fixed_memcheck_context(synthetic_description(), "p3c-normal-v1",
            authorize_fixed_memcheck=granted, operator_id="operator", authorization_reference="ref")


@pytest.mark.parametrize("task", ["EXECUTE_CANDIDATE", "../../fixture", "p3c-freed-read-v1"])
def test_only_two_reviewed_tasks_are_admitted_without_launching(task):
    with patch.object(controller, "_transport") as run, pytest.raises(ValueError):
        controller.run_fixed_memcheck_wsl(task, authorize_fixed_memcheck=True,
            operator_id="operator", authorization_reference="scope", linux_project_root="/mnt/f/project")
    run.assert_not_called()


@pytest.mark.parametrize("field,value", [("nonce", "f" * 32), ("run_id", "f" * 32),
    ("request_id", "f" * 32), ("extra", True)])
def test_transport_identity_confusion_rejected(field, value):
    packet = describe_packet(synthetic_description())
    packet[field] = value
    with pytest.raises(ValueError):
        parse_packet(packet)


def test_collector_substitution_and_duplicate_json_are_rejected():
    packet = describe_packet(synthetic_description())
    packet["description"]["collector_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="采集器"):
        parse_packet(packet)
    with pytest.raises(ValueError):
        controller.parse_memcheck_packet(b'{"nonce":"x","nonce":"y"}', operation="DESCRIBE", nonce="e" * 32,
            request_id="a" * 32, run_id="b" * 32, target_environment="wsl:Ubuntu-22.04")


@pytest.mark.parametrize("change", ["raw", "tool", "operator", "worker", "platform"])
def test_raw_execution_packet_binds_request_authority_and_observed_worker(change):
    record, request, auth, policy, raw = synthetic_memcheck_case()
    value = record.model_dump(mode="python")
    value["worker_identity"] = worker_identity(100)
    packet = describe_packet(synthetic_description(), operation="EXECUTE", target_environment=request.target_environment,
        description=None, status=record.status, record=value,
        raw_files={name: base64.b64encode(data).decode() for name, data in raw.items()})
    if change == "raw": packet["raw_files"]["memcheck.xml"] = base64.b64encode(b"replaced").decode()
    if change == "tool":
        request = request.model_copy(update={"tools": {**request.tools,
            "compiler": request.tools["compiler"].model_copy(update={"file_sha256": "f" * 64})}})
    if change == "operator": auth = auth.model_copy(update={"operator_id": "UNTRUSTED"})
    if change == "worker": packet["worker_identity"]["pid"] += 1
    if change == "platform": packet["record"]["target_environment"] = "wsl:Other"
    with pytest.raises(ValueError):
        parse_packet(packet, expected_request=request, authorization=auth, policy=policy)


def test_launcher_failure_uses_scoped_cancel_and_independent_status(tmp_path):
    desc = synthetic_description()
    calls = []
    def fake_transport(payload, handle, **kwargs):
        calls.append(payload["operation"])
        assert payload["run_id"] == handle.run_id
        if payload["operation"] == "DESCRIBE":
            packet = describe_packet(desc, nonce=payload["nonce"], request_id=handle.request_id, run_id=handle.run_id)
            return None, controller.MemcheckPacket.model_validate(packet), []
        return None, None, ["SYNTHETIC_LAUNCHER_FAILURE"]
    with patch.object(controller, "_transport", side_effect=fake_transport), patch.object(controller, "save_memcheck_evidence") as save:
        result = controller.run_fixed_memcheck_wsl("p3c-normal-v1", authorize_fixed_memcheck=True,
            operator_id="SYNTHETIC_OPERATOR", authorization_reference="SYNTHETIC_SCOPE",
            linux_project_root="/mnt/f/project", output_root=tmp_path)
    assert calls == ["DESCRIBE", "EXECUTE", "CANCEL", "STATUS"]
    assert result["effective_state"] == "UNKNOWN" and result["evidence_directory"] is None
    assert result["candidate_execution_status"] == "NOT_EXECUTED" and result["verification_status"] == "NOT_VERIFIED"
    save.assert_not_called()
    session = next((tmp_path / "controller").iterdir())
    assert (session / "task_handle.private.json").is_file()
    assert "UNKNOWN" in (session / "controller_report.zh-CN.md").read_text(encoding="utf-8")


def test_unmeasured_windows_launcher_is_fail_closed(tmp_path):
    handle = controller._new_handle(distro="Ubuntu-22.04", user="pocdev", linux_python="/tools/python",
        linux_project_root="/mnt/f/project")
    identity = {"requested_executable": "wsl.exe", "resolved_path": None, "status": "UNKNOWN",
                "file_sha256": None, "source": "SYNTHETIC_UNKNOWN"}
    from src.models.tool_result import ToolIdentity
    with patch.object(controller, "_windows_host", return_value=True), patch.object(controller, "measure_tool_identity", return_value=ToolIdentity(**identity)), \
         patch.object(controller, "build_execution_worker_source", return_value=b"SYNTHETIC"), patch.object(controller, "run_tool", side_effect=OSError("NO_LAUNCH")) as run:
        with pytest.raises(OSError):
            controller._transport(controller._envelope("DESCRIBE", handle), handle, artifact_root=tmp_path)
    assert run.call_args.kwargs["allowed_tool_identities"] == {}
    assert run.call_args.args[0][0] == "wsl.exe"
