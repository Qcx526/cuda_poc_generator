"""SYNTHETIC offline records only; no compiler, fixture or Valgrind is run."""

import base64
import json
import os
from pathlib import Path
import stat
from unittest.mock import patch

import pytest

from src.memcheck_evidence import (parse_memcheck_evidence, read_memcheck_evidence,
    reassess_memcheck_evidence, render_memcheck_report, save_memcheck_evidence)
from src.memcheck_registry import fixed_source, inner_argv
from src.models.lifecycle import canonical_sha256
from src.models.memcheck import (MemcheckAuthorization, MemcheckExecutionRecord, MemcheckPolicy,
                                 MemcheckProcess, MemcheckRequest)
from src.models.tool_result import digest_bytes


def synthetic_memcheck_case(*, kind="InvalidWrite", xml_transform=None, task="p3c-invalid-write-v1"):
    """Explicitly synthetic execution observations for offline contract tests."""
    ids = {"request_id": "a" * 32, "run_id": "b" * 32}
    source = fixed_source(task)
    guard = (Path(__file__).resolve().parent.parent / "src/memcheck_sandbox.py").read_bytes()
    tools = {role: {"requested_executable": "/synthetic/" + role, "resolved_path": "/synthetic/" + role,
        "status": "OBSERVED", "file_sha256": "1" * 64, "source": "SYNTHETIC_NOT_REAL_CAPTURE"}
        for role in ("compiler", "valgrind", "valgrind_launcher", "memcheck", "bwrap", "guard_python")}
    request = MemcheckRequest.model_validate({**ids, "task_id": task, "source_sha256": digest_bytes(source),
        "description_sha256": "2" * 64, "collector_sha256": digest_bytes(guard),
        "platform_environment_id": "sha256:" + "3" * 64,
        "platform_probe_id": "SYNTHETIC_NO_REAL_PLATFORM", "snapshot_sha256": "4" * 64,
        "target_environment": "wsl:SYNTHETIC", "target_boot_id": "SYNTHETIC", "observed_monotonic_ns": 100,
        "tools": tools, "helper_images": {}, "resource_limits": {}, "authorization_reference": "SYNTHETIC_TEST_ONLY"})
    authorization = MemcheckAuthorization.model_validate({**ids, "task_id": task,
        "request_sha256": canonical_sha256(request), "operator_id": "SYNTHETIC_OPERATOR",
        "authorization_reference": request.authorization_reference, "issuer_kind": "operator",
        "target_boot_id": request.target_boot_id, "not_before_monotonic_ns": 100, "expires_monotonic_ns": 1000000})
    policy = MemcheckPolicy.model_validate({"request_sha256": canonical_sha256(request),
        "description_sha256": request.description_sha256, "allowed_operator_ids": [authorization.operator_id],
        "allowed_authorization_references": [authorization.authorization_reference],
        "allowed_images": {value["resolved_path"]: value["file_sha256"] for value in tools.values()},
        "native_task_root": "/synthetic", "resource_limits": request.resource_limits})
    error = "" if kind is None else ("<error><unique>0x1</unique><tid>1</tid><kind>" + kind + "</kind>"
        "<what>SYNTHETIC diagnostic description</what><stack><frame><ip>0x401001</ip>"
        "<fn>synthetic_frame</fn><file>fixture.c</file><line>10</line></frame></stack></error>")
    xml = ("<?xml version='1.0' encoding='UTF-8'?><valgrindoutput><protocolversion>4</protocolversion>"
        "<protocoltool>memcheck</protocoltool><pid>4321</pid><args><vargv><exe>/synthetic/valgrind_launcher</exe>"
        "<arg>--tool=memcheck</arg><arg>--xml=yes</arg><arg>--xml-file=/out/memcheck.xml</arg></vargv>"
        "<argv><exe>/target/fixture.bin</exe></argv></args><status><state>RUNNING</state></status>" + error +
        "<status><state>FINISHED</state></status></valgrindoutput>").encode()
    if xml_transform:
        xml = xml_transform(xml)
    raw = {"fixture.c": source, "sandbox_guard.py": guard,
        "fixture.bin": b"SYNTHETIC_NOT_EXECUTABLE", "compile.stdout.bin": b"",
        "compile.stderr.bin": b"SYNTHETIC compile stderr\r\n", "memcheck.stdout.bin": b"SYNTHETIC stdout\0\xff",
        "memcheck.stderr.bin": b"SYNTHETIC stderr\r\n", "memcheck.xml": xml}

    def process(step):
        argv = inner_argv(step, request.tools)
        kernel_limits = {key: [getattr(request.resource_limits, key)] * 2 for key in (
            "cpu_seconds", "memory_bytes", "max_file_bytes", "max_open_files", "core_bytes")}
        names = ("user", "mnt", "net", "pid", "ipc", "uts")
        config = {"schema_version": "1.0", **ids, "nonce": "c" * 32, "step_id": step, "task_id": task,
            "source_sha256": request.source_sha256,
            "executable_sha256": None if step == "compile" else digest_bytes(raw["fixture.bin"]),
            "tools": {key: value.model_dump(mode="json") for key, value in request.tools.items()},
            "allowed_images": policy.allowed_images, "limits": request.resource_limits.model_dump(mode="json"),
            "outer_namespaces": {key: "SYNTHETIC_OUTER_" + key for key in names}}
        boundaries = {"private_" + key: True for key in names}
        boundaries.update({"host_paths_absent": True, "gpu_devices_absent": True, "no_new_privs": True, "source_readonly": True})
        if step == "memcheck": boundaries["target_readonly"] = True
        ready = {"schema_version": "1.0", **ids, "nonce": "c" * 32, "step_id": step, "pid": 42,
            "start_ticks": 555,
            "limits": kernel_limits, "namespaces": {key: "SYNTHETIC_INNER_" + key for key in names},
            "boundaries": boundaries, "source_sha256": request.source_sha256, "argv": argv,
            "guard_python_image": {"path": request.tools["guard_python"].resolved_path,
                "sha256": request.tools["guard_python"].file_sha256}}
        host = {"bwrap_identity": {"pid": 100, "pgid": 100, "session_id": 100, "start_ticks": 100,
                "uid": 1000, "gid": 1000}, "bwrap_image": request.tools["bwrap"].model_dump(mode="json"),
            "guard_identity": {"pid": 101, "pgid": 100, "session_id": 100, "start_ticks": 555}}
        result = {"schema_version": "1.0", **ids, "nonce": "c" * 32, "step_id": step,
            "guard_pid": 42, "child_pid": 4321, "returncode": 0, "linux_signal": None,
            "error": None, "remaining_pids": [], "all_tracees_reaped": True,
            "source_sha256": request.source_sha256, "executable_sha256": config["executable_sha256"],
            "argv": argv, "finished_monotonic_ns": 300}
        trace = [{"event": "EXEC", "pid": 4321, "monotonic_ns": 150, "identity": {"pid": 4321},
            "image_path": argv[0], "image_sha256": "1" * 64, "argv": argv, "limits": kernel_limits},
            {"event": "REAPED", "pid": 4321, "monotonic_ns": 200, "returncode": 0}]
        for suffix, value in (("argv.json", ["/synthetic/bwrap"]), ("config.json", config),
                ("ready.json", ready), ("result.json", result), ("host_identity.json", host)):
            raw[step + "." + suffix] = json.dumps(value).encode()
        raw[step + ".trace.jsonl"] = b"".join(json.dumps(event).encode() + b"\n" for event in trace)
        return {"started": True, "action_started": True, "argv": ["/synthetic/bwrap"], "cwd": "/synthetic",
            "target_environment": request.target_environment, "tool_identity": request.tools["bwrap"],
            "pid": 100, "pgid": 100, "session_id": 100, "start_ticks": 100, "uid": 1000, "gid": 1000,
            "worker_pid": 99, "started_at": "2026-10-17T00:00:00+00:00", "finished_at": "2026-10-17T00:00:01+00:00",
            "duration_seconds": 1.0, "returncode": 0, "timed_out": False, "cancelled": False,
            "truncated": False, "capture_failed": False,
            "stdout_b64": base64.b64encode(raw[step + ".stdout.bin"]).decode(),
            "stderr_b64": base64.b64encode(raw[step + ".stderr.bin"]).decode(),
            "stdout_sha256": digest_bytes(raw[step + ".stdout.bin"]),
            "stderr_sha256": digest_bytes(raw[step + ".stderr.bin"]),
            "stdout_size_bytes": len(raw[step + ".stdout.bin"]), "stderr_size_bytes": len(raw[step + ".stderr.bin"]),
            "resource_limits": request.resource_limits,
            "resources": {"status": "ENFORCED", "wall_watchdog": True, "output_cap": True, "process_group": True,
                "cpu_seconds": request.resource_limits.cpu_seconds, "memory_bytes": request.resource_limits.memory_bytes,
                "verification_source": "SYNTHETIC_NOT_ENFORCED", "network_isolation": "NAMESPACE_CONFIRMED"},
            "cleanup": {"status": "CONFIRMED", "termination_method": "NONE", "parent_reaped": True,
                "group_absent": True, "descendants_absent": True, "checked_at": "2026-10-17T00:00:01+00:00",
                "source": "SYNTHETIC_NOT_OBSERVED"}, "diagnostics": [],
            "inner_argv": argv, "ready_observation": ready, "host_observation": host,
            "inner_result": result, "trace_events": trace, "inner_pid": 4321,
            "inner_returncode": 0, "inner_linux_signal": None}

    states = ["CREATED", "AUTHORIZED", "PREFLIGHT_READY", "STARTING", "RUNNING", "COMPLETED"]
    steps = [{"step_id": step, "status": "COMPLETED", "process": process(step)}
             for step in ("compile", "memcheck")]
    for step in steps:
        raw[step["step_id"] + ".process_result.json"] = json.dumps(
            MemcheckProcess.model_validate(step["process"]).model_dump(mode="json")).encode()
    record = MemcheckExecutionRecord.model_validate({**ids, "task_id": task,
        "request_sha256": canonical_sha256(request), "authorization_sha256": canonical_sha256(authorization),
        "policy_sha256": canonical_sha256(policy), "snapshot_sha256": request.snapshot_sha256,
        "platform_environment_id": request.platform_environment_id, "platform_probe_id": request.platform_probe_id,
        "target_environment": request.target_environment, "source_sha256": request.source_sha256,
        "executable_sha256": digest_bytes(raw["fixture.bin"]), "worker_identity": {"scope": "SYNTHETIC"},
        "status": "COMPLETED", "events": [{"sequence": i, "state": state,
            "observed_at": "2026-10-17T00:00:00+00:00", "source": "SYNTHETIC", "reason": "SYNTHETIC"}
            for i, state in enumerate(states)], "steps": steps, "artifacts": {name: {"file": name, "size_bytes": len(value),
                "sha256": digest_bytes(value)} for name, value in raw.items()}, "diagnostics": []})
    return record, request, authorization, policy, raw


def parse_case(**kwargs):
    record, req, auth, policy, raw = synthetic_memcheck_case(**kwargs)
    return parse_memcheck_evidence(record, req, auth, policy, raw, expected_record_sha256=canonical_sha256(record)), raw


@pytest.mark.parametrize("kind,expected", [(None, None), ("InvalidWrite", "INVALID_WRITE"), ("InvalidRead", "INVALID_READ")])
def test_fixed_memcheck_reuses_xml_grammar_without_cve_upgrade(kind, expected):
    evidence, _ = parse_case(kind=kind)
    assert evidence.parse_status == "PARSED"
    assert evidence.real_cve_verification == "NOT_VERIFIED" and evidence.cve_id is None
    assert evidence.candidate_execution_status == "NOT_EXECUTED" and not evidence.qualified_for_cve_verification
    assert len(evidence.observations) == int(expected is not None)
    if expected:
        assert evidence.observations[0].classification == expected
        assert evidence.observations[0].root_cause_status == "UNKNOWN"
    assert reassess_memcheck_evidence(evidence, expected_record_sha256=evidence.record_sha256) == evidence


@pytest.mark.parametrize("mutation", ["source", "binary", "stdout", "missing", "extra", "pin", "authorization", "run"])
def test_bound_execution_and_raw_file_identity_cannot_be_replaced(mutation):
    record, req, auth, policy, raw = synthetic_memcheck_case()
    pin = canonical_sha256(record)
    if mutation == "source": raw["fixture.c"] += b"changed"
    if mutation == "binary": raw["fixture.bin"] += b"changed"
    if mutation == "stdout": raw["memcheck.stdout.bin"] += b"changed"
    if mutation == "missing": raw.pop("memcheck.xml")
    if mutation == "extra": raw["extra.bin"] = b"changed"
    if mutation == "pin": pin = "e" * 64
    if mutation == "authorization": auth = auth.model_copy(update={"operator_id": "other"})
    if mutation == "run": record = record.model_copy(update={"run_id": "e" * 32})
    with pytest.raises(ValueError):
        parse_memcheck_evidence(record, req, auth, policy, raw, expected_record_sha256=pin)


@pytest.mark.parametrize("transform,reason", [
    (lambda x: x[:-10], "XML_MALFORMED_OR_TRUNCATED"),
    (lambda x: x.replace(b"<protocolversion>4", b"<protocolversion>5"), "XML_UNSUPPORTED_PROTOCOL"),
    (lambda x: x.replace(b"<pid>4321", b"<pid>9999"), "XML_PROCESS_ID_CONFLICT"),
    (lambda x: x.replace(b"/target/fixture.bin", b"/target/replaced.bin"), "XML_TOOL_OR_INPUT_IDENTITY_CONFLICT"),
])
def test_real_grammar_incompatibility_is_preserved_without_repair(transform, reason):
    evidence, _ = parse_case(xml_transform=transform)
    assert evidence.parse_status == "REJECTED" and evidence.diagnostic_codes == [reason]
    assert not evidence.observations and evidence.real_cve_verification == "NOT_VERIFIED"
    assert "NOT_VERIFIED" in render_memcheck_report(evidence)


def test_chinese_report_is_deterministic_and_does_not_invent_addresses():
    evidence, _ = parse_case()
    report = render_memcheck_report(evidence)
    assert report.encode("utf-8").decode("utf-8") == report
    assert report == render_memcheck_report(evidence)
    assert "固定无害 CPU Memcheck 诊断报告" in report
    assert "每进程 RLIMIT" in report and "不是物理内存" in report
    assert "/valgrindoutput/error[1]/kind[1]" in report
    assert "UNKNOWN" in report and "NOT_EXECUTED" in report and "NOT_VERIFIED" in report
    changed = evidence.model_dump(mode="python")
    changed["observations"][0]["classification"] = "INVALID_READ"
    with pytest.raises(ValueError, match="重新解析不同"):
        render_memcheck_report(changed)


@pytest.mark.parametrize("tamper", [None, "xml", "binary", "report", "parsed", "missing", "extra", "run"])
def test_offline_archive_rechecks_original_bytes_and_report(tmp_path, tamper):
    evidence, raw = parse_case()
    folder, pin = save_memcheck_evidence(evidence, raw, output_root=tmp_path)
    if tamper == "xml": (folder / "raw/memcheck.xml").write_bytes(b"changed")
    if tamper == "binary": (folder / "raw/fixture.bin").write_bytes(b"changed")
    if tamper == "report": (folder / "report.zh-CN.md").write_bytes(b"changed")
    if tamper == "parsed": (folder / "parsed.json").write_bytes(b"{}")
    if tamper == "missing": (folder / "raw/memcheck.stderr.bin").unlink()
    if tamper == "extra": (folder / "extra.bin").write_bytes(b"changed")
    if tamper == "run":
        import shutil
        other = tmp_path / ("e" * 32)
        shutil.copytree(folder, other)
        folder = other
    if tamper:
        with pytest.raises((ValueError, OSError)):
            read_memcheck_evidence(folder, expected_manifest_sha256=pin)
    else:
        assert read_memcheck_evidence(folder, expected_manifest_sha256=pin) == evidence
        assert (folder / "raw/memcheck.xml").read_bytes() == raw["memcheck.xml"]
        assert (folder / "report.zh-CN.md").read_bytes() == render_memcheck_report(evidence).encode("utf-8")
        with pytest.raises(FileExistsError):
            save_memcheck_evidence(evidence, raw, output_root=tmp_path)


def test_repinning_manifest_does_not_rebind_original_xml(tmp_path):
    evidence, raw = parse_case()
    folder, _ = save_memcheck_evidence(evidence, raw, output_root=tmp_path)
    path = folder / "raw/memcheck.xml"
    path.write_bytes(path.read_bytes().replace(b"InvalidWrite", b"InvalidRead"))
    manifest_file = folder / "manifest.json"
    manifest = json.loads(manifest_file.read_bytes())
    manifest["files"]["raw/memcheck.xml"] = {"sha256": digest_bytes(path.read_bytes()), "size_bytes": path.stat().st_size}
    manifest_file.write_bytes(json.dumps(manifest).encode())
    with pytest.raises(ValueError):
        read_memcheck_evidence(folder, expected_manifest_sha256=digest_bytes(manifest_file.read_bytes()))


def test_no_process_launch_and_no_cve_archive(tmp_path):
    with patch("subprocess.Popen", side_effect=AssertionError("offline means no process")):
        evidence, raw = parse_case()
        assert render_memcheck_report(evidence)
        with pytest.raises(ValueError, match="不得归入真实 CVE"):
            save_memcheck_evidence(evidence, raw, output_root=tmp_path / "CVE-2025-23308")


def test_disk_failure_is_not_reported_as_saved(tmp_path):
    evidence, raw = parse_case()
    with patch("src.memcheck_evidence._write_new", side_effect=OSError("disk failure")), pytest.raises(OSError):
        save_memcheck_evidence(evidence, raw, output_root=tmp_path)


@pytest.mark.parametrize("change", ["trace_image", "trace_limits", "trace_projection", "process_projection", "result_run",
    "result_nonce", "result_returncode", "ready_boundaries", "argv_projection", "missing_source", "missing_binary",
    "host_image", "host_start_ticks", "host_projection", "missing_host", "guard_python_image"])
def test_original_process_control_files_bind_their_structured_projections(change):
    record, request, authorization, policy, raw = synthetic_memcheck_case()
    payload = record.model_dump(mode="python")
    process = payload["steps"][-1]["process"]
    if change in {"trace_image", "trace_limits"}:
        events = process["trace_events"]
        if change == "trace_image":
            events[0]["image_path"] = "/unregistered/replaced-tool"
        else:
            events[0]["limits"]["memory_bytes"] = [1, 1]
        raw["memcheck.trace.jsonl"] = b"".join(json.dumps(event).encode() + b"\n" for event in events)
    elif change == "trace_projection":
        process["trace_events"][0]["image_sha256"] = "f" * 64
    elif change == "process_projection":
        raw["memcheck.process_result.json"] = b'{"tampered":true}'
    elif change in {"result_run", "result_nonce", "result_returncode"}:
        result = process["inner_result"]
        if change == "result_run": result["run_id"] = "e" * 32
        elif change == "result_nonce": result["nonce"] = "e" * 32
        else: result["returncode"] = 7
        raw["memcheck.result.json"] = json.dumps(result).encode()
    elif change == "ready_boundaries":
        process["ready_observation"]["boundaries"]["host_paths_absent"] = False
        raw["memcheck.ready.json"] = json.dumps(process["ready_observation"]).encode()
    elif change == "guard_python_image":
        process["ready_observation"]["guard_python_image"]["sha256"] = "f" * 64
        raw["memcheck.ready.json"] = json.dumps(process["ready_observation"]).encode()
    elif change in {"host_image", "host_start_ticks", "host_projection"}:
        if change == "host_image": process["host_observation"]["bwrap_image"]["file_sha256"] = "f" * 64
        else: process["host_observation"]["guard_identity"]["start_ticks"] = 123
        if change != "host_projection":
            raw["memcheck.host_identity.json"] = json.dumps(process["host_observation"]).encode()
    elif change == "missing_host":
        raw.pop("memcheck.host_identity.json")
        payload["artifacts"].pop("memcheck.host_identity.json")
        process["host_observation"] = None
    elif change == "argv_projection":
        raw["memcheck.argv.json"] = json.dumps(["/wrong/bwrap"]).encode()
    elif change == "missing_source":
        raw.pop("fixture.c")
        payload["artifacts"].pop("fixture.c")
    else:
        raw.pop("fixture.bin")
        payload["artifacts"].pop("fixture.bin")
    for name, value in raw.items():
        payload["artifacts"][name] = {"file": name, "size_bytes": len(value), "sha256": digest_bytes(value)}
    with pytest.raises(ValueError):
        changed = MemcheckExecutionRecord.model_validate(payload)
        parse_memcheck_evidence(changed, request, authorization, policy, raw,
                                expected_record_sha256=canonical_sha256(changed))


def test_incomplete_timeout_trace_can_be_reported_without_inventing_inner_exit():
    record, request, authorization, policy, raw = synthetic_memcheck_case()
    payload = record.model_dump(mode="python")
    payload["status"] = payload["events"][-1]["state"] = payload["steps"][-1]["status"] = "TIMED_OUT"
    p = payload["steps"][-1]["process"]
    p.update(timed_out=True, returncode=-9, linux_signal=9, inner_pid=None, inner_returncode=None,
             inner_linux_signal=None, inner_result=None)
    raw.pop("memcheck.result.json")
    payload["artifacts"].pop("memcheck.result.json")
    raw["memcheck.process_result.json"] = json.dumps(MemcheckProcess.model_validate(p).model_dump(mode="json")).encode()
    payload["artifacts"]["memcheck.process_result.json"] = {"file": "memcheck.process_result.json",
        "size_bytes": len(raw["memcheck.process_result.json"]),
        "sha256": digest_bytes(raw["memcheck.process_result.json"])}
    changed = MemcheckExecutionRecord.model_validate(payload)
    evidence = parse_memcheck_evidence(changed, request, authorization, policy, raw,
        expected_record_sha256=canonical_sha256(changed))
    assert evidence.parse_status == "REJECTED" and not evidence.observations
    assert evidence.diagnostic_codes == ["CAPTURE_OR_CLEANUP_INCOMPLETE"]
    assert evidence.record.steps[-1].process.inner_pid is None
    assert "TIMED_OUT" in render_memcheck_report(evidence)


def test_new_archive_uses_private_directory_and_posix_file_modes(tmp_path):
    from src.memcheck_evidence import protect_directory
    evidence, raw = parse_case()
    with patch("src.memcheck_evidence.protect_directory", wraps=protect_directory) as protect:
        folder, _ = save_memcheck_evidence(evidence, raw, output_root=tmp_path)
    protect.assert_called_once_with(folder)
    if os.name != "nt":
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert stat.S_IMODE((folder / "raw").stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in folder.rglob("*") if path.is_file())


def test_failed_private_protection_cannot_claim_saved_evidence(tmp_path):
    evidence, raw = parse_case()
    with patch("src.memcheck_evidence.protect_directory", side_effect=OSError("protection unavailable")), pytest.raises(OSError):
        save_memcheck_evidence(evidence, raw, output_root=tmp_path)
