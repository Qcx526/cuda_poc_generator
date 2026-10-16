"""SYNTHETIC packets exercise the read-only protocol; no CVE is executed."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from src.host_diagnostics_probe import (_capabilities, _version, _write_archive,
    build_diagnostic_worker_source, parse_diagnostic_packet, read_host_diagnostics_archive,
    render_diagnostics_report, run_host_diagnostics_probe)
from src.models.host_diagnostics import DiagnosticFact, HostDiagnosticsProbe
from src.models.lifecycle import canonical_sha256
from src.models.tool_result import digest_argv, seal_tool_result


PROBE = "a" * 32
NONCE = "b" * 32
LABEL = "wsl:Ubuntu-22.04"


def identity(name, observed=False):
    return {"requested_executable": name, "resolved_path": "/usr/bin/" + name if observed else None,
            "status": "OBSERVED" if observed else "UNKNOWN", "file_sha256": "1" * 64 if observed else None,
            "source": "SYNTHETIC diagnostic identity"}


def tool_result(argv, raw=b"", *, tool=None, platform_type="wsl", environment=LABEL,
                code=0, truncated=False, input_bytes=None):
    # These are labelled in-memory test values, never actual tool observations.
    tool = tool or identity("valgrind", True)
    return seal_tool_result({
        "run_id": "c" * 32, "argv": argv, "cwd": "C:\\" if platform_type == "windows" else "/",
        "target_environment": environment, "platform_type": platform_type,
        "start_status": "STARTED", "end_status": "OUTPUT_LIMIT" if truncated else ("NORMAL_EXIT" if code == 0 else "NONZERO_EXIT"),
        "returncode": code, "timed_out": False, "truncated": truncated,
        "started_at": "2026-10-16T01:00:00+00:00", "finished_at": "2026-10-16T01:00:01+00:00",
        "duration_seconds": 1.0,
        "resource_limits": {"timeout_seconds": 3.0, "max_output_bytes": 1048576,
                            "termination_scope": "WINDOWS_DIRECT_CHILD" if platform_type == "windows" else "POSIX_PROCESS_GROUP"},
        "stdout_b64": base64.b64encode(raw).decode(), "stderr_b64": "",
        "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stdin_sha256": hashlib.sha256(input_bytes).hexdigest() if input_bytes else None,
        "stdin_size_bytes": len(input_bytes) if input_bytes else 0,
        "command_identity": {"source": "SYNTHETIC version-only test", "argv_sha256": digest_argv(argv)},
        "tool_identity": tool, "diagnostics": [], "evidence_directory": "SYNTHETIC-in-memory"})


def packet():
    _, checksum = build_diagnostic_worker_source(probe_id=PROBE, nonce=NONCE, backend="wsl", environment_label=LABEL)
    target = {"platform_type": "wsl", "environment_label": LABEL, "wsl_distribution": "Ubuntu-22.04",
              "kernel": "5.15.0-microsoft-standard-WSL2", "architecture": "x86_64", "boot_id_sha256": "d" * 64}
    target["diagnostic_environment_id"] = "sha256:" + canonical_sha256(target)
    return {"schema_version": "1.0", "probe_id": PROBE, "nonce": NONCE, "worker_source_sha256": checksum,
            "target": target, "tools": [{"tool_id": name, "identity": identity(name), "identity_after": None, "process": None}
                for name in ("valgrind", "gdb", "cuobjdump", "nvdisasm")]}


def parse(value):
    return parse_diagnostic_packet(json.dumps(value).encode(), probe_id=PROBE, nonce=NONCE,
                                  backend="wsl", environment_label=LABEL, worker_source_sha256=packet()["worker_source_sha256"])


def record():
    value = packet()
    source, checksum = build_diagnostic_worker_source(probe_id=PROBE, nonce=NONCE, backend="wsl", environment_label=LABEL)
    target, tools = parse(value)
    raw = json.dumps(value).encode()
    executable = str(Path(sys.executable).resolve())
    host_identity = {**identity("python", True), "resolved_path": executable}
    launcher = tool_result([executable, "-I", "-"], raw=raw, tool=host_identity,
                            platform_type="windows" if os.name == "nt" else "linux", environment="local", input_bytes=source)
    payload = {"probe_schema_version": "1.0", "probe_id": PROBE, "nonce": NONCE,
               "report_locale": "zh-CN", "domain": "READ_ONLY_CAPABILITY", "backend": "wsl", "requested_environment": LABEL,
               "worker_source_sha256": checksum, "observed_at": "2026-10-16T01:00:01+00:00", "status": "PARTIAL",
               "target": target.model_dump(mode="json"), "tools": [x.model_dump(mode="json") for x in tools],
               "capabilities": _capabilities(), "launcher": launcher.model_dump(mode="json"),
               "worker_packet_sha256": hashlib.sha256(raw).hexdigest(), "diagnostics_zh": [],
               "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    payload["record_sha256"] = canonical_sha256(payload)
    return HostDiagnosticsProbe.model_validate(payload), source


def test_fixed_worker_bundle_and_bad_identity():
    source, checksum = build_diagnostic_worker_source(probe_id=PROBE, nonce=NONCE, backend="wsl", environment_label=LABEL)
    assert hashlib.sha256(source.split(b"\n", 1)[1]).hexdigest() == checksum
    assert b'"--version"' in source
    assert b"shell=False" in source
    with pytest.raises(ValueError):
        build_diagnostic_worker_source(probe_id="../outside", nonce=NONCE, backend="wsl", environment_label=LABEL)
    with pytest.raises(TypeError):
        build_diagnostic_worker_source(probe_id=PROBE, nonce=NONCE, backend="wsl", environment_label=LABEL, argv=["sh"])


def test_unknown_tools_remain_unknown_and_not_validated():
    target, tools = parse(packet())
    assert target.environment_label == LABEL
    assert all(x.version is None and x.diagnostic_effectiveness == "NOT_CHECKED" for x in tools)


@pytest.mark.parametrize("field,value", [("nonce", "e" * 32), ("probe_id", "e" * 32),
                                         ("worker_source_sha256", "e" * 64), ("schema_version", "9.9")])
def test_stale_and_replaced_worker_packet_rejected(field, value):
    data = packet()
    data[field] = value
    with pytest.raises(ValueError):
        parse(data)


@pytest.mark.parametrize("change", ["foreign_label", "foreign_kernel", "target_hash", "duplicate_tool", "arbitrary_argv", "extra_key"])
def test_target_confusion_and_registry_injection_rejected(change):
    data = packet()
    if change == "foreign_label":
        data["target"]["environment_label"] = "wsl:another"
    elif change == "foreign_kernel":
        data["target"]["kernel"] = "Linux-native"
    elif change == "target_hash":
        data["target"]["diagnostic_environment_id"] = "sha256:" + "0" * 64
    elif change == "duplicate_tool":
        data["tools"][1] = copy.deepcopy(data["tools"][0])
    elif change == "arbitrary_argv":
        data["tools"][0]["argv"] = ["sh", "-c", "arbitrary"]
    else:
        data["cwd"] = "/unknown"
    with pytest.raises(ValueError):
        parse(data)


def test_packet_rejects_duplicate_json_keys_and_oversize():
    kwargs = dict(probe_id=PROBE, nonce=NONCE, backend="wsl", environment_label=LABEL, worker_source_sha256="f" * 64)
    with pytest.raises(ValueError):
        parse_diagnostic_packet(b'{"nonce":"x","nonce":"y"}', **kwargs)
    with pytest.raises(ValueError):
        parse_diagnostic_packet(b"x" * 1048577, **kwargs)


@pytest.mark.parametrize("name,raw,expected", [("valgrind", b"valgrind-3.19.0\n", "3.19.0"),
    ("gdb", b"GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1\n", "12.1"),
    ("cuobjdump", b"Cuda compilation tools, release 12.8, V12.8.90\n", "12.8.90"),
    ("nvdisasm", b"Cuda compilation tools, release 12.8, V12.8.90\n", "12.8.90")])
def test_version_is_observed_only_from_complete_specific_banner(name, raw, expected):
    data = packet()
    tool = identity(name, True)
    entry = next(item for item in data["tools"] if item["tool_id"] == name)
    result = tool_result([tool["resolved_path"], "--version"], raw=raw, tool=tool)
    entry.update(identity=tool, identity_after=tool, process=result.model_dump(mode="json"))
    _, tools = parse(data)
    selected = next(x for x in tools if x.tool_id == name)
    assert selected.version == expected
    assert selected.diagnostic_effectiveness == "NOT_CHECKED"


@pytest.mark.parametrize("case", ["nonzero", "truncated", "replaced", "unrecognized", "bad_encoding"])
def test_unqualified_version_banner_is_unknown(case):
    tool = identity("valgrind", True)
    raw = b"valgrind-3.19.0\n"
    if case == "unrecognized":
        raw = b"crash valgrind 3.19.0 arbitrary text"
    if case == "bad_encoding":
        raw = b"\xffvalgrind-3.19.0"
    result = tool_result([tool["resolved_path"], "--version"], raw=raw, tool=tool,
                        code=1 if case == "nonzero" else 0, truncated=case == "truncated")
    after = {**tool, "file_sha256": "e" * 64} if case == "replaced" else tool
    data = packet()
    data["tools"][0].update(identity=tool, identity_after=after, process=result.model_dump(mode="json"))
    _, tools = parse(data)
    assert tools[0].version is None


def test_extra_arguments_cannot_enter_tool_result_projection():
    data = packet()
    tool = identity("valgrind", True)
    result = tool_result([tool["resolved_path"], "--version", "unreviewed-input"], tool=tool)
    data["tools"][0].update(identity=tool, identity_after=tool, process=result.model_dump(mode="json"))
    with pytest.raises(ValueError):
        parse(data)


def test_report_is_utf8_chinese_deterministic_after_json_roundtrip():
    value, _ = record()
    report = render_diagnostics_report(value).encode("utf-8")
    reordered = HostDiagnosticsProbe.model_validate_json(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    assert render_diagnostics_report(reordered).encode("utf-8") == report
    assert "主机侧诊断能力" in report.decode("utf-8")
    assert "NOT_EXECUTED" in report.decode("utf-8") and "NOT_VERIFIED" in report.decode("utf-8")
    assert value.capabilities["cve_experiment_isolation"].status == "UNSUPPORTED"


def test_archive_keeps_raw_bytes_and_can_rebuild(tmp_path):
    value, source = record()
    folder = _write_archive(tmp_path, value, source)
    original = (folder / "launcher_stdout.bin").read_bytes()
    restored = read_host_diagnostics_archive(folder)
    assert restored == value
    assert original == value.launcher.stdout_bytes()
    assert (folder / "report.zh-CN.md").read_bytes() == render_diagnostics_report(restored).encode("utf-8")
    with pytest.raises(FileExistsError):
        _write_archive(tmp_path, value, source)
    assert (folder / "launcher_stdout.bin").read_bytes() == original


@pytest.mark.parametrize("file", ["launcher_stdout.bin", "diagnostic_probe.json", "worker_source.py", "report.zh-CN.md"])
def test_archive_rejects_tamper_and_missing_files(tmp_path, file):
    value, source = record()
    folder = _write_archive(tmp_path, value, source)
    selected = folder / file
    selected.write_bytes(selected.read_bytes() + b"x")
    with pytest.raises(ValueError):
        read_host_diagnostics_archive(folder)
    selected.unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        read_host_diagnostics_archive(folder)


def test_archive_rejects_traversal_member(tmp_path):
    value, source = record()
    folder = _write_archive(tmp_path, value, source)
    manifest = json.loads((folder / "artifact_manifest.json").read_bytes())
    manifest["files"]["../outside"] = {"size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    (folder / "artifact_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        read_host_diagnostics_archive(folder)


def test_capability_models_fail_closed_on_unknown_claimed_value():
    with pytest.raises(ValidationError):
        DiagnosticFact(status="UNKNOWN", value=True, reason_zh="未知", sources=[])
    value, _ = record()
    mutated = value.model_copy(update={"verification_status": "VERIFIED"})
    with pytest.raises(ValidationError):
        render_diagnostics_report(mutated)


def test_probe_has_no_arbitrary_commands_interface():
    with pytest.raises(TypeError):
        run_host_diagnostics_probe(argv=["sh"])
    with pytest.raises(ValueError):
        run_host_diagnostics_probe(backend="shell")


def test_missing_launcher_has_a_failed_chinese_archive(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows launcher failure path is Windows-specific")
    monkeypatch.setattr("src.host_diagnostics_probe.shutil.which", lambda _: None)
    result = run_host_diagnostics_probe(output_root=tmp_path)
    assert result["record"].status == "FAILED"
    restored = read_host_diagnostics_archive(result["evidence_directory"])
    assert restored.target is None and restored.verification_status == "NOT_VERIFIED"
    assert "没有启动远端查询" in render_diagnostics_report(restored)
