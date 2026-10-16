"""SYNTHETIC XML/Mock probes only. No fixture compilation or execution."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src.host_diagnostic_tasks import (DIAGNOSTIC_TASKS, diagnostic_source, get_diagnostic_task,
    main, parse_harmless_diagnostic, prepare_diagnostic, read_harmless_evidence,
    reassess_harmless_diagnostic, rebuild_preparation, render_harmless_report,
    render_preparation_report, save_harmless_evidence, save_preparation)
from src.models.harmless_diagnostic import HarmlessDiagnosticCollection
from src.models.lifecycle import canonical_sha256
from src.models.tool_result import digest_argv, seal_tool_result
from tests.test_host_diagnostics_probe import record as synthetic_probe, identity, tool_result
from tests.test_host_parser_evidence import synthetic_collection


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def diagnostic_fixture(kind="InvalidWrite", *, domain="SYNTHETIC", transform=None, code=0):
    """Use existing synthetic XML grammar; discard the old CVE-specific model."""
    old, xml, stdout, stderr = synthetic_collection(kind, returncode=code)
    xml = xml.replace(b"/synthetic/nvdisasm", b"/synthetic/fixture").replace(b"<arg>/synthetic/input.cubin</arg>", b"")
    if transform:
        xml = transform(xml)
    process = old.process.model_dump(mode="python", exclude={"record_id"})
    process["argv"] = process["argv"][:-2] + ["/synthetic/fixture"]
    process["command_identity"]["argv_sha256"] = digest_argv(process["argv"])
    process = seal_tool_result(process)
    value = dict(domain=domain, collector="p3c-synthetic-xml4/1.0" if domain == "SYNTHETIC" else "p3c-unverified-import-xml4/1.0",
        collection_id=old.collection_id, request_id=old.request_id, run_id=old.run_id,
        task_id="p3c-invalid-write-v1", source_sha256=DIAGNOSTIC_TASKS["p3c-invalid-write-v1"].source_sha256,
        executable={**old.target.executable.model_dump(mode="python"), "resolved_path": "/synthetic/fixture"},
        build_record_sha256="1" * 64, platform_environment_id=old.platform_environment_id,
        platform_probe_id="SYNTHETIC-NO-CVE", snapshot_sha256=old.snapshot_sha256,
        diagnostic_tool=old.diagnostic_tool, diagnostic_tool_version="SYNTHETIC-3.22.0",
        diagnostic_version_record_sha256=old.diagnostic_version_record_sha256,
        target_argv=["/synthetic/fixture"], process=process, observed_pid=old.observed_pid,
        diagnostic_artifact={**old.diagnostic_artifact.model_dump(mode="python"), "sha256": sha(xml), "size_bytes": len(xml)},
        stdout_artifact=old.stdout_artifact, stderr_artifact=old.stderr_artifact,
        capture_complete=True, cleanup_status="CONFIRMED")
    return HarmlessDiagnosticCollection.model_validate(value), xml, stdout, stderr


def parse_fixture(*args, **kwargs):
    collection, xml, stdout, stderr = diagnostic_fixture(*args, **kwargs)
    return parse_harmless_diagnostic(collection, diagnostic_bytes=xml, stdout_bytes=stdout, stderr_bytes=stderr,
                                    expected_collection_sha256=canonical_sha256(collection))


@pytest.mark.parametrize("task", list(DIAGNOSTIC_TASKS))
def test_registry_source_sha_and_no_automatic_execution(task):
    raw = diagnostic_source(task)
    assert sha(raw) == get_diagnostic_task(task).source_sha256
    assert b"system(" not in raw and b"exec(" not in raw and b"socket(" not in raw
    assert "cve" not in task and "cuda" not in task
    with pytest.raises(FrozenInstanceError):
        get_diagnostic_task(task).source_file = "replacement.c"


def test_registry_is_immutable_and_does_not_expand_p2_allowlist():
    from src.registered_actions import REGISTERED_ACTIONS
    with pytest.raises(TypeError):
        DIAGNOSTIC_TASKS["arbitrary"] = object()
    assert not set(DIAGNOSTIC_TASKS).intersection(REGISTERED_ACTIONS)


@pytest.mark.parametrize("name", ["unknown", "../normal.c", "CVE-2025-23308", "sh -c test", ["cc"], None])
def test_unknown_or_llm_task_is_rejected(name):
    with pytest.raises(ValueError):
        get_diagnostic_task(name)


def test_replaced_fixture_fails_closed(tmp_path):
    (tmp_path / "normal.c").write_bytes(b"replacement")
    with patch("src.host_diagnostic_tasks.FIXTURE_ROOT", tmp_path), pytest.raises(ValueError, match="SHA-256"):
        diagnostic_source("p3c-normal-v1")


@pytest.mark.parametrize("task", list(DIAGNOSTIC_TASKS))
def test_missing_tool_and_unauthorized_preparation_cannot_start(task):
    probe, _ = synthetic_probe()
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        result = prepare_diagnostic(task_id=task, probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
    assert result.status == "REJECTED" and result.experiment_status == "NOT_CHECKED"
    assert result.p2_preflight_status == "UNSUPPORTED" and result.resource_status == "UNSUPPORTED"
    assert result.cve_id is None
    assert {"OPERATOR_AUTHORIZATION_MISSING", "ISOLATION_NOT_CONFIRMED", "VALGRIND_IDENTITY_UNKNOWN"} <= set(result.blockers)
    assert "没有启动诊断进程" not in result.model_dump()  # No fictional PID/process result field.
    assert "process" not in result.model_dump()


def test_probe_identity_change_blocks_preparation():
    probe, _ = synthetic_probe()
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe), pytest.raises(ValueError, match="摘要"):
        prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256="0" * 64)


@pytest.mark.parametrize("failure", [False, True])
def test_installed_or_failed_tool_does_not_bypass_other_gates(failure):
    from src.models.host_diagnostics import HostDiagnosticsProbe, DiagnosticToolCapability
    probe, _ = synthetic_probe()
    raw = probe.model_dump(mode="python", exclude={"record_sha256"})
    tool = identity("valgrind", True)
    process = tool_result(["/usr/bin/valgrind", "--version"], raw=b"valgrind-3.22.0\n", tool=tool, code=2 if failure else 0)
    raw["tools"][0] = DiagnosticToolCapability.model_validate(dict(tool_id="valgrind", identity=tool, identity_after=tool,
        process=process.model_dump(mode="python"), version=None if failure else "3.22.0",
        version_status="UNKNOWN" if failure else "OBSERVED")).model_dump(mode="python")
    raw["record_sha256"] = canonical_sha256(raw)
    probe = HostDiagnosticsProbe.model_validate(raw)
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        prepared = prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
    assert prepared.status == "REJECTED" and prepared.p2_preflight_status == "UNSUPPORTED"
    assert "OPERATOR_AUTHORIZATION_MISSING" in prepared.blockers
    assert ("VALGRIND_VERSION_UNCONFIRMED" in prepared.blockers) == failure


def test_preparation_chinese_rebuild_and_no_fake_logs(tmp_path):
    probe, _ = synthetic_probe()
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        record = prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
    folder = save_preparation(record, output_root=tmp_path)
    pin = sha((folder / "preparation.json").read_bytes())
    assert rebuild_preparation(folder, expected_preparation_sha256=pin).encode() == (folder / "report.zh-CN.md").read_bytes()
    assert {p.name for p in folder.iterdir()} == {"preparation.json", "report.zh-CN.md"}
    assert "未收到操作者" in render_preparation_report(record)
    with pytest.raises(FileExistsError):
        save_preparation(record, output_root=tmp_path)
    (folder / "preparation.json").write_bytes(b"tampered")
    with pytest.raises(ValueError):
        rebuild_preparation(folder, expected_preparation_sha256=pin)


@pytest.mark.parametrize("kind,classification", [(None, None), ("InvalidRead", "INVALID_READ"),
    ("InvalidWrite", "INVALID_WRITE"), ("InvalidFree", "INVALID_FREE")])
def test_generic_no_cve_parse_reuses_p3b_nodes(kind, classification):
    parsed = parse_fixture(kind)
    assert parsed.parse_status == "PARSED" and parsed.collection.cve_id is None
    assert parsed.collection.domain == "SYNTHETIC"
    assert not parsed.authenticated_real_capture and not parsed.qualified_for_cve_verification
    if classification:
        assert parsed.observations[0].classification == classification
        assert parsed.observations[0].root_cause_status == "UNKNOWN"
        assert parsed.observations[0].kind_locator.xml_node == "/valgrindoutput/error[1]/kind[1]"
    else:
        assert not parsed.observations
    assert reassess_harmless_diagnostic(parsed, expected_collection_sha256=parsed.collection_sha256) == parsed


@pytest.mark.parametrize("code", [0, 1, -11])
def test_exit_or_signal_does_not_prove_cve(code):
    parsed = parse_fixture(None, code=code)
    assert parsed.parse_status == "PARSED" and parsed.real_cve_verification == "NOT_VERIFIED"
    assert not parsed.observations


def test_import_cannot_claim_real_authenticated_capture():
    imported = parse_fixture("InvalidWrite", domain="UNVERIFIED_IMPORT")
    assert not imported.authenticated_real_capture
    assert "未独立认证" in render_harmless_report(imported)
    for key, value in [("domain", "REAL_CAPTURE"), ("execution_authorized", True), ("cve_id", "CVE-2025-23308")]:
        raw = imported.collection.model_dump(mode="python")
        raw[key] = value
        with pytest.raises(ValueError):
            HarmlessDiagnosticCollection.model_validate(raw)


@pytest.mark.parametrize("mutation", ["run", "tool", "target", "source", "stdout", "cve"])
def test_identity_conflicts_are_not_rebound(mutation):
    collection, xml, stdout, stderr = diagnostic_fixture()
    raw = collection.model_dump(mode="python")
    if mutation == "run": raw["run_id"] = "e" * 32
    if mutation == "tool": raw["diagnostic_tool"]["file_sha256"] = "e" * 64
    if mutation == "target": raw["executable"]["resolved_path"] = "/other"
    if mutation == "source": raw["source_sha256"] = "e" * 64
    if mutation == "stdout": stdout += b"changed"
    if mutation == "cve": raw["cve_id"] = "CVE-2025-23339"
    with pytest.raises(ValueError):
        parse_harmless_diagnostic(raw, diagnostic_bytes=xml, stdout_bytes=stdout, stderr_bytes=stderr,
                                  expected_collection_sha256=canonical_sha256(collection))


@pytest.mark.parametrize("path", [r"C:\fixture.exe", "/safe/../other", "/safe/fixt\\ure", "relative", "/safe/\x00x"])
def test_linux_collection_rejects_foreign_or_unsafe_paths(path):
    collection, *_ = diagnostic_fixture()
    raw = collection.model_dump(mode="python")
    raw["executable"]["resolved_path"] = path
    raw["target_argv"] = [path]
    with pytest.raises(ValueError):
        HarmlessDiagnosticCollection.model_validate(raw)


@pytest.mark.parametrize("transform,reason", [
    (lambda x: x[:-10], "损坏"),
    (lambda x: x.replace(b"<protocolversion>4", b"<protocolversion>5"), "协议 4"),
    (lambda x: x.replace(b"<pid>4321", b"<pid>9999"), "PID"),
    (lambda x: x.replace(b"/synthetic/fixture", b"/synthetic/other"), "argv"),
    (lambda x: x.replace(b"FINISHED", b"RUNNING"), "FINISHED"),
])
def test_bad_xml_fail_closed_with_specific_chinese_reason(transform, reason):
    evidence = parse_fixture(transform=transform)
    assert evidence.parse_status == "REJECTED" and not evidence.observations
    assert reason in render_harmless_report(evidence)


@pytest.mark.parametrize("field,value", [("capture_complete", False), ("cleanup_status", "UNKNOWN"), ("cleanup_status", "FAILED")])
def test_incomplete_capture_rejects_inference(field, value):
    c, xml, stdout, stderr = diagnostic_fixture()
    raw = c.model_dump(mode="python")
    raw[field] = value
    c = HarmlessDiagnosticCollection.model_validate(raw)
    result = parse_harmless_diagnostic(c, diagnostic_bytes=xml, stdout_bytes=stdout, stderr_bytes=stderr,
                                      expected_collection_sha256=canonical_sha256(c))
    assert result.parse_status == "REJECTED" and not result.observations


def test_derived_observation_tampering_is_rejected():
    parsed = parse_fixture()
    raw = parsed.model_dump(mode="python")
    raw["observations"][0]["classification"] = "INVALID_READ"
    with pytest.raises(ValueError):
        reassess_harmless_diagnostic(raw, expected_collection_sha256=parsed.collection_sha256)


def test_report_escapes_imported_text_without_changing_raw_bytes():
    c, xml, stdout, stderr = diagnostic_fixture()
    raw = c.model_dump(mode="python")
    raw["diagnostic_tool_version"] = "x`\n# VERIFIED <script>"
    raw["platform_probe_id"] = "x\n# VERIFIED"
    c = HarmlessDiagnosticCollection.model_validate(raw)
    parsed = parse_harmless_diagnostic(c, diagnostic_bytes=xml, stdout_bytes=stdout, stderr_bytes=stderr,
                                      expected_collection_sha256=canonical_sha256(c))
    report = render_harmless_report(parsed)
    assert "\n# VERIFIED" not in report and "<script>" not in report
    assert parsed.raw_artifacts[0].raw_bytes() == xml


@pytest.mark.parametrize("tamper", [None, "xml", "stdout", "parsed", "manifest", "missing", "extra", "run"])
def test_offline_original_byte_archive_reassessment(tmp_path, tamper):
    parsed = parse_fixture()
    folder, pin = save_harmless_evidence(parsed, output_root=tmp_path)
    if tamper == "xml": (folder / "raw/memcheck.xml").write_bytes(b"changed")
    if tamper == "stdout": (folder / "raw/stdout.bin").write_bytes(b"changed")
    if tamper == "parsed": (folder / "parsed.json").write_bytes(b"{}")
    if tamper == "manifest": (folder / "manifest.json").write_bytes(b"{}")
    if tamper == "missing": (folder / "raw/stderr.bin").unlink()
    if tamper == "extra": (folder / "extra.json").write_bytes(b"{}")
    if tamper == "run":
        import shutil
        destination = tmp_path / ("e" * 32)
        shutil.copytree(folder, destination)
        folder = destination
    if tamper:
        with pytest.raises((ValueError, OSError)):
            read_harmless_evidence(folder, expected_manifest_sha256=pin)
    else:
        reread = read_harmless_evidence(folder, expected_manifest_sha256=pin)
        assert reread == parsed
        assert render_harmless_report(reread).encode() == (folder / "report.zh-CN.md").read_bytes()
        with pytest.raises(FileExistsError):
            save_harmless_evidence(parsed, output_root=tmp_path)


def test_raw_xml_cannot_be_replaced_even_if_parsed_object_left_intact(tmp_path):
    parsed = parse_fixture()
    folder, _ = save_harmless_evidence(parsed, output_root=tmp_path)
    file = folder / "raw/memcheck.xml"
    file.write_bytes(file.read_bytes().replace(b"InvalidWrite", b"InvalidRead"))
    manifest_file = folder / "manifest.json"
    manifest = json.loads(manifest_file.read_bytes())
    manifest["files"]["raw/memcheck.xml"] = {"sha256": sha(file.read_bytes()), "byte_length": file.stat().st_size}
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        read_harmless_evidence(folder, expected_manifest_sha256=sha(manifest_file.read_bytes()))


def test_preparation_and_parse_do_not_start_any_process():
    probe, _ = synthetic_probe()
    with patch("subprocess.Popen", side_effect=AssertionError("no launch allowed")), \
         patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
        assert parse_fixture().parse_status == "PARSED"


def test_no_cve_diagnostic_cannot_be_archived_under_real_cve(tmp_path):
    with pytest.raises(ValueError, match="通用诊断目录"):
        save_harmless_evidence(parse_fixture(), output_root=tmp_path / "CVE-2025-23308/runs")


def test_cli_offline_reparse_verify_and_prepare(tmp_path, capsys):
    c, xml, stdout, stderr = diagnostic_fixture()
    for name, data in (("collection.json", json.dumps(c.model_dump(mode="json")).encode()), ("xml.bin", xml), ("out.bin", stdout), ("err.bin", stderr)):
        (tmp_path / name).write_bytes(data)
    assert main(["reparse", "--collection", str(tmp_path / "collection.json"), "--collection-sha256", canonical_sha256(c),
        "--xml", str(tmp_path / "xml.bin"), "--stdout", str(tmp_path / "out.bin"), "--stderr", str(tmp_path / "err.bin"),
        "--output-root", str(tmp_path / "archives")]) == 0
    folder = tmp_path / "archives" / c.run_id
    pin = sha((folder / "manifest.json").read_bytes())
    assert main(["verify", "--directory", str(folder), "--manifest-sha256", pin]) == 0
    assert "SYNTHETIC" in capsys.readouterr().out
    probe, _ = synthetic_probe()
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        assert main(["prepare", "--probe-dir", "SYNTHETIC", "--probe-sha256", probe.record_sha256,
            "--task", "p3c-normal-v1", "--output-root", str(tmp_path / "preparations")]) == 2
    assert "NOT_CHECKED" in capsys.readouterr().out


def test_diagnostic_archive_write_failure_is_not_success(tmp_path):
    with patch("src.host_diagnostic_tasks._write_new", side_effect=OSError("disk")), pytest.raises(OSError):
        save_harmless_evidence(parse_fixture(), output_root=tmp_path)


@pytest.mark.parametrize("name", ["CON", "NUL", "stdout.bin."])
def test_raw_member_windows_aliases_are_rejected(name):
    collection, *_ = diagnostic_fixture()
    raw = collection.model_dump(mode="python")
    raw["stdout_artifact"]["artifact_file"] = name
    with pytest.raises(ValueError):
        HarmlessDiagnosticCollection.model_validate(raw)


def test_raw_member_case_aliases_are_rejected():
    collection, *_ = diagnostic_fixture()
    raw = collection.model_dump(mode="python")
    raw["stderr_artifact"]["artifact_file"] = "STDOUT.BIN"
    with pytest.raises(ValueError):
        HarmlessDiagnosticCollection.model_validate(raw)


@pytest.mark.parametrize("kind", ["preparation", "evidence"])
@pytest.mark.parametrize("cve_dir", ["CVE-2025-23308", "cve-2025-23308"])
def test_read_side_also_refuses_generic_archives_copied_into_cve(tmp_path, kind, cve_dir):
    import shutil
    if kind == "evidence":
        folder, pin = save_harmless_evidence(parse_fixture(), output_root=tmp_path / "original")
    else:
        probe, _ = synthetic_probe()
        with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
            record = prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
        folder = save_preparation(record, output_root=tmp_path / "original")
        pin = sha((folder / "preparation.json").read_bytes())
    target = tmp_path / cve_dir / folder.name
    shutil.copytree(folder, target)
    with pytest.raises(ValueError, match="通用诊断目录"):
        if kind == "evidence": read_harmless_evidence(target, expected_manifest_sha256=pin)
        else: rebuild_preparation(target, expected_preparation_sha256=pin)


def test_preparation_blocker_is_escaped_in_report():
    probe, _ = synthetic_probe()
    with patch("src.host_diagnostic_tasks.read_host_diagnostics_archive", return_value=probe):
        record = prepare_diagnostic(task_id="p3c-normal-v1", probe_directory="SYNTHETIC", expected_probe_sha256=probe.record_sha256)
    record = record.model_copy(update={"blockers": ["x\n# VERIFIED <script>"]})
    report = render_preparation_report(record)
    assert "\n# VERIFIED" not in report and "<script>" not in report


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX special-node rejection; Windows has no mkfifo")
def test_extra_fifo_is_rejected_without_opening_it(tmp_path):
    folder, pin = save_harmless_evidence(parse_fixture(), output_root=tmp_path)
    os.mkfifo(folder / "unlisted.fifo")
    with pytest.raises(ValueError, match="特殊文件"):
        read_harmless_evidence(folder, expected_manifest_sha256=pin)


def test_serialized_record_over_read_limit_cannot_report_saved_archive(tmp_path):
    with patch("src.host_diagnostic_tasks.MAX_FILE", 100), pytest.raises(ValueError, match="读取上限"):
        save_harmless_evidence(parse_fixture(), output_root=tmp_path)
