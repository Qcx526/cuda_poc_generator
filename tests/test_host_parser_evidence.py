"""SYNTHETIC diagnostics only. No host parser or vulnerability input is run."""

import base64
import hashlib

import pytest
from pydantic import ValidationError

from src.host_parser_evidence import parse_host_parser_evidence, reassess_host_parser_evidence
from src.host_parser_oracle import evaluate_host_parser_requirements, project_host_parser_to_p3a
from src.host_parser_report import render_host_parser_report_zh
from src.models.host_parser import HostParserCollection, HostParserEvidence
from src.models.lifecycle import canonical_sha256
from src.models.tool_result import classify_returncode, digest_argv, seal_tool_result
from src.oracle import evaluate_oracle


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(path, digest):
    return {"requested_executable": path, "resolved_path": path, "status": "OBSERVED",
            "file_sha256": digest, "source": "SYNTHETIC_FIXTURE"}


def synthetic_collection(error_kind="InvalidWrite", *, cve="CVE-2025-23308", returncode=0,
                         prose="Invalid write of size 4", xml_transform=None, domain="SYNTHETIC"):
    """Build labeled XML fixtures and matching immutable capture declarations."""
    component = "nvdisasm" if cve == "CVE-2025-23308" else "cuobjdump"
    target = "/synthetic/" + component
    source = "/synthetic/input.cubin"
    diagnostic = "/synthetic/memcheck.xml"
    argv = ["/synthetic/valgrind", "--tool=memcheck", "--xml=yes", "--xml-file=" + diagnostic, target, source]
    errors = "" if error_kind is None else (
        f"<error><unique>0x1</unique><tid>1</tid><kind>{error_kind}</kind><what>{prose}</what>"
        "<stack><frame><ip>0x401001</ip><obj>/synthetic/target</obj><fn>synthetic_frame</fn>"
        "<file>fixture.c</file><line>10</line></frame><frame><ip>0x401002</ip></frame></stack></error>")
    xml = ("<?xml version='1.0' encoding='UTF-8'?><valgrindoutput>"
        "<protocolversion>4</protocolversion><protocoltool>memcheck</protocoltool><pid>4321</pid>"
        "<args><vargv><exe>/synthetic/valgrind</exe><arg>--tool=memcheck</arg><arg>--xml=yes</arg>"
        f"<arg>--xml-file={diagnostic}</arg></vargv><argv><exe>{target}</exe><arg>{source}</arg></argv></args>"
        "<status><state>RUNNING</state><time>00:00:00:00.001</time></status>" + errors +
        "<status><state>FINISHED</state><time>00:00:00:00.002</time></status></valgrindoutput>").encode("utf-8")
    if xml_transform:
        xml = xml_transform(xml)
    stdout, stderr = b"SYNTHETIC stdout\x00\xff", b"SYNTHETIC stderr\r\n"
    state, signal, exception = classify_returncode(returncode, "linux")
    process = seal_tool_result({"run_id": "b" * 32, "argv": argv, "cwd": "/synthetic",
        "target_environment": "wsl:synthetic", "platform_type": "linux", "start_status": "STARTED",
        "end_status": state, "returncode": returncode, "linux_signal": signal,
        "windows_exception_code": exception, "timed_out": False, "truncated": False,
        "started_at": "2026-10-16T00:00:00+00:00", "finished_at": "2026-10-16T00:00:01+00:00",
        "duration_seconds": 1.0, "resource_limits": {"timeout_seconds": 2.0,
            "max_output_bytes": 1024, "termination_scope": "POSIX_PROCESS_GROUP"},
        "stdout_b64": base64.b64encode(stdout).decode(), "stderr_b64": base64.b64encode(stderr).decode(),
        "stdout_sha256": _hash(stdout), "stderr_sha256": _hash(stderr),
        "command_identity": {"source": "SYNTHETIC_FIXTURE", "argv_sha256": digest_argv(argv)},
        "tool_identity": _identity(argv[0], "a" * 64), "diagnostics": [], "evidence_directory": "SYNTHETIC"})
    def artifact(name, path, raw):
        return {"artifact_file": name, "original_path": path, "sha256": _hash(raw), "size_bytes": len(raw)}
    collection = HostParserCollection.model_validate({"collection_id": "c" * 32, "cve_id": cve,
        "domain": domain, "collector": "p3b-synthetic-valgrind-1.0" if domain == "SYNTHETIC" else "p3b-imported-valgrind-1.0",
        "diagnostic_format": "VALGRIND_MEMCHECK_XML_V4", "request_id": "d" * 32, "run_id": "b" * 32,
        "platform_environment_id": "sha256:" + "e" * 64, "platform_probe_id": "SYNTHETIC-probe",
        "snapshot_sha256": "f" * 64,
        "target": {"component": component, "executable": _identity(target, "1" * 64), "build": None,
                   "build_status": "UNKNOWN"},
        "input": {"file": artifact("input.cubin", source, b"SYNTHETIC_NOT_A_REAL_CUBIN"),
                  "container_format": "ELF32", "payload_format": "CUDA_CUBIN", "format_status": "DOCUMENTED",
                  "format_evidence": "SYNTHETIC declared fixture only"},
        "diagnostic_tool": process.tool_identity, "diagnostic_tool_version": "SYNTHETIC-3.22.0",
        "diagnostic_tool_version_status": "DOCUMENTED",
        "diagnostic_version_record_sha256": "2" * 64, "target_argv": [target, source],
        "process": process, "observed_pid": 4321,
        "diagnostic_artifact": artifact("memcheck.xml", diagnostic, xml),
        "stdout_artifact": artifact("stdout.bin", "/synthetic/stdout.bin", stdout),
        "stderr_artifact": artifact("stderr.bin", "/synthetic/stderr.bin", stderr),
        "capture_complete": True, "cleanup_status": "CONFIRMED",
        "source_scope": "SYNTHETIC" if domain == "SYNTHETIC" else "IMPORTED_HOST_DIAGNOSTIC"})
    return collection, xml, stdout, stderr


def parse_case(*args, **kwargs):
    collection, xml, stdout, stderr = synthetic_collection(*args, **kwargs)
    evidence = parse_host_parser_evidence(collection, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(collection))
    return evidence


@pytest.mark.parametrize("kind,classification,direction", [
    ("InvalidRead", "INVALID_READ", "READ"), ("InvalidWrite", "INVALID_WRITE", "WRITE"),
    ("InvalidFree", "INVALID_FREE", "UNKNOWN"), ("MismatchedFree", "INVALID_FREE", "UNKNOWN"),
    ("UninitValue", "UNINITIALIZED_VALUE", "UNKNOWN"), ("UninitCondition", "UNINITIALIZED_VALUE", "UNKNOWN"),
    ("Overlap", "OTHER", "UNKNOWN"), ("SyscallParam", "OTHER", "UNKNOWN"),
    ("ClientCheck", "OTHER", "UNKNOWN"), ("Leak_DefinitelyLost", "OTHER", "UNKNOWN"),
    ("UnknownFutureKind", "UNSUPPORTED", "UNKNOWN"),
])
def test_structured_error_kind_only(kind, classification, direction):
    evidence = parse_case(kind)
    assert evidence.parse_status == "PARSED"
    item = evidence.observations[0]
    assert (item.classification, item.access_type) == (classification, direction)
    assert item.kind_locator.xml_node == "/valgrindoutput/error[1]/kind[1]"
    assert item.memory_region == item.lifetime_category == item.root_cause_status == "UNKNOWN"
    assert item.fault_address is None and item.access_size_bytes is None
    assert evidence.real_cve_verification == "NOT_VERIFIED"


@pytest.mark.parametrize("code", [0, 1, 7, -11])
def test_exit_and_signal_without_memory_error_never_prove_cve(code):
    evidence = parse_case(None, returncode=code)
    assert not evidence.observations
    result = evaluate_host_parser_requirements(evidence, expected_cve_id=evidence.collection.cve_id,
        expected_collection_sha256=evidence.collection_sha256)
    assert result.verdict == result.real_cve_verification == "NOT_VERIFIED"
    assert result.requirements[3].status == "UNKNOWN"


@pytest.mark.parametrize("prose", ["heap-buffer-overflow at 0xDEAD WRITE of size 8",
    "stack-buffer-overflow at 0xBEEF", "use-after-free from known CVE root cause",
    "CVE-2025-23308 VERIFIED", "Address 0x10 is 0 bytes inside a block free'd"])
def test_prose_does_not_create_region_address_size_lifetime_or_root_cause(prose):
    item = parse_case(prose=prose).observations[0]
    assert item.description_original == prose
    assert item.memory_region == item.lifetime_category == item.root_cause_status == "UNKNOWN"
    assert item.fault_address is None and item.access_size_bytes is None


def test_partial_frames_have_only_actual_nodes():
    frames = parse_case().observations[0].frames
    assert frames[0].instruction_pointer == "0x401001"
    assert frames[0].line == 10
    assert frames[0].field_locators["line"].xml_node.endswith("/frame[1]/line[1]")
    assert frames[1].function is None and frames[1].line is None
    assert set(frames[1].field_locators) == {"instruction_pointer"}


@pytest.mark.parametrize("transform,code", [
    (lambda raw: raw[:-20], "XML_MALFORMED_OR_TRUNCATED"),
    (lambda raw: raw.replace(b"<protocolversion>4", b"<protocolversion>3"), "XML_UNSUPPORTED_PROTOCOL"),
    (lambda raw: raw.replace(b"<protocoltool>memcheck", b"<protocoltool>helgrind"), "XML_UNSUPPORTED_PROTOCOL"),
    (lambda raw: raw.replace(b"<state>FINISHED</state>", b"<state>RUNNING</state>"), "XML_MISSING_FINISHED"),
    (lambda raw: raw.replace(b"<pid>4321", b"<pid>4322"), "XML_PROCESS_ID_CONFLICT"),
    (lambda raw: raw.replace(b"/synthetic/input.cubin</arg>", b"/synthetic/other.cubin</arg>"), "XML_TOOL_OR_INPUT_IDENTITY_CONFLICT"),
    (lambda raw: raw.replace(b"<exe>/synthetic/nvdisasm", b"<exe>/synthetic/other"), "XML_TOOL_OR_INPUT_IDENTITY_CONFLICT"),
    (lambda raw: raw.replace(b"<line>10", b"<line>not-a-line"), "XML_INVALID_FRAME_LINE"),
    (lambda raw: raw.replace(b"<ip>0x401001", b"<ip>imaginary"), "XML_INVALID_INSTRUCTION_POINTER"),
    (lambda raw: raw.replace(b"<kind>InvalidWrite</kind>", b"<kind>InvalidWrite</kind><kind>InvalidRead</kind>"), "XML_REQUIRED_OR_DUPLICATE_NODE:kind"),
    (lambda raw: raw.replace(b"<valgrindoutput>", b"<!DOCTYPE valgrindoutput><valgrindoutput>"), "XML_DTD_OR_ENTITY_FORBIDDEN"),
    (lambda raw: raw.replace(b"<valgrindoutput>", b"<!ENTITY evil 'x'><valgrindoutput>"), "XML_DTD_OR_ENTITY_FORBIDDEN"),
    (lambda raw: raw.replace(b"encoding='UTF-8'", b"encoding='UTF-16'"), "XML_UTF8_REQUIRED"),
    (lambda raw: raw + b"\xff", "XML_UTF8_REQUIRED"),
    (lambda raw: raw.replace(b"<valgrindoutput>", b"<valgrindoutput xmlns='unknown'>"), "XML_UNSUPPORTED_ROOT"),
])
def test_malformed_unsupported_or_identity_conflicting_xml_rejected(transform, code):
    evidence = parse_case(xml_transform=transform)
    assert evidence.parse_status == "REJECTED"
    assert evidence.observations == []
    assert evidence.diagnostic_codes == [code]
    assert evidence.raw_artifacts[0].raw_bytes()


@pytest.mark.parametrize("change", ["run", "tool", "input", "cve", "platform", "request", "collector"])
def test_collection_rebinding_rejected_by_independent_pin(change):
    collection, xml, stdout, stderr = synthetic_collection()
    data = collection.model_dump(mode="python")
    if change == "run":
        # Without resealing the process record the strict model rejects it first.
        data["run_id"] = "9" * 32
    elif change == "tool":
        data["target"]["executable"]["file_sha256"] = "9" * 64
    elif change == "input":
        data["input"]["file"]["sha256"] = "9" * 64
    elif change == "cve":
        data["cve_id"] = "CVE-2025-23339"
    elif change == "platform":
        data["platform_environment_id"] = "sha256:" + "9" * 64
    elif change == "request":
        data["request_id"] = "9" * 32
    else:
        data["collector"] = "p3b-imported-valgrind-1.0"
    with pytest.raises(ValueError):
        changed = HostParserCollection.model_validate(data)
        parse_host_parser_evidence(changed, diagnostic_bytes=xml, stdout_bytes=stdout,
            stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(collection))


@pytest.mark.parametrize("name", ["diagnostic", "stdout", "stderr"])
def test_raw_source_replacement_rejected(name):
    collection, xml, stdout, stderr = synthetic_collection()
    data = {"diagnostic_bytes": xml, "stdout_bytes": stdout, "stderr_bytes": stderr}
    data[name + "_bytes"] += b"replaced"
    with pytest.raises(ValueError):
        parse_host_parser_evidence(collection, **data, expected_collection_sha256=canonical_sha256(collection))


@pytest.mark.parametrize("field,value", [("capture_complete", False), ("cleanup_status", "UNKNOWN"),
                                         ("cleanup_status", "FAILED")])
def test_incomplete_capture_or_cleanup_cannot_infer(field, value):
    collection, xml, stdout, stderr = synthetic_collection()
    data = collection.model_dump(mode="python")
    data[field] = value
    collection = HostParserCollection.model_validate(data)
    evidence = parse_host_parser_evidence(collection, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(collection))
    assert evidence.parse_status == "REJECTED" and not evidence.observations


@pytest.mark.parametrize("format_name", ["ASAN_UNSUPPORTED", "UBSAN_UNSUPPORTED"])
def test_unimplemented_diagnostic_formats_preserve_bytes_without_inference(format_name):
    collection, xml, stdout, stderr = synthetic_collection()
    data = collection.model_dump(mode="python")
    data["diagnostic_format"] = format_name
    collection = HostParserCollection.model_validate(data)
    evidence = parse_host_parser_evidence(collection, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(collection))
    assert evidence.parse_status == "UNSUPPORTED" and not evidence.observations


def test_offline_roundtrip_and_reassessment_are_identical():
    evidence = parse_case()
    restored = HostParserEvidence.model_validate_json(evidence.model_dump_json())
    rebuilt = reassess_host_parser_evidence(restored, expected_collection_sha256=evidence.collection_sha256)
    assert rebuilt.model_dump_json() == evidence.model_dump_json()
    assert rebuilt.raw_artifacts[1].raw_bytes() == b"SYNTHETIC stdout\x00\xff"


@pytest.mark.parametrize("change", ["kind", "frame", "raw", "pin"])
def test_derived_observation_tampering_rejected(change):
    evidence = parse_case()
    data = evidence.model_dump(mode="python")
    if change == "kind":
        data["observations"][0]["classification"] = "INVALID_READ"
    elif change == "frame":
        data["observations"][0]["frames"][0]["function"] = "invented_root_cause"
    elif change == "raw":
        data["raw_artifacts"][0]["raw_b64"] = base64.b64encode(b"invented").decode()
    else:
        data["collection_sha256"] = "9" * 64
    with pytest.raises(ValueError):
        changed = HostParserEvidence.model_validate(data)
        reassess_host_parser_evidence(changed, expected_collection_sha256=evidence.collection_sha256)


@pytest.mark.parametrize("cve", ["CVE-2025-23308", "CVE-2025-23339"])
def test_six_preparation_requirements_and_p3a_adapter_never_verify(cve):
    evidence = parse_case(cve=cve)
    assessment = evaluate_host_parser_requirements(evidence,
        expected_collection_sha256=evidence.collection_sha256, expected_cve_id=cve)
    assert len(assessment.requirements) == 6
    assert [x.status for x in assessment.requirements] == ["UNKNOWN", "UNKNOWN", "SATISFIED", "SATISFIED", "UNKNOWN", "UNKNOWN"]
    plan, corpus = project_host_parser_to_p3a(evidence,
        expected_collection_sha256=evidence.collection_sha256, expected_cve_id=cve)
    result = evaluate_oracle(plan, corpus, trusted_plan_sha256=canonical_sha256(plan))
    assert result.eligibility.status == "UNKNOWN"
    assert result.verdict != "VERIFIED" and result.real_cve_verification == "NOT_VERIFIED"
    assert all(x.status == "UNKNOWN" for x in result.conditions[-2:])
    assert any(x.status == "SATISFIED" for x in result.conditions)


def test_same_error_cannot_be_mapped_to_another_cve():
    evidence = parse_case()
    with pytest.raises(ValueError, match="another CVE"):
        evaluate_host_parser_requirements(evidence, expected_collection_sha256=evidence.collection_sha256,
            expected_cve_id="CVE-2025-23339")


def test_imported_xml_cannot_self_declare_objective_cve_evidence():
    # This imported observation is still generated SYNTHETIC test data.
    evidence = parse_case(domain="IMPORTED_OBSERVATION")
    assert evidence.production_qualification == "UNSUPPORTED"
    assert evidence.qualified_for_cve_verification is False
    with pytest.raises(ValueError, match="UNSUPPORTED"):
        project_host_parser_to_p3a(evidence, expected_collection_sha256=evidence.collection_sha256,
            expected_cve_id=evidence.collection.cve_id)


@pytest.mark.parametrize("field", ["qualified_for_cve_verification", "real_cve_verification"])
def test_contract_refuses_production_verification_flags(field):
    data = parse_case().model_dump(mode="python")
    data[field] = True if field == "qualified_for_cve_verification" else "VERIFIED"
    with pytest.raises(ValidationError):
        HostParserEvidence.model_validate(data)


def test_nested_model_copy_does_not_launder_invalid_type():
    evidence = parse_case()
    tampered = evidence.collection.model_copy(update={"capture_complete": 1})
    with pytest.raises(ValidationError):
        parse_host_parser_evidence(tampered, diagnostic_bytes=evidence.raw_artifacts[0].raw_bytes(),
            stdout_bytes=evidence.raw_artifacts[1].raw_bytes(), stderr_bytes=evidence.raw_artifacts[2].raw_bytes(),
            expected_collection_sha256=evidence.collection_sha256)


def test_chinese_report_is_deterministic_and_keeps_scientific_bytes():
    evidence = parse_case()
    before = evidence.model_dump_json()
    report = render_host_parser_report_zh(evidence)
    assert "报告语言：`zh-CN`" in report
    assert "SYNTHETIC 合成测试" in report
    assert "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。" in report
    assert "目标 CVE 判定：NOT_VERIFIED" in report
    assert "/valgrindoutput/error[1]/kind[1]" in report
    assert evidence.collection.diagnostic_artifact.sha256 in report
    assert report.encode("utf-8").decode("utf-8") == report
    restored = HostParserEvidence.model_validate_json(before)
    assert render_host_parser_report_zh(restored).encode("utf-8") == report.encode("utf-8")
    assert evidence.model_dump_json() == before


@pytest.mark.parametrize("kind", ["ASAN_UNSUPPORTED", "UBSAN_UNSUPPORTED"])
def test_unsupported_report_explains_why_not_verified_in_chinese(kind):
    collection, xml, stdout, stderr = synthetic_collection()
    data = collection.model_dump(mode="python")
    data["diagnostic_format"] = kind
    collection = HostParserCollection.model_validate(data)
    evidence = parse_host_parser_evidence(collection, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(collection))
    report = render_host_parser_report_zh(evidence)
    assert "该诊断格式尚未实现" in report
    assert "NOT_VERIFIED" in report


def test_host_report_refuses_unknown_locale_or_changed_derived_fields():
    evidence = parse_case()
    with pytest.raises(ValueError, match="report_locale"):
        render_host_parser_report_zh(evidence, report_locale="en-US")
    changed = evidence.model_dump(mode="python")
    changed["observations"][0]["frames"][0]["function"] = "fabricated"
    with pytest.raises(ValueError, match="reevaluation"):
        render_host_parser_report_zh(HostParserEvidence.model_validate(changed))


@pytest.mark.parametrize("transform,expected", [
    (lambda raw: raw.replace(b"<valgrindoutput>", b"<valgrindoutput><x>" * 40), "XML_MALFORMED_OR_TRUNCATED"),
    (lambda raw: raw.replace(b"</valgrindoutput>", b"<x>" * 35 + b"</x>" * 35 + b"</valgrindoutput>"), "XML_STRUCTURE_LIMIT"),
    (lambda raw: raw + b" " * (2 * 1024 * 1024), "XML_SIZE_LIMIT"),
    (lambda raw: raw.replace(b"</valgrindoutput>", b"<status><state>FINISHED</state></status></valgrindoutput>"), "XML_DUPLICATE_FINISHED"),
    (lambda raw: raw.replace(b"<status><state>RUNNING", b"<status><state>UNSUPPORTED_STATE"), "XML_UNSUPPORTED_PROCESS_STATE"),
    (lambda raw: raw.replace(b"<frame>", b"<frame bogus='attribute'>", 1), "XML_UNSUPPORTED_NODE_PROFILE"),
])
def test_explicit_parser_bounds_and_unsupported_variants(transform, expected):
    evidence = parse_case(xml_transform=transform)
    assert evidence.parse_status == "REJECTED"
    assert evidence.diagnostic_codes == [expected]


@pytest.mark.parametrize("key", ["collection_id", "request_id", "run_id", "diagnostic_tool",
                               "process", "target", "input", "snapshot_sha256"])
def test_collection_required_bindings_cannot_be_omitted(key):
    collection, _, _, _ = synthetic_collection()
    data = collection.model_dump(mode="python")
    del data[key]
    with pytest.raises(ValidationError):
        HostParserCollection.model_validate(data)


def test_unknown_cve_paths_and_free_form_collector_rejected():
    collection, _, _, _ = synthetic_collection()
    for field, value in (("cve_id", "../../CVE-2025-23308"), ("collector", "llm-generated-trusted-collector"),
                         ("source_scope", "CVE_TRIGGER"), ("execution_authorized", True)):
        data = collection.model_dump(mode="python")
        data[field] = value
        with pytest.raises(ValidationError):
            HostParserCollection.model_validate(data)


@pytest.mark.parametrize("container,payload", [("ELF32", "CUDA_CUBIN"), ("ELF64", "CUDA_CUBIN"),
    ("CUDA_FATBIN", "UNKNOWN"), ("ELF64", "DEBUG_INFO"), ("ELF32", "RELOCATION_DATA"), ("UNKNOWN", "UNKNOWN")])
def test_container_and_payload_formats_remain_distinct_without_qualification(container, payload):
    collection, xml, stdout, stderr = synthetic_collection()
    data = collection.model_dump(mode="python")
    data["input"].update(container_format=container, payload_format=payload)
    changed = HostParserCollection.model_validate(data)
    evidence = parse_host_parser_evidence(changed, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(changed))
    assert evidence.collection.input.container_format == container
    assert evidence.collection.input.payload_format == payload
    assessment = evaluate_host_parser_requirements(evidence, expected_collection_sha256=evidence.collection_sha256,
        expected_cve_id=evidence.collection.cve_id)
    assert assessment.requirements[1].status == "UNKNOWN"


def test_unsupported_affected_fixed_comparison_does_not_manufacture_root_cause():
    first, xml, stdout, stderr = synthetic_collection()
    data = first.model_dump(mode="python")
    data["target"].update(build="12.9.19", build_status="DOCUMENTED")
    fixed = HostParserCollection.model_validate(data)
    evidence = parse_host_parser_evidence(fixed, diagnostic_bytes=xml, stdout_bytes=stdout,
        stderr_bytes=stderr, expected_collection_sha256=canonical_sha256(fixed))
    assessment = evaluate_host_parser_requirements(evidence, expected_collection_sha256=evidence.collection_sha256,
        expected_cve_id=evidence.collection.cve_id)
    assert assessment.requirements[-1].method_status == "UNIMPLEMENTED"
    assert assessment.requirements[-1].status == "UNKNOWN"
    assert assessment.real_cve_verification == "NOT_VERIFIED"
