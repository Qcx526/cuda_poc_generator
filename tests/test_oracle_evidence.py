"""SYNTHETIC adapter tests; the optional pinned smoke test only reads files."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.oracle_evidence import EvidenceCorpus, load_p2c_evidence, _tool_version


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def synthetic(raw=b'{"domain":"SYNTHETIC","value":7}', name="observations.json"):
    return EvidenceCorpus.from_synthetic(label="SYNTHETIC", artifacts={name: raw},
        binding={"request_id": "a" * 32, "tool_sha256": {"nvcc": "b" * 64}})


def mock_context(tmp_path):
    """A deliberately mocked trusted-reader result, never actual observations."""
    record_data = {"status": "COMPLETED", "candidate_execution_status": "NOT_EXECUTED",
        "verification_status": "NOT_VERIFIED", "diagnostics": ["not an objective fact"],
        "cuda_smoke": {"source_sha256": "d" * 64, "steps": [{"step_id": "compile", "state": "COMPLETED",
            "process": {"returncode": 0, "linux_signal": None, "truncated": False}}]}}
    platform_data = {"cuda_toolkit_version": {"status": "OBSERVED", "value": "12.8"},
        "nvcc_version": {"status": "CONFIGURED", "value": "unmeasured"},
        "kernel": {"status": "UNKNOWN", "value": None}}
    artifacts = {"execution_record.json": json.dumps(record_data).encode(),
        "platform_snapshot.json": json.dumps(platform_data).encode(),
        "execution_request.json": b'{"domain":"SYNTHETIC"}',
        "stdout.bin": b"CVE VERIFIED: prose must never be trusted",
        "report.md": b"# A summary is not objective evidence"}
    identities = {"request_id": "a" * 32, "run_id": "b" * 32,
        "platform_environment_id": "sha256:" + "c" * 64, "platform_probe_id": "synthetic-probe",
        "candidate_sha256": "d" * 64, "snapshot_sha256": "e" * 64,
        "tool_record_id": "sha256:" + "f" * 64, "request_sha256": "1" * 64,
        "authorization_sha256": "2" * 64, "policy_sha256": "3" * 64,
        "target_environment": "wsl:SYNTHETIC"}
    record = SimpleNamespace(**identities, action_id="p2c-cuda-smoke-v1", cuda_smoke=object(),
        tool_identity=SimpleNamespace(file_sha256="6" * 64, resolved_path="/synthetic/nvdisasm"))
    manifest = SimpleNamespace(capture_complete=True, truncated=False, execution_record_sha256="4" * 64,
        collector_version="p2c-1.1", artifacts={name: SimpleNamespace(sha256=digest(raw))
                                               for name, raw in artifacts.items()})
    request = SimpleNamespace(cuda_toolchain=SimpleNamespace(tools={
        "nvcc": SimpleNamespace(file_sha256="5" * 64, resolved_path="/synthetic/nvcc"),
        "nvdisasm": SimpleNamespace(file_sha256="6" * 64, resolved_path="/synthetic/nvdisasm")}, version_records={}))
    raw_manifest = json.dumps({"request_id": identities["request_id"], "run_id": identities["run_id"],
                              "execution_record_sha256": manifest.execution_record_sha256}).encode()
    (tmp_path / "manifest.json").write_bytes(raw_manifest)
    context = {"record": record, "manifest": manifest, "request": request, "artifacts": artifacts,
        "native_verification": SimpleNamespace(status="VERIFIED"),
        "cleanup_confirmation": "CONFIRMED", "effective_status": "COMPLETED"}
    return context, digest(raw_manifest)


def load_mock(tmp_path, context, pin):
    with patch("src.oracle_evidence.read_execution_evidence", return_value=context):
        return load_p2c_evidence(tmp_path, expected_manifest_sha256=pin)


def version_fixture(role="cuobjdump", release="12.8", build="12.8.90"):
    banners = {"nvcc": "nvcc: NVIDIA (R) Cuda compiler driver",
        "cuobjdump": "cuobjdump: NVIDIA (R) fat binary listing tool",
        "nvdisasm": "nvdisasm: NVIDIA (R) CUDA disassembler"}
    raw = (banners[role] + "\nCopyright SYNTHETIC test fixture\n" +
           "Cuda compilation tools, release " + release + ", V" + build + "\n").encode()
    identity = SimpleNamespace(status="OBSERVED", resolved_path="/synthetic/" + role,
                               file_sha256=digest(role.encode()))
    record = SimpleNamespace(end_status="NORMAL_EXIT", returncode=0, truncated=False, capture_failed=False,
        tool_identity=identity, argv=[identity.resolved_path, "--version"], stdout_sha256=digest(raw),
        stdout_bytes=lambda: raw, model_dump=lambda **kwargs: {"domain": "SYNTHETIC", "role": role})
    return record, identity


def test_synthetic_label_and_no_real_world_upgrade():
    corpus = synthetic()
    assert corpus.domain == "SYNTHETIC" and corpus.scope == "SYNTHETIC"
    assert corpus.original_source == "SYNTHETIC_FIXTURE"
    assert "SYNTHETIC_RULE_TEST_ONLY" in corpus.diagnostics
    with pytest.raises(ValueError):
        EvidenceCorpus.from_synthetic(label="OBJECTIVE", artifacts={}, binding={})
    with pytest.raises(TypeError):
        EvidenceCorpus.from_synthetic(artifacts={}, binding={})
    with pytest.raises(ValueError, match="pinned P2-C loader"):
        replace(corpus, domain="OBJECTIVE", scope="TOOLCHAIN_SMOKE")


def test_corpus_is_immutable_and_copies_caller_maps():
    raw = b'{"value":{"items":[1,2]}}'
    artifacts = {"observations.json": raw}
    binding = {"tool_sha256": {"nvcc": "a" * 64}}
    corpus = EvidenceCorpus.from_synthetic(label="SYNTHETIC", artifacts=artifacts, binding=binding)
    artifacts["observations.json"] = b"replacement"
    binding["tool_sha256"]["nvcc"] = "b" * 64
    assert corpus.artifacts["observations.json"] == raw
    assert corpus.binding["tool_sha256"]["nvcc"] == "a" * 64
    with pytest.raises(TypeError):
        corpus.binding["tool_sha256"]["nvcc"] = "c" * 64
    with pytest.raises(FrozenInstanceError):
        corpus.qualified = False
    value = corpus.resolve("observations.json", digest(raw), "/value")
    value["items"].append(3)
    assert corpus.resolve("observations.json", digest(raw), "/value/items") == [1, 2]


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":-Infinity}', b'{"x":1e999}', b'{"x":', b"not JSON", b'\xff'])
def test_malformed_or_nonfinite_json_rejected(raw):
    corpus = synthetic(raw)
    with pytest.raises(ValueError):
        corpus.resolve("observations.json", digest(raw), "/x")


@pytest.mark.parametrize("pointer", ["x", "/items/-", "/items/01", "/items/3", "/items/~2", "/items/0/extra", "/missing"])
def test_invalid_pointer_or_absent_location_rejected(pointer):
    raw = b'{"items":[1,2]}'
    corpus = synthetic(raw)
    with pytest.raises(ValueError):
        corpus.resolve("observations.json", digest(raw), pointer)


def test_rfc6901_escaped_keys_and_unmodified_values():
    raw = b'{"a/b":{"~key":[true,null,4]}}'
    assert synthetic(raw).resolve("observations.json", digest(raw), "/a~1b/~0key") == [True, None, 4]


def test_wrong_hash_missing_artifact_and_markdown_rejected():
    corpus = synthetic()
    for filename, expected in (("observations.json", "f" * 64), ("other.json", "0" * 64),
                                ("../observations.json", "0" * 64)):
        with pytest.raises(ValueError):
            corpus.resolve(filename, expected, "/value")
    raw = b'{"value":"VERIFIED"}'
    with pytest.raises(ValueError):
        synthetic(raw, name="report.md").resolve("report.md", digest(raw), "/value")


def test_manifest_pin_checked_before_original_reader(tmp_path):
    _, pin = mock_context(tmp_path)
    with patch("src.oracle_evidence.read_execution_evidence") as reader:
        with pytest.raises(ValueError, match="manifest SHA-256 mismatch"):
            load_p2c_evidence(tmp_path, expected_manifest_sha256="0" * 64)
        reader.assert_not_called()
    assert len(pin) == 64


def test_changed_manifest_during_read_rejected(tmp_path):
    context, pin = mock_context(tmp_path)

    def replace_manifest(*args, **kwargs):
        (tmp_path / "manifest.json").write_bytes(b"replacement")
        return context

    with patch("src.oracle_evidence.read_execution_evidence", side_effect=replace_manifest):
        with pytest.raises(ValueError, match="changed while being read"):
            load_p2c_evidence(tmp_path, expected_manifest_sha256=pin)


def test_original_reader_integrity_failure_is_not_suppressed(tmp_path):
    _, pin = mock_context(tmp_path)
    with patch("src.oracle_evidence.read_execution_evidence", side_effect=ValueError("original hash mismatch")):
        with pytest.raises(ValueError, match="original hash mismatch"):
            load_p2c_evidence(tmp_path, expected_manifest_sha256=pin)


def test_p2c_binding_metadata_and_observed_field_whitelist(tmp_path):
    context, pin = mock_context(tmp_path)
    corpus = load_mock(tmp_path, context, pin)
    assert corpus.qualified and corpus.domain == "OBJECTIVE"
    assert corpus.scope == "TOOLCHAIN_SMOKE" and "cve_id" not in corpus.binding
    assert corpus.binding["tool_sha256"]["nvcc"] == "5" * 64
    assert corpus.binding["tool_sha256"]["nvdisasm"] == "6" * 64
    assert corpus.binding["manifest_sha256"] == pin
    filename = "platform_snapshot.json"
    assert corpus.resolve(filename, corpus.artifact_sha256[filename], "/cuda_toolkit_version/value") == "12.8"
    for pointer in ("/nvcc_version/value", "/kernel/value", "/cuda_toolkit_version", "/cuda_toolkit_version/status"):
        with pytest.raises(ValueError):
            corpus.resolve(filename, corpus.artifact_sha256[filename], pointer)
    filename = "execution_record.json"
    for pointer, expected in (("/status", "COMPLETED"), ("/verification_status", "NOT_VERIFIED"),
                              ("/cuda_smoke/steps/0/process/returncode", 0)):
        assert corpus.resolve(filename, corpus.artifact_sha256[filename], pointer) == expected
    for pointer in ("/diagnostics/0", "", "/cuda_smoke/steps", "/cuda_smoke/steps/00/process/returncode"):
        with pytest.raises(ValueError):
            corpus.resolve(filename, corpus.artifact_sha256[filename], pointer)
    for filename in ("report.md", "stdout.bin"):
        with pytest.raises(ValueError):
            corpus.resolve(filename, corpus.artifact_sha256[filename], "")


@pytest.mark.parametrize("mutation,diagnostic", [
    ("native", "NATIVE_EVIDENCE_NOT_VERIFIED"), ("capture", "CAPTURE_INCOMPLETE"),
    ("truncated", "CAPTURE_INCOMPLETE"), ("cleanup", "CLEANUP_NOT_CONFIRMED"),
    ("execution", "EXECUTION_NOT_COMPLETED"),
])
def test_incomplete_observations_retained_but_not_qualified(tmp_path, mutation, diagnostic):
    context, pin = mock_context(tmp_path)
    if mutation == "native":
        context["native_verification"].status = "INCOMPLETE"
    elif mutation == "capture":
        context["manifest"].capture_complete = False
    elif mutation == "truncated":
        context["manifest"].truncated = True
    elif mutation == "cleanup":
        context["cleanup_confirmation"] = "UNKNOWN"
    else:
        context["effective_status"] = "UNKNOWN"
    corpus = load_mock(tmp_path, context, pin)
    assert not corpus.qualified and diagnostic in corpus.diagnostics
    assert corpus.resolve("execution_record.json", corpus.artifact_sha256["execution_record.json"], "/verification_status") == "NOT_VERIFIED"


def test_only_fixed_p2c_action_can_load_as_objective(tmp_path):
    context, pin = mock_context(tmp_path)
    context["record"].action_id = "arbitrary-candidate"
    with pytest.raises(ValueError, match="fixed P2-C toolchain smoke"):
        load_mock(tmp_path, context, pin)


def test_step_tool_role_cannot_be_replaced_by_another_authorized_tool(tmp_path):
    context, pin = mock_context(tmp_path)
    corpus = load_mock(tmp_path, context, pin)
    corpus.validate_tool_binding("execution_record.json", "/cuda_smoke/steps/0/process/returncode", "nvcc", "5" * 64)
    corpus.validate_tool_binding("execution_record.json", "/cuda_smoke/source_sha256", "nvcc", "5" * 64)
    corpus.validate_tool_binding("execution_record.json", "/status", "nvdisasm", "6" * 64)
    corpus.validate_tool_binding("platform_snapshot.json", "/cuda_toolkit_version/value", "nvcc", "5" * 64)
    with pytest.raises(ValueError, match="different actual tool role"):
        corpus.validate_tool_binding("execution_record.json", "/cuda_smoke/steps/0/process/returncode", "nvdisasm", "6" * 64)
    with pytest.raises(ValueError, match="different actual tool role"):
        corpus.validate_tool_binding("execution_record.json", "/status", "nvcc", "5" * 64)
    with pytest.raises(ValueError, match="different actual tool role"):
        corpus.validate_tool_binding("execution_record.json", "/cuda_smoke/source_sha256", "nvdisasm", "6" * 64)
    with pytest.raises(ValueError, match="role or hash"):
        corpus.validate_tool_binding("execution_record.json", "/status", "nvdisasm", "5" * 64)


@pytest.mark.parametrize("field,role,sha,valid", [
    ("nvcc_version", "nvcc", "5" * 64, True),
    ("nvcc_version", "nvdisasm", "6" * 64, False),
    ("compute_sanitizer_version", "nvdisasm", "6" * 64, False),
])
def test_component_specific_platform_versions_cannot_be_rebound(tmp_path, field, role, sha, valid):
    context, pin = mock_context(tmp_path)
    filename = "platform_snapshot.json"
    document = json.loads(context["artifacts"][filename])
    document[field] = {"status": "OBSERVED", "value": "12.8.93"}
    raw = json.dumps(document).encode()
    context["artifacts"][filename] = raw
    context["manifest"].artifacts[filename].sha256 = digest(raw)
    corpus = load_mock(tmp_path, context, pin)
    if valid:
        corpus.validate_tool_binding(filename, "/" + field + "/value", role, sha)
    else:
        with pytest.raises(ValueError, match="different actual tool role"):
            corpus.validate_tool_binding(filename, "/" + field + "/value", role, sha)


def test_narrow_version_parser_preserves_per_tool_build_and_canonical_record_hash():
    record, identity = version_fixture()
    parsed = _tool_version("cuobjdump", record, identity)
    assert parsed["release"] == "12.8" and parsed["build"] == "12.8.90"
    assert len(parsed["record_sha256"]) == 64
    nvcc, nvcc_identity = version_fixture("nvcc", build="12.8.93")
    assert _tool_version("nvcc", nvcc, nvcc_identity)["build"] == "12.8.93"
    assert _tool_version("nvdisasm", record, identity) is None


@pytest.mark.parametrize("change", ["nonzero", "truncated", "capture", "argv", "identity", "status",
                                   "duplicate", "nonascii", "release_mismatch"])
def test_narrow_version_parser_unknown_for_unqualified_or_ambiguous_output(change):
    record, identity = version_fixture()
    if change == "nonzero":
        record.returncode = 1
    elif change == "truncated":
        record.truncated = True
    elif change == "capture":
        record.capture_failed = True
    elif change == "argv":
        record.argv.append("--other")
    elif change == "identity":
        record.tool_identity = SimpleNamespace(file_sha256="0" * 64)
    elif change == "status":
        record.end_status = "TIMED_OUT"
    elif change == "release_mismatch":
        record, identity = version_fixture(release="12.7", build="12.8.90")
    else:
        raw = record.stdout_bytes() + (b"Cuda compilation tools, release 12.8, V12.8.90\n"
                                       if change == "duplicate" else b"\xff")
        record.stdout_bytes = lambda: raw
        record.stdout_sha256 = digest(raw)
    assert _tool_version("cuobjdump", record, identity) is None


def test_measured_tool_release_conflicting_with_platform_is_rejected(tmp_path):
    context, pin = mock_context(tmp_path)
    nvcc, nvcc_identity = version_fixture("nvcc", build="12.8.93")
    context["request"].cuda_toolchain.tools["nvcc"] = nvcc_identity
    context["request"].cuda_toolchain.version_records["nvcc"] = nvcc
    context["snapshot"] = SimpleNamespace(cuda_toolkit_version=SimpleNamespace(status="OBSERVED", value="12.7"))
    with pytest.raises(ValueError, match="Toolkit release conflicts"):
        load_mock(tmp_path, context, pin)


@pytest.mark.skipif(not (os.environ.get("P3A_P2C_EVIDENCE_DIR") and os.environ.get("P3A_P2C_MANIFEST_SHA256")),
                    reason="optional read-only compatibility check requires operator-selected evidence folder and independent manifest pin")
def test_optional_real_smoke_is_only_toolchain_observations():
    corpus = load_p2c_evidence(Path(os.environ["P3A_P2C_EVIDENCE_DIR"]),
                              expected_manifest_sha256=os.environ["P3A_P2C_MANIFEST_SHA256"])
    assert corpus.domain == "OBJECTIVE" and corpus.scope == "TOOLCHAIN_SMOKE"
    name = "execution_record.json"
    assert corpus.resolve(name, corpus.artifact_sha256[name], "/verification_status") == "NOT_VERIFIED"
    assert corpus.resolve(name, corpus.artifact_sha256[name], "/candidate_execution_status") == "NOT_EXECUTED"
