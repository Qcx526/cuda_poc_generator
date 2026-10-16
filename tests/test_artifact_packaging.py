"""SYNTHETIC offline filesystem attacks; no PoC or CUDA process is executed."""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest

from src import artifact_packaging as ap
from src.artifact_cli import main
from src.models.artifact_package import ArtifactManifest, safe_member
from src.models.generation import CandidateResult
from src.models.lifecycle import canonical_sha256
from src.models.normalized_input import normalize_input_files
from src.oracle_catalog import ROOT

CVE = "CVE-2025-23308"
RUN = "a" * 32


@pytest.fixture
def review(tmp_path):
    run = ap.import_review_run(CVE, RUN, output_root=tmp_path)
    return tmp_path, run


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def rewrite_archive(path, change):
    with zipfile.ZipFile(path) as archive:
        entries = [(x, archive.read(x)) for x in archive.infolist()]
    entries = change(entries)
    with zipfile.ZipFile(path, "w") as archive:
        for info, raw in entries:
            archive.writestr(info, raw)
    return digest(path.read_bytes())


def test_review_zip_bytes_and_independent_integrity(review):
    root, run = review
    path, result = ap.package_run(CVE, RUN, output_root=root)
    check = ap.verify_package(path, expected_sha256=digest(path.read_bytes()))
    assert check == result
    assert check.file_count == 12
    assert check.real_cve_verification == "NOT_VERIFIED"
    assert check.candidate_execution_status == "NOT_EXECUTED"
    assert check.package_kind == "RESEARCH_ONLY"
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            assert archive.read(name) == (run / name).read_bytes()
        text = archive.read("README.zh-CN.md").decode("utf-8")
        assert "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。" in text
    index = json.loads((root / CVE / "index.json").read_text(encoding="utf-8"))
    assert index["runs"][RUN]["package"]["sha256"] == check.package_sha256
    assert check.authenticity == "UNAUTHENTICATED_EXTERNAL_HASH_PIN"


def test_chinese_report_rebuild_exact_bytes(review):
    root, run = review
    rebuilt = ap.rebuild_review_report(CVE, RUN, output_root=root).encode("utf-8")
    assert rebuilt == (run / "reports/review.zh-CN.md").read_bytes()
    assert "CVE-2025-23308" in rebuilt.decode("utf-8")


def test_original_sources_remain_unchanged(review):
    root, run = review
    manifest, _ = ap.read_review_run(CVE, RUN, output_root=root)
    for item in manifest.files:
        if item.artifact_type == "INPUT_ASSERTION":
            original = ROOT / "data" / "inputs" / CVE / Path(item.relative_path).name
            assert original.read_bytes() == (run / item.relative_path).read_bytes()
            assert item.sha256 == digest(original.read_bytes())


@pytest.mark.parametrize("cve", ["../CVE-2025-23308", "CVE-2025-23308/../x", "CVE-25-1234",
    "cve-2025-23308", "CVE-2025-23308\\x", "F:\\x", "CVE-2025-23308\n", "CVE-2025-123"])
def test_reject_cve_path_and_unbound_names(tmp_path, cve):
    with pytest.raises(ValueError):
        ap.import_review_run(cve, RUN, output_root=tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("run_id", ["../escape", "A" * 32, "a" * 31, "b" * 33, "..", "F:\\run", "a" * 32 + "\n"])
def test_reject_run_path(tmp_path, run_id):
    with pytest.raises(ValueError):
        ap.import_review_run(CVE, run_id, output_root=tmp_path)


@pytest.mark.parametrize("name", ["/absolute", "../x", "a/../x", "a\\b", "a//b", "./x", "a/",
    "F:x", "CON", "aux.txt", "LPT1.txt", "COM9", "x.", "x ", "a/PRN", "a/./x"])
def test_safe_portable_names(name):
    with pytest.raises(ValueError):
        safe_member(name)


def test_independent_multiple_runs_and_cves(review):
    root, first = review
    original = (first / "artifact_manifest.json").read_bytes()
    ap.import_review_run(CVE, "b" * 32, output_root=root)
    ap.import_review_run("CVE-2025-23339", RUN, output_root=root)
    assert (first / "artifact_manifest.json").read_bytes() == original
    assert len(json.loads((root / CVE / "index.json").read_text(encoding="utf-8"))["runs"]) == 2


def test_same_run_and_zip_never_overwrite(review):
    root, run = review
    manifest = (run / "artifact_manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        ap.import_review_run(CVE, RUN, output_root=root)
    path, _ = ap.package_run(CVE, RUN, output_root=root)
    raw = path.read_bytes()
    with pytest.raises(FileExistsError):
        ap.package_run(CVE, RUN, output_root=root)
    assert path.read_bytes() == raw
    assert (run / "artifact_manifest.json").read_bytes() == manifest


def test_parent_round_hash_reference(review):
    root, run = review
    ap.import_review_run(CVE, "b" * 32, output_root=root, parent_run_id=RUN,
        parent_manifest_sha256=digest((run / "artifact_manifest.json").read_bytes()))
    with pytest.raises(ValueError):
        ap.import_review_run(CVE, "c" * 32, output_root=root, parent_run_id=RUN,
                             parent_manifest_sha256="0" * 64)


def test_casefold_duplicate_manifest_member(review):
    _, run = review
    data = json.loads((run / "artifact_manifest.json").read_bytes())
    extra = dict(data["files"][0])
    extra["relative_path"] = extra["relative_path"].upper()
    data["files"].append(extra)
    with pytest.raises(ValueError):
        ArtifactManifest.model_validate(data)


def test_cross_cve_manifest_and_run_rejected(review):
    _, run = review
    data = json.loads((run / "artifact_manifest.json").read_bytes())
    data["files"][0]["cve_id"] = "CVE-2025-23339"
    with pytest.raises(ValueError):
        ArtifactManifest.model_validate(data)
    data["files"][0]["cve_id"] = CVE
    data["files"][0]["run_id"] = "b" * 32
    with pytest.raises(ValueError):
        ArtifactManifest.model_validate(data)


@pytest.mark.parametrize("field,value", [("real_cve_verification", "VERIFIED"),
    ("candidate_execution_status", "COMPLETED"), ("package_kind", "COMPLETE"),
    ("evidence_domain", "SYNTHETIC"), ("report_locale", "en-US")])
def test_cannot_promote_synthetic_or_research_to_experiment(review, field, value):
    _, run = review
    data = json.loads((run / "artifact_manifest.json").read_bytes())
    data[field] = value
    with pytest.raises(ValueError):
        ArtifactManifest.model_validate(data)


@pytest.mark.parametrize("mutation", ["missing", "truncate", "tamper", "extra"])
def test_local_evidence_missing_or_changed_rejected(review, mutation):
    root, run = review
    target = run / "reports/review.zh-CN.md"
    if mutation == "missing":
        target.unlink()
    elif mutation == "extra":
        (run / "evidence/secret.txt").write_bytes(b"SYNTHETIC NOT A SECRET")
    else:
        target.write_bytes(target.read_bytes()[:-5] if mutation == "truncate" else b"tampered")
    with pytest.raises((ValueError, OSError)):
        ap.package_run(CVE, RUN, output_root=root)
    assert not list((root / CVE).glob("packages/*.zip"))


@pytest.mark.parametrize("mutation", ["traversal", "backslash", "absolute", "duplicate", "symlink", "missing", "replace"])
def test_zip_member_attacks_rejected(review, mutation):
    root, _ = review
    path, _ = ap.package_run(CVE, RUN, output_root=root)
    def change(entries):
        if mutation == "missing":
            return entries[1:]
        if mutation == "replace":
            return [(info, b"replacement" if info.filename.startswith("reports/") else raw) for info, raw in entries]
        info = zipfile.ZipInfo({"traversal": "../escape", "backslash": "a\\b", "absolute": "/x"}.get(
            mutation, entries[0][0].filename if mutation == "duplicate" else "evidence/link"))
        info.create_system = 3
        info.external_attr = ((stat.S_IFLNK if mutation == "symlink" else stat.S_IFREG) | 0o644) << 16
        return entries + [(info, b"SYNTHETIC")]
    pinned = rewrite_archive(path, change)
    with pytest.raises(ValueError):
        ap.verify_package(path, expected_sha256=pinned)


def test_zip_truncation_and_external_pin(review):
    root, _ = review
    path, result = ap.package_run(CVE, RUN, output_root=root)
    with pytest.raises(ValueError):
        ap.verify_package(path, expected_sha256="0" * 64)
    path.write_bytes(path.read_bytes()[:-40])
    with pytest.raises(ValueError):
        ap.verify_package(path, expected_sha256=digest(path.read_bytes()))
    assert result.real_cve_verification == "NOT_VERIFIED"


def test_zip_null_byte_filename_rejected(review):
    root, _ = review
    path, _ = ap.package_run(CVE, RUN, output_root=root)
    raw = path.read_bytes().replace(b"reports/review.zh-CN.md", b"reports/review\x00zh-CN.md")
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        ap.verify_package(path, expected_sha256=digest(raw))


def test_symlink_file_or_directory_rejected(review, tmp_path):
    root, run = review
    target = run / "reports/review.zh-CN.md"
    raw = target.read_bytes()
    outside = tmp_path / "outside.md"
    outside.write_bytes(raw)
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("当前 Windows 账户不支持创建符号链接；WSL 必须执行此负例")
    with pytest.raises(ValueError):
        ap.package_run(CVE, RUN, output_root=root)


def test_disk_write_failure_does_not_claim_success(tmp_path, monkeypatch):
    original = ap._write_new
    def fail(path, raw):
        if str(path).endswith("artifact_manifest.json"):
            raise OSError("SYNTHETIC disk failure")
        return original(path, raw)
    monkeypatch.setattr(ap, "_write_new", fail)
    with pytest.raises(OSError):
        ap.import_review_run(CVE, RUN, output_root=tmp_path)
    assert not (tmp_path / CVE / "index.json").exists()
    assert not list(tmp_path.rglob("*.zip"))


def test_exclusive_lock_prevents_index_race(review):
    root, _ = review
    lock = root / CVE / ".packaging.lock"
    lock.write_bytes(b"SYNTHETIC another packager")
    with pytest.raises(FileExistsError):
        ap.package_run(CVE, RUN, output_root=root)
    assert lock.exists()


def test_cli_import_package_verify_and_rebuild(tmp_path, capsys):
    assert main(["import-review", "--cve", CVE, "--run-id", RUN, "--output-root", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["package", "--cve", CVE, "--run-id", RUN, "--output-root", str(tmp_path)]) == 0
    response = json.loads(capsys.readouterr().out)
    assert main(["verify", "--package", response["package"], "--expected-sha256",
                 response["verification"]["package_sha256"]]) == 0
    capsys.readouterr()
    assert main(["rebuild-report", "--cve", CVE, "--run-id", RUN, "--output-root", str(tmp_path)]) == 0
    assert "CVE-2025-23308" in capsys.readouterr().out


def generation_fixture(tmp_path, *, generated=True):
    source = tmp_path / "legacy"
    source.mkdir()
    bundle = normalize_input_files(ROOT / "data/inputs" / CVE)
    normalized = bundle.model_dump(mode="json")
    normalized.update(run_id=RUN, input_status="VALID")
    (source / "input_manifest_v1.json").write_bytes(ap._bytes(normalized))
    candidate_raw = b"# SYNTHETIC offline candidate; never executed\nprint('fixture')\n"
    candidate = CandidateResult(run_id=RUN, generation="GENERATED" if generated else "GENERATION_FAILED",
        static="STATIC_VALID" if generated else "NOT_CHECKED", source_file="cuda_poc_v1.py" if generated else None,
        sha256=digest(candidate_raw) if generated else None)
    (source / "cuda_poc_v1.status.json").write_bytes(ap._bytes(candidate))
    if generated:
        (source / "cuda_poc_v1.py").write_bytes(candidate_raw)
    artifacts = {"input_manifest": {"file": "input_manifest_v1.json", "sha256": digest((source / "input_manifest_v1.json").read_bytes())},
        "candidate_status": {"file": "cuda_poc_v1.status.json", "sha256": digest((source / "cuda_poc_v1.status.json").read_bytes())}}
    if generated:
        artifacts["candidate"] = {"file": "cuda_poc_v1.py", "sha256": digest(candidate_raw)}
    record = {"schema_version": "1.0", "run_id": RUN, "cve_id": CVE, "status": "COMPLETE" if generated else "GENERATION_FAILED",
        "input_status": "VALID", "analysis_status": "NOT_ANALYZED", "candidate": candidate.model_dump(mode="json"),
        "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED", "artifacts": artifacts,
        "preexisting_artifacts": {}, "diagnostics": []}
    (source / "cuda_run_v1.json").write_bytes(ap._bytes(record))
    return source, record


@pytest.mark.parametrize("generated", [True, False])
def test_generation_archive_includes_only_current_artifacts(tmp_path, generated):
    source, record = generation_fixture(tmp_path, generated=generated)
    (source / "old_private.log").write_bytes(b"SYNTHETIC stale data")
    outputs = tmp_path / "outputs"
    run = ap.create_generation_run(CVE, RUN, source, record, output_root=outputs)
    manifest, _ = ap.read_review_run(CVE, RUN, output_root=outputs)
    assert manifest.package_kind == "GENERATION_RESEARCH_INCOMPLETE"
    assert (run / "poc/cuda_poc_v1.py").exists() is generated
    assert not (run / "old_private.log").exists()
    path, result = ap.package_run(CVE, RUN, output_root=outputs)
    assert ap.verify_package(path, expected_sha256=digest(path.read_bytes())) == result
    assert result.real_cve_verification == "NOT_VERIFIED"


def test_missing_original_inputs_still_explicitly_incomplete(tmp_path):
    source, record = generation_fixture(tmp_path)
    outputs = tmp_path / "outputs"
    ap.create_generation_run(CVE, RUN, source, record, output_root=outputs,
                              input_directory=tmp_path / "unavailable")
    manifest, _ = ap.read_review_run(CVE, RUN, output_root=outputs)
    assert next(x for x in manifest.categories if x.category == "input").status == "MISSING"
    assert any("原始输入" in x for x in manifest.missing_evidence)


@pytest.mark.parametrize("mutation", ["run", "cve", "candidate_hash", "candidate_file", "unknown_artifact", "candidate_bytes"])
def test_generation_identity_conflicts_fail_closed(tmp_path, mutation):
    source, record = generation_fixture(tmp_path)
    if mutation == "run":
        record["run_id"] = "b" * 32
    elif mutation == "cve":
        record["cve_id"] = "CVE-2025-23339"
    elif mutation == "candidate_hash":
        record["candidate"]["sha256"] = "0" * 64
    elif mutation == "candidate_file":
        record["artifacts"]["candidate"]["file"] = "../unknown.py"
    elif mutation == "unknown_artifact":
        record["artifacts"]["secret"] = {"file": "old_private.log", "sha256": "0" * 64}
    else:
        (source / "cuda_poc_v1.py").write_bytes(b"changed")
    (source / "cuda_run_v1.json").write_bytes(ap._bytes(record))
    with pytest.raises(ValueError):
        ap.create_generation_run(CVE, RUN, source, record, output_root=tmp_path / "outputs")
