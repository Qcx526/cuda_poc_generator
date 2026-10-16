"""Offline Mock generation-to-ZIP tests. No provider/candidate is executed."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from src.artifact_packaging import read_review_run, verify_package
from src.generation_delivery import (GenerationDelivery, deliver_generation,
    rebuild_delivery_report, render_delivery_report)
from tests.test_baseline import OfflineTestCase

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def offline_pipeline():
    case = OfflineTestCase()
    case.setUp()
    pipeline = case.pipeline_module.CudaPipeline()
    pipeline.llm = case.fake_llm()
    pipeline.data_loader.rag_enabled = False
    with patch.object(case.pipeline_module, "probe_environment", return_value={"schema_version": "legacy"}), \
         patch.object(case.pipeline_module.CudaPipeline, "_query_web_search", return_value=""):
        yield pipeline
    case.doCleanups()


def run(pipeline, root, cve="CVE-2024-0124", **kwargs):
    return pipeline.run(input_dir=str(ROOT / "data/inputs" / cve), output_dir=str(root), **kwargs)


def test_generation_to_zip_with_external_digest_and_unchanged_v1(offline_pipeline, tmp_path):
    pipeline = offline_pipeline
    result = run(pipeline, tmp_path, package_artifacts=True)
    receipt = pipeline.last_delivery
    assert result["status"] == "COMPLETE" and "delivery" not in result
    assert receipt["package_status"] == "INTEGRITY_VERIFIED"
    source = tmp_path / result["cve_id"]
    assert json.loads((source / "cuda_run_v1.json").read_bytes()) == result
    assert receipt["run_id"] == result["run_id"]
    verified = verify_package(receipt["package_path"], expected_sha256=receipt["package_sha256"])
    assert verified.run_id == result["run_id"] and verified.candidate_execution_status == "NOT_EXECUTED"
    manifest, content = read_review_run(result["cve_id"], result["run_id"], output_root=tmp_path)
    assert content["poc/cuda_poc_v1.py"] == (source / "cuda_poc_v1.py").read_bytes()
    assert manifest.real_cve_verification == "NOT_VERIFIED"
    directory = source / "delivery_attempts" / result["run_id"]
    assert rebuild_delivery_report(directory).encode("utf-8") == (directory / "report.zh-CN.md").read_bytes()
    assert "本轮未执行生成的 PoC" in rebuild_delivery_report(directory)


def test_default_python_api_keeps_exactly_six_v1_files(offline_pipeline, tmp_path):
    result = run(offline_pipeline, tmp_path)
    assert offline_pipeline.last_delivery is None
    assert len(list((tmp_path / result["cve_id"]).iterdir())) == 6


def test_two_runs_preserve_earlier_zip_and_receipt(offline_pipeline, tmp_path):
    first = run(offline_pipeline, tmp_path, package_artifacts=True)
    receipt = deepcopy(offline_pipeline.last_delivery)
    raw = Path(receipt["package_path"]).read_bytes()
    second = run(offline_pipeline, tmp_path, package_artifacts=True)
    assert first["run_id"] != second["run_id"]
    assert Path(receipt["package_path"]).read_bytes() == raw
    assert hashlib.sha256(raw).hexdigest() == receipt["package_sha256"]


@pytest.mark.parametrize("field,value", [("package_artifacts", 1), ("package_artifacts", "true"), ("archive_artifacts", 1)])
def test_invalid_options_clear_previous_receipt(offline_pipeline, tmp_path, field, value):
    offline_pipeline.last_delivery = {"package_path": "old.zip"}
    with pytest.raises(ValueError):
        run(offline_pipeline, tmp_path, **{field: value})
    assert offline_pipeline.last_delivery is None


@pytest.mark.parametrize("failed_function", ["create_generation_run", "package_run"])
def test_archive_and_zip_failure_do_not_reuse_previous_success(offline_pipeline, tmp_path, failed_function):
    run(offline_pipeline, tmp_path, package_artifacts=True)
    old = deepcopy(offline_pipeline.last_delivery)
    with patch("src.generation_delivery." + failed_function, side_effect=OSError("disk test")):
        with pytest.raises(RuntimeError, match="交付不完整"):
            run(offline_pipeline, tmp_path, package_artifacts=True)
    current = offline_pipeline.last_delivery
    assert current["run_id"] != old["run_id"]
    assert current["package_status"] in {"FAILED", "NOT_PACKAGED"}
    assert current["package_path"] is None and current["package_sha256"] is None
    assert Path(old["package_path"]).is_file()
    assert current["real_cve_verification"] == "NOT_VERIFIED"


def test_receipt_disk_failure_is_not_success(offline_pipeline, tmp_path):
    with patch("src.generation_delivery.save_delivery_receipt", side_effect=OSError("disk test")):
        with pytest.raises(RuntimeError, match="交付不完整"):
            run(offline_pipeline, tmp_path, package_artifacts=True)
    assert offline_pipeline.last_delivery["package_status"] == "FAILED"
    assert offline_pipeline.last_delivery["package_sha256"] is None


def test_model_failure_archives_only_current_partial_artifacts(offline_pipeline, tmp_path):
    run(offline_pipeline, tmp_path, package_artifacts=True)
    old = deepcopy(offline_pipeline.last_delivery)
    offline_pipeline.llm.structured_generate.side_effect = RuntimeError("Mock provider failed")
    with pytest.raises(RuntimeError, match="Mock provider failed"):
        run(offline_pipeline, tmp_path, package_artifacts=True)
    delivery = offline_pipeline.last_delivery
    assert delivery["run_id"] != old["run_id"]
    assert delivery["package_status"] == "NOT_PACKAGED"
    assert delivery["package_path"] is None
    _, content = read_review_run(delivery["cve_id"], delivery["run_id"], output_root=tmp_path)
    assert "poc/cuda_poc_v1.py" not in content and "analysis/cuda_analysis_v1.json" not in content


@pytest.mark.parametrize("mutation", ["candidate", "input", "analysis"])
def test_inconsistent_complete_record_cannot_be_delivered(offline_pipeline, tmp_path, mutation):
    record = run(offline_pipeline, tmp_path)
    record = deepcopy(record)
    if mutation == "candidate":
        record["candidate"].update(generation="GENERATION_FAILED", source_file=None, sha256=None)
    else:
        record[mutation + "_status"] = "INVALID"
    receipt = deliver_generation(run_record=record, source_directory=tmp_path / record["cve_id"],
        output_root=tmp_path, input_directory=ROOT / "data/inputs" / record["cve_id"], cve_id=record["cve_id"])
    assert receipt.archive_status == "FAILED" and receipt.package_path is None


@pytest.mark.parametrize("move", ["cve", "run", "directory"])
def test_receipt_cross_target_or_run_is_rejected(offline_pipeline, tmp_path, move):
    result = run(offline_pipeline, tmp_path, package_artifacts=True)
    source = tmp_path / result["cve_id"] / "delivery_attempts" / result["run_id"]
    target = tmp_path / ("CVE-2025-23308" if move == "cve" else result["cve_id"]) / (
        "unknown" if move == "directory" else "delivery_attempts") / ("e" * 32 if move == "run" else result["run_id"])
    target.mkdir(parents=True)
    for name in ("delivery.json", "report.zh-CN.md"):
        (target / name).write_bytes((source / name).read_bytes())
    with pytest.raises(ValueError, match="身份冲突"):
        rebuild_delivery_report(target)


def test_wrong_verification_run_is_rejected(offline_pipeline, tmp_path):
    import src.generation_delivery as module
    original = module.package_run
    def wrong(*args, **kwargs):
        path, verified = original(*args, **kwargs)
        return path, verified.model_copy(update={"run_id": "e" * 32})
    with patch.object(module, "package_run", side_effect=wrong), pytest.raises(RuntimeError):
        run(offline_pipeline, tmp_path, package_artifacts=True)
    assert offline_pipeline.last_delivery["package_status"] == "FAILED"
    assert offline_pipeline.last_delivery["package_path"] is None


def test_unbound_invalid_input_has_no_cve_zip(offline_pipeline, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError):
        offline_pipeline.run(input_dir=str(empty), output_dir=str(tmp_path / "out"), package_artifacts=True)
    receipt = offline_pipeline.last_delivery
    assert receipt["cve_id"] is None and receipt["package_status"] == "NOT_PACKAGED"
    directory = tmp_path / "out/unbound_generation/delivery_attempts" / receipt["run_id"]
    assert "没有生成本轮 ZIP" in rebuild_delivery_report(directory)


@pytest.mark.parametrize("field,value", [("candidate_execution_status", "EXECUTED"), ("real_cve_verification", "VERIFIED"),
    ("package_status", "INTEGRITY_VERIFIED"), ("cve_id", "../../escape")])
def test_delivery_contract_forbids_promotion(field, value):
    record = dict(run_id="a" * 32, generation_status="INPUT_INVALID", archive_status="NOT_ARCHIVED",
        package_status="NOT_PACKAGED", explanation_zh="没有完整材料。")
    record[field] = value
    with pytest.raises(ValueError):
        GenerationDelivery.model_validate(record)


def test_cli_package_is_explicit_and_keeps_original_run_kwargs(tmp_path, capsys):
    import main
    with patch.object(sys, "argv", ["main.py", "--input-dir", str(tmp_path), "--package"]), \
         patch.object(main, "setup_logging"), patch("src.pipeline.CudaPipeline") as factory:
        factory.return_value.last_delivery = {"package_status": "INTEGRITY_VERIFIED", "package_path": "current.zip", "package_sha256": "a" * 64}
        main.main()
        assert factory.return_value.package_artifacts is True
        factory.return_value.run.assert_called_once_with(input_dir=str(tmp_path), output_dir=None)
    output = capsys.readouterr().out
    assert "current.zip" in output and "包外 SHA-256" in output and "NOT_VERIFIED" in output


def test_cli_failed_package_has_nonzero_exit(tmp_path):
    import main
    with patch.object(sys, "argv", ["main.py", "--input-dir", str(tmp_path), "--package"]), \
         patch.object(main, "setup_logging"), patch("src.pipeline.CudaPipeline") as factory:
        factory.return_value.last_delivery = None
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 1


def test_real_cli_path_with_mock_llm_completes_current_zip(offline_pipeline, tmp_path, capsys):
    import main
    with patch.object(sys, "argv", ["main.py", "--cve-id", "CVE-2024-0124", "--output-dir", str(tmp_path), "--package"]), \
         patch.object(main, "setup_logging"), patch("src.pipeline.CudaPipeline", return_value=offline_pipeline):
        main.main()
    output = capsys.readouterr().out
    receipt = offline_pipeline.last_delivery
    assert receipt["package_status"] == "INTEGRITY_VERIFIED"
    assert receipt["package_path"] in output and receipt["package_sha256"] in output
    assert verify_package(receipt["package_path"], expected_sha256=receipt["package_sha256"]).real_cve_verification == "NOT_VERIFIED"


def test_separate_cves_get_separate_bound_current_packages(offline_pipeline, tmp_path):
    from tests.test_baseline import ANALYSIS
    from src.llm_client import StructuredResponse
    first = run(offline_pipeline, tmp_path, package_artifacts=True)
    first_delivery = deepcopy(offline_pipeline.last_delivery)
    analysis = deepcopy(ANALYSIS)
    analysis["root_cause_analysis"]["cve_id"] = "CVE-2025-23308"
    offline_pipeline.llm.structured_generate.return_value = StructuredResponse(analysis, raw_response=json.dumps(analysis))
    second = run(offline_pipeline, tmp_path, cve="CVE-2025-23308", package_artifacts=True)
    second_delivery = offline_pipeline.last_delivery
    assert first_delivery["cve_id"] != second_delivery["cve_id"]
    assert first["run_id"] != second["run_id"]
    for receipt in (first_delivery, second_delivery):
        verified = verify_package(receipt["package_path"], expected_sha256=receipt["package_sha256"])
        assert verified.cve_id == receipt["cve_id"] and verified.run_id == receipt["run_id"]


def test_delivery_report_escapes_paths_and_rejects_changed_text(offline_pipeline, tmp_path):
    result = run(offline_pipeline, tmp_path, package_artifacts=True)
    receipt = GenerationDelivery.model_validate(offline_pipeline.last_delivery)
    assert render_delivery_report(receipt).encode("utf-8").decode("utf-8") == render_delivery_report(receipt)
    folder = tmp_path / result["cve_id"] / "delivery_attempts" / result["run_id"]
    (folder / "report.zh-CN.md").write_bytes(b"modified")
    with pytest.raises(ValueError):
        rebuild_delivery_report(folder)
