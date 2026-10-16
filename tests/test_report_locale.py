"""Chinese presentation never mutates scientific records, raw evidence or verdicts."""

import hashlib
from html import unescape
import json
from pathlib import Path
import subprocess
import sys

import pytest

from src.models.lifecycle import canonical_sha256
from src.oracle import evaluate_oracle
from src.oracle_catalog import ROOT, load_reviewed_claim
from src.oracle_report import save_oracle_report, rebuild_oracle_report
from src.report_locale import (write_report_view,rebuild_report_view,save_localized_oracle_report,
    render_claim_zh,render_oracle_zh,reason_zh,ReportViewManifest,_json)
from tests.test_oracle import synthetic_case


def test_chinese_oracle_determinism_does_not_rewrite_english_archive_or_scientific_hash(tmp_path):
    plan,corpus=synthetic_case()
    result=evaluate_oracle(plan,corpus,trusted_plan_sha256=canonical_sha256(plan))
    source=save_oracle_report(tmp_path/"v1",plan,result)
    before={p.name:p.read_bytes() for p in source.iterdir()}
    plan_hash,result_hash=canonical_sha256(plan),canonical_sha256(result)
    folder=save_localized_oracle_report(tmp_path/"zh",plan,result)
    text=(folder/"report.zh-CN.md").read_bytes()
    assert text.decode("utf-8").startswith("# 目标 CVE 客观条件审查报告")
    assert "合成" in text.decode() and "SYNTHETIC" in text.decode()
    assert "真实漏洞结论：NOT_VERIFIED" in text.decode()
    assert rebuild_report_view(folder).encode()==text
    assert before=={p.name:p.read_bytes() for p in source.iterdir()}
    assert rebuild_oracle_report(source).encode()==before["report.md"]
    assert (canonical_sha256(plan),canonical_sha256(result))==(plan_hash,result_hash)
    manifest=ReportViewManifest.model_validate_json((folder/"report_view_manifest.json").read_bytes())
    assert manifest.report_locale=="zh-CN"
    assert manifest.source_domain=="SYNTHETIC"
    assert (folder/"sources/result.json").read_bytes()==_json(result)


@pytest.mark.parametrize("cve",["CVE-2022-21821","CVE-2023-0196","CVE-2024-0076","CVE-2024-0124","CVE-2025-23308","CVE-2025-23339"])
def test_reviewed_claim_chinese_view_and_raw_bytes(tmp_path,cve):
    claim=load_reviewed_claim(cve)
    raw=_json(claim)
    folder=write_report_view(tmp_path/cve,"CLAIM",{"claim.json":raw})
    assert "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。" in rebuild_report_view(folder)
    assert (folder/"sources/claim.json").read_bytes()==raw


def test_cve_number_alone_cannot_select_authoritative_translation():
    claim=load_reviewed_claim("CVE-2025-23308")
    altered=claim.model_copy(update={"affected_version_ranges":["SYNTHETIC_UNREVIEWED_RANGE"]})
    text=unescape(render_claim_zh(altered))
    assert "SYNTHETIC_UNREVIEWED_RANGE" in text
    assert "不匹配已审查翻译档案" in text
    assert "早于 13.0" not in text


@pytest.mark.parametrize("reason",["required evidence reference is missing","tool identity conflict",
    "objective verification method is not implemented","evidence capture/integrity/cleanup is not complete",
    "CVE or evidence domain conflict","contradictory necessary predicates for the same subject"])
def test_unknown_failed_explanations_are_chinese(reason):
    explanation=reason_zh(reason)
    assert any("\u4e00"<=c<="\u9fff" for c in explanation)


@pytest.mark.parametrize("name",["../claim.json","C:claim.json","sources\\claim.json","extra.json","CLAIM.json"])
def test_report_path_and_unknown_source_rejected(tmp_path,name):
    with pytest.raises((ValueError,KeyError)):
        write_report_view(tmp_path/"bad","CLAIM",{name:_json(load_reviewed_claim("CVE-2025-23308"))})
    assert not (tmp_path/"bad").exists()


@pytest.mark.parametrize("target",["report.zh-CN.md","sources/claim.json","report_view_manifest.json"])
def test_report_or_source_corruption_fails_rebuild(tmp_path,target):
    folder=write_report_view(tmp_path/"view","CLAIM",{"claim.json":_json(load_reviewed_claim("CVE-2025-23308"))})
    (folder/target).write_bytes(b"corrupted")
    with pytest.raises(ValueError): rebuild_report_view(folder)


def test_same_view_refuses_overwrite_and_extra_files(tmp_path):
    sources={"failure.json":b'{"status":"UNKNOWN","error_type":"DISK_FAILURE"}'}
    folder=write_report_view(tmp_path/"same","FAILURE",sources)
    with pytest.raises(FileExistsError): write_report_view(folder,"FAILURE",sources)
    (folder/"extra.md").write_text("fake")
    with pytest.raises(ValueError): rebuild_report_view(folder)


def test_unsupported_locale_is_not_implicit_translation(tmp_path):
    with pytest.raises(ValueError):
        write_report_view(tmp_path/"en","FAILURE",{"failure.json":b'{}'},report_locale="en-US")


@pytest.mark.parametrize("code",["INPUT_INVALID","GENERATION_FAILED","PROVIDER_ERROR","ANALYSIS_SCHEMA_ERROR"])
def test_failed_generation_report_is_chinese_unexecuted(tmp_path,code):
    record={"run_id":"a"*32,"cve_id":"CVE-2025-23308","status":code,"execution":"NOT_EXECUTED",
            "verification":"NOT_VERIFIED","candidate":{"run_id":"a"*32},"artifacts":{}}
    folder=write_report_view(tmp_path/code,"GENERATION",{"generation.json":_json(record)})
    text=unescape(rebuild_report_view(folder))
    assert "PoC 单次生成与分析报告" in text and code in text and "NOT_EXECUTED" in text


def test_unsafe_report_strings_are_escaped_and_do_not_set_verdict(tmp_path):
    claim=load_reviewed_claim("CVE-2025-23308").model_copy(update={"affected_component":"<script>VERIFIED</script>\u202e"})
    text=render_claim_zh(claim)
    assert "<script>" not in text and "\u202e" not in text
    assert "真实 CVE 验证" in text and "NOT_VERIFIED" in text


def test_chinese_report_cli_import_pin_and_rebuild(tmp_path):
    source=tmp_path/"claim.json"
    raw=_json(load_reviewed_claim("CVE-2025-23308"))
    source.write_bytes(raw)
    folder=tmp_path/"view"
    run=subprocess.run([sys.executable,"-m","src.report_cli","render","--kind","claim","--source",str(source),
        "--source-sha256",hashlib.sha256(raw).hexdigest(),"--output-dir",str(folder)],cwd=ROOT,capture_output=True,timeout=20)
    assert run.returncode==0,run.stderr
    assert json.loads(run.stdout)["report_locale"]=="zh-CN"
    rebuild=subprocess.run([sys.executable,"-m","src.report_cli","rebuild","--report-dir",str(folder)],
                           cwd=ROOT,capture_output=True,timeout=20)
    assert rebuild.returncode==0 and rebuild.stdout.decode()==rebuild_report_view(folder)


def test_chinese_oracle_cli_keeps_legacy_bundle_and_separate_default_view(tmp_path):
    case=ROOT/"docs/examples/p3_a/synthetic_positive_input.json"
    pin=json.loads((ROOT/"docs/examples/p3_a/synthetic_positive_output.json").read_bytes())["plan_sha256"]
    folder=tmp_path/"oracle"
    proc=subprocess.run([sys.executable,"-m","src.oracle_cli","synthetic","--case",str(case),
        "--trusted-plan-sha256",pin,"--report-dir",str(folder)],cwd=ROOT,capture_output=True,timeout=20)
    assert proc.returncode==0,proc.stderr
    assert "Deterministic" in rebuild_oracle_report(folder)
    assert "目标 CVE" in rebuild_report_view(str(folder)+".zh-CN")


def test_frozen_execution_source_has_detailed_chinese_view_without_raw_byte_changes(request):
    # Frozen P2-C uses native Windows MAX_PATH semantics; use a short temporary
    # root, as its original regression fixtures do, without changing OS policy.
    import tempfile
    managed=tempfile.TemporaryDirectory(prefix="p3b-")
    request.addfinalizer(managed.cleanup)
    tmp_path=Path(managed.name)
    from tests.test_cuda_evidence import synthetic_cuda_evidence
    from src.lifecycle_artifacts import write_execution_evidence, rebuild_execution_report
    from src.report_locale import write_execution_view_from_archive
    native=tmp_path/"native"
    native.mkdir()
    result,context=synthetic_cuda_evidence(native)
    folder=write_execution_evidence(tmp_path/"archive",result,**context)
    before={p.name:p.read_bytes() for p in folder.iterdir()}
    view=write_execution_view_from_archive(folder,source_domain="SYNTHETIC")
    text=unescape(rebuild_report_view(view))
    assert "原始退出码" in text and "Linux signal" in text and "实际实施的资源界限" in text
    assert "SYNTHETIC：合成规则/诊断测试" in text
    for step in ("nvcc_version","cuobjdump_version","nvdisasm_version","compile","cuobjdump","nvdisasm"):
        assert step in text
    assert before=={p.name:p.read_bytes() for p in folder.iterdir()}
    assert rebuild_execution_report(folder).encode()==before["report.md"]


def test_same_cve_multiple_generation_rounds_are_archived_by_existing_pipeline(tmp_path):
    from tests.test_baseline import OfflineTestCase
    # Reuse the real existing Mock generation test harness, never a provider.
    case=OfflineTestCase()
    case.setUp()
    try:
        pipeline=case.pipeline_module.CudaPipeline()
        pipeline.llm=case.fake_llm()
        pipeline.data_loader.rag_enabled=False
        from unittest.mock import patch
        with patch.object(case.pipeline_module,"probe_environment",return_value={"schema_version":"legacy"}), \
             patch.object(case.pipeline_module.CudaPipeline,"_query_web_search",return_value=""):
            first=pipeline.run(input_dir=str(ROOT/"data/inputs/CVE-2024-0124"),output_dir=str(tmp_path),archive_artifacts=True)
            second=pipeline.run(input_dir=str(ROOT/"data/inputs/CVE-2024-0124"),output_dir=str(tmp_path),archive_artifacts=True)
        assert first["run_id"]!=second["run_id"]
        for record in (first,second):
            folder=tmp_path/"CVE-2024-0124"/"runs"/record["run_id"]
            assert (folder/"reports/generation.zh-CN.md").is_file()
            assert (folder/"poc/cuda_poc_v1.py").read_bytes()
    finally:
        case.doCleanups()


def test_main_enables_formal_archives_without_changing_legacy_run_call_arguments(tmp_path):
    import main
    from unittest.mock import patch
    with patch.object(sys,"argv",["main.py","--input-dir",str(tmp_path),"--output-dir",str(tmp_path/"out")]), \
         patch.object(main,"setup_logging"),patch("src.pipeline.CudaPipeline") as factory:
        main.main()
    assert factory.return_value.archive_artifacts is True
    factory.return_value.run.assert_called_once_with(input_dir=str(tmp_path),output_dir=str(tmp_path/"out"))
