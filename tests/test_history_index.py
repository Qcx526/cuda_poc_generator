# -*- coding: utf-8 -*-
"""History retrieval: read-only, evidence-based, deterministic.

The failure this guards against: a prompt that merely mentions ``hDevice=0x...``
was treated as a successful run, and a run that returned STATUS_INVALID_PARAMETER
from the escape was read as "reached the vendor dispatcher".
"""

import json
from pathlib import Path

from src import history_index


def _log(directory: Path, calls, handles="", state="API_REJECTED", source="poc.py"):
    directory.mkdir(parents=True, exist_ok=True)
    payload = {"state": state, "reason": "r", "next_move": "n",
               "detail": {"result": {"stage": "escape", "status": calls[0]["status"],
                                     "calls": calls}}}
    text = ("[CPG_PROBE] cve outcome=%s\nCPG_DRIVER %s\n%s\n"
            % (state, json.dumps(payload, ensure_ascii=False), handles))
    (directory / "run.log").write_text(text, encoding="utf-8")
    (directory / source).write_text("import ctypes\n", encoding="utf-8")
    return directory


def test_history_is_found_outside_the_current_workdir(tmp_path):
    other = tmp_path / "elsewhere"
    _log(other, [{"api": "D3DKMTCreateDevice", "status": 0}], "hAdapter=0x40000040 hDevice=0x40000080")
    assert history_index.scan([other])


def test_a_setup_path_run_is_classified_as_setup(tmp_path):
    run = _log(tmp_path / "r", [{"api": "D3DKMTCreateDevice", "status": 0}],
               "hAdapter=0x40 hDevice=0x80")
    experiment = history_index.scan([run.parent])[0]
    assert experiment.classification == history_index.SETUP_PATH_SUCCESS
    assert experiment.evidence_level == history_index.EXECUTION_RECORD


def test_invalid_parameter_is_never_a_trigger(tmp_path):
    """The escape was refused; that is not a trigger and not a dispatcher proof."""
    run = _log(tmp_path / "r", [
        {"api": "D3DKMTCreateDevice", "status": 0},
        {"api": "D3DKMTEscape", "status": -1073741811}])
    experiment = history_index.scan([run.parent])[0]
    assert experiment.classification != history_index.VULNERABILITY_TRIGGERED
    # The call happened; nothing proves the handler behind it ran.
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_a_prompt_mention_is_not_evidence(tmp_path):
    """Files that only talk about hDevice must not create an experiment."""
    directory = tmp_path / "prompt_only"
    directory.mkdir(parents=True)
    (directory / "analyst_prompt_round3.txt").write_text(
        "上一轮 hDevice=0x40000080 hContext=0x400000c0 成功", encoding="utf-8")
    assert history_index.scan([tmp_path]) == []


def test_missing_environment_stays_unknown(tmp_path):
    run = _log(tmp_path / "r", [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    experiment = history_index.scan([run.parent])[0]
    assert experiment.gpu == history_index.UNKNOWN
    assert experiment.driver_version == history_index.UNKNOWN
    assert experiment.os_version == history_index.UNKNOWN


def test_an_empty_tree_returns_nothing(tmp_path):
    assert history_index.scan([tmp_path / "absent"]) == []


def test_ids_are_deterministic_regardless_of_scan_order(tmp_path):
    one = _log(tmp_path / "a", [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    two = _log(tmp_path / "b", [{"api": "D3DKMTOpenAdapterFromHdc", "status": 0}], "hAdapter=0x40")
    forward = {item.experiment_id for item in history_index.scan([tmp_path])}
    backward = {item.experiment_id for item in history_index.scan([tmp_path])}
    assert forward == backward
    assert len(forward) == 2
    assert one and two


def test_relevant_experiments_rank_first(tmp_path):
    mine = _log(tmp_path / "CVE-2026-47571" / "r1",
                [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    other = _log(tmp_path / "CVE-2020-0001" / "r1",
                 [{"api": "DeviceIoControl", "status": -1}])
    experiments = history_index.scan([tmp_path])
    chosen = history_index.select(experiments, cve="CVE-2026-47571", limit=2)
    assert chosen[0].cve_id == "CVE-2026-47571"
    assert mine and other


def test_git_style_archive_participates_in_the_index(tmp_path):
    """Any directory works as a root, including a checked-out archive."""
    archive = tmp_path / "archive" / "2026-10-30"
    _log(archive, [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    assert history_index.scan([tmp_path / "archive"])


def test_scanning_does_not_modify_artifacts(tmp_path):
    run = _log(tmp_path / "r", [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    log = run / "run.log"
    before = (log.read_bytes(), log.stat().st_mtime_ns)
    history_index.scan([tmp_path])
    after = (log.read_bytes(), log.stat().st_mtime_ns)
    assert before == after


def test_rendering_includes_the_evidence_and_not_just_a_verdict(tmp_path):
    run = _log(tmp_path / "r", [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    text = history_index.render(history_index.scan([run.parent]))
    assert "SETUP_PATH_SUCCESS" in text
    assert "EXECUTION_RECORD" in text
    assert "调用序列" in text


def test_render_without_history_says_so():
    assert "没有可用" in history_index.render([])


def test_reuse_line_is_parsed_from_the_generated_code():
    from src.driver_generator import parse_reuse

    code = ("# REUSE: experiment=abc123 unchanged=OpenAdapterFromLuid changed=CreateDevice why=历史成功\n"
            "# CHANGE: api=x from=a to=b why=c\nprint(1)\n")
    plan = parse_reuse(code)
    assert plan["experiment"] == "abc123"
    assert plan["unchanged"] == "OpenAdapterFromLuid"
    assert plan["changed"] == "CreateDevice"


def test_an_escape_call_alone_is_only_observed(tmp_path):
    run = _log(tmp_path / "r", [{"api": "D3DKMTEscape", "status": -1073741811}])
    experiment = history_index.scan([run.parent])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED
    assert experiment.classification != history_index.DRIVER_INTERFACE_REACHED


def test_a_probe_hit_string_in_the_log_is_not_a_hit(tmp_path):
    """The candidate prints to the same file; text cannot promote a run."""
    directory = tmp_path / "r"
    _log(directory, [{"api": "D3DKMTEscape", "status": -1073741811}],
         "PROBE_HIT nvlddmkm+0x1406912f0")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_a_trusted_sidecar_record_upgrades_the_classification(tmp_path):
    """Evidence lives in a sidecar written by the pipeline, not in the log."""
    directory = tmp_path / "r"
    _log(directory, [{"api": "D3DKMTEscape", "status": -1073741811}])
    (directory / "external_evidence.json").write_text(json.dumps({
        "written_by": "driver_exec",
        "records": [{"producer": "cdb_trace", "hit": True, "where": "nvlddmkm+0x1"}]}),
        encoding="utf-8")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.DRIVER_INTERFACE_REACHED


def test_a_sidecar_from_an_untrusted_producer_is_ignored(tmp_path):
    directory = tmp_path / "r"
    _log(directory, [{"api": "D3DKMTEscape", "status": -1073741811}])
    (directory / "external_evidence.json").write_text(json.dumps({
        "written_by": "driver_exec",
        "records": [{"producer": "poc.py", "hit": True}]}), encoding="utf-8")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_a_sidecar_not_written_by_the_pipeline_is_ignored(tmp_path):
    directory = tmp_path / "r"
    _log(directory, [{"api": "D3DKMTEscape", "status": -1073741811}])
    (directory / "external_evidence.json").write_text(json.dumps({
        "written_by": "candidate", "records": [{"producer": "cdb_trace", "hit": True}]}),
        encoding="utf-8")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_a_candidate_printing_cpg_external_does_not_upgrade(tmp_path):
    """The log contains the candidate's stdout, so a line in it proves nothing."""
    directory = tmp_path / "r"
    _log(directory, [{"api": "D3DKMTEscape", "status": -1073741811}])
    (directory / "run.log").write_text(
        (directory / "run.log").read_text(encoding="utf-8")
        + 'CPG_EXTERNAL [{"producer": "cdb_trace", "hit": true}]\n', encoding="utf-8")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_evidence_inside_the_candidate_payload_is_ignored(tmp_path):
    """CPG_RESULT.evidence is the candidate speaking about itself."""
    directory = tmp_path / "r"
    directory.mkdir(parents=True)
    payload = {"state": "API_REJECTED", "detail": {"result": {
        "calls": [{"api": "D3DKMTEscape", "status": -1073741790}],
        "evidence": {"probe": "dxgkrnl!DxgkDdiEscape"}}}}
    (directory / "run.log").write_text("CPG_DRIVER " + json.dumps(payload),
                                       encoding="utf-8")
    experiment = history_index.scan([tmp_path])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_a_status_code_is_not_evidence(tmp_path):
    """A zero status is still just a return value, not proof of entry."""
    run = _log(tmp_path / "r", [{"api": "D3DKMTEscape", "status": 0}])
    experiment = history_index.scan([run.parent])[0]
    assert experiment.classification == history_index.D3DKMT_ESCAPE_CALL_OBSERVED


def test_an_archived_copy_keeps_its_identity_and_cve(tmp_path):
    """An archive named after the experiment id must still resolve its CVE."""
    run = _log(tmp_path / "CVE-2026-9999" / "round1",
               [{"api": "D3DKMTCreateDevice", "status": 0}], "hDevice=0x80")
    original = history_index.scan([tmp_path])[0]

    archive = tmp_path / "archive" / original.experiment_id
    archive.mkdir(parents=True)
    for name in ("run.log", "poc.py"):
        (archive / name).write_bytes((run / name).read_bytes())
    (archive / "experiment.json").write_text(
        json.dumps({"experiment_id": original.experiment_id, "cve_id": "CVE-2026-9999"}),
        encoding="utf-8")

    rebuilt = history_index.scan([tmp_path / "archive"])[0]
    assert rebuilt.experiment_id == original.experiment_id
    assert rebuilt.cve_id == original.cve_id
    assert rebuilt.classification == original.classification
