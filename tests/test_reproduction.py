"""Offline reproduction evidence: parsing, verdict rules and report rendering."""

import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from src.reproduction import (
    ReproductionEvidence,
    attach_runs,
    decide,
    is_crash_exit,
    parse_log,
    parse_log_file,
    parse_step_events,
    redact_paths,
    render_report,
    write_report,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANITIZED_LOG = PROJECT_ROOT / "tests" / "fixtures" / "execution" / "cve_2025_23339_sanitized.run.log"

CRASH = 3221225477  # 0xC0000005 access violation, as recorded on Windows


def evidence(text="", **kwargs):
    return parse_log(text, **kwargs)


class TestParsing(unittest.TestCase):
    def test_real_log_yields_nine_steps_and_two_crashing_samples(self):
        result = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        self.assertEqual(len({step.step_id for step in result.steps}), 9)
        self.assertEqual({step.status for step in result.steps}, {"START", "OK"})
        self.assertEqual(len(result.runs), 2)
        self.assertTrue(all(run.label == "MALICIOUS" for run in result.runs))
        self.assertTrue(all(run.crashed for run in result.runs))

    def test_step_start_and_ok_are_kept_in_order(self):
        events = parse_step_events("[CUDA_STEP:S01] probe — START\n[CUDA_STEP:S01] probe — OK\n")
        self.assertEqual([event.status for event in events], ["START", "OK"])

    def test_failure_detail_is_captured(self):
        events = parse_step_events("[CUDA_STEP:S04] payload — FAIL: bad leb128\n")
        self.assertEqual(events[0].status, "FAIL")
        self.assertEqual(events[0].detail, "bad leb128")

    def test_control_artifacts_are_labelled_apart_from_the_benign_baseline(self):
        result = evidence("_ctrlA_zero_content.cubin -> exit=0\n"
                          "benign.cubin -> exit=0\n"
                          "malicious_41414141.cubin -> exit=3221225477 (crash)\n")
        labels = [run.label for run in result.runs]
        self.assertEqual(labels, ["CONTROL", "BENIGN", "MALICIOUS"])

    def test_control_with_benign_content_is_still_a_control(self):
        # "_ctrlD_benign_content_at_eof" must not be counted as the baseline.
        result = evidence("_ctrlD_benign_content_at_eof.cubin -> exit=0\n"
                          "benign.cubin -> exit=0\n")
        self.assertEqual([run.label for run in result.runs], ["CONTROL", "BENIGN"])

    def test_size_restored_malicious_variant_stays_malicious(self):
        # It carries the payload; "ctrl" in the name only names the experiment.
        result = evidence("_ctrl_size_restored_malicious_41414141.cubin -> exit=139\n")
        self.assertEqual(result.runs[0].label, "MALICIOUS")
        self.assertTrue(result.runs[0].crashed)

    def test_crash_exit_codes_are_recognised_by_fault_not_by_nonzero(self):
        self.assertTrue(is_crash_exit(CRASH))
        self.assertTrue(is_crash_exit(139))
        self.assertFalse(is_crash_exit(0))
        self.assertFalse(is_crash_exit(1))
        self.assertFalse(is_crash_exit(2))

    def test_negative_signal_codes_are_recognised(self):
        # subprocess reports a segfault as -11, not as 139.
        self.assertTrue(is_crash_exit(-11))
        self.assertTrue(is_crash_exit(-6))
        self.assertFalse(is_crash_exit(-1))
        self.assertFalse(is_crash_exit(-9))

    def test_absolute_paths_are_redacted(self):
        text = r"wrote C:\Users\alice\out\x.cubin and /home/bob/out/y.cubin"
        redacted = redact_paths(text)
        self.assertNotIn("alice", redacted)
        self.assertNotIn("bob", redacted)
        self.assertEqual(redacted.count("<path>"), 2)

    def test_log_digest_is_bound_to_the_file_bytes(self):
        result = parse_log_file(str(SANITIZED_LOG))
        import hashlib
        self.assertEqual(result.source_log_sha256,
                         hashlib.sha256(SANITIZED_LOG.read_bytes()).hexdigest())

    def test_crlf_logs_parse_identically_to_lf(self):
        # Real Windows runs write CRLF; a trailing CR must not hide a step.
        text = SANITIZED_LOG.read_text(encoding="utf-8")
        crlf = text.replace("\n", "\r\n")
        self.assertEqual(parse_step_events(crlf), parse_step_events(text))
        self.assertEqual(len({step.step_id for step in parse_step_events(crlf)}), 9)

    def test_empty_log_parses_to_empty_evidence(self):
        result = evidence("")
        self.assertEqual(result.steps, [])
        self.assertEqual(result.runs, [])


class TestVerdictRules(unittest.TestCase):
    def test_real_log_alone_is_unknown_without_controls(self):
        # The historical log never recorded the control runs, so the evidence
        # cannot exclude "this tool crashes on any input".
        result = decide(parse_log_file(str(SANITIZED_LOG), target_version_in_range=True))
        self.assertEqual(result.verdict, "UNKNOWN")
        self.assertIn("缺少良性基线", result.reasons[0])

    def test_crash_with_clean_baseline_is_supported(self):
        base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        with_controls = attach_runs(base, [
            {"artifact": "benign.cubin", "exit_code": 0},
            {"artifact": "_ctrlA_zero_content.cubin", "exit_code": 0},
        ])
        result = decide(with_controls)
        self.assertEqual(result.verdict, "SUPPORTED")
        self.assertEqual(result.benign_runs, 1)
        self.assertEqual(result.benign_crashes, 0)
        self.assertEqual(result.control_runs, 1)
        self.assertTrue(any("未采集寄存器" in reason for reason in result.reasons))

    def test_any_crashing_control_blocks_support(self):
        # One control crashing among several already shows the crash is not tied
        # to the controlled variable. Counting it as support would claim a
        # trigger the run did not isolate, so it is refused instead of noted.
        base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        with_controls = attach_runs(base, [
            {"artifact": "benign.cubin", "exit_code": 0},
            {"artifact": "_ctrlA_zero_content.cubin", "exit_code": 0},
            {"artifact": "_ctrlC_size_shrunk.cubin", "exit_code": CRASH},
        ])
        result = decide(with_controls)
        self.assertNotEqual(result.verdict, "SUPPORTED")
        self.assertEqual(result.control_crashes, 1)
        self.assertTrue(any("机制对照" in reason for reason in result.reasons))

    def test_all_controls_crashing_refutes_the_claimed_trigger(self):
        base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        attached = attach_runs(base, [
            {"artifact": "benign.cubin", "exit_code": 0},
            {"artifact": "poc_shsize_12.cubin", "exit_code": CRASH, "label": "CONTROL"},
            {"artifact": "poc_shsize_24.cubin", "exit_code": CRASH, "label": "CONTROL"},
        ])
        result = decide(attached)
        self.assertEqual(result.verdict, "UNKNOWN")
        self.assertIn("同样崩溃", result.reasons[0])

    def test_benign_baseline_that_also_crashes_removes_discriminating_power(self):
        base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        with_controls = attach_runs(base, [{"artifact": "benign.cubin", "exit_code": CRASH}])
        result = decide(with_controls)
        self.assertEqual(result.verdict, "UNKNOWN")
        self.assertIn("不具区分力", result.reasons[0])

    def test_control_only_without_a_baseline_stays_unknown(self):
        base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        attached = attach_runs(base, [{"artifact": "_ctrlA_zero_content.cubin", "exit_code": 0}])
        result = decide(attached)
        self.assertEqual(result.verdict, "UNKNOWN")
        self.assertIn("缺少良性基线", result.reasons[0])

    def test_out_of_range_target_is_not_a_failed_reproduction(self):
        result = decide(parse_log_file(str(SANITIZED_LOG), target_version_in_range=False))
        self.assertEqual(result.verdict, "NOT_VERIFIED")
        self.assertIn("环境前提不满足", result.reasons[0])

    def test_no_crash_is_not_reproduced(self):
        result = decide(evidence("malicious_a.cubin -> exit=0\n"
                                 "benign.cubin -> exit=0\n", target_version_in_range=True))
        self.assertEqual(result.verdict, "NOT_VERIFIED")

    def test_failed_step_is_named_when_nothing_crashed(self):
        text = ("[CUDA_STEP:S04] payload — FAIL\n"
                "malicious_a.cubin -> exit=1\n")
        result = decide(evidence(text, target_version_in_range=True))
        self.assertEqual(result.verdict, "NOT_VERIFIED")
        self.assertEqual(result.failed_steps, ["S04"])
        self.assertIn("S04", result.reasons[0])

    def test_empty_evidence_is_unknown(self):
        self.assertEqual(decide(evidence("")).verdict, "UNKNOWN")

    def test_unknown_label_never_counts_as_a_controlled_sample(self):
        result = decide(evidence("sample.cubin -> exit=3221225477 (crash)\n"))
        self.assertEqual(result.verdict, "UNKNOWN")
        self.assertEqual(result.malicious_runs, 0)


class TestExternalRuns(unittest.TestCase):
    def test_attach_rejects_non_integer_exit_codes(self):
        base = evidence("")
        with self.assertRaises(ValueError):
            attach_runs(base, [{"artifact": "benign.cubin", "exit_code": "0"}])

    def test_attach_rejects_missing_fields(self):
        base = evidence("")
        with self.assertRaises(ValueError):
            attach_runs(base, [{"artifact": "benign.cubin"}])

    def test_caller_cannot_relabel_a_benign_file_as_malicious(self):
        base = evidence("")
        with self.assertRaises(ValueError):
            attach_runs(base, [{"artifact": "benign.cubin", "exit_code": 0, "label": "MALICIOUS"}])

    def test_explicit_label_is_allowed_only_for_an_unrecognisable_name(self):
        attached = attach_runs(evidence(""), [
            {"artifact": "poc_shsize_12.cubin", "exit_code": 139, "label": "CONTROL"}])
        self.assertEqual(attached.runs[0].label, "CONTROL")

    def test_explicit_label_must_be_a_known_role(self):
        with self.assertRaises(ValueError):
            attach_runs(evidence(""), [
                {"artifact": "poc_shsize_12.cubin", "exit_code": 0, "label": "WHATEVER"}])


class TestReport(unittest.TestCase):
    def test_report_states_the_boundary_and_contains_no_absolute_path(self):
        parsed = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        result = decide(parsed)
        report = render_report(parsed, result)
        self.assertIn("判定：`UNKNOWN`", report)
        self.assertIn("不等同于", report)
        self.assertIn("原始日志 SHA-256", report)
        self.assertNotIn("F:\\", report)
        self.assertNotIn("/home/", report)

    def test_report_is_deterministic(self):
        parsed = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        result = decide(parsed)
        self.assertEqual(render_report(parsed, result), render_report(parsed, result))

    def test_write_report_emits_three_files(self):
        parsed = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
        result = decide(parsed)
        with tempfile.TemporaryDirectory() as directory:
            path = write_report(directory, parsed, result)
            files = sorted(p.name for p in Path(directory).iterdir())
            self.assertEqual(files, ["report.zh-CN.md", "reproduction_evidence.json",
                                     "reproduction_result.json"])
            self.assertEqual(path.name, "report.zh-CN.md")
            payload = json.loads((Path(directory) / "reproduction_result.json").read_text())
            self.assertEqual(payload["verdict"], "UNKNOWN")


class TestEvidenceModel(unittest.TestCase):
    def test_evidence_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            ReproductionEvidence.model_validate({
                "source_log_sha256": "0" * 64, "steps": [], "runs": [], "extra": 1,
            })

    def test_evidence_requires_a_real_digest(self):
        with self.assertRaises(ValidationError):
            ReproductionEvidence.model_validate({
                "source_log_sha256": "not-a-digest", "steps": [], "runs": [],
            })


if __name__ == "__main__":
    unittest.main()


def test_a_crashing_control_blocks_support_even_when_not_all_of_them_crash():
    """One crashing control already breaks the one-variable isolation."""
    base = parse_log_file(str(SANITIZED_LOG), target_version_in_range=True)
    attached = attach_runs(base, [
        {"artifact": "benign.cubin", "exit_code": 0},
        {"artifact": "_ctrlA_zero_content.cubin", "exit_code": CRASH},
        {"artifact": "_ctrlB_inbounds.cubin", "exit_code": 0},
        {"artifact": "_ctrlC_size_shrunk.cubin", "exit_code": 0},
    ])
    result = decide(attached)
    assert result.verdict != "SUPPORTED"
    assert any("机制对照" in reason for reason in result.reasons)
