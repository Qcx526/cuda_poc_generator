# -*- coding: utf-8 -*-
"""Tests for sample discovery and the ready-to-wire loop stages."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from src.closed_loop import LoopConfig, LoopState
from src.loop_stages import (StageContext, build_docker_command, make_execute_stage,
                             make_generate_stage, make_grader, parse_candidate_path,
                             parse_runs)
from src.samples import Sample, apply_manifest, discover, summarise


class TestSampleDiscovery(unittest.TestCase):
    def test_labels_come_from_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("benign.cubin", "_ctrlA_zero.cubin", "malicious_1.cubin",
                         "poc_x.cubin", "notes.txt"):
                (root / name).write_bytes(b"\x7fELF")
            samples = discover(root)
            labels = {s.name: s.label for s in samples}
            self.assertEqual(labels["benign.cubin"], "BENIGN")
            self.assertEqual(labels["_ctrlA_zero.cubin"], "CONTROL")
            self.assertEqual(labels["malicious_1.cubin"], "MALICIOUS")
            self.assertEqual(labels["poc_x.cubin"], "UNKNOWN")
            self.assertNotIn("notes.txt", labels)

    def test_manifest_only_overrides_unrecognised_names(self):
        samples = [Sample("poc_x.bin", Path("poc_x.bin"), "UNKNOWN"),
                   Sample("benign.bin", Path("benign.bin"), "BENIGN")]
        resolved = apply_manifest(samples, {"poc_x.bin": "CONTROL"})
        self.assertEqual(resolved[0].label, "CONTROL")
        with self.assertRaises(ValueError):
            apply_manifest(samples, {"benign.bin": "MALICIOUS"})
        with self.assertRaises(ValueError):
            apply_manifest(samples, {"poc_x.bin": "WHATEVER"})

    def test_summary_counts_roles(self):
        samples = [Sample("malicious.bin", Path("m"), "MALICIOUS"),
                   Sample("poc.bin", Path("p"), "UNKNOWN")]
        self.assertEqual(summarise(samples)["MALICIOUS"], 1)
        self.assertEqual(summarise(samples)["UNKNOWN"], 1)


class TestGenerateStage(unittest.TestCase):
    def test_candidate_path_is_extracted(self):
        self.assertEqual(
            parse_candidate_path("[+] Candidate saved: F:\\x\\cuda_poc_v1.py\n"),
            "F:\\x\\cuda_poc_v1.py")
        self.assertIsNone(parse_candidate_path("nothing here"))

    def test_missing_candidate_becomes_a_stage_error(self):
        ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                           container_image="img", workdir=Path("out"))
        fake = lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "boom")
        state = make_generate_stage(ctx, fake)(LoopState(iteration=1))
        self.assertIn("no candidate", state.stage_error)
        self.assertIn("boom", state.stage_error)


class TestExecuteStage(unittest.TestCase):
    def test_command_is_hardened(self):
        ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                           container_image="cpg/cuda112-py3:1.0",
                           workdir=Path("out"))
        command = " ".join(build_docker_command(ctx, Path("C:/x/cuda_poc_v1.py")))
        for flag in ("--network none", "--cap-drop ALL", "--read-only",
                     "--pids-limit", "--memory 2g"):
            self.assertIn(flag, command)
        self.assertIn("python3 cuda_poc_v1.py", command)

    def test_mount_source_is_the_directory_not_the_file(self):
        # Mounting the .py file itself made the container see /work as a file
        # and fail with "cd: /work: Not a directory".
        ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                           container_image="img", workdir=Path("out"))
        command = build_docker_command(ctx, Path("data/x/poc.py"))
        mount = command[command.index("-v") + 1]
        self.assertTrue(mount.endswith("/x:/work:rw"), mount)
        self.assertNotIn("poc.py:", mount)

    def test_observation_is_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                               container_image="img", workdir=Path(tmp))
            fake = lambda *a, **k: subprocess.CompletedProcess(
                a[0], 0, "malicious.cubin -> exit=139\n", "")
            state = make_execute_stage(ctx, fake)(
                LoopState(iteration=2, candidate_file=str(Path(tmp) / "poc.py")))
            self.assertTrue(Path(state.observation_file).is_file())
            self.assertIn("exit=139", Path(state.observation_file).read_text())


class TestGrader(unittest.TestCase):
    def test_explicit_contract_line_is_preferred(self):
        runs = parse_runs("[CPG_RUN] malicious.cubin exit=139\n[CPG_RUN] benign.cubin exit=0\n")
        self.assertEqual([r["exit_code"] for r in runs], [139, 0])

    def test_runs_are_parsed_from_the_harness_convention(self):
        runs = parse_runs("malicious.cubin -> exit=139\nbenign.cubin -> exit=0\n")
        self.assertEqual([r["exit_code"] for r in runs], [139, 0])

    def test_declared_labels_and_negative_exit_codes_are_parsed(self):
        runs = parse_runs("[CPG_LABEL] crafted_overflow.cubin MALICIOUS\n"
                          "[CPG_RUN] crafted_overflow.cubin exit=-11\n")
        self.assertEqual(runs[0]["label"], "MALICIOUS")
        self.assertEqual(runs[0]["exit_code"], -11)

    def test_declared_label_and_name_in_agreement_yield_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "obs.txt"
            log.write_text("[CPG_LABEL] crafted_overflow.cubin MALICIOUS\n"
                           "[CPG_RUN] crafted_overflow.cubin exit=-11\n"
                           "[CPG_LABEL] crafted_benign.cubin BENIGN\n"
                           "[CPG_RUN] crafted_benign.cubin exit=0\n",
                           encoding="utf-8")
            result = make_grader(LoopConfig(cve_id="CVE-X"), version_in_range=True)(
                LoopState(iteration=1, observation_file=str(log)))
            self.assertEqual(result.verdict, "SUPPORTED")

    def test_clean_differential_yields_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "obs.txt"
            log.write_text("malicious.cubin -> exit=139\nbenign.cubin -> exit=0\n",
                           encoding="utf-8")
            config = LoopConfig(cve_id="CVE-X")
            result = make_grader(config, version_in_range=True)(
                LoopState(iteration=1, observation_file=str(log)))
            self.assertEqual(result.verdict, "SUPPORTED")

    def test_failing_step_is_reported_instead_of_a_generic_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "obs.txt"
            log.write_text("[CUDA_STEP:S02] build cubin — FAIL | lacks .debug_abbrev\n",
                           encoding="utf-8")
            result = make_grader(LoopConfig(cve_id="CVE-X"))(
                LoopState(iteration=1, observation_file=str(log)))
            self.assertEqual(result.verdict, "NOT_VERIFIED")
            self.assertIn("步骤失败", result.reasons[0])
            self.assertIn("debug_abbrev", result.reasons[0])

    def test_contradictory_label_is_graded_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "obs.txt"
            log.write_text("[CPG_LABEL] benign.cubin MALICIOUS\n"
                           "[CPG_RUN] benign.cubin exit=0\n", encoding="utf-8")
            result = make_grader(LoopConfig(cve_id="CVE-X"))(
                LoopState(iteration=1, observation_file=str(log)))
            self.assertEqual(result.verdict, "NOT_VERIFIED")
            self.assertIn("标签冲突", result.reasons[0])

    def test_no_runs_is_reported_as_unreached_rather_than_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "obs.txt"
            log.write_text("nothing happened\n", encoding="utf-8")
            config = LoopConfig(cve_id="CVE-X")
            result = make_grader(config)(LoopState(iteration=1,
                                                   observation_file=str(log)))
            self.assertEqual(result.verdict, "NOT_VERIFIED")
            self.assertIn("未到达解析器", result.reasons[0])


class TestRunnerWiring(unittest.TestCase):
    def test_controller_gets_all_stages_and_a_grader(self):
        from src.loop_runner import build_controller
        with tempfile.TemporaryDirectory() as tmp:
            controller = build_controller(
                cve_id="CVE-X", tier="userland_toolchain", iterations=1,
                image="img", workdir=Path(tmp), project_root=Path("."),
                version_in_range=True, allow_kernel=False, python_exe="python",
                runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""))
            self.assertEqual(set(controller.stages), {"generate", "execute"})
            self.assertIsNone(controller.preflight())

    def test_kernel_tier_is_still_blocked_by_the_controller(self):
        from src.loop_runner import build_controller
        with tempfile.TemporaryDirectory() as tmp:
            controller = build_controller(
                cve_id="CVE-X", tier="driver_kernel", iterations=1,
                image="img", workdir=Path(tmp), project_root=Path("."),
                version_in_range=True, allow_kernel=False, python_exe="python",
                runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""))
            self.assertIsNotNone(controller.preflight())

    def test_outputs_are_written_next_to_observations(self):
        from src.loop_runner import write_outputs
        from src.closed_loop import LoopResult
        with tempfile.TemporaryDirectory() as tmp:
            path = write_outputs(
                LoopResult(cve_id="CVE-X", status="EXHAUSTED", iterations_used=1,
                           final_verdict="UNKNOWN", reasons=["r"]), Path(tmp))
            self.assertTrue(path.is_file())
            self.assertIn("CVE-X", path.read_text(encoding="utf-8"))


class TestReachedProbe(unittest.TestCase):
    def test_cdb_hit_line_is_the_only_positive_signal(self):
        from src.probe_reached import parse_observation
        self.assertTrue(parse_observation("Breakpoint 0 hit").reached)
        self.assertTrue(parse_observation("Breakpoint 12 hit").reached)
        self.assertFalse(parse_observation("... CPG_DONE ...").reached)
        self.assertIsNone(parse_observation("no markers").reached)

    def test_echoed_breakpoint_command_is_not_a_hit(self):
        # Regression: cdb echoes the bp command, so a marker embedded in that
        # command made every run look like a hit.
        from src.probe_reached import parse_observation
        text = ('0:014> bp nvgpucomp64+0x150315a ".echo CPG_HIT; q"\n'
                "ntdll!NtTerminateProcess://nCPG_DONE//n")
        self.assertFalse(parse_observation(text).reached)

    def test_command_file_carries_module_and_rva(self):
        from src.probe_reached import build_command_file
        text = build_command_file("nvgpucomp64+0x15030f1")
        self.assertIn("bp nvgpucomp64+0x15030f1", text)
        self.assertIn("CPG_DONE", text)

    def test_ready_line_yields_the_pid(self):
        from src.probe_reached import parse_ready
        self.assertEqual(parse_ready("[CPG_READY] 4242"), 4242)
        self.assertIsNone(parse_ready("paused pid=1"))

    def test_execute_stage_records_the_observation(self):
        from src.probe_reached import ReachedObservation
        with tempfile.TemporaryDirectory() as tmp:
            ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                               container_image="img", workdir=Path(tmp),
                               tier="driver_userland", module="nvgpucomp64",
                               rva=0x15030F1, cdb_path="cdb.exe")
            fake = lambda **kw: ReachedObservation(False, "never executed",
                                                   "no artifacts\n")
            state = make_execute_stage(ctx, probe=fake)(
                LoopState(iteration=1, candidate_file=str(Path(tmp) / "poc.py")))
            self.assertFalse(state.reached)
            self.assertIn("never executed",
                          Path(state.observation_file).read_text(encoding="utf-8"))

    def test_controller_turns_unreached_into_path_not_reached(self):
        from src.probe_reached import ReachedObservation
        from src.loop_runner import build_controller
        with tempfile.TemporaryDirectory() as tmp:
            controller = build_controller(
                cve_id="CVE-X", tier="driver_userland", iterations=1,
                image="img", workdir=Path(tmp), project_root=Path("."),
                version_in_range=True, allow_kernel=False, python_exe="python",
                runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""),
                fixed_candidate=str(Path(tmp) / "poc.py"))
            # Replace the execute stage with one that observes an unreachable target.
            ctx = StageContext(project_root=Path("."), cve_id="CVE-X",
                               container_image="img", workdir=Path(tmp),
                               tier="driver_userland", module="m", rva=1,
                               cdb_path="c")
            fake = lambda **kw: ReachedObservation(False, "never executed", "")
            controller.stages["execute"] = make_execute_stage(ctx, probe=fake)
            result = controller.run()
            self.assertEqual(result.trace[0].diagnosis_code, "PATH_NOT_REACHED")


class TestPeExports(unittest.TestCase):
    def test_known_export_resolves_to_an_rva(self):
        from src.pe_exports import export_rva
        kernel32 = Path("C:/Windows/System32/kernel32.dll")
        if not kernel32.is_file():
            self.skipTest("kernel32 not present")
        rva = export_rva(kernel32, "GetTickCount")
        self.assertIsInstance(rva, int)
        self.assertGreater(rva, 0)

    def test_missing_export_returns_none(self):
        from src.pe_exports import export_rva
        kernel32 = Path("C:/Windows/System32/kernel32.dll")
        if not kernel32.is_file():
            self.skipTest("kernel32 not present")
        self.assertIsNone(export_rva(kernel32, "DefinitelyNotExported_xyz"))


if __name__ == "__main__":
    unittest.main()
