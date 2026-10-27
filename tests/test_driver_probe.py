# -*- coding: utf-8 -*-
"""A probe that kills the machine must still produce a verdict afterwards."""

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from datetime import datetime, timedelta

from src.driver_probe import arm, harvest, read_marker, summarise

LONG_AGO = datetime(2000, 1, 1)
from src.driver_crash import bugcheck_name, normalise_code, parse_bugcheck_record


class TestArmAndHarvest(unittest.TestCase):
    def test_a_completed_probe_reports_its_exit_code(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py")
            result = harvest(root, bugcheck_time=LONG_AGO,
                             boot_event_time=LONG_AGO, exit_code=0)
            self.assertEqual(result["outcome"], "exited")
            self.assertEqual(result["exit_code"], 0)

    def test_a_reboot_after_arming_is_a_crash(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py")
            time.sleep(1.1)
            # A bugcheck recorded after arming is the crash, whatever uptime says.
            result = harvest(root, bugcheck={"code": "0x000000d1",
                                             "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
                                             "params": []},
                             bugcheck_time=datetime.now() + timedelta(seconds=1),
                             boot_event_time=LONG_AGO)
            self.assertEqual(result["outcome"], "crashed")
            self.assertTrue(result["rebooted"])
            self.assertIn("DRIVER_IRQL", summarise(result))

    def test_a_restart_without_a_bugcheck_is_not_a_crash(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py")
            result = harvest(root, bugcheck_time=LONG_AGO,
                             boot_event_time=datetime.now() + timedelta(seconds=1))
            self.assertEqual(result["outcome"], "rebooted_without_bugcheck")
            self.assertIn("no bugcheck", summarise(result))

    def test_no_marker_means_nothing_was_probed(self):
        with TemporaryDirectory() as tmp:
            self.assertEqual(harvest(Path(tmp))["outcome"], "no_marker")

    def test_the_marker_survives_as_plain_json(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py", note="driver tier")
            payload = json.loads((root / "probe_armed.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["note"], "driver tier")
            self.assertEqual(read_marker(root)["candidate"], str(root / "poc.py"))


class TestBugcheckParsing(unittest.TestCase):
    def test_codes_normalise_regardless_of_width(self):
        self.assertEqual(normalise_code("0xa"), "0x0000000a")
        self.assertEqual(normalise_code("0x0000000A"), "0x0000000a")
        self.assertEqual(normalise_code("10"), "0x0000000a")

    def test_a_rendered_event_names_the_driver_fault(self):
        text = ("The computer has rebooted from a bugcheck.  The bugcheck was: "
                "0x000000d1 (0x0000000000000028, 0x0000000000000002, "
                "0x0000000000000000, 0xfffff80512345678).")
        parsed = parse_bugcheck_record(text)
        self.assertEqual(parsed["code"], "0x000000d1")
        self.assertEqual(parsed["name"], "DRIVER_IRQL_NOT_LESS_OR_EQUAL")
        self.assertEqual(len(parsed["params"]), 4)

    def test_an_xml_event_is_understood_too(self):
        text = '<EventData><Data Name="BugcheckCode">209</Data>' \
               '<Data Name="BugcheckParameter1">0xffffffff</Data></EventData>'
        parsed = parse_bugcheck_record(text)
        self.assertEqual(parsed["code"], "0x000000d1")
        self.assertEqual(parsed["params"], ["0xffffffff"])

    def test_unrelated_text_is_not_mistaken_for_a_crash(self):
        self.assertIsNone(parse_bugcheck_record("Windows updated successfully"))


if __name__ == "__main__":
    unittest.main()


class TestScanMode(unittest.TestCase):
    def test_scan_finds_every_armed_probe_under_a_root(self):
        from tools.harvest_probe import scan

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "v1" / "CVE-A"
            second = root / "v1" / "CVE-B"
            for workdir in (first, second):
                workdir.mkdir(parents=True)
                arm(workdir, workdir / "poc.py")
            time.sleep(1.1)

            scan(root)

            log = (root / "harvest.log").read_text(encoding="utf-8")
            self.assertIn("CVE-A", log)
            self.assertIn("CVE-B", log)


class TestDriverStage(unittest.TestCase):
    def test_three_variants_are_armed_and_reported(self):
        from src.closed_loop import LoopState
        from src.loop_stages import StageContext, make_execute_stage

        seen = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def runner(command, **kwargs):
            seen.append(command)
            return Result()

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "poc.py"
            candidate.write_text("print(1)\n", encoding="utf-8")
            context = StageContext(project_root=root, cve_id="CVE-X",
                                   container_image="img", workdir=root / "wd",
                                   tier="driver_kernel", python_exe="python")
            state = make_execute_stage(context, runner=runner)(
                LoopState(iteration=1, candidate_file=str(candidate)))

            text = Path(state.observation_file).read_text(encoding="utf-8")

        # A parameter set per arm, and the variant is named on the command line.
        self.assertEqual(len(seen), 3)
        self.assertIn("--variant", seen[1])
        self.assertIn("crafted", " ".join(seen[1]))
        for prefix in ("benign", "crafted", "ctrl"):
            self.assertIn("[CPG_PROBE] %s_poc outcome=" % prefix, text)
