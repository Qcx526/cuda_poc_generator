# -*- coding: utf-8 -*-
"""A probe that kills the machine must still produce a verdict afterwards."""

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.driver_probe import arm, harvest, read_marker, summarise
from src.driver_crash import bugcheck_name, normalise_code, parse_bugcheck_record


class TestArmAndHarvest(unittest.TestCase):
    def test_a_completed_probe_reports_its_exit_code(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py")
            result = harvest(root, uptime_seconds=10_000, exit_code=0)
            self.assertEqual(result["outcome"], "exited")
            self.assertEqual(result["exit_code"], 0)

    def test_a_reboot_after_arming_is_a_crash(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            arm(root, root / "poc.py")
            time.sleep(1.1)
            # Uptime shorter than the time since arming means the machine
            # restarted after the probe was armed.
            result = harvest(root, uptime_seconds=0.3,
                             bugcheck={"code": "0x000000d1",
                                       "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
                                       "params": []})
            self.assertEqual(result["outcome"], "crashed")
            self.assertTrue(result["rebooted"])
            self.assertIn("DRIVER_IRQL", summarise(result))

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
