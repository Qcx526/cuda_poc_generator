# -*- coding: utf-8 -*-
"""The sweep must stop on anything that is not a plain refusal."""

import unittest

from tools.sweep_escapes import REFUSED, classify


class TestClassify(unittest.TestCase):
    def test_a_refusal_is_not_interesting(self):
        self.assertEqual(classify({"status": -1073741811}), "refused")
        self.assertEqual(classify({"status": -1073741637}), "refused")

    def test_success_stops_the_sweep(self):
        self.assertEqual(classify({"status": 0}), "stop")

    def test_a_timeout_stops_the_sweep(self):
        self.assertEqual(classify({"outcome": "timeout"}), "stop")

    def test_a_process_that_died_without_status_stops(self):
        """No status means the code did something the harness cannot read."""
        self.assertEqual(classify({"status": None, "returncode": 139}), "stop")

    def test_the_refusal_set_is_what_we_think(self):
        self.assertEqual(REFUSED, {-1073741811, -1073741637})
