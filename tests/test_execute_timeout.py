# -*- coding: utf-8 -*-
"""A hung candidate must cost minutes, not the whole budget."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.closed_loop import LoopState
from src.loop_stages import _EXECUTE_TIMEOUT, StageContext, make_execute_stage


class TestExecuteTimeout(unittest.TestCase):
    def test_the_runner_is_given_a_bounded_timeout(self):
        seen = {}

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def runner(command, **kwargs):
            seen.update(kwargs)
            return Result()

        with TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "poc.py"
            candidate.write_text("print('hi')\n", encoding="utf-8")
            context = StageContext(project_root=Path(tmp), cve_id="CVE-X",
                                   container_image="img", workdir=Path(tmp),
                                   tier="userland_toolchain", python_exe="python")
            stage = make_execute_stage(context, runner=runner)
            stage(LoopState(iteration=1, candidate_file=str(candidate)))

        self.assertEqual(seen.get("timeout"), _EXECUTE_TIMEOUT)
        self.assertLessEqual(_EXECUTE_TIMEOUT, 300)


if __name__ == "__main__":
    unittest.main()
