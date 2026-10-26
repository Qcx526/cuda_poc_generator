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


class TestTimeoutIsReadable(unittest.TestCase):
    def test_timeout_becomes_a_clear_stage_error(self):
        import subprocess as sp

        from src.loop_stages import StageContext, make_execute_stage

        def runner(command, **kwargs):
            raise sp.TimeoutExpired(cmd=command, timeout=kwargs.get("timeout", 0))

        with TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "poc.py"
            candidate.write_text("print('hi')\n", encoding="utf-8")
            context = StageContext(project_root=Path(tmp), cve_id="CVE-X",
                                   container_image="img", workdir=Path(tmp),
                                   tier="userland_toolchain", python_exe="python")
            state = make_execute_stage(context, runner=runner)(
                LoopState(iteration=1, candidate_file=str(candidate)))

        self.assertIn("timed out", state.stage_error or "")
        self.assertNotIn("docker", state.stage_error or "")
