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


class TestStaleCandidates(unittest.TestCase):
    def test_a_candidate_from_an_earlier_run_is_not_reused(self):
        """Grading yesterday's script under today's run is worse than failing."""
        import os
        import time

        from src.loop_stages import _find_candidate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "data" / "outputs" / "CVE-X"
            out.mkdir(parents=True)
            stale = out / "cuda_poc_v1.py"
            stale.write_text("print('old')\n", encoding="utf-8")
            old = time.time() - 3600
            os.utime(stale, (old, old))

            self.assertIsNone(_find_candidate(root, "CVE-X", since=time.time()))
            self.assertIsNotNone(_find_candidate(root, "CVE-X"))


class TestStaleArtifacts(unittest.TestCase):
    def test_artifacts_from_an_earlier_run_are_set_aside(self):
        from src.loop_stages import quarantine_stale_artifacts

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.cubin").write_bytes(b"\x7fELF")
            (root / "artifacts.json").write_text("{}", encoding="utf-8")
            (root / "keep.py").write_text("x", encoding="utf-8")

            moved = quarantine_stale_artifacts(root)

            self.assertEqual(moved, 2)
            self.assertFalse((root / "old.cubin").exists())
            self.assertFalse((root / "artifacts.json").exists())
            self.assertTrue((root / "keep.py").exists())
            self.assertEqual(len(list(root.glob("_stale_*/*.cubin"))), 1)
