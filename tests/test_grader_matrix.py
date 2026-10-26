# -*- coding: utf-8 -*-
"""The grader must exercise artifacts itself, not trust the candidate's report."""

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.grader_matrix import parse_invocations, render_matrix_script, tool_name


class TestInvocations(unittest.TestCase):
    def test_single_tool_specs_keep_working(self):
        self.assertEqual(parse_invocations([], ["cuobjdump", "{artifact}"]),
                         [["cuobjdump", "{artifact}"]])

    def test_several_tools_are_all_kept(self):
        both = [["nvdisasm", "{artifact}"], ["cuobjdump", "-x", "{artifact}"]]
        self.assertEqual(parse_invocations(both, ["ignored"]), both)

    def test_tool_name_strips_the_directory(self):
        self.assertEqual(tool_name(["/usr/local/cuda/bin/nvdisasm", "{a}"]), "nvdisasm")


class TestMatrixScript(unittest.TestCase):
    def test_every_artifact_meets_every_tool(self):
        """A faulting tool is recorded even if another tool says the file is fine."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "crafted.cubin").write_bytes(b"\x7fELF")
            (root / "benign.cubin").write_bytes(b"\x7fELF")
            tool = root / "faketool"
            # $1 is the artifact: the template puts the placeholder first.
            tool.write_text("#!/bin/sh\ncase \"$1\" in *crafted*) exit 11;; esac\nexit 0\n")
            tool.chmod(0o755)

            script = root / "_matrix.sh"
            script.write_text(render_matrix_script([["faketool", "{artifact}"]]))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            out = subprocess.run(["sh", "_matrix.sh"], cwd=tmp, env=env,
                                 capture_output=True, text=True).stdout

            self.assertIn("[CPG_RUN] crafted.cubin::faketool exit=11", out)
            self.assertIn("[CPG_RUN] benign.cubin::faketool exit=0", out)

    def test_quoted_arguments_survive(self):
        script = render_matrix_script([["tool", "--flag", "a b", "{artifact}"]])
        self.assertIn("'a b'", script)
        self.assertIn('"$artifact"', script)


if __name__ == "__main__":
    unittest.main()
