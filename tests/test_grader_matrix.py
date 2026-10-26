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


def test_script_is_written_without_carriage_returns(tmp_path):
    """A CRLF script fails inside the container without an error message."""
    from src.loop_stages import _write_matrix_script

    target = tmp_path / "_grader_matrix.sh"
    _write_matrix_script(target, [["faketool", "{artifact}"]])
    assert b"\r" not in target.read_bytes()


def test_script_is_written_without_carriage_returns(tmp_path):
    """A CRLF script fails inside the container without an error message."""
    from src.loop_stages import _write_matrix_script

    target = tmp_path / "_grader_matrix.sh"
    _write_matrix_script(target, [["faketool", "{artifact}"]])
    assert b"\r" not in target.read_bytes()


def test_the_fallback_is_capped():
    """Undeclared sweeps must not decide the run length."""
    from src.grader_matrix import FALLBACK_LIMIT

    script = render_matrix_script([["faketool", "{artifact}"]])
    assert "count" in script
    assert str(FALLBACK_LIMIT) in script


def test_the_matrix_runs_after_the_candidate_not_before(tmp_path):
    """The manifest is written during the run, so it can only be read after."""
    from src.closed_loop import LoopState
    from src.loop_stages import StageContext, make_execute_stage

    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def runner(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            (tmp_path / "benign.cubin").write_bytes(b"\x7fELF")
            (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
            (tmp_path / "artifacts.json").write_text(
                '{"benign": ["benign.cubin"], "crafted": ["poc.cubin"]}',
                encoding="utf-8")
        return Result()

    spec_dir = tmp_path / "specs" / "CVE-X"
    spec_dir.mkdir(parents=True)
    (spec_dir / "spec.json").write_text(
        '{"cve_id": "CVE-X", "anchor": {"invocations": [["faketool", "{artifact}"]]}}',
        encoding="utf-8")
    candidate = tmp_path / "poc.py"
    candidate.write_text("print(1)\n", encoding="utf-8")
    context = StageContext(project_root=tmp_path, cve_id="CVE-X",
                           container_image="img", workdir=tmp_path / "wd",
                           tier="userland_toolchain", python_exe="python")
    make_execute_stage(context, runner=runner)(LoopState(iteration=1, candidate_file=str(candidate)))

    assert len(calls) == 2
    script = (tmp_path / "_grader_matrix.sh").read_text(encoding="utf-8")
    assert "[CPG_LABEL] benign.cubin BENIGN" in script
    assert "for artifact in *.cubin" not in script


def test_the_matrix_runs_after_the_candidate_not_before(tmp_path):
    """The manifest is written during the run, so it can only be read after."""
    from src.closed_loop import LoopState
    from src.loop_stages import StageContext, make_execute_stage

    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def runner(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            (tmp_path / "benign.cubin").write_bytes(b"\x7fELF")
            (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
            (tmp_path / "artifacts.json").write_text(
                '{"benign": ["benign.cubin"], "crafted": ["poc.cubin"]}',
                encoding="utf-8")
        return Result()

    spec_dir = tmp_path / "specs" / "CVE-X"
    spec_dir.mkdir(parents=True)
    (spec_dir / "spec.json").write_text(
        '{"cve_id": "CVE-X", "anchor": {"invocations": [["faketool", "{artifact}"]]}}',
        encoding="utf-8")
    candidate = tmp_path / "poc.py"
    candidate.write_text("print(1)\n", encoding="utf-8")
    context = StageContext(project_root=tmp_path, cve_id="CVE-X",
                           container_image="img", workdir=tmp_path / "wd",
                           tier="userland_toolchain", python_exe="python")
    make_execute_stage(context, runner=runner)(LoopState(iteration=1, candidate_file=str(candidate)))

    assert len(calls) == 2
    script = (tmp_path / "_grader_matrix.sh").read_text(encoding="utf-8")
    assert "[CPG_LABEL] benign.cubin BENIGN" in script
    assert "for artifact in *.cubin" not in script


def test_label_lines_count_as_a_declaration(tmp_path):
    """Candidates declare roles in one of two ways; both are explicit."""
    from src.loop_stages import _declared_artifacts

    (tmp_path / "benign.cubin").write_bytes(b"\x7fELF")
    (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
    log = "[CPG_LABEL] benign.cubin BENIGN\n[CPG_LABEL] poc.cubin MALICIOUS\n"

    pairs, note = _declared_artifacts(tmp_path, log)

    assert sorted(pairs) == [["benign.cubin", "BENIGN"], ["poc.cubin", "MALICIOUS"]]
    assert "CPG_LABEL" in note
