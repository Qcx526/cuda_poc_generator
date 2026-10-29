# -*- coding: utf-8 -*-
"""The framework's own runs outrank the candidate's log.

A candidate can print any exit code it likes. The second pass exists to replace
that claim with a measurement; if both end up in the same file, the grader counts
one run twice and can compare a claim against itself.
"""

from pathlib import Path

from src.closed_loop import LoopState
from src.loop_stages import StageContext, make_execute_stage

CANDIDATE_LOG = (
    "[CPG_LABEL] poc.cubin MALICIOUS\n"
    "[CPG_RUN] poc.cubin exit=-11\n"
    "[CPG_VERDICT] differential confirmed\n"
)


class Runner:
    """Answers the candidate run and the matrix run differently."""

    def __init__(self, matrix_output: str):
        self.matrix_output = matrix_output
        self.commands = []

    def __call__(self, command, cwd=None, timeout=None):
        self.commands.append(command)
        joined = " ".join(str(part) for part in command)

        class Result:
            returncode = 0
            stderr = ""

        result = Result()
        result.stdout = self.matrix_output if "_grader_matrix.sh" in joined else CANDIDATE_LOG
        return result


def _run(tmp_path: Path, matrix_output: str):
    root = tmp_path
    (root / "specs" / "CVE-X").mkdir(parents=True)
    (root / "specs" / "CVE-X" / "spec.json").write_text(
        '{"cve_id": "CVE-X", "anchor": {"invocations": [["nvdisasm", "{artifact}"]]}}',
        encoding="utf-8")
    work = root / "work"
    work.mkdir()
    candidate = work / "cuda_poc_v1.py"
    candidate.write_text("print('hi')\n", encoding="utf-8")
    (work / "artifacts.json").write_text('{"crafted": ["poc.cubin"]}', encoding="utf-8")
    (work / "poc.cubin").write_bytes(b"\x7fELF")

    context = StageContext(project_root=root, cve_id="CVE-X", container_image="img",
                           workdir=work, tier="userland_toolchain", python_exe="py")
    runner = Runner(matrix_output)
    state = make_execute_stage(context, runner=runner)(LoopState(
        iteration=1, candidate_file=str(candidate)))
    return work, state


def test_framework_lines_replace_the_candidate_log(tmp_path):
    work, _ = _run(tmp_path, "[CPG_RUN] poc.cubin::nvdisasm exit=139\n"
                             "[CPG_CRASH] poc.cubin off=0xd799 module=nvdisasm\n")
    written = (work / "iteration_1_observation.txt").read_text(encoding="utf-8")
    assert "::nvdisasm exit=139" in written
    assert "CPG_VERDICT" not in written, "候选自述不应进入判定用的观测"
    kept = (work / "iteration_1_candidate.txt").read_text(encoding="utf-8")
    assert "CPG_VERDICT" in kept, "候选日志要留着供诊断"


def test_without_framework_runs_the_candidate_log_survives(tmp_path):
    work, _ = _run(tmp_path, "[CPG_MATRIX] 规格未声明可执行的工具命令\n")
    written = (work / "iteration_1_observation.txt").read_text(encoding="utf-8")
    assert "CPG_VERDICT" in written
    assert "CPG_MATRIX" in written
