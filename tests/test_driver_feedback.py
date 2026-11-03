# -*- coding: utf-8 -*-
"""Feedback must change the next program, not just the next paragraph.

The failure this guards against was observed on a real host: round 1 called
CreateDCW and got NULL, round 2 called CreateDCW again and got NULL. The prompt
had said "fix the call"; the code had not changed.
"""

import json
from pathlib import Path

import pytest

from src import driver_feedback, driver_generator, driver_loop
from src.backends import ExecutionObservation
from src.closed_loop import LoopState


def _payload(api="CreateDCW", status=-1, stage="open", notes=""):
    return {"state": "API_CALL_FAILED", "reason": "CreateDCW 调用失败（返回 -1/NULL）",
            "next_move": "调用本身失败：核对接口签名与句柄来源",
            "detail": {"result": {"stage": stage, "status": status,
                                  "calls": [{"api": api, "status": status}],
                                  "notes": notes}}}


def test_feedback_names_the_api_arguments_and_return_value():
    source = 'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'
    feedback = driver_feedback.build(_payload(), previous_source=source)
    assert feedback.failed_api == "CreateDCW"
    assert "DISPLAY" in feedback.failed_call_arguments
    assert feedback.returned_value == "-1"
    assert feedback.win32_error != driver_feedback.UNKNOWN
    assert feedback.ntstatus == driver_feedback.UNKNOWN


def test_unknown_stays_unknown_instead_of_being_invented():
    feedback = driver_feedback.build(_payload(), previous_source="")
    assert feedback.failed_call_arguments == driver_feedback.UNKNOWN
    assert "UNKNOWN" not in feedback.failed_api


def test_the_generator_prompt_carries_the_failure_facts(tmp_path):
    class Client:
        seen = ""

        def chat(self, messages, temperature=None, max_tokens=None):
            Client.seen = messages[-1]["content"]
            return '```python\n# CHANGE: api=CreateDCW from=CreateDCW to=EnumDisplayDevicesW why=null\nprint(1)\n```'

    feedback = driver_feedback.build(_payload(), previous_source=(
        'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'))
    driver_generator.generate(Client(), cve="CVE-T", analysis={}, workdir=tmp_path,
                              feedback=feedback.as_dict(),
                              previous_code='hdc = gdi32.CreateDCW("DISPLAY", None, None, None)')
    assert "CreateDCW" in Client.seen
    assert "failed_call_arguments" in Client.seen
    assert "本轮必须遵守" in Client.seen
    prompt = (tmp_path / "CVE-T" / "round1" / "generator_prompt.txt").read_text(encoding="utf-8")
    assert "CreateDCW" in prompt and "DISPLAY" in prompt


def test_the_same_failing_call_is_a_repeat():
    source = 'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'
    feedback = driver_feedback.build(_payload(), previous_source=source)
    assert driver_feedback.is_repeat(feedback, source) is True


def test_a_changed_argument_is_not_a_repeat():
    previous = 'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'
    current = 'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY34", None, None)\n'
    feedback = driver_feedback.build(_payload(), previous_source=previous)
    assert driver_feedback.is_repeat(feedback, current) is False


def test_a_comment_only_edit_is_still_a_repeat():
    """Cosmetic changes must not be able to satisfy the progress check."""
    previous = 'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'
    current = ('# 这次换个思路\n'
               'hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n')
    feedback = driver_feedback.build(_payload(), previous_source=previous)
    assert driver_feedback.is_repeat(feedback, current) is True


def test_a_candidate_that_did_not_reach_the_api_is_not_flagged():
    feedback = driver_feedback.build(_payload(), previous_source=(
        'user32.EnumDisplayDevicesW(None, 0, byref(dev), 0)\n'))
    assert driver_feedback.is_repeat(feedback, 'x = 1\n') is False


def test_success_path_is_retrieved_across_archives(tmp_path):
    """A run that created a device is found even when it lives elsewhere.

    Retrieval used to look only inside the current workdir, which is why the
    historical setup path was never visible to the model.
    """
    run = tmp_path / "archive" / "round2"
    run.mkdir(parents=True)
    (run / "run.log").write_text(
        '[CPG_PROBE] x outcome=API_REJECTED\n'
        'CPG_DRIVER {"state": "API_REJECTED", "detail": {"result": {"calls": '
        '[{"api": "D3DKMTCreateDevice", "status": 0}]}}}\n'
        'hAdapter=0x40000040 hDevice=0x40000080\n', encoding="utf-8")
    (run / "poc.py").write_text('user32.EnumDisplayDevicesW(None, 0, byref(dev), 0)\n',
                                encoding="utf-8")

    from src import history_index
    experiments = history_index.scan([tmp_path])
    setup = [item for item in experiments
             if item.classification == history_index.SETUP_PATH_SUCCESS]
    assert setup, "a completed setup path should be classified as such"
    text = history_index.render(setup)
    assert "SETUP_PATH_SUCCESS" in text
    assert "0x40000080" in text or "D3DKMTCreateDevice" in text


def test_an_empty_archive_yields_no_history(tmp_path):
    """Nothing to reuse must be reported as nothing, not invented."""
    from src import history_index
    assert history_index.scan([tmp_path / "absent"]) == []
    assert "没有可用" in history_index.render([])


class StubClient:
    """Analyst JSON first, then code that repeats or changes the failing call."""

    def __init__(self, code):
        self.code = code
        self.prompts = []

    def chat(self, messages, temperature=None, max_tokens=None):
        text = messages[-1]["content"]
        self.prompts.append(text)
        # The generator prompt also carries the analysis, so the analysis keys
        # cannot identify the role; the generator's own constraint header can.
        if "本轮必须遵守" not in text:
            return json.dumps({
                "vulnerability_primitive": "authz", "affected_component": "nvlddmkm",
                "candidate_entry_points": [], "required_api_sequence": [],
                "object_lifecycle": [], "input_structure_hypotheses": [],
                "trigger_constraints": [], "candidate_mutation_axes": [],
                "expected_runtime_behavior": "x", "next_experiment": "y",
            }, ensure_ascii=False)
        return "```python\n%s\n```" % self.code


class FailingBackend:
    name = "mock"
    platform = "windows"
    privilege = "user"

    def __init__(self, api="CreateDCW"):
        self.api = api
        self.calls = 0

    def available(self):
        return True

    def run(self, candidate, *, timeout):
        self.calls += 1
        payload = {"stage": "open", "status": -1, "reached": False,
                   "calls": [{"api": self.api, "status": -1}]}
        return ExecutionObservation(backend="mock", exit_code=0,
                                    stdout="CPG_RESULT " + json.dumps(payload))


def test_two_identical_failed_rounds_stop_the_iteration(tmp_path):
    """Repeating the same call twice is the signal to re-derive, not to retry."""
    repeated = ('hdc = gdi32.CreateDCW("DISPLAY", "\\\\.\\\\DISPLAY1", None, None)\n'
                'print("CPG_RESULT " + __import__("json").dumps('
                '{"stage": "open", "status": -1, "reached": False, '
                '"calls": [{"api": "CreateDCW", "status": -1}]}))')
    controller = driver_loop.build_controller(
        cve="CVE-T-NP", iterations=3, workdir=tmp_path,
        client=StubClient(repeated), backend=FailingBackend())
    result = controller.run()
    assert result.status in ("ERROR", "EXHAUSTED")
    joined = " ".join(result.reasons)
    assert "NO_PROGRESS" in joined or result.iterations_used < 3


def test_cuda_path_still_has_its_own_generate_stage():
    from src.loop_stages import select_generate_stage
    from src.closed_loop import TargetTier

    class Ctx:
        tier = TargetTier.TOOLCHAIN
        project_root = str(Path.cwd())
        cve_id = "CVE-2024-0076"
        python_exe = "python"
        workdir = Path(".")

    assert callable(select_generate_stage(Ctx()))


def test_change_plan_is_parsed_from_a_real_header():
    """The header's values are argument lists: commas and '=' inside them."""
    code = ('# CHANGE: api=D3DKMTEscape from=Type=0,Flags=1 to=Type=0,Flags=0 '
            'why=上一轮返回 0xC000000D\nimport ctypes\n')
    plan = driver_generator.parse_change_plan(code)
    assert plan["api"] == "D3DKMTEscape"
    assert plan["from"] == "Type=0,Flags=1"
    assert plan["to"] == "Type=0,Flags=0"
    assert "0xC000000D" in plan["why"]


def test_a_candidate_without_the_header_has_no_plan():
    assert driver_generator.parse_change_plan("print(1)\n") == {}
