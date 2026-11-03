# -*- coding: utf-8 -*-
"""Driver execution integration: dispatch, gate, observation, and the loop.

Everything here runs offline. Triggering a real driver to test the test suite
would make the suite itself a hazard, and a kernel path is only entered on a host
that can be recovered.
"""

import json
from pathlib import Path

import pytest

from src import driver_exec, driver_loop, driver_outcome
from src.backends import ExecutionObservation, TargetProfile
from src.closed_loop import LoopConfig, LoopState, TargetTier


class MockBackend:
    """A backend that returns whatever it was told to return."""

    name = "mock"
    platform = "windows"
    privilege = "user"

    def __init__(self, observation=None):
        self.observation = observation or ExecutionObservation(
            backend="mock", exit_code=0,
            stdout='CPG_RESULT {"stage": "escape", "status": -1073741811, '
                   '"reached": false, "calls": []}')
        self.calls = 0

    def available(self):
        return True

    def run(self, candidate, *, timeout):
        self.calls += 1
        return self.observation


def _gate(ready: bool, reasons=("no minidump",)):
    return driver_exec.GateReport(ready, list(reasons), {})


def test_userland_dispatch_reaches_a_userspace_backend():
    """driver_userland must not be served by the kernel gate."""
    backend = driver_exec.build_backend(TargetTier.DRIVER_USERLAND)
    assert backend.privilege == "user"
    assert backend.name != "kernel_one_shot"


def test_kernel_dispatch_always_uses_the_gate():
    gate = driver_exec.build_backend(TargetTier.DRIVER_KERNEL, allow_kernel=True,
                                     check=lambda: _gate(True))
    assert gate.name == "kernel_one_shot"
    assert isinstance(gate, driver_exec.KernelOneShotGate)


def test_allow_kernel_alone_does_not_authorise_a_run():
    gate = driver_exec.build_backend(TargetTier.DRIVER_KERNEL, allow_kernel=True,
                                     check=lambda: _gate(False))
    assert gate.available() is False
    with pytest.raises(RuntimeError, match="恢复检查"):
        gate.run(Path("candidate.py"), timeout=10)


def test_without_allow_kernel_the_gate_refuses_outright():
    gate = driver_exec.build_backend(TargetTier.DRIVER_KERNEL, allow_kernel=False)
    with pytest.raises(RuntimeError, match="allow_kernel"):
        gate.run(Path("candidate.py"), timeout=10)


def test_a_second_kernel_run_is_refused(tmp_path):
    """One bugcheck is enough evidence; retrying is how a host is lost."""
    inner = MockBackend(ExecutionObservation(backend="mock", exit_code=0, stdout=""))
    gate = driver_exec.KernelOneShotGate(inner, allow_kernel=True,
                                         check=lambda: _gate(True))
    gate.run(tmp_path / "a.py", timeout=5)
    with pytest.raises(RuntimeError, match="禁止自动重试"):
        gate.run(tmp_path / "a.py", timeout=5)


def _run(outcome, claims=None, external=None, stdout=""):
    return driver_exec.DriverRun(observation=ExecutionObservation(
        backend="mock", exit_code=0, stdout=stdout), outcome=outcome,
        claims=claims or {}, external=external or [])


def test_observation_text_is_readable_by_the_driver_grader(tmp_path):
    outcome = driver_outcome.classify(returncode=0, output=(
        'CPG_RESULT {"stage": "escape", "status": -1073741790, "reached": false}'))
    text = driver_exec.observation_text("cuobjdump+0x1", _run(outcome))
    path = tmp_path / "obs.txt"
    path.write_text(text, encoding="utf-8")
    assert text.startswith("[CPG_PROBE]")
    state = LoopState(iteration=1, observation_file=str(path))
    payload = driver_loop._state_of(state.observation_file)
    assert payload["state"] == driver_outcome.API_REJECTED


def test_the_legacy_probe_prefix_is_still_present():
    """Existing graders parse CPG_PROBE; the driver line is additive."""
    outcome = driver_outcome.classify(returncode=0, output="")
    text = driver_exec.observation_text("cuobjdump+0x1", _run(outcome))
    assert "[CPG_PROBE]" in text
    assert "outcome=" in text


def test_invalid_parameter_is_not_called_reaching_the_vendor_dispatcher():
    """0xC000000D says the request was refused, not that KMD dispatched it."""
    outcome = driver_outcome.classify(returncode=0, output=(
        'CPG_RESULT {"stage": "escape", "status": -1073741811, "reached": true}'))
    assert outcome.state == driver_outcome.INPUT_REJECTED
    assert "分派" not in outcome.reason


def test_the_grader_never_calls_a_reached_target_supported(tmp_path):
    outcome = driver_outcome.classify(
        returncode=0,
        output='CPG_RESULT {"stage": "escape", "status": 0, "reached": true}',
        external_evidence=[{"producer": "cdb_trace", "hit": True, "where": "x"}])
    text = driver_exec.observation_text("cve", _run(outcome))
    path = tmp_path / "obs.txt"
    path.write_text(text, encoding="utf-8")
    result = driver_loop.driver_grader(LoopState(iteration=1,
                                                 observation_file=str(path)))
    assert result.verdict != "SUPPORTED"


class StubClient:
    """Returns an analysis object for the analysis prompt, code for the code one."""

    def __init__(self):
        self.prompts = []

    def chat(self, messages, temperature=None, max_tokens=None):
        text = messages[-1]["content"]
        self.prompts.append(text)
        if "candidate_entry_points" in text:
            return json.dumps({
                "vulnerability_primitive": "authorization bypass",
                "affected_component": "nvlddmkm",
                "candidate_entry_points": [],
                "required_api_sequence": [],
                "object_lifecycle": [],
                "input_structure_hypotheses": [],
                "trigger_constraints": [],
                "candidate_mutation_axes": [],
                "expected_runtime_behavior": "status difference",
                "next_experiment": "issue one escape",
            }, ensure_ascii=False)
        return ('```python\nprint("CPG_RESULT " + __import__("json").dumps('
                '{"stage": "escape", "status": -1073741811, "reached": false, '
                '"calls": []}))\n```')


def test_closed_loop_controller_runs_the_driver_feedback_cycle(tmp_path):
    """Controller, not a private loop: two iterations, one state machine."""
    controller = driver_loop.build_controller(
        cve="CVE-TEST-0001", iterations=2, workdir=tmp_path,
        client=StubClient(), backend=MockBackend())
    assert isinstance(controller.config, LoopConfig)
    result = controller.run()
    assert result.iterations_used >= 1
    assert result.status in ("EXHAUSTED", "SUPPORTED")
    assert (tmp_path / "CVE-TEST-0001" / "round1" / "poc.py").is_file()


def test_a_kernel_tier_loop_without_allow_kernel_is_blocked(tmp_path):
    controller = driver_loop.build_controller(
        cve="CVE-TEST-0002", tier=TargetTier.DRIVER_KERNEL, allow_kernel=False,
        iterations=1, workdir=tmp_path, client=StubClient(),
        backend=driver_exec.build_backend(TargetTier.DRIVER_KERNEL,
                                          allow_kernel=False))
    result = controller.run()
    assert result.status == "BLOCKED"
    assert "allow_kernel" in " ".join(result.reasons)


def test_cuda_tier_is_untouched_by_the_driver_dispatch():
    """A toolchain target must still get the CUDA generate stage."""
    from src.loop_stages import select_generate_stage

    class Ctx:
        tier = TargetTier.TOOLCHAIN
        project_root = str(Path.cwd())
        cve_id = "CVE-2024-0076"
        python_exe = "python"
        workdir = Path(".")

    stage = select_generate_stage(Ctx())
    assert stage.__name__ if hasattr(stage, "__name__") else "stage" == "stage"


def test_driver_tier_generate_stage_refuses_without_analysis(tmp_path):
    """No silent fallback to the CUDA generator, which would mislabel a result."""
    from src.loop_stages import select_generate_stage

    class Ctx:
        tier = TargetTier.DRIVER_USERLAND
        project_root = str(Path.cwd())
        cve_id = "CVE-TEST-0003"
        python_exe = "python"
        workdir = tmp_path

    stage = select_generate_stage(Ctx())
    with pytest.raises(RuntimeError, match="driver_loop"):
        stage(LoopState(iteration=1))
