

def test_template_residue_lines_are_removed():
    """A stray chat-template tag must not survive into the script."""
    from src.code_generator import CudaCodeGenerator

    raw = "import os\n</parameter>\nprint(1)\n"
    assert CudaCodeGenerator._clean_code(raw) == "import os\nprint(1)\n"


def test_generation_is_blocked_when_the_generator_says_invalid(tmp_path):
    """An invalid candidate must not reach the container."""
    from src.loop_stages import StageContext, make_generate_stage

    class FakeRun:
        returncode = 0
        stdout = "[!] STATIC_INVALID: SyntaxError at line 906: invalid syntax\n"
        stderr = ""

    context = StageContext(project_root=tmp_path, cve_id="CVE-X",
                           container_image="img", workdir=tmp_path,
                           tier="userland_toolchain", python_exe="python")
    stage = make_generate_stage(context, runner=lambda *a, **k: FakeRun())
    from src.closed_loop import LoopState
    state = stage(LoopState(iteration=1))
    assert state.stage_error and "STATIC_INVALID" in state.stage_error
    assert state.candidate_file is None


def test_minimal_mode_adds_the_size_constraint(monkeypatch):
    """The constraint is opt-in: absent by default, present when asked for."""
    import importlib

    import src.code_generator as cg

    monkeypatch.delenv("CPG_MINIMAL_POC", raising=False)
    importlib.reload(cg)
    assert "size-constrained" not in cg.system_prompt()

    monkeypatch.setenv("CPG_MINIMAL_POC", "1")
    assert "size-constrained" in cg.system_prompt()
    monkeypatch.delenv("CPG_MINIMAL_POC", raising=False)
