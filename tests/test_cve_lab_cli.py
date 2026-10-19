"""Offline command routing: no Windows launcher or candidate process is started."""

from src import cve_lab


def test_execute_rejects_unregistered_mode_without_dispatch(monkeypatch):
    from src import staged_fixture

    called = []
    monkeypatch.setattr(staged_fixture, "run_staged_fixture_wsl", lambda **kw: called.append(kw))
    try:
        cve_lab.main(["execute", "--mode", "arbitrary-candidate", "--operator-id", "reviewer",
            "--authorization-reference", "ticket", "--linux-project-root", "/mnt/f/project"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("unknown execution mode was accepted")
    assert called == []


def test_fixed_execute_requires_explicit_operator_grant(monkeypatch):
    from src import staged_fixture

    def require_grant(**kwargs):
        assert kwargs["authorize_fixed_fixture"] is False
        raise ValueError("操作者授权缺失")

    monkeypatch.setattr(staged_fixture, "run_staged_fixture_wsl", require_grant)
    result = cve_lab.main(["execute", "--mode", "fixed-staged-normal", "--operator-id", "reviewer",
        "--authorization-reference", "ticket", "--linux-project-root", "/mnt/f/project"])
    assert result == 2


def test_fixed_execute_passes_explicit_scope_and_returns_status(monkeypatch, capsys):
    from src import staged_fixture

    calls = []

    def run(**kwargs):
        calls.append(kwargs)
        return {"status": "COMPLETED", "verification_status": "NOT_VERIFIED"}

    monkeypatch.setattr(staged_fixture, "run_staged_fixture_wsl", run)
    result = cve_lab.main(["execute", "--mode", "fixed-staged-normal", "--authorize-fixed-fixture",
        "--operator-id", "reviewer", "--authorization-reference", "ticket",
        "--linux-project-root", "/mnt/f/project"])
    assert result == 0
    assert len(calls) == 1
    assert calls[0]["authorize_fixed_fixture"] is True
    assert calls[0]["linux_project_root"] == "/mnt/f/project"
    assert "NOT_VERIFIED" in capsys.readouterr().out


def test_evaluate_is_offline_and_requires_verified_integrity(monkeypatch):
    from src import staged_fixture

    monkeypatch.setattr(staged_fixture, "evaluate_staged_fixture_archive",
        lambda archive: {"integrity_status": "FAILED", "archive": archive})
    assert cve_lab.main(["evaluate", "--archive", "local-evidence"]) == 2
