"""P2-B runner regressions: immutable harmless registry actions only."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from src.lifecycle_process import (assess_cgroup_v2, describe_process_identity,
                                   inspect_cleanup, run_registered_action)
from src.models.execution import ExecutionResourceLimits
from src.tools.process import canonical_target_environment, measure_tool_identity


LINUX = os.name == "posix" and sys.platform.startswith("linux")


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.expected = measure_tool_identity(sys.executable)
        self.ids = {name: uuid.uuid4().hex for name in ("request_id", "run_id", "nonce")}
        self.limits = ExecutionResourceLimits(wall_time_seconds=2.0, cpu_seconds=1,
                                              memory_bytes=268435456, max_output_bytes=4096)

    def execute(self, fixture="p2b-normal-v1", **kwargs):
        return run_registered_action(fixture, kwargs.pop("limits", self.limits),
                                     expected_tool=kwargs.pop("expected_tool", self.expected), cwd=self.root,
                                     target_environment=canonical_target_environment(), **self.ids, **kwargs)


class TestRunnerBoundaries(RunnerTestCase):
    def test_unknown_action_never_launches(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            for name in ("EXECUTE_CANDIDATE", "sh -c id", "../normal.py", ""):
                with self.assertRaises(ValueError):
                    self.execute(name)
            launch.assert_not_called()

    def test_invalid_identity_never_launches(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            self.ids["run_id"] = "not-a-run-id"
            with self.assertRaises(ValueError):
                self.execute()
            launch.assert_not_called()

    def test_invalid_limits_never_launch(self):
        limits = self.limits.model_dump(mode="python")
        limits["cpu_seconds"] = 0
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            with self.assertRaises(ValueError):
                self.execute(limits=limits)
            launch.assert_not_called()

    @unittest.skipIf(LINUX, "native Linux exercises the supported adapter")
    def test_windows_adapter_is_unsupported_without_launch(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute()
        self.assertEqual(outcome.state, "UNSUPPORTED")
        self.assertFalse(outcome.process.started)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.process.cleanup.status, "NOT_STARTED")
        launch.assert_not_called()

    def test_cleanup_without_start_is_not_started(self):
        self.assertEqual(inspect_cleanup({"process_identity": None})["status"], "NOT_STARTED")

    def test_cleanup_inspection_failure_is_unknown(self):
        with patch("src.lifecycle_process._group_members", side_effect=OSError("not readable")):
            result = inspect_cleanup({"process_identity": {"pid": 123, "pgid": 123, "session_id": 123}})
        self.assertEqual(result["status"], "UNKNOWN")

    def test_reused_group_is_not_accepted_as_owned(self):
        identity = {"pid": 123, "pgid": 123, "session_id": 123, "start_ticks": 10, "uid": 1000, "gid": 1000}
        reused = {**identity, "start_ticks": 20}
        with patch("src.lifecycle_process._group_members", return_value=[reused]):
            result = inspect_cleanup({"process_identity": identity})
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["remaining_pids"], [123])

    def test_cgroup_observation_never_claims_enforcement(self):
        result = assess_cgroup_v2()
        self.assertFalse(result["implemented"])
        self.assertIn(result["status"], {"OBSERVED", "UNKNOWN", "UNSUPPORTED"})


@unittest.skipUnless(LINUX, "requires native Linux /proc, resource limits and process groups")
class TestNativeLifecycleProcess(RunnerTestCase):
    def assert_clean(self, outcome):
        self.assertEqual(outcome.process.cleanup.status, "CONFIRMED", outcome.process.diagnostics)
        self.assertTrue(outcome.process.cleanup.parent_reaped)
        self.assertTrue(outcome.process.cleanup.group_absent)
        self.assertTrue(outcome.process.cleanup.descendants_absent)
        self.assertEqual(inspect_cleanup(outcome.process)["status"], "CONFIRMED")

    def test_normal_exit_actual_identity_limits_and_capture(self):
        events = []
        outcome = self.execute(on_event=lambda kind, details: events.append((kind, details)))
        self.assertEqual(outcome.state, "COMPLETED", outcome.process.diagnostics)
        self.assertEqual(outcome.process.returncode, 0)
        self.assertEqual(outcome.stdout, b"P2-B harmless normal exit\n")
        self.assertEqual(outcome.stderr, b"")
        self.assertEqual(hashlib.sha256(outcome.stdout).hexdigest(), outcome.process.stdout_sha256)
        self.assertEqual(outcome.process.resources.status, "ENFORCED")
        self.assertEqual(outcome.process.resources.memory_bytes, 268435456)
        self.assertEqual(outcome.process.resources.gpu_vram_limit, "NOT_IMPLEMENTED")
        self.assertEqual(outcome.process.tool_identity.file_sha256, self.expected.file_sha256)
        names = [kind for kind, _ in events]
        self.assertLess(names.index("WORKER_CHILD_STARTED"), names.index("RESOURCE_READY"))
        self.assertLess(names.index("RESOURCE_READY"), names.index("RUNNING"))
        proof = next(details for kind, details in events if kind == "RESOURCE_READY")
        self.assertEqual(proof["parent_pid"], os.getpid())
        self.assertEqual(proof["parent_death_signal"], signal.SIGKILL)
        self.assert_clean(outcome)

    def test_nonzero_exit_is_not_success(self):
        outcome = self.execute("p2b-nonzero-v1")
        self.assertEqual(outcome.state, "NONZERO_EXIT")
        self.assertEqual(outcome.process.returncode, 7)
        self.assertIsNone(outcome.process.linux_signal)
        self.assert_clean(outcome)

    def test_wall_timeout_preserves_prefix_and_reaps(self):
        limits = self.limits.model_copy(update={"wall_time_seconds": 0.3})
        outcome = self.execute("p2b-timeout-v1", limits=limits)
        self.assertEqual(outcome.state, "TIMED_OUT", outcome.process.diagnostics)
        self.assertTrue(outcome.process.timed_out)
        self.assertEqual(outcome.process.linux_signal, 9)
        self.assertIn(b"harmless timeout wait", outcome.stdout)
        self.assert_clean(outcome)

    def test_output_limit_is_aggregate_and_raw_hash_is_prefix_hash(self):
        limits = self.limits.model_copy(update={"max_output_bytes": 128})
        outcome = self.execute("p2b-output-v1", limits=limits)
        self.assertEqual(outcome.state, "RESOURCE_LIMIT", outcome.process.diagnostics)
        self.assertTrue(outcome.process.truncated)
        self.assertEqual(len(outcome.stdout) + len(outcome.stderr), 128)
        self.assertEqual(outcome.process.stdout_sha256, hashlib.sha256(outcome.stdout).hexdigest())
        self.assertIn("output", outcome.process.resource_limit_reason)
        self.assert_clean(outcome)

    def test_same_group_child_is_observed_killed_and_reaped(self):
        limits = self.limits.model_copy(update={"wall_time_seconds": 0.4})
        outcome = self.execute("p2b-child-cleanup-v1", limits=limits)
        self.assertEqual(outcome.state, "TIMED_OUT", outcome.process.diagnostics)
        self.assertTrue(outcome.process.cleanup.observed_descendant_pids)
        for pid in outcome.process.cleanup.observed_descendant_pids:
            self.assertFalse(Path("/proc", str(pid)).exists())
        self.assert_clean(outcome)

    def test_cpu_limit_has_native_usage_evidence(self):
        limits = self.limits.model_copy(update={"wall_time_seconds": 5.0})
        outcome = self.execute("p2b-cpu-limit-v1", limits=limits)
        self.assertEqual(outcome.state, "RESOURCE_LIMIT", outcome.process.diagnostics)
        self.assertIn("RLIMIT_CPU", outcome.process.resource_limit_reason)
        self.assertEqual(outcome.process.linux_signal, 9)
        self.assertIsNotNone(outcome.process.cpu_usage_seconds)
        self.assert_clean(outcome)

    def test_bound_cancel_after_running_is_observed(self):
        cancel = self.root / "cancel.json"

        def event(kind, details):
            if kind == "RUNNING":
                cancel.write_text(json.dumps({**self.ids, "action": "CANCEL"}), encoding="utf-8")
                cancel.chmod(0o600)

        outcome = self.execute("p2b-timeout-v1", cancellation_file=cancel, on_event=event)
        self.assertEqual(outcome.state, "CANCELLED", outcome.process.diagnostics)
        self.assertTrue(outcome.process.cancelled)
        self.assert_clean(outcome)

    def test_buffered_ready_after_cancel_cannot_become_identity_rejection_or_go(self):
        cancel = self.root / "cancel-buffered-ready.json"
        observed = []
        def event(kind, details):
            observed.append(kind)
            if kind == "WORKER_CHILD_STARTED":
                # Let the fixed guard send READY and wait for GO while the
                # trusted parent callback is still active, then cancel it.
                time.sleep(0.35)
                cancel.write_text(json.dumps({**self.ids, "action": "CANCEL"}), encoding="utf-8")
                cancel.chmod(0o600)
        outcome = self.execute("p2b-timeout-v1", cancellation_file=cancel, on_event=event)
        self.assertEqual(outcome.state, "CANCELLED", outcome.process.diagnostics)
        self.assertTrue(outcome.process.cancelled)
        self.assertFalse(outcome.process.action_started)
        self.assertNotIn("RUNNING", observed)
        self.assertIn("CONTROL_MESSAGE_AFTER_STOP", observed)
        self.assert_clean(outcome)

    def test_foreign_cancel_cannot_cancel_a_different_run(self):
        cancel = self.root / "cancel.json"
        cancel.write_text(json.dumps({**self.ids, "run_id": uuid.uuid4().hex, "action": "CANCEL"}), encoding="utf-8")
        cancel.chmod(0o600)
        outcome = self.execute(cancellation_file=cancel)
        self.assertEqual(outcome.state, "COMPLETED", outcome.process.diagnostics)
        self.assertFalse(outcome.process.cancelled)

    def test_unavailable_resource_limit_does_not_start(self):
        with patch("resource.getrlimit", return_value=(0, 0)), patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute()
        self.assertEqual(outcome.state, "UNSUPPORTED")
        self.assertFalse(outcome.process.started)
        launch.assert_not_called()

    def test_unavailable_subreaper_never_starts_a_process(self):
        with patch("src.lifecycle_process._set_subreaper", side_effect=OSError("not supported")), patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute()
        self.assertEqual(outcome.state, "UNSUPPORTED")
        self.assertFalse(outcome.process.started)
        launch.assert_not_called()

    def test_unobserved_expected_identity_is_rejected(self):
        unknown = self.expected.model_copy(update={"status": "UNKNOWN", "resolved_path": None, "file_sha256": None})
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute(expected_tool=unknown)
        self.assertEqual(outcome.state, "REJECTED")
        launch.assert_not_called()

    def test_unreadable_tool_identity_does_not_start(self):
        identity = self.expected.model_copy(update={"status": "UNKNOWN", "file_sha256": None})
        with patch("src.lifecycle_process.measure_tool_identity", return_value=identity), patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute()
        self.assertEqual(outcome.state, "REJECTED")
        self.assertFalse(outcome.process.started)
        launch.assert_not_called()

    def test_start_failure_has_no_false_running_state(self):
        with patch("src.lifecycle_process.subprocess.Popen", side_effect=OSError("synthetic launch failure")):
            outcome = self.execute()
        self.assertEqual(outcome.state, "START_FAILED")
        self.assertFalse(outcome.process.started)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.process.cleanup.status, "NOT_STARTED")

    def test_actual_spawned_executable_hash_failure_blocks_action(self):
        unknown = self.expected.model_copy(update={"status": "UNKNOWN", "file_sha256": None})
        with patch("src.lifecycle_process.measure_tool_identity",
                   side_effect=[self.expected, self.expected, unknown]):
            outcome = self.execute()
        self.assertEqual(outcome.state, "REJECTED", outcome.process.diagnostics)
        self.assertTrue(outcome.process.started)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.process.tool_identity.status, "UNKNOWN")
        self.assertEqual(outcome.stdout, b"")
        self.assert_clean(outcome)

    def test_process_identity_observation_failure_remains_unknown(self):
        from src import lifecycle_process
        original = lifecycle_process._process_identity
        calls = 0

        def fail_initial(pid):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic /proc identity unavailable")
            return original(pid)

        with patch("src.lifecycle_process._process_identity", side_effect=fail_initial):
            outcome = self.execute()
        self.assertTrue(outcome.process.started)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.state, "CLEANUP_FAILED")
        self.assertEqual(inspect_cleanup(outcome.process)["status"], "UNKNOWN")

    def test_parent_event_sink_failure_before_start_prevents_launch(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            outcome = self.execute(on_event=lambda kind, details: (_ for _ in ()).throw(OSError("journal full")))
        self.assertFalse(outcome.process.started)
        self.assertNotEqual(outcome.state, "COMPLETED")
        launch.assert_not_called()

    def test_journal_failure_at_resource_gate_blocks_action(self):
        def event(kind, details):
            if kind == "RESOURCE_READY":
                raise OSError("synthetic disk failure")

        outcome = self.execute(on_event=event)
        self.assertFalse(outcome.process.action_started)
        self.assertNotEqual(outcome.state, "COMPLETED")
        self.assertEqual(outcome.stdout, b"")
        self.assert_clean(outcome)

    def test_deadline_expiring_during_gate_validation_blocks_action(self):
        def event(kind, details):
            if kind == "RESOURCE_READY":
                time.sleep(0.2)

        limits = self.limits.model_copy(update={"wall_time_seconds": 0.1})
        outcome = self.execute(limits=limits, on_event=event)
        self.assertEqual(outcome.state, "TIMED_OUT", outcome.process.diagnostics)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.stdout, b"")
        self.assert_clean(outcome)

    def test_cancel_received_during_gate_validation_blocks_action(self):
        cancel = self.root / "cancel.json"

        def event(kind, details):
            if kind == "RESOURCE_READY":
                cancel.write_text(json.dumps({**self.ids, "action": "CANCEL"}), encoding="utf-8")
                cancel.chmod(0o600)

        outcome = self.execute(cancellation_file=cancel, on_event=event)
        self.assertEqual(outcome.state, "CANCELLED", outcome.process.diagnostics)
        self.assertFalse(outcome.process.action_started)
        self.assertEqual(outcome.stdout, b"")
        self.assert_clean(outcome)

    def test_unconfirmed_group_scan_is_cleanup_failed(self):
        with patch("src.lifecycle_process._group_members", side_effect=OSError("synthetic proc failure")):
            outcome = self.execute()
        self.assertEqual(outcome.state, "CLEANUP_FAILED")
        self.assertIn(outcome.process.cleanup.status, {"FAILED", "UNKNOWN"})

    def test_final_event_sink_failure_cannot_return_completed(self):
        def event(kind, details):
            if kind == "PROCESS_FINISHED":
                raise OSError("synthetic final journal failure")

        outcome = self.execute(on_event=event)
        self.assertEqual(outcome.state, "CAPTURE_FAILED")
        self.assertTrue(outcome.process.capture_failed)
        self.assert_clean(outcome)

    def test_native_current_process_identity_is_observed(self):
        identity = describe_process_identity(os.getpid())
        self.assertEqual(identity["pid"], os.getpid())
        self.assertEqual(identity["uid"], os.getuid())
        self.assertEqual(identity["gid"], os.getgid())
        self.assertGreater(identity["start_ticks"], 0)

    def test_worker_death_kills_fixed_action_and_its_fork_child(self):
        """Only this test's own worker is killed; adopted children are reaped."""
        from src.lifecycle_process import _set_subreaper
        project = Path(__file__).resolve().parents[1]
        harness = '''import json, pathlib, sys
sys.path.insert(0, PROJECT_ROOT)
from src.lifecycle_process import run_registered_action
from src.models.execution import ExecutionResourceLimits
from src.tools.process import canonical_target_environment, measure_tool_identity
def observed(kind, details):
    if kind == "DESCENDANT_OBSERVED":
        print(json.dumps(details, sort_keys=True), flush=True)
run_registered_action("p2b-child-cleanup-v1",
    ExecutionResourceLimits(wall_time_seconds=5.0,cpu_seconds=2,memory_bytes=268435456,max_output_bytes=4096),
    expected_tool=measure_tool_identity(sys.executable),cwd=pathlib.Path(PROJECT_ROOT),
    target_environment=canonical_target_environment(),request_id="a"*32,run_id="b"*32,nonce="c"*32,
    on_event=observed)
'''.replace("PROJECT_ROOT", repr(str(project)))
        previous = _set_subreaper(True)
        worker = None
        tracked = set()
        statuses = {}
        try:
            worker = subprocess.Popen([sys.executable, "-I", "-c", harness], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, start_new_session=True, cwd=self.root)
            with selectors.DefaultSelector() as selector:
                selector.register(worker.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(3), "owned harmless worker did not report descendant identity")
                identity = json.loads(worker.stdout.readline())
            tracked = {identity["pid"], identity["pgid"]}
            self.assertTrue(all(pid > 0 for pid in tracked))
            worker.kill()
            self.assertEqual(worker.wait(timeout=2), -signal.SIGKILL)
            deadline = time.monotonic() + 3
            while tracked and time.monotonic() < deadline:
                for pid in list(tracked):
                    try:
                        reaped, status = os.waitpid(pid, os.WNOHANG)
                        if reaped:
                            statuses[pid] = os.waitstatus_to_exitcode(status)
                    except ChildProcessError:
                        pass
                    if not Path("/proc", str(pid)).exists():
                        tracked.remove(pid)
                time.sleep(0.01)
            self.assertFalse(tracked, "parent-death protected owned descendants were not reaped")
            self.assertEqual(statuses[identity["pgid"]], -signal.SIGKILL)
        finally:
            if worker is not None:
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=2)
                # If an assertion fails, recover only the already observed,
                # owned fixture group. Never signal a guessed or global target.
                if tracked:
                    try:
                        os.killpg(identity["pgid"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 2
                    while tracked and time.monotonic() < deadline:
                        for pid in list(tracked):
                            try:
                                reaped, _ = os.waitpid(pid, os.WNOHANG)
                                if reaped:
                                    tracked.remove(pid)
                            except ChildProcessError:
                                if not Path("/proc", str(pid)).exists():
                                    tracked.remove(pid)
                        time.sleep(0.01)
                worker.stdout.close()
                worker.stderr.close()
            _set_subreaper(previous)
