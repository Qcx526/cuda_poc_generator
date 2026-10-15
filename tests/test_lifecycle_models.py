"""Synthetic P2-B contracts only; no native process, WSL or GPU launch."""

import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest

from pydantic import ValidationError

from src.models.execution import (ExecutionRequest, PreflightPolicy, request_sha256,
                                  snapshot_sha256)
from src.models.execution_binding import bind_candidate_to_tool
from src.models.lifecycle import (ArtifactReference, CleanupObservation, EvidenceManifest,
                                  ExecutionRecord, LifecycleEvent, ProcessObservation,
                                  RemoteRecoveryCheck, canonical_sha256, validate_transition)
from src.registered_actions import REGISTERED_ACTIONS, get_registered_action
from tests.test_execution_bridge import fixed_request, fixture_authority


NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def synthetic_context(action_id="p2b-normal-v1"):
    """Explicitly synthetic request/authority/snapshot/tool association for tests."""
    old_request, snapshot, observation = fixed_request()
    action = get_registered_action(action_id)
    request = old_request.model_dump(mode="python")
    request.update(request_schema_version="1.1", expected_artifacts=["stdout.bin", "stderr.bin", "process_result.json"],
                   candidate_sha256=action.sha256, fixture_id=action.fixture_id,
                   candidate_path="/workspace/" + action.relative_path)
    request["binding"] = bind_candidate_to_tool(action.source, snapshot, observation,
                                                 expected_probe_id=request["platform_probe_id"],
                                                 expected_tool_record_id=observation.record_id)
    request = ExecutionRequest.model_validate(request)
    authorization, policy = fixture_authority(request, snapshot)
    raw_policy = policy.model_dump(mode="python")
    raw_policy["fixture_hashes"] = {action.fixture_id: action.sha256}
    policy = PreflightPolicy.model_validate(raw_policy)
    return request, authorization, policy, snapshot, observation


def synthetic_record(*, state="COMPLETED", action_id="p2b-normal-v1"):
    """A clearly fabricated observation for offline schema/report tests only."""
    request, authorization, policy, snapshot, observation = synthetic_context(action_id)
    action = get_registered_action(action_id)
    started = state not in {"REJECTED", "UNKNOWN", "UNSUPPORTED", "START_FAILED"}
    sequence = ["CREATED"]
    if state not in {"REJECTED", "UNKNOWN", "UNSUPPORTED"}:
        sequence += ["AUTHORIZED", "PREFLIGHT_READY", "STARTING"]
        if started:
            sequence += ["RUNNING"]
    sequence += [state]
    events = [LifecycleEvent(sequence=index, state=status,
                             observed_at=(NOW + timedelta(milliseconds=index)).isoformat(),
                             source="synthetic offline test observer", reason="synthetic " + status)
              for index, status in enumerate(sequence)]
    process = None
    if started:
        stdout = b"synthetic harmless output\n"
        resources = {"status": "ENFORCED", "wall_watchdog": True, "output_cap": True,
                     "process_group": True, "cpu_seconds": request.resource_limits.cpu_seconds,
                     "memory_bytes": request.resource_limits.memory_bytes,
                     "verification_source": "synthetic limits observation; not a real process"}
        cleanup = {"status": "CONFIRMED", "termination_method": "NONE", "parent_reaped": True,
                   "group_absent": True, "descendants_absent": True,
                   "checked_at": events[-1].observed_at, "source": "synthetic independent cleanup"}
        process = ProcessObservation(
            started=True, action_started=True,
            argv=[request.tool_identity.resolved_path, "-I", "-c", action.source.decode("utf-8")],
            cwd=request.cwd, target_environment=request.binding.target_environment,
            tool_identity=request.tool_identity, pid=10001, pgid=10001, session_id=10001,
            start_ticks=1000, worker_pid=10000, uid=1000, gid=1000,
            started_at=events[-2].observed_at, finished_at=events[-1].observed_at,
            duration_seconds=0.001, returncode=7 if state == "NONZERO_EXIT" else 0,
            timed_out=state == "TIMED_OUT", cancelled=state == "CANCELLED",
            truncated=state == "RESOURCE_LIMIT", capture_failed=state == "CAPTURE_FAILED",
            resource_limit_reason="OUTPUT_CAP" if state == "RESOURCE_LIMIT" else None,
            stdout_b64=base64.b64encode(stdout).decode("ascii"), stderr_b64="",
            stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_size_bytes=len(stdout), stderr_size_bytes=0, resource_limits=request.resource_limits,
            resources=resources, cleanup=cleanup, diagnostics=["synthetic process observations"])
        if state == "CLEANUP_FAILED":
            value = process.model_dump(mode="python")
            value["cleanup"].update(status="UNKNOWN", group_absent=False, remaining_pids=[10002])
            process = ProcessObservation.model_validate(value)
    return ExecutionRecord(
        request_id=request.request_id, run_id="f" * 32, request_sha256=request_sha256(request),
        authorization_sha256=canonical_sha256(authorization), policy_sha256=canonical_sha256(policy),
        snapshot_sha256=snapshot_sha256(snapshot), candidate_sha256=request.candidate_sha256,
        platform_environment_id=request.platform_environment_id, platform_probe_id=request.platform_probe_id,
        target_environment=request.binding.target_environment, tool_record_id=observation.record_id,
        tool_identity=request.tool_identity, authorization_reference=request.authorization_reference,
        operator_id=authorization.operator_id, action_id=action_id, status=state, events=events,
        process=process, worker_pid=10000, started_at=events[0].observed_at,
        finished_at=events[-1].observed_at, diagnostics=["SYNTHETIC EXAMPLE; not execution evidence"],
        fixture_execution_status="STARTED" if started else "NOT_STARTED")


def synthetic_recovery(record=None):
    record = synthetic_record() if record is None else record
    return RemoteRecoveryCheck(request_id=record.request_id, run_id=record.run_id, status="CONFIRMED",
                               worker_alive=False, group_empty=True, identity_match=True,
                               checked_at=(NOW + timedelta(seconds=1)).isoformat(),
                               observer_pid=10003, observer_uid=1000, diagnostics=["SYNTHETIC recovery"])


class TestLifecycleModel(unittest.TestCase):
    def test_all_registered_sources_match_reviewed_files(self):
        self.assertEqual(len(REGISTERED_ACTIONS), 6)
        for action in REGISTERED_ACTIONS.values():
            with self.subTest(action=action.fixture_id):
                self.assertEqual(Path(action.relative_path).read_bytes(), action.source)
                self.assertEqual(hashlib.sha256(action.source).hexdigest(), action.sha256)
                compile(action.source, action.relative_path, "exec")

    def test_registry_and_entries_cannot_be_mutated(self):
        with self.assertRaises(TypeError):
            REGISTERED_ACTIONS["evil"] = get_registered_action("p2b-normal-v1")
        with self.assertRaises(FrozenInstanceError):
            get_registered_action("p2b-normal-v1").source = b"untrusted source"

    def test_unknown_action_argv_or_alias_is_never_accepted(self):
        for value in ("EXECUTE_CANDIDATE", "normal", "; echo injected", ["python"], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                get_registered_action(value)

    def test_valid_normal_record_roundtrip_preserves_scientific_boundary(self):
        record = synthetic_record()
        self.assertEqual(ExecutionRecord.model_validate_json(record.model_dump_json()), record)
        self.assertEqual(record.verification_status, "NOT_VERIFIED")
        self.assertEqual(record.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(record.fixture_execution_status, "STARTED")

    def test_supported_terminal_statuses_have_explicit_observations(self):
        for state in ("COMPLETED", "NONZERO_EXIT", "TIMED_OUT", "CANCELLED", "RESOURCE_LIMIT",
                      "CAPTURE_FAILED", "CLEANUP_FAILED", "REJECTED", "UNKNOWN", "UNSUPPORTED", "START_FAILED"):
            with self.subTest(state=state):
                self.assertEqual(synthetic_record(state=state).status, state)

    def test_illegal_transition_and_any_transition_after_terminal_rejected(self):
        for previous, following in (("CREATED", "RUNNING"), ("AUTHORIZED", "COMPLETED"),
                                     ("COMPLETED", "RUNNING"), ("REJECTED", "AUTHORIZED"),
                                     ("RUNNING", "CREATED"), ("CREATED", "CREATED")):
            with self.subTest(pair=(previous, following)), self.assertRaises(ValueError):
                validate_transition(previous, following)

    def test_event_sequence_and_time_are_not_rewritten(self):
        for mutation in ("sequence", "timestamp", "initial", "terminal"):
            data = synthetic_record().model_dump(mode="python")
            if mutation == "sequence":
                data["events"][1]["sequence"] = 42
            elif mutation == "timestamp":
                data["events"][1]["observed_at"] = "2020-01-01T00:00:00+00:00"
            elif mutation == "initial":
                data["events"][0]["state"] = "AUTHORIZED"
            else:
                data["events"][-1]["state"] = "UNKNOWN"
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                ExecutionRecord.model_validate(data)

    def test_missing_authority_cannot_claim_authorized(self):
        value = synthetic_record().model_dump(mode="python")
        value["authorization_sha256"] = None
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(value)

    def test_completion_requires_real_process_zero_exit_and_cleanup(self):
        for mutation in ("process", "returncode", "timed_out", "cancelled", "truncated", "capture_failed", "cleanup"):
            data = synthetic_record().model_dump(mode="python")
            if mutation == "process":
                data["process"] = None
                data["fixture_execution_status"] = "NOT_STARTED"
            elif mutation == "returncode":
                data["process"]["returncode"] = 7
            elif mutation == "cleanup":
                data["process"]["cleanup"].update(status="UNKNOWN", group_absent=False)
            else:
                data["process"][mutation] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                ExecutionRecord.model_validate(data)

    def test_unknown_start_metadata_can_be_preserved_without_inventing_values(self):
        process = synthetic_record().process.model_dump(mode="python")
        process.update(action_started=False, pgid=None, session_id=None, start_ticks=None, uid=None, gid=None)
        process["resources"].update(status="UNKNOWN", cpu_seconds=None, memory_bytes=None)
        checked = ProcessObservation.model_validate(process)
        self.assertTrue(checked.started)
        self.assertFalse(checked.action_started)

    def test_action_gate_cannot_open_without_complete_native_identity(self):
        for key in ("pgid", "session_id", "start_ticks", "uid", "gid"):
            process = synthetic_record().process.model_dump(mode="python")
            process[key] = None
            with self.subTest(key=key), self.assertRaises(ValidationError):
                ProcessObservation.model_validate(process)

    def test_source_argv_and_candidate_hash_are_exact_registered_bytes(self):
        for mutation in ("argv", "candidate", "action"):
            data = synthetic_record().model_dump(mode="python")
            if mutation == "argv":
                data["process"]["argv"][-1] += "\nprint('unregistered')\n"
            elif mutation == "candidate":
                data["candidate_sha256"] = "0" * 64
            else:
                data["action_id"] = "unregistered"
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                ExecutionRecord.model_validate(data)

    def test_output_hash_length_and_aggregate_cap_are_validated(self):
        for mutation in ("hash", "length", "cap", "base64"):
            process = synthetic_record().process.model_dump(mode="python")
            if mutation == "hash":
                process["stdout_sha256"] = "0" * 64
            elif mutation == "length":
                process["stdout_size_bytes"] += 1
            elif mutation == "cap":
                process["resource_limits"]["max_output_bytes"] = 1
            else:
                process["stdout_b64"] = "not base64!"
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                ProcessObservation.model_validate(process)

    def test_false_signal_or_inferred_resource_limits_rejected(self):
        process = synthetic_record().process.model_dump(mode="python")
        process["linux_signal"] = 9
        with self.assertRaises(ValidationError):
            ProcessObservation.model_validate(process)
        process = synthetic_record().process.model_dump(mode="python")
        process["resources"]["memory_bytes"] += 1
        with self.assertRaises(ValidationError):
            ProcessObservation.model_validate(process)

    def test_revalidate_mutated_nested_model_without_boolean_integer_coercion(self):
        record = synthetic_record()
        modified = record.process.model_copy(update={"pid": True})
        payload = record.model_dump(mode="python")
        payload["process"] = modified
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(payload)
        modified_record = record.model_copy(update={"candidate_execution_status": "EXECUTED"})
        with self.assertRaises(ValidationError):
            canonical_sha256(modified_record)

    def test_cleanup_confirmation_requires_actual_absence_and_reaping(self):
        data = synthetic_record().process.cleanup.model_dump(mode="python")
        for key in ("parent_reaped", "group_absent", "descendants_absent"):
            payload = deepcopy(data)
            payload[key] = False
            with self.subTest(key=key), self.assertRaises(ValidationError):
                CleanupObservation.model_validate(payload)

    def test_separate_recovery_needs_dead_worker_empty_group_and_identity(self):
        recovery = synthetic_recovery()
        for key in ("worker_alive", "group_empty", "identity_match"):
            data = recovery.model_dump(mode="python")
            data[key] = True if key == "worker_alive" else False
            with self.subTest(key=key), self.assertRaises(ValidationError):
                RemoteRecoveryCheck.model_validate(data)

    def test_manifest_file_paths_must_not_escape_evidence_directory(self):
        for path in ("../stdout.bin", "/stdout.bin", "C:\\stdout.bin", "nested/stdout.bin"):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                ArtifactReference(file=path, size_bytes=0, sha256="0" * 64)

    def test_manifest_cannot_claim_completion_without_recovery(self):
        record = synthetic_record()
        data = dict(request_id=record.request_id, run_id=record.run_id,
                    execution_record_sha256=canonical_sha256(record), request_sha256=record.request_sha256,
                    authorization_sha256=record.authorization_sha256, policy_sha256=record.policy_sha256,
                    snapshot_sha256=record.snapshot_sha256, candidate_sha256=record.candidate_sha256,
                    platform_environment_id=record.platform_environment_id, platform_probe_id=record.platform_probe_id,
                    tool_record_id=record.tool_record_id, tool_file_sha256=record.tool_identity.file_sha256,
                    remote_status="COMPLETED", effective_status="COMPLETED", cleanup_confirmation="UNKNOWN",
                    artifacts={"stdout.bin": dict(file="stdout.bin", size_bytes=0, sha256="0" * 64)},
                    capture_complete=True, truncated=False, protection={"status": "SYNTHETIC"})
        with self.assertRaises(ValidationError):
            EvidenceManifest.model_validate(data)

    def test_lost_running_observation_requires_unknown_fixture_status(self):
        data = synthetic_record().model_dump(mode="python")
        data.update(status="UNKNOWN", process=None, fixture_execution_status="NOT_STARTED")
        data["events"][-1]["state"] = "UNKNOWN"
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)
        data["fixture_execution_status"] = "UNKNOWN"
        self.assertEqual(ExecutionRecord.model_validate(data).fixture_execution_status, "UNKNOWN")

    def test_observed_process_cannot_belong_to_another_target_or_worker(self):
        for key, value in (("target_environment", "wsl:Other"), ("worker_pid", 20000)):
            data = synthetic_record().model_dump(mode="python")
            data["process"][key] = value
            with self.subTest(key=key), self.assertRaises(ValidationError):
                ExecutionRecord.model_validate(data)

    def test_process_time_cannot_be_outside_record_lifecycle(self):
        data = synthetic_record().model_dump(mode="python")
        data["process"]["started_at"] = "2020-01-01T00:00:00+00:00"
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)

    def test_zero_exit_cannot_be_called_nonzero_or_cve_verified(self):
        data = synthetic_record(state="NONZERO_EXIT").model_dump(mode="python")
        data["process"]["returncode"] = 0
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)
        data = synthetic_record().model_dump(mode="python")
        data["verification_status"] = "VERIFIED"
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)

    def test_missing_timeout_resource_or_capture_observation_is_rejected(self):
        for state, flag in (("TIMED_OUT", "timed_out"), ("RESOURCE_LIMIT", "resource_limit_reason"),
                            ("CAPTURE_FAILED", "capture_failed")):
            data = synthetic_record(state=state).model_dump(mode="python")
            data["process"][flag] = None if flag == "resource_limit_reason" else False
            with self.subTest(state=state), self.assertRaises(ValidationError):
                ExecutionRecord.model_validate(data)

    def test_record_unknown_fields_and_nonfinite_duration_are_rejected(self):
        data = synthetic_record().model_dump(mode="python")
        data["llm_override"] = "COMPLETED"
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)
        data.pop("llm_override")
        data["process"]["duration_seconds"] = float("nan")
        with self.assertRaises(ValidationError):
            ExecutionRecord.model_validate(data)

    def test_request_versions_preserve_exact_artifact_contracts(self):
        old, _, _ = fixed_request()
        current, *_ = synthetic_context()
        self.assertEqual(old.request_schema_version, "1.0")
        self.assertEqual(set(old.expected_artifacts), {"stdout.bin", "stderr.bin", "tool_result.json"})
        self.assertEqual(current.request_schema_version, "1.1")
        self.assertEqual(set(current.expected_artifacts), {"stdout.bin", "stderr.bin", "process_result.json"})
        for version, wrong_artifact in (("1.0", "process_result.json"), ("1.1", "tool_result.json")):
            data = current.model_dump(mode="python")
            data.update(request_schema_version=version, expected_artifacts=["stdout.bin", "stderr.bin", wrong_artifact])
            with self.subTest(version=version), self.assertRaises(ValidationError):
                ExecutionRequest.model_validate(data)

    def test_request_required_artifacts_cannot_be_missing_duplicated_or_mixed(self):
        current, *_ = synthetic_context()
        for files in (["stdout.bin", "stderr.bin"], ["stdout.bin", "stdout.bin", "process_result.json"],
                      ["stdout.bin", "tool_result.json", "process_result.json"],
                      ["stdout.bin", "stderr.bin", "process_result.json", "tool_result.json"]):
            data = current.model_dump(mode="python")
            data["expected_artifacts"] = files
            with self.subTest(files=files), self.assertRaises(ValidationError):
                ExecutionRequest.model_validate(data)


if __name__ == "__main__":
    unittest.main()
