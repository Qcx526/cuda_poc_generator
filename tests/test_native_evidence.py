"""Synthetic native-file evidence tests; no CUDA or external process is run."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.lifecycle_artifacts import (_write_file, _sync_directory, EvidenceWriteError,
                                     write_execution_evidence, read_execution_evidence, rebuild_execution_report)
from src.models.lifecycle import ExecutionRecord
from src.native_evidence import (export_native_evidence, validate_native_evidence, NativeEvidenceBundle)
from tests.test_lifecycle_artifacts import synthetic_lifecycle_context


def native_context(folder):
    result, context = synthetic_lifecycle_context()
    record = ExecutionRecord.model_validate(result["record"])
    values = {"execution_record.json": record.model_dump(mode="json"),
        "request.json": context["request"].model_dump(mode="json"),
        "authorization.json": context["authorization"].model_dump(mode="json"),
        "policy.json": context["policy"].model_dump(mode="json"),
        "snapshot.json": context["snapshot"],
        "tool_record.json": context["binding_tool_result"].model_dump(mode="json"),
        "preflight.json": {"preflight_schema_version": "1.0", "request_id": record.request_id,
            "status": "READY", "diagnostics": [], "checked_at": record.started_at,
            "measured_candidate_sha256": record.candidate_sha256,
            "measured_tool_sha256": context["request"].tool_identity.file_sha256,
            "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"},
        "lease.json": {"request_id": record.request_id, "run_id": record.run_id,
            "target_environment": record.target_environment, "worker": {"pid": record.worker_pid}}}
    for name, value in values.items():
        (folder / name).write_bytes((json.dumps(value, sort_keys=True) + "\n").encode())
    (folder / "stdout.bin").write_bytes(record.process.stdout_bytes())
    (folder / "stderr.bin").write_bytes(record.process.stderr_bytes())
    (folder / "worker_events.jsonl").write_bytes(b"")
    return record, result, context


def validate(bundle, record, context):
    return validate_native_evidence(bundle, record, context["request"], context["authorization"],
        context["policy"], context["snapshot"], context["binding_tool_result"])


class TestNativeOriginalEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.record, self.result, self.context = native_context(self.folder)

    def test_exact_original_bytes_round_trip_and_immutable_index(self):
        first = export_native_evidence(self.folder, self.record)
        second = export_native_evidence(self.folder, self.record)
        self.assertEqual(first, second)
        files, observed = validate(first, self.record, self.context)
        self.assertEqual(observed.status, "VERIFIED")
        self.assertEqual(files["execution_record.json"], (self.folder / "execution_record.json").read_bytes())
        self.assertEqual(first.index_sha256, hashlib.sha256((self.folder / "native_evidence_index.json").read_bytes()).hexdigest())

    def test_changed_or_missing_original_after_index_is_rejected(self):
        for name, raw in (("stdout.bin", b"replacement"), ("lease.json", None)):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                record, _, _ = native_context(root)
                export_native_evidence(root, record)
                (root / name).unlink() if raw is None else (root / name).write_bytes(raw)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    export_native_evidence(root, record)

    def test_unavailable_or_initially_incomplete_is_never_verified(self):
        files, observation = validate(None, self.record, self.context)
        self.assertEqual(files, {})
        self.assertEqual(observation.status, "UNAVAILABLE")
        (self.folder / "stdout.bin").unlink()
        bundle = export_native_evidence(self.folder, self.record)
        _, observation = validate(bundle, self.record, self.context)
        self.assertEqual(observation.status, "INCOMPLETE")
        self.assertIn("stdout.bin", bundle.index.missing_files)

    def test_corrupt_or_truncated_transport_does_not_validate(self):
        bundle = export_native_evidence(self.folder, self.record).model_dump(mode="python")
        for field in ("index_b64", "files_b64"):
            data = deepcopy(bundle)
            if field == "index_b64":
                data[field] = data[field][:-4]
            else:
                data[field]["stdout.bin"] = base64.b64encode(b"altered").decode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                NativeEvidenceBundle.model_validate(data)

    def test_foreign_run_or_windows_authority_is_rejected(self):
        bundle = export_native_evidence(self.folder, self.record)
        changed = self.record.model_dump(mode="python")
        changed["run_id"] = "f" * 32
        with self.assertRaises(ValueError):
            validate(bundle, ExecutionRecord.model_validate(changed), self.context)
        changed_context = dict(self.context)
        changed_context["authorization"] = self.context["authorization"].model_copy(update={"operator_id": "foreign"})
        with self.assertRaises(ValueError):
            validate(bundle, self.record, changed_context)

    def test_native_lease_cannot_describe_a_different_task(self):
        lease = json.loads((self.folder / "lease.json").read_bytes())
        lease["run_id"] = "f" * 32
        (self.folder / "lease.json").write_text(json.dumps(lease), encoding="utf-8")
        bundle = export_native_evidence(self.folder, self.record)
        with self.assertRaises(ValueError):
            validate(bundle, self.record, self.context)

    def test_arbitrary_file_and_symlink_cannot_be_exported(self):
        with self.assertRaises(ValueError):
            export_native_evidence(self.folder, self.record, expected_native_files=["../outside"])
        if os.name == "nt":
            return
        original = self.folder / "stdout.bin"
        original.unlink()
        original.symlink_to(self.folder / "stderr.bin")
        with self.assertRaises(ValueError):
            export_native_evidence(self.folder, self.record)

    def test_index_fsync_failure_is_not_a_successful_export(self):
        with patch("src.native_evidence.os.fsync", side_effect=OSError("synthetic storage failure")):
            with self.assertRaises(OSError):
                export_native_evidence(self.folder, self.record)


class TestAtomicEvidencePublication(unittest.TestCase):
    def test_fsync_and_atomic_publication_preserve_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            _write_file(root, "sample.bin", b"exact raw bytes\r\n", None)
            self.assertEqual((root / "sample.bin").read_bytes(), b"exact raw bytes\r\n")
            self.assertFalse(list(root.glob(".*.tmp")))
            with self.assertRaises(EvidenceWriteError):
                _write_file(root, "sample.bin", b"overwrite", None)
            self.assertEqual((root / "sample.bin").read_bytes(), b"exact raw bytes\r\n")

    def test_fsync_failure_does_not_publish_a_file(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.lifecycle_artifacts.os.fsync", side_effect=OSError("synthetic disk failure")):
                with self.assertRaises(EvidenceWriteError):
                    _write_file(Path(folder), "manifest.json", b"{}", None)
            self.assertFalse((Path(folder) / "manifest.json").exists())

    def test_atomic_replace_failure_keeps_evidence_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.lifecycle_artifacts.os.replace", side_effect=OSError("synthetic atomic replace unavailable")):
                with self.assertRaises(EvidenceWriteError):
                    _write_file(Path(folder), "manifest.json", b"{}", None)
            self.assertFalse((Path(folder) / "manifest.json").exists())

    def test_directory_fsync_is_reported_without_windows_guarantee(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(_sync_directory(Path(folder)), "UNSUPPORTED" if os.name == "nt" else "APPLIED")

    def test_legacy_report_and_manifest_continue_offline_rebuild(self):
        result, context = synthetic_lifecycle_context()
        with tempfile.TemporaryDirectory() as folder:
            location = write_execution_evidence(folder, result, **context)
            checked = read_execution_evidence(location)
            self.assertEqual(checked["manifest"].evidence_schema_version, "1.0")
            self.assertEqual(rebuild_execution_report(location), (location / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
