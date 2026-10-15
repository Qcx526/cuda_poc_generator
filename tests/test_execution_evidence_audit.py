"""Independent negative evidence review using entirely synthetic process data."""

import json
from pathlib import Path
import tempfile
import unittest

from src.execution_artifacts import (read_execution_evidence, render_execution_report,
                                     write_execution_evidence)
from src.models.tool_result import digest_bytes
from tests.test_execution_artifacts import synthetic_authority, synthetic_bridge_result


class TestIndependentEvidenceBinding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.result, self.request = synthetic_bridge_result()
        self.authorization, self.policy = synthetic_authority(self.result["packet"], self.request)

    def save(self):
        return write_execution_evidence(self.root, self.result, request=self.request,
                                        authorization=self.authorization, policy=self.policy)

    @staticmethod
    def rewrite_artifact_manifest(folder, name, raw):
        """Rehash one modified local artifact; cross-record identity must still fail."""
        (folder / name).write_bytes(raw)
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["artifacts"][name] = {"size_bytes": len(raw), "sha256": digest_bytes(raw)}
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        packet = json.loads((folder / "worker_packet.json").read_bytes())
        (folder / "report.md").write_bytes(render_execution_report(manifest, packet).encode("utf-8"))

    def test_same_request_id_cannot_attach_another_authorization_scope(self):
        for field, value in (("candidate_sha256", "d" * 64), ("tool_file_sha256", "d" * 64),
                             ("authorized_action", "COMPILE"), ("authorization_reference", "another-reference"),
                             ("fixture_id", "another-fixture")):
            changed = self.authorization.model_dump(mode="python")
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                write_execution_evidence(self.root, self.result, request=self.request,
                                         authorization=changed, policy=self.policy)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_same_request_id_cannot_attach_another_resource_grant(self):
        changed = self.authorization.model_dump(mode="python")
        changed["resource_limits"]["cpu_seconds"] += 1
        with self.assertRaises(ValueError):
            write_execution_evidence(self.root, self.result, request=self.request,
                                     authorization=changed, policy=self.policy)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_equivalent_scope_but_changed_issuer_cannot_replace_original_worker_grant(self):
        changed = self.authorization.model_dump(mode="python")
        changed["issuer_kind"] = "trusted_policy"
        with self.assertRaisesRegex(ValueError, "original worker input"):
            write_execution_evidence(self.root, self.result, request=self.request,
                                     authorization=changed, policy=self.policy)

    def test_policy_with_matching_request_but_changed_max_age_is_not_original_worker_input(self):
        changed = self.policy.model_dump(mode="python")
        changed["max_snapshot_age_seconds"] += 1
        with self.assertRaisesRegex(ValueError, "original worker input"):
            write_execution_evidence(self.root, self.result, request=self.request,
                                     authorization=self.authorization, policy=changed)

    def test_target_tool_and_fixture_policy_cannot_be_substituted(self):
        for field, value in (("expected_probe_id", "another-probe"), ("expected_snapshot_sha256", "d" * 64),
                             ("scope_root", "/another-root"),
                             ("allowed_tools", {self.request.tool_identity.resolved_path: "d" * 64}),
                             ("fixture_hashes", {self.request.fixture_id: "d" * 64})):
            changed = self.policy.model_dump(mode="python")
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                write_execution_evidence(self.root, self.result, request=self.request,
                                         authorization=self.authorization, policy=changed)

    def test_completed_fixture_requires_both_original_authority_artifacts(self):
        for authority in ({}, {"authorization": self.authorization}, {"policy": self.policy}):
            with self.subTest(authority=list(authority)), self.assertRaises(ValueError):
                write_execution_evidence(self.root, self.result, request=self.request, **authority)

    def test_rehashing_changed_authorization_cannot_break_original_worker_binding(self):
        folder = self.save()
        changed = self.authorization.model_dump(mode="json")
        changed["issuer_kind"] = "trusted_policy"
        self.rewrite_artifact_manifest(folder, "operator_authorization.json", json.dumps(changed).encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "original worker input"):
            read_execution_evidence(folder)

    def test_rehashing_changed_policy_cannot_break_original_worker_binding(self):
        folder = self.save()
        changed = self.policy.model_dump(mode="json")
        changed["max_snapshot_age_seconds"] += 1
        self.rewrite_artifact_manifest(folder, "preflight_policy.json", json.dumps(changed).encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "original worker input"):
            read_execution_evidence(folder)

    def test_normal_transport_cannot_suppress_its_worker_packet(self):
        result = dict(self.result, packet=None)
        with self.assertRaisesRegex(ValueError, "successful transport"):
            write_execution_evidence(self.root, result, request=self.request,
                                     authorization=self.authorization, policy=self.policy)
        folder = self.save()
        manifest = json.loads((folder / "manifest.json").read_bytes())
        del manifest["artifacts"]["worker_packet.json"]
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "successful transport"):
            read_execution_evidence(folder)

    def test_manifest_cannot_remove_both_authorization_records_from_completed_fixture(self):
        folder = self.save()
        manifest = json.loads((folder / "manifest.json").read_bytes())
        del manifest["artifacts"]["operator_authorization.json"]
        del manifest["artifacts"]["preflight_policy.json"]
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "original operator authorization"):
            read_execution_evidence(folder)
