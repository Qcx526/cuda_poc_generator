"""Operator/transport mocks and deterministic preparation reports; no CUDA."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import cuda_smoke as cli
from src.cuda_smoke_worker import CudaSmokeDescription
from src.lifecycle_artifacts import (write_cuda_readiness_evidence, read_cuda_readiness_evidence, rebuild_execution_report)
from src.lifecycle_bridge import parse_lifecycle_packet
from tests.test_cuda_contracts import synthetic_cuda_context
from tests.test_cuda_evidence import synthetic_cuda_evidence, transport_for


class TestCudaOperatorEntry(unittest.TestCase):
    def options(self):
        return {"authorize_safe_cuda_smoke": False, "authorization_reference": "synthetic-approval",
                "operator_id": "synthetic-operator", "linux_project_root": "/project"}

    def test_missing_authorization_never_communicates_or_dispatches(self):
        with patch.object(cli, "describe_cuda_smoke_wsl") as describe, patch.object(cli, "run_task_wsl") as execute:
            with self.assertRaises(ValueError):
                cli.run_safe_cuda_smoke(**self.options())
            describe.assert_not_called()
            execute.assert_not_called()

    def test_unknown_backend_or_blank_operator_is_rejected_before_communication(self):
        for changed in ({"backend": "local"}, {"operator_id": " "}, {"authorization_reference": "bad\nref"}):
            with patch.object(cli, "describe_cuda_smoke_wsl") as describe:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    cli.run_safe_cuda_smoke(**{**self.options(), "authorize_safe_cuda_smoke": True, **changed})
                describe.assert_not_called()

    def test_help_has_no_action_side_effects(self):
        output = io.StringIO()
        with patch.object(cli, "run_safe_cuda_smoke") as execute, redirect_stdout(output):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--authorize-safe-cuda-smoke", output.getvalue())
        execute.assert_not_called()

    def test_arbitrary_argv_or_source_is_not_a_cli_option(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["--authorization-reference", "ref", "--operator-id", "op", "--linux-project-root", "/project",
                      "--authorize-safe-cuda-smoke", "--source", "unknown.cu"])
        self.assertEqual(caught.exception.code, 2)

    def test_completed_process_without_verified_native_files_has_nonzero_cli_status(self):
        args = ["--authorization-reference", "ref", "--operator-id", "op", "--linux-project-root", "/project",
                "--authorize-safe-cuda-smoke"]
        for state, native, expected in (("COMPLETED", "VERIFIED", 0), ("COMPLETED", "FAILED", 1),
                                          ("UNKNOWN", "VERIFIED", 1), ("NONZERO_EXIT", "VERIFIED", 1)):
            with patch.object(cli, "run_safe_cuda_smoke", return_value={"effective_state": state, "native_evidence": native}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args), expected)

    def test_operator_scope_binds_all_tools_and_target_clock(self):
        req, _, policy, snapshot, _ = synthetic_cuda_context()
        description = CudaSmokeDescription(description_schema_version="1.0", status="DESCRIBED", snapshot=snapshot,
            scope=req.cuda_toolchain, native_task_root="/private/lifecycle_tasks", source_sha256=req.candidate_sha256,
            resource_support=policy.resource_support, diagnostics=[])
        built, auth, trusted, _, _ = cli.build_cuda_operator_context(description.model_dump(mode="json"),
            run_id="a" * 32, operator_id="op", authorization_reference="ref", arch="sm_75")
        self.assertEqual(built.cuda_toolchain, auth.cuda_toolchain)
        self.assertEqual(built.cuda_toolchain, trusted.cuda_toolchain)
        self.assertEqual(auth.authorization_clock, "TARGET_BOOT_MONOTONIC")
        self.assertEqual(auth.not_before_monotonic_ns, built.cuda_toolchain.observed_monotonic_ns)
        self.assertEqual(built.cwd, "/private/lifecycle_tasks/" + "a" * 32 + "/work")
        self.assertEqual(built.resource_limits.memory_bytes, 4294967296)
        with self.assertRaises(ValueError):
            cli.build_cuda_operator_context(description.model_dump(mode="json"), run_id="a" * 32,
                operator_id="op", authorization_reference="ref", arch="sm_86")


class TestCudaReadinessEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        native = self.root / "synthetic_native"
        native.mkdir()
        result, context = synthetic_cuda_evidence(native)
        self.packet = deepcopy(result["worker_packet"])
        self.packet.pop("native_evidence")
        self.packet.update(operation="DESCRIBE_CUDA", record=None,
            cuda_description={"description_schema_version": "1.0", "status": "UNSUPPORTED", "snapshot": None,
                "scope": None, "native_task_root": "/private/lifecycle_tasks",
                "source_sha256": context["request"].candidate_sha256,
                "resource_support": {"status": "UNKNOWN", "mechanisms": [], "source": "SYNTHETIC unavailable toolchain"},
                "diagnostics": ["NVCC_NOT_OBSERVED"]})
        self.transport = transport_for(self.packet, "3" * 32)

    def test_failed_description_has_original_bytes_and_rebuildable_report(self):
        folder = write_cuda_readiness_evidence(self.root, self.transport, self.packet, [])
        checked = read_cuda_readiness_evidence(folder)
        self.assertEqual(checked["description"].status, "UNSUPPORTED")
        self.assertEqual(rebuild_execution_report(folder), (folder / "report.md").read_text(encoding="utf-8"))
        self.assertEqual((folder / "transport_stdout.bin").read_bytes(), self.transport.stdout_bytes())
        self.assertFalse((folder / "execution_record.json").exists())

    def test_packet_truncation_or_foreign_nonce_is_rejected(self):
        options = {"operation": "DESCRIBE_CUDA", "nonce": self.packet["nonce"],
            "request_id": self.packet["request_id"], "run_id": self.packet["run_id"],
            "target_environment": self.packet["target_environment"]}
        with self.assertRaises(ValueError):
            parse_lifecycle_packet(self.transport.stdout_bytes()[:-5], **options)
        with self.assertRaises(ValueError):
            parse_lifecycle_packet(self.transport.stdout_bytes(), **{**options, "nonce": "f" * 32})

    def test_saved_description_raw_log_tamper_cannot_be_rebuilt(self):
        folder = write_cuda_readiness_evidence(self.root, self.transport, self.packet, [])
        (folder / "transport_stdout.bin").write_bytes(b"altered")
        with self.assertRaises(ValueError):
            read_cuda_readiness_evidence(folder)


if __name__ == "__main__":
    unittest.main()
