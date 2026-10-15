"""No native tool runs: target labels must come from the observed WSL process."""

from contextlib import ExitStack
from copy import deepcopy
import os
import unittest
from unittest.mock import Mock, patch

from pydantic import ValidationError

from src import platform_worker as worker
from src.models.execution_binding import bind_candidate_to_tool
from src.models.platform import PlatformSnapshot
from src.tools.process import canonical_target_environment
from tests.test_p1c_integration import synthetic_tool_record


class TestP2PlatformIdentity(unittest.TestCase):
    def observe(self, *, distro="Ubuntu-22.04", environment="local", backend="local",
                host="Linux", kernel="6.6-microsoft-standard-WSL2"):
        request = {"probe_id": "fixed-identity-probe", "nonce": "fixed-identity-nonce",
                   "execution_backend": backend, "environment_label": environment}
        query = Mock(side_effect=AssertionError("no native query is allowed by this fixture"))
        discover = Mock(return_value=None)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            if distro is not None:
                os.environ["WSL_DISTRO_NAME"] = distro
            stack.enter_context(patch.object(worker.platform, "system", return_value=host))
            stack.enter_context(patch.object(worker.platform, "release", return_value=kernel))
            stack.enter_context(patch.object(worker.platform, "version", return_value=kernel))
            stack.enter_context(patch.object(worker.platform, "machine", return_value="x86_64"))
            stack.enter_context(patch.object(worker.platform, "python_version", return_value="3.10.12"))
            stack.enter_context(patch.object(worker, "_find_tool", discover))
            stack.enter_context(patch.object(worker.Path, "read_bytes", return_value=b'PRETTY_NAME="Fixed synthetic Linux"\n'))
            try:
                result = worker.probe_platform(request, runner=query)
            except ValueError:
                discover.assert_not_called()
                query.assert_not_called()
                raise
        query.assert_not_called()
        return result

    def test_local_wsl_probe_uses_actual_distribution_and_observed_provenance(self):
        result = self.observe()
        snapshot = PlatformSnapshot.model_validate(result["snapshot"])
        self.assertEqual(snapshot.execution_backend, "local")
        self.assertEqual(snapshot.platform_type, "wsl")
        self.assertEqual(snapshot.metadata["environment_label"], "wsl:Ubuntu-22.04")
        self.assertEqual(snapshot.metadata["wsl_distribution"]["status"], "OBSERVED")
        self.assertEqual(snapshot.metadata["wsl_distribution"]["value"], "Ubuntu-22.04")
        self.assertEqual(snapshot.provenance["wsl_environment"].environment, "wsl:Ubuntu-22.04")
        with patch("src.tools.process.current_platform_type", return_value="wsl"), \
                patch.dict(os.environ, {"WSL_DISTRO_NAME": "Ubuntu-22.04"}):
            self.assertEqual(snapshot.metadata["environment_label"], canonical_target_environment())

    def test_legacy_local_and_wsl_aliases_canonicalize_to_same_actual_target(self):
        labels = [self.observe(environment=value, backend="wsl")["snapshot"]["metadata"]["environment_label"]
                  for value in ("local", "wsl", "wsl:Ubuntu-22.04")]
        self.assertEqual(labels, ["wsl:Ubuntu-22.04"] * 3)

    def test_missing_observation_cannot_be_replaced_by_requested_label(self):
        with self.assertRaisesRegex(ValueError, "identity is unavailable"):
            self.observe(distro=None, backend="wsl", environment="wsl:Ubuntu-22.04")

    def test_malformed_observation_rejected_before_tool_discovery(self):
        for distro in ("", " Ubuntu", "Ubuntu ", "Ubuntu/../other", "Ubuntu\n", "-Ubuntu"):
            with self.subTest(distro=distro), self.assertRaisesRegex(ValueError, "identity is unavailable"):
                self.observe(distro=distro)

    def test_foreign_request_distribution_is_rejected_before_queries(self):
        with self.assertRaisesRegex(ValueError, "differs from the observed"):
            self.observe(backend="wsl", environment="wsl:Different-Distro")

    def test_environment_variable_cannot_turn_non_wsl_kernel_into_wsl(self):
        for kernel in ("6.6.0-generic", "5.15.0-linux"):
            with self.subTest(kernel=kernel), self.assertRaisesRegex(ValueError, "non-WSL"):
                self.observe(kernel=kernel, backend="wsl", environment="wsl:Ubuntu-22.04")

    def test_distro_metadata_cannot_disagree_with_target(self):
        value = self.observe()["snapshot"]
        value["metadata"]["wsl_distribution"]["value"] = "Different-Distro"
        with self.assertRaises(ValidationError):
            PlatformSnapshot.model_validate(value)

    def test_unobserved_distro_metadata_cannot_claim_target_identity(self):
        value = self.observe()["snapshot"]
        value["metadata"]["wsl_distribution"].update(status="CONFIGURED", source_ids=[])
        with self.assertRaises(ValidationError):
            PlatformSnapshot.model_validate(value)

    def test_changed_environment_metadata_with_changed_sources_still_checks_observed_distro(self):
        value = self.observe()["snapshot"]
        value["metadata"]["environment_label"] = "wsl:Different-Distro"
        for source in value["provenance"].values():
            source["environment"] = "wsl:Different-Distro"
        with self.assertRaises(ValidationError):
            PlatformSnapshot.model_validate(value)

    def test_stored_distribution_identity_must_have_valid_distro_syntax(self):
        for distro in ("Ubuntu/../other", "Ubuntu\n", " Ubuntu", "Ubuntu "):
            value = self.observe()["snapshot"]
            value["metadata"]["wsl_distribution"]["value"] = distro
            target = "wsl:" + distro
            value["metadata"]["environment_label"] = target
            for source in value["provenance"].values():
                source["environment"] = target
            with self.subTest(distro=distro), self.assertRaises(ValidationError):
                PlatformSnapshot.model_validate(value)

    def test_new_observation_keeps_candidate_tool_target_check(self):
        from src.models.tool_result import compute_record_id

        snapshot = self.observe(backend="wsl")["snapshot"]
        tool = synthetic_tool_record()
        binding = bind_candidate_to_tool(b"fixed harmless source", snapshot, tool,
                                         expected_probe_id="fixed-identity-probe", expected_tool_record_id=tool.record_id)
        self.assertEqual(binding.target_environment, "wsl:Ubuntu-22.04")
        mismatched = deepcopy(tool.model_dump(mode="json"))
        mismatched["target_environment"] = "local"
        mismatched["record_id"] = compute_record_id(mismatched)
        with self.assertRaisesRegex(ValueError, "different environments"):
            bind_candidate_to_tool(b"fixed harmless source", snapshot, mismatched,
                                   expected_probe_id="fixed-identity-probe", expected_tool_record_id=mismatched["record_id"])


if __name__ == "__main__":
    unittest.main()
