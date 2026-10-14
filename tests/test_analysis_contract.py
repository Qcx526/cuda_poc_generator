"""Offline strict-analysis checks; no provider request or candidate execution."""

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from src.core_expert import CudaSecurityExpert, _CUDA_EXPERT_OUTPUT_SCHEMA, _CUDA_EXPERT_SYSTEM_PROMPT
from src.llm_client import LLMClient, StructuredOutputError, StructuredResponse
from src.models.analysis import AnalysisValidationError, ExpertAnalysis, resolve_target_cve, validate_analysis


def valid_analysis():
    """Complete harmless fixture, independent of CVE factual correctness."""
    return {
        "root_cause_analysis": {
            "cve_id": "CVE-2024-0124",
            "cwe_id": "CWE-416",
            "cuda_attack_surface": "Offline fixture",
            "vulnerability_class": "fixture",
            "primitive": "fixture",
            "root_cause_description": "Synthetic test proposal; not a verified vulnerability.",
            "affected_code_path": "fixture",
            "controllability": "fixture",
            "relevant_mitigations": [],
        },
        "verification_strategy": {
            "goal": "Test a static candidate without executing it",
            "preconditions": [],
            "steps": [{
                "step_id": "S01",
                "description": "Prepare a harmless source fixture",
                "pseudocode": "print a constant",
                "success_condition": "Candidate exists",
                "failure_condition": "Candidate is absent",
                "expected_cuda_behavior": "No CUDA calls",
            }],
            "confidence": 0.5,
            "cuda_version_range": "Not applicable",
            "gpu_arch_range": "Not applicable",
        },
    }


class TestStrictAnalysisModel(unittest.TestCase):
    def assert_schema_error(self, value):
        with self.assertRaises(AnalysisValidationError) as caught:
            validate_analysis(value, expected_cve_id="CVE-2024-0124")
        self.assertEqual(caught.exception.category, "SCHEMA_ERROR")
        self.assertTrue(caught.exception.diagnostics)
        return caught.exception

    def test_complete_output_round_trips_without_synthesizing_optional_fields(self):
        raw = valid_analysis()
        result = validate_analysis(raw, expected_cve_id="CVE-2024-0124")
        self.assertEqual(result.model_dump(exclude_unset=True), raw)
        self.assertNotIn("evidence", result.model_dump(exclude_unset=True)["verification_strategy"])

    def test_all_advertised_root_cause_fields_are_required(self):
        for key in valid_analysis()["root_cause_analysis"]:
            with self.subTest(field=key):
                value = valid_analysis()
                del value["root_cause_analysis"][key]
                self.assert_schema_error(value)

    def test_all_advertised_strategy_fields_are_required(self):
        for key in valid_analysis()["verification_strategy"]:
            with self.subTest(field=key):
                value = valid_analysis()
                del value["verification_strategy"][key]
                self.assert_schema_error(value)

    def test_all_six_step_fields_are_required(self):
        for key in valid_analysis()["verification_strategy"]["steps"][0]:
            with self.subTest(field=key):
                value = valid_analysis()
                del value["verification_strategy"]["steps"][0][key]
                self.assert_schema_error(value)

    def test_absent_top_level_fields_and_non_object_roots_are_rejected(self):
        for value in ({}, {"raw": "private fixture"}, [], None, "{}"):
            with self.subTest(value_type=type(value).__name__):
                self.assert_schema_error(value)

    def test_strings_are_strict_nonblank_and_never_coerced(self):
        for invalid in ("", " \t\r\n", 1, True, None, [], {}):
            with self.subTest(value_type=type(invalid).__name__):
                value = valid_analysis()
                value["root_cause_analysis"]["root_cause_description"] = invalid
                self.assert_schema_error(value)
                value = valid_analysis()
                value["verification_strategy"]["steps"][0]["pseudocode"] = invalid
                self.assert_schema_error(value)

    def test_required_lists_and_their_elements_are_strict(self):
        for group, field in (("root_cause_analysis", "relevant_mitigations"),
                             ("verification_strategy", "preconditions")):
            for invalid in ("fixture", {}, None, ("fixture",), [1], [True], [" \n"]):
                with self.subTest(group=group, field=field, value_type=type(invalid).__name__):
                    value = valid_analysis()
                    value[group][field] = invalid
                    self.assert_schema_error(value)

    def test_steps_are_required_nonempty_strict_objects(self):
        for invalid in ([], "fixture", {}, None, ["fixture"]):
            with self.subTest(value_type=type(invalid).__name__):
                value = valid_analysis()
                value["verification_strategy"]["steps"] = invalid
                self.assert_schema_error(value)

    def test_confidence_is_finite_in_range_and_nonboolean(self):
        for invalid in (-0.01, 1.01, float("nan"), float("inf"), -float("inf"),
                        "0.5", True, False, None):
            with self.subTest(value_type=type(invalid).__name__, value=invalid):
                value = valid_analysis()
                value["verification_strategy"]["confidence"] = invalid
                self.assert_schema_error(value)
        for boundary in (0, 1, 0.0, 1.0):
            with self.subTest(boundary=boundary):
                value = valid_analysis()
                value["verification_strategy"]["confidence"] = boundary
                self.assertEqual(validate_analysis(value).verification_strategy.confidence, boundary)

    def test_step_ids_have_required_format_unique_contiguous_order(self):
        for ids in (("S00",), ("S1",), ("S001",), ("s01",), ("S01 ",),
                    ("S01", "S01"), ("S01", "S03"), ("S02", "S01")):
            with self.subTest(ids=ids):
                value = valid_analysis()
                step = value["verification_strategy"]["steps"][0]
                value["verification_strategy"]["steps"] = [dict(step, step_id=item) for item in ids]
                self.assert_schema_error(value)
        value = valid_analysis()
        value["verification_strategy"]["steps"].append(
            dict(value["verification_strategy"]["steps"][0], step_id="S02")
        )
        self.assertEqual(len(validate_analysis(value).verification_strategy.steps), 2)

    def test_cve_format_and_target_identity_are_separate_failures(self):
        for invalid in ("unknown", "cve-2024-0124", "CVE-24-0124", "CVE-2024-1", "CVE-2024-0124\n"):
            with self.subTest(cve=invalid):
                value = valid_analysis()
                value["root_cause_analysis"]["cve_id"] = invalid
                self.assert_schema_error(value)
        value = valid_analysis()
        value["root_cause_analysis"]["cve_id"] = "CVE-2025-10000"
        with self.assertRaises(AnalysisValidationError) as caught:
            validate_analysis(value, expected_cve_id="CVE-2024-0124")
        self.assertEqual(caught.exception.category, "CVE_MISMATCH")
        self.assertNotIn("CVE-2025-10000", str(caught.exception.diagnostics))

    def test_cwe_requires_ascii_identifier_format_without_taxonomy_claims(self):
        for invalid in ("unknown", "CWE-", "416", "cwe-416", "CWE-416\n", "CWE-４１６", True):
            with self.subTest(cwe=invalid):
                value = valid_analysis()
                value["root_cause_analysis"]["cwe_id"] = invalid
                self.assert_schema_error(value)
        value = valid_analysis()
        value["root_cause_analysis"]["cwe_id"] = "CWE-999999999"
        self.assertEqual(validate_analysis(value).root_cause_analysis.cwe_id, "CWE-999999999")

    def test_unknown_keys_are_rejected_at_every_level(self):
        for location in ("root", "root_cause_analysis", "verification_strategy", "step"):
            with self.subTest(location=location):
                value = valid_analysis()
                target = value if location == "root" else (
                    value["verification_strategy"]["steps"][0] if location == "step" else value[location]
                )
                target["unexpected"] = "private fixture value"
                exc = self.assert_schema_error(value)
                self.assertNotIn("private fixture value", str(exc.diagnostics))
                self.assertNotIn("private fixture value", str(exc))
        value = valid_analysis()
        value["private fixture key"] = "private fixture value"
        exc = self.assert_schema_error(value)
        self.assertNotIn("private fixture key", str(exc.diagnostics))

    def test_legacy_optional_explanations_remain_compatible(self):
        value = valid_analysis()
        value["verification_strategy"]["evidence"] = ["Offline model-cited source; unverified"]
        value["verification_strategy"]["steps"][0]["expected_outcome"] = "Harmless candidate"
        self.assertEqual(validate_analysis(value).model_dump(exclude_unset=True), value)

    def test_prompt_schema_is_generated_from_the_runtime_model(self):
        self.assertEqual(_CUDA_EXPERT_OUTPUT_SCHEMA, ExpertAnalysis.model_json_schema())
        root = _CUDA_EXPERT_OUTPUT_SCHEMA["$defs"]["RootCauseAnalysis"]
        strategy = _CUDA_EXPERT_OUTPUT_SCHEMA["$defs"]["VerificationStrategy"]
        self.assertEqual(set(root["required"]), set(valid_analysis()["root_cause_analysis"]))
        self.assertEqual(set(strategy["required"]), set(valid_analysis()["verification_strategy"]))
        self.assertFalse(_CUDA_EXPERT_OUTPUT_SCHEMA["additionalProperties"])


class TestStrictJsonParsing(unittest.TestCase):
    def test_plain_object_and_complete_fences_preserve_exact_response(self):
        for raw in (' \r\n {"fixture": [1, "text"]}\t ',
                    ' \n```json\r\n{"fixture": true}\r\n``` \n',
                    '```\n{"fixture": null}\n```'):
            with self.subTest(raw=raw):
                result = LLMClient._strict_parse_json(raw)
                self.assertIsInstance(result, dict)
                self.assertIsInstance(result, StructuredResponse)
                self.assertEqual(result.raw_response, raw)
                self.assertIn("fixture", result)

    def test_invalid_truncated_or_surrounded_json_is_rejected_unchanged(self):
        invalid = ("", " \r\n\t", "private fixture content", "[]", "null", '"text"',
                   '{"private":', "{} {}", 'prefix {"fixture":1}', '{"fixture":1} suffix',
                   'Here is:\n```json\n{}\n```', '```json\n{}', '```json\n{}\n``` trailing',
                   '```json\n{}\n```\n```json\n{}\n```', '{"private":"unterminated}')
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(StructuredOutputError) as caught:
                    LLMClient._strict_parse_json(raw)
                self.assertEqual(caught.exception.category, "PARSE_ERROR")
                self.assertEqual(caught.exception.raw_response, raw)
                self.assertNotIn("private fixture content", str(caught.exception))
                self.assertNotIn("private fixture content", str(caught.exception.diagnostics))

    def test_duplicate_keys_are_rejected_in_nested_and_root_objects(self):
        for raw in ('{"fixture":1,"fixture":2}', '{"fixture":{"x":1,"x":2}}'):
            with self.subTest(raw=raw), self.assertRaises(StructuredOutputError) as caught:
                LLMClient._strict_parse_json(raw)
            self.assertEqual(caught.exception.diagnostics[0]["code"], "duplicate_json_key")

    def test_non_finite_constants_and_exponent_overflow_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity", "1e9999"):
            raw = '{"fixture":' + constant + "}"
            with self.subTest(constant=constant), self.assertRaises(StructuredOutputError) as caught:
                LLMClient._strict_parse_json(raw)
            self.assertEqual(caught.exception.raw_response, raw)
            self.assertTrue(caught.exception.diagnostics[0]["code"].startswith("non_finite"))

    def test_structured_generate_uses_strict_parser_once(self):
        client = object.__new__(LLMClient)
        raw = "  private fixture response \r\n"
        with patch.object(client, "chat", return_value=raw) as chat, \
                patch.object(client, "_safe_parse_json") as permissive:
            with self.assertRaises(StructuredOutputError) as caught:
                client.structured_generate("offline system", "offline user")
        self.assertEqual(caught.exception.raw_response, raw)
        chat.assert_called_once()
        permissive.assert_not_called()

    def test_chat_retains_provider_whitespace_while_returning_legacy_stripped_text(self):
        client = object.__new__(LLMClient)
        client.model = "offline-model"
        client.max_retries = 1
        client._timeout = 1
        client._api_key_env = "OFFLINE_FIXTURE_KEY"
        raw = ' \r\n{"fixture":1}\t '
        client.chat_model = MagicMock()
        client.chat_model.invoke.return_value = SimpleNamespace(content=raw)
        result = client.structured_generate("offline system", "offline user")
        self.assertEqual(result.raw_response, raw)
        self.assertEqual(client.last_chat_raw_response, raw)
        self.assertEqual(client.chat([{"role": "user", "content": "offline"}]), raw.strip())

    def test_non_text_provider_content_fails_without_http_retry(self):
        client = object.__new__(LLMClient)
        client.model = "offline-model"
        client.max_retries = 3
        client._timeout = 1
        client._api_key_env = "OFFLINE_FIXTURE_KEY"
        client.chat_model = MagicMock()
        client.chat_model.invoke.return_value = SimpleNamespace(content=[{"text": "fixture"}])
        with patch("src.llm_client.time.sleep") as sleep, self.assertRaises(StructuredOutputError):
            client.structured_generate("offline system", "offline user")
        client.chat_model.invoke.assert_called_once()
        sleep.assert_not_called()
        self.assertIsNone(client.last_chat_raw_response)


class TestExpertContract(unittest.TestCase):
    def test_valid_analysis_preserves_dict_and_original_response(self):
        llm = MagicMock()
        value = valid_analysis()
        raw = " \r\n" + json.dumps(value) + "\t "
        llm.structured_generate.return_value = StructuredResponse(value, raw)
        expert = CudaSecurityExpert(llm)
        result = expert.analyze({}, expected_cve_id="CVE-2024-0124")
        self.assertEqual(result, value)
        self.assertEqual(expert.last_raw_response, raw)
        self.assertEqual(llm.structured_generate.call_args.kwargs["json_schema"], ExpertAnalysis.model_json_schema())
        self.assertIn("unverified research assertions", llm.structured_generate.call_args.kwargs["user_prompt"])
        llm.structured_generate.assert_called_once()

    def test_invalid_analysis_raises_and_retains_original_response_without_retry(self):
        for invalid in ({}, {"root_cause_analysis": {"cve_id": "CVE-2024-0124"}}):
            with self.subTest(invalid=invalid):
                llm = MagicMock()
                raw = " \n" + json.dumps(invalid) + "\n "
                llm.structured_generate.return_value = StructuredResponse(invalid, raw)
                expert = CudaSecurityExpert(llm)
                with self.assertRaises(AnalysisValidationError):
                    expert.analyze({}, expected_cve_id="CVE-2024-0124")
                self.assertEqual(expert.last_raw_response, raw)
                llm.structured_generate.assert_called_once()

    def test_parse_errors_preserve_raw_response_and_category(self):
        raw = "  private malformed fixture \n"
        llm = MagicMock()
        llm.structured_generate.side_effect = StructuredOutputError(
            raw, [{"path": [], "code": "invalid_json"}]
        )
        expert = CudaSecurityExpert(llm)
        with self.assertRaises(StructuredOutputError) as caught:
            expert.analyze({}, expected_cve_id="CVE-2024-0124")
        self.assertEqual(expert.last_raw_response, raw)
        self.assertEqual(caught.exception.category, "PARSE_ERROR")
        llm.structured_generate.assert_called_once()

    def test_provider_failure_resets_prior_response_and_is_not_a_schema_failure(self):
        llm = MagicMock()
        llm.structured_generate.return_value = StructuredResponse(valid_analysis(), "prior fixture")
        expert = CudaSecurityExpert(llm)
        expert.analyze({})
        llm.structured_generate.side_effect = RuntimeError("offline provider failure")
        with self.assertRaises(RuntimeError):
            expert.analyze({})
        self.assertIsNone(expert.last_raw_response)

    def test_target_cve_mismatch_is_rejected(self):
        value = valid_analysis()
        value["root_cause_analysis"]["cve_id"] = "CVE-2025-10000"
        llm = MagicMock()
        llm.structured_generate.return_value = StructuredResponse(value, json.dumps(value))
        expert = CudaSecurityExpert(llm)
        with self.assertRaises(AnalysisValidationError) as caught:
            expert.analyze({}, expected_cve_id="CVE-2024-0124")
        self.assertEqual(caught.exception.category, "CVE_MISMATCH")

    def test_direct_expert_binds_input_target_when_expected_parameter_is_omitted(self):
        value = valid_analysis()
        value["root_cause_analysis"]["cve_id"] = "CVE-2025-10000"
        llm = MagicMock()
        llm.structured_generate.return_value = StructuredResponse(value, json.dumps(value))
        expert = CudaSecurityExpert(llm)
        with self.assertRaises(AnalysisValidationError) as caught:
            expert.analyze({"root_cause": {"cve_id": "CVE-2024-0124"}})
        self.assertEqual(caught.exception.category, "CVE_MISMATCH")
        llm.structured_generate.assert_called_once()

    def test_ambiguous_input_ids_block_the_expert_request(self):
        contexts = (
            {"root_cause": {"cve_id": "CVE-2024-0124"},
             "attack_surface": {"cve_id": "CVE-2025-10000"}},
            {"root_cause": {"cve_id": "CVE-2024-0124",
                            "root_cause": {"cve_id": "CVE-2025-10000"}}},
        )
        for context in contexts:
            with self.subTest(context=context):
                llm = MagicMock()
                expert = CudaSecurityExpert(llm)
                expert.last_raw_response = "prior private fixture"
                with self.assertRaises(AnalysisValidationError) as caught:
                    expert.analyze(context)
                self.assertEqual(caught.exception.category, "CVE_MISMATCH")
                self.assertEqual(caught.exception.diagnostics[0]["code"], "ambiguous_input_target")
                self.assertIsNone(expert.last_raw_response)
                llm.structured_generate.assert_not_called()

    def test_malformed_input_ids_block_the_expert_request(self):
        for target in (None, "", "unknown", 1, True, "CVE-2024-0124 ", "CVE-２０２４-０１２４"):
            with self.subTest(target=target):
                llm = MagicMock()
                expert = CudaSecurityExpert(llm)
                with self.assertRaises(AnalysisValidationError) as caught:
                    expert.analyze({"root_cause": {"cve_id": target}})
                self.assertEqual(caught.exception.category, "SCHEMA_ERROR")
                llm.structured_generate.assert_not_called()

    def test_explicit_expected_target_disagreement_blocks_the_expert_request(self):
        llm = MagicMock()
        expert = CudaSecurityExpert(llm)
        with self.assertRaises(AnalysisValidationError) as caught:
            expert.analyze({"root_cause": {"cve_id": "CVE-2024-0124"}},
                           expected_cve_id="CVE-2025-10000")
        self.assertEqual(caught.exception.category, "CVE_MISMATCH")
        self.assertEqual(caught.exception.diagnostics[0]["code"], "input_target_mismatch")
        llm.structured_generate.assert_not_called()

    def test_target_resolution_supports_flat_wrapped_and_legacy_empty_contexts(self):
        target = "CVE-2024-0124"
        for context in ({"root_cause": {"cve_id": target}},
                        {"root_cause": {"root_cause": {"cve_id": target}}},
                        {"cve_id": target},
                        {"root_cause": {"cve_id": target, "root_cause": {"cve_id": target}}}):
            with self.subTest(context=context):
                self.assertEqual(resolve_target_cve(context), target)
                self.assertEqual(resolve_target_cve(context, expected_cve_id=target), target)
        self.assertIsNone(resolve_target_cve({}))
        self.assertEqual(resolve_target_cve({}, expected_cve_id=target), target)
        llm = MagicMock()
        llm.structured_generate.return_value = valid_analysis()
        self.assertEqual(CudaSecurityExpert(llm).analyze({}), valid_analysis())

    def test_invalid_explicit_expected_target_blocks_the_expert_request(self):
        for target in ("unknown", "CVE-２０２４-０１２４", 1, True):
            with self.subTest(target=target):
                llm = MagicMock()
                with self.assertRaises(AnalysisValidationError) as caught:
                    CudaSecurityExpert(llm).analyze({}, expected_cve_id=target)
                self.assertEqual(caught.exception.category, "SCHEMA_ERROR")
                llm.structured_generate.assert_not_called()

    def test_seven_layer_system_prompt_is_unchanged_from_baseline(self):
        # Compare the actual Python literal from the accepted baseline, offline.
        import ast
        result = subprocess.run(
            ["git", "show", "9a7bd531ace1177dfb2a7597f2dd6a7bf0e1b35e:src/core_expert.py"],
            cwd=Path(__file__).resolve().parent.parent, capture_output=True, check=True,
        )
        module = ast.parse(result.stdout.decode("utf-8"))
        original = next(ast.literal_eval(node.value) for node in module.body
                        if isinstance(node, ast.Assign) and any(
                            isinstance(target, ast.Name) and target.id == "_CUDA_EXPERT_SYSTEM_PROMPT"
                            for target in node.targets
                        ))
        self.assertEqual(_CUDA_EXPERT_SYSTEM_PROMPT, original)


if __name__ == "__main__":
    unittest.main()
