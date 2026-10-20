"""P1-A offline contract regressions; never execute a candidate or call a provider."""

import ast
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import MagicMock, patch

from tests.test_baseline import ANALYSIS, OfflineTestCase, PROJECT_ROOT, SAFE_CODE


CASE_ID = "CVE-2024-0124"
CASE_SOURCE = PROJECT_ROOT / "data" / "inputs" / CASE_ID


class TestPipelineAnalysisGate(OfflineTestCase):
    """Exercise the actual parser, expert, and generator behind offline boundaries."""

    @contextmanager
    def pipeline(self, outputs, responses):
        cfg = self.config()
        cfg.config["paths"]["outputs_dir"] = str(outputs)
        cfg.config["rag"]["enabled"] = False
        client = object.__new__(self.llm_module.LLMClient)
        client.chat = MagicMock(side_effect=responses)
        env = {"gpu": {"gpu_count": 0}, "toolchain": {}, "os": {}}
        with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                patch.object(self.pipeline_module, "LLMClient", return_value=client) as constructor, \
                patch.object(self.pipeline_module, "probe_environment", return_value=env) as probe, \
                patch.object(self.pipeline_module.CudaDataLoader, "build_or_load_knowledge_base") as rag, \
                patch.object(self.pipeline_module.CudaPipeline, "_query_web_search", return_value="") as search, \
                redirect_stdout(StringIO()):
            pipeline = self.pipeline_module.CudaPipeline()
            client.offline_constructor = constructor
            yield pipeline, client, probe, rag, search

    def report(self, outputs):
        files = list(Path(outputs).rglob("cuda_run_v1.json"))
        self.assertEqual(len(files), 1, "Each single-shot run must have one machine-readable report")
        return json.loads(files[0].read_text(encoding="utf-8"))

    def assert_no_current_candidate(self, outputs):
        self.assertEqual(list(Path(outputs).rglob("cuda_poc_v1.py")), [])
        self.assertEqual(list(Path(outputs).rglob("cuda_analysis_v1.json")), [])

    def test_missing_input_stops_all_analysis_and_generation_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            shutil.copytree(CASE_SOURCE, inputs)
            (inputs / "7_root_cause.json").unlink()
            outputs = root / "outputs"
            with self.pipeline(outputs, []) as (pipeline, client, probe, rag, search), \
                    patch.object(self.pipeline_module.CudaSecurityExpert, "analyze") as expert, \
                    patch.object(self.pipeline_module.CudaCodeGenerator, "generate") as generate:
                with self.assertRaises(ValueError):
                    pipeline.run(input_dir=str(inputs))
            client.chat.assert_not_called()
            client.offline_constructor.assert_not_called()
            expert.assert_not_called()
            generate.assert_not_called()
            probe.assert_not_called()
            rag.assert_not_called()
            search.assert_not_called()
            self.assert_no_current_candidate(outputs)
            report = self.report(outputs)
            self.assertEqual(report["status"], "INPUT_INVALID")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_cli_invalid_input_exits_nonzero_before_provider_setup(self):
        import main as cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            shutil.copytree(CASE_SOURCE, inputs)
            (inputs / "7_root_cause.json").unlink()
            outputs = root / "outputs"
            argv = ["main.py", "--input-dir", str(inputs), "--output-dir", str(outputs), "--no-rag"]
            with self.pipeline(outputs, []) as (_, client, _, _, _), \
                    patch.object(sys, "argv", argv), patch.object(cli, "setup_logging"), \
                    redirect_stdout(StringIO()) as console:
                with self.assertRaises(SystemExit) as failure:
                    cli.main()
            self.assertEqual(failure.exception.code, 1)
            self.assertIn("[ERROR]", console.getvalue())
            client.offline_constructor.assert_not_called()
            client.chat.assert_not_called()
            self.assertEqual(self.report(outputs)["status"], "INPUT_INVALID")

    def test_invalid_analysis_responses_cannot_reach_codegen(self):
        missing = deepcopy(ANALYSIS)
        del missing["verification_strategy"]["steps"][0]["pseudocode"]
        mismatch = deepcopy(ANALYSIS)
        mismatch["root_cause_analysis"]["cve_id"] = "CVE-2024-9999"
        cases = (
            (" \t\r\n{\"truncated\":\r\n ", "ANALYSIS_PARSE_ERROR"),
            (" \t\r\n" + json.dumps(missing) + "\r\n\t ", "ANALYSIS_SCHEMA_ERROR"),
            (" \t\r\n" + json.dumps(mismatch) + "\r\n\t ", "ANALYSIS_CVE_MISMATCH"),
        )
        for raw, expected_status in cases:
            with self.subTest(status=expected_status), tempfile.TemporaryDirectory() as directory:
                outputs = Path(directory)
                with self.pipeline(outputs, [raw, raw]) as (pipeline, client, _, _, _), \
                        patch.object(self.pipeline_module.CudaCodeGenerator, "generate") as generate:
                    with self.assertRaises(ValueError):
                        pipeline.run(input_dir=str(CASE_SOURCE))
                # The client may take one bounded repair attempt before the
                # strict parser gives up; codegen must never be reached.
                self.assertGreaterEqual(client.chat.call_count, 1)
                self.assertLessEqual(client.chat.call_count, 2)
                generate.assert_not_called()
                self.assert_no_current_candidate(outputs)
                raw_files = list(outputs.rglob("cuda_analysis_v1.raw.txt"))
                self.assertEqual(len(raw_files), 1)
                self.assertEqual(raw_files[0].read_bytes().decode("utf-8"), raw)
                report = self.report(outputs)
                self.assertEqual(report["status"], expected_status)
                self.assertEqual(report["execution"], "NOT_EXECUTED")
                self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_pipeline_defends_against_an_expert_returning_unvalidated_data(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, []) as (pipeline, client, _, _, _), \
                    patch.object(self.pipeline_module.CudaSecurityExpert, "analyze", return_value={"unexpected": "payload"}), \
                    patch.object(self.pipeline_module.CudaCodeGenerator, "generate") as generate:
                with self.assertRaises(ValueError):
                    pipeline.run(input_dir=str(CASE_SOURCE))
            generate.assert_not_called()
            client.chat.assert_not_called()
            self.assert_no_current_candidate(outputs)
            self.assertEqual(self.report(outputs)["status"], "ANALYSIS_SCHEMA_ERROR")

    def test_valid_analysis_preserves_raw_and_existing_single_shot_artifacts(self):
        analysis = deepcopy(ANALYSIS)
        analysis["root_cause_analysis"]["root_cause_description"] = "离线合同测试；未验证漏洞。"
        raw = " \t\r\n" + json.dumps(analysis, ensure_ascii=False) + "\r\n\t "
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [raw, SAFE_CODE]) as (pipeline, client, probe, rag, search):
                result = pipeline.run(input_dir=str(CASE_SOURCE))
            output = outputs / CASE_ID
            saved_analysis = json.loads((output / "cuda_analysis_v1.json").read_text(encoding="utf-8"))
            self.assertEqual(saved_analysis, analysis)
            self.assertEqual((output / "cuda_analysis_v1.raw.txt").read_bytes().decode("utf-8"), raw)
            candidate = (output / "cuda_poc_v1.py").read_bytes()
            ast.parse(candidate.decode("utf-8"))
            self.assertEqual((output / "cuda_poc_v1.py").read_text(encoding="utf-8"), SAFE_CODE)
            self.assertEqual(client.chat.call_count, 2, "One analysis and one code request are single-shot")
            probe.assert_called_once()
            rag.assert_called_once()
            search.assert_called_once()
            report = self.report(outputs)
            self.assertEqual(result, report)
            self.assertEqual(report["candidate"]["generation"], "GENERATED")
            self.assertEqual(report["candidate"]["static"], "STATIC_VALID")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")
            status = json.loads((output / "cuda_poc_v1.status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["generation"], "GENERATED")
            self.assertEqual(status["static"], "STATIC_VALID")
            self.assertEqual(status["sha256"], hashlib.sha256(candidate).hexdigest())

    def test_provider_failure_has_no_candidate_or_verification_success(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [RuntimeError("offline provider failure")]) as (pipeline, client, _, _, _), \
                    patch.object(self.pipeline_module.CudaCodeGenerator, "generate") as generate:
                with self.assertRaises(RuntimeError):
                    pipeline.run(input_dir=str(CASE_SOURCE))
            client.chat.assert_called_once()
            generate.assert_not_called()
            self.assert_no_current_candidate(outputs)
            report = self.report(outputs)
            self.assertEqual(report["status"], "PROVIDER_ERROR")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_codegen_provider_failure_preserves_analysis_without_false_success(self):
        raw = json.dumps(ANALYSIS)
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [raw, RuntimeError("offline code generation failure")]) as (pipeline, client, _, _, _):
                with self.assertRaises(RuntimeError):
                    pipeline.run(input_dir=str(CASE_SOURCE))
            self.assertEqual(client.chat.call_count, 2)
            self.assertTrue((outputs / CASE_ID / "cuda_analysis_v1.json").is_file())
            self.assertEqual(list(outputs.rglob("cuda_poc_v1.py")), [])
            report = self.report(outputs)
            self.assertEqual(report["status"], "GENERATION_FAILED")
            self.assertEqual(report["candidate"]["generation"], "GENERATION_FAILED")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_empty_code_response_is_a_generation_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [json.dumps(ANALYSIS), " \t\r\n "]) as (pipeline, client, _, _, _):
                with self.assertRaises(ValueError):
                    pipeline.run(input_dir=str(CASE_SOURCE))
            self.assertEqual(client.chat.call_count, 2)
            self.assertEqual(list(outputs.rglob("cuda_poc_v1.py")), [])
            report = self.report(outputs)
            self.assertEqual(report["status"], "GENERATION_FAILED")
            self.assertEqual(report["candidate"]["generation"], "GENERATION_FAILED")
            self.assertEqual(report["candidate"]["static"], "NOT_CHECKED")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_static_valid_source_that_would_raise_is_never_executed(self):
        sentinel = 'raise RuntimeError("candidate execution must never happen")\n'
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [json.dumps(ANALYSIS), sentinel]) as (pipeline, client, _, _, _):
                report = pipeline.run(input_dir=str(CASE_SOURCE))
            self.assertEqual((outputs / CASE_ID / "cuda_poc_v1.py").read_text(encoding="utf-8"), sentinel)
            self.assertEqual(client.chat.call_count, 2)
            self.assertEqual(report["candidate"]["generation"], "GENERATED")
            self.assertEqual(report["candidate"]["static"], "STATIC_VALID")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_static_invalid_candidate_is_saved_without_execution_or_verification(self):
        raw = json.dumps(ANALYSIS)
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [raw, "def invalid(:\n", "def invalid(:\n", "def invalid(:\n"]) as (pipeline, client, _, _, _):
                report = pipeline.run(input_dir=str(CASE_SOURCE))
            self.assertEqual(client.chat.call_count, 4, "Analysis plus at most three candidate requests")
            output = outputs / CASE_ID
            with self.assertRaises(SyntaxError):
                ast.parse((output / "cuda_poc_v1.py").read_text(encoding="utf-8"))
            self.assertEqual(report["candidate"]["generation"], "GENERATED")
            self.assertEqual(report["candidate"]["static"], "STATIC_INVALID")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")
            status = json.loads((output / "cuda_poc_v1.status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["correction_attempts"], 2)
            self.assertTrue(status["errors"])


    def test_codegen_model_routing_builds_a_second_client(self):
        cfg = self.config()
        cfg.config["llm"]["codegen_model"] = "codegen-model-x"
        first, second = MagicMock(), MagicMock()
        with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                patch.object(self.pipeline_module, "LLMClient",
                             side_effect=[first, second]) as constructor, \
                patch.object(self.pipeline_module, "CudaCodeGenerator") as generator:
            pipeline = self.pipeline_module.CudaPipeline()
            pipeline._initialize_components("out")
        self.assertEqual(constructor.call_count, 2)
        self.assertEqual(constructor.call_args_list[1].kwargs.get("model_override"),
                         "codegen-model-x")
        self.assertIs(generator.call_args.args[0], second)

    def test_failed_second_run_does_not_reuse_prior_candidate_as_current_success(self):
        raw = json.dumps(ANALYSIS)
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            with self.pipeline(outputs, [raw, SAFE_CODE, "not JSON", "not JSON"]) as (pipeline, client, _, _, _):
                first_report = pipeline.run(input_dir=str(CASE_SOURCE))
                saved = outputs / CASE_ID / "cuda_poc_v1.py"
                previous_bytes = saved.read_bytes()
                with self.assertRaises(ValueError):
                    pipeline.run(input_dir=str(CASE_SOURCE))
            self.assertEqual(saved.read_bytes(), previous_bytes, "Failure must not delete user's previous candidate")
            self.assertFalse((outputs / CASE_ID / CASE_ID).exists(), "Repeated runs must not nest CVE directories")
            # analysis + codegen + one bounded JSON repair
            self.assertEqual(client.chat.call_count, 4)
            report = self.report(outputs)
            self.assertEqual(report["status"], "ANALYSIS_PARSE_ERROR")
            self.assertEqual(report["candidate"]["generation"], "NOT_GENERATED")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")
            self.assertTrue(report["preexisting_artifacts"])
            self.assertNotIn("candidate", report.get("artifacts", {}))
            self.assertNotEqual(report["run_id"], first_report["run_id"])
            status = json.loads((outputs / CASE_ID / "cuda_poc_v1.status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["run_id"], report["run_id"])
            self.assertEqual(status["generation"], "NOT_GENERATED")
            self.assertIsNone(status["source_file"])
            self.assertIsNone(status["sha256"])


class TestDirectGeneratorTargetGate(OfflineTestCase):
    """Public generator callers must satisfy the same target identity contract."""

    def test_mismatched_analysis_target_never_requests_or_saves_code(self):
        analysis = deepcopy(ANALYSIS)
        analysis["root_cause_analysis"]["cve_id"] = "CVE-2024-9999"
        client = self.fake_llm()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            generator = self.codegen_module.CudaCodeGenerator(
                client, self.library_module.CudaLibrary(), directory,
            )
            with self.assertRaises(ValueError) as failure:
                generator.generate({"root_cause": {"cve_id": CASE_ID}}, analysis)
            self.assertEqual(getattr(failure.exception, "category", None), "CVE_MISMATCH")
            client.chat.assert_not_called()
            self.assertFalse((Path(directory) / "cuda_poc_v1.py").exists())
            self.assertEqual(generator.last_result.generation, "GENERATION_FAILED")
            self.assertEqual(generator.last_result.execution, "NOT_EXECUTED")
            self.assertEqual(generator.last_result.verification, "NOT_VERIFIED")
            self.assertIsNone(generator.last_result.source_file)
            self.assertIsNone(generator.last_result.sha256)

    def test_conflicting_or_malformed_context_ids_never_request_code(self):
        contexts = (
            {"root_cause": {"cve_id": CASE_ID},
             "vulnerability_type": {"cve_id": "CVE-2024-9999"}},
            {"root_cause": {"cve_id": "invalid-target"}},
            {"root_cause": {"cve_id": 1234}},
        )
        for context in contexts:
            with self.subTest(context=context), tempfile.TemporaryDirectory() as directory, \
                    redirect_stdout(StringIO()):
                client = self.fake_llm()
                generator = self.codegen_module.CudaCodeGenerator(
                    client, self.library_module.CudaLibrary(), directory,
                )
                with self.assertRaises(ValueError):
                    generator.generate(context, deepcopy(ANALYSIS))
                client.chat.assert_not_called()
                self.assertFalse((Path(directory) / "cuda_poc_v1.py").exists())
                self.assertEqual(generator.last_result.generation, "GENERATION_FAILED")
                self.assertEqual(generator.last_result.execution, "NOT_EXECUTED")
                self.assertEqual(generator.last_result.verification, "NOT_VERIFIED")

    def test_matching_normalized_target_preserves_single_shot_generation(self):
        context = self.loader_module.CudaDataLoader(self.config()).load_normalized_inputs(
            str(CASE_SOURCE),
        ).require_valid().dimensions
        client = self.fake_llm()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            generator = self.codegen_module.CudaCodeGenerator(
                client, self.library_module.CudaLibrary(), directory,
            )
            returned = generator.generate(context, deepcopy(ANALYSIS))
            self.assertEqual(returned, SAFE_CODE)
            self.assertEqual((Path(directory) / "cuda_poc_v1.py").read_text(encoding="utf-8"), SAFE_CODE)
            client.chat.assert_called_once()
            self.assertEqual(generator.last_result.generation, "GENERATED")
            self.assertEqual(generator.last_result.static, "STATIC_VALID")
            self.assertEqual(generator.last_result.execution, "NOT_EXECUTED")
            self.assertEqual(generator.last_result.verification, "NOT_VERIFIED")


class TestNormalizedRagQueryCompatibility(OfflineTestCase):
    """Check retrieval query information without initializing RAG or embeddings."""

    def query_for_case(self, case_id):
        loader = self.loader_module.CudaDataLoader(self.config())
        context = loader.load_normalized_inputs(
            str(PROJECT_ROOT / "data" / "inputs" / case_id),
        ).require_valid().dimensions
        loader.rag_enabled = True
        pipeline = object.__new__(self.pipeline_module.CudaPipeline)
        pipeline.data_loader = loader
        with patch.object(loader, "query_knowledge", return_value="offline retrieval result") as retrieve, \
                patch.object(loader, "build_or_load_knowledge_base") as initialize, \
                redirect_stdout(StringIO()):
            returned = pipeline._query_rag(context)
        self.assertEqual(returned, "offline retrieval result")
        retrieve.assert_called_once()
        initialize.assert_not_called()
        return context, retrieve.call_args.args[0]

    def test_flat_case_keeps_distinct_short_and_formal_component_labels(self):
        context, query = self.query_for_case("CVE-2024-0076")
        affected = context["affected_component"]
        self.assertNotEqual(affected["name"], affected["component_name"])
        self.assertIn("CUDA Component name: " + affected["name"], query)
        self.assertIn("CUDA Component component_name: " + affected["component_name"], query)
        self.assertIn(context["vulnerability_type"]["cwe_id"], query)
        self.assertIn(context["root_cause"]["summary"][:80], query)

    def test_wrapped_case_keeps_vulnerable_code_summary_in_query(self):
        context, query = self.query_for_case("CVE-2025-23339")
        self.assertIn("CVE-2025-23339", query)
        self.assertIn(context["vulnerability_type"]["cwe_id"], query)
        self.assertIn(context["root_cause"]["vulnerable_code_summary"][:80], query)
