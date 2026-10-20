"""Offline regression checks; never call providers, CUDA tools, or generated code."""

import ast
import builtins
from contextlib import redirect_stdout
from copy import deepcopy
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "default.yaml"
INPUT_KEYS = (
    "os_environment", "cuda_environment", "affected_component", "attack_surface",
    "vulnerability_type", "impact_controllability", "root_cause",
)
SAFE_CODE = '"""Harmless offline generation fixture."""\nprint("offline fixture")\n'
ANALYSIS = {
    "root_cause_analysis": {
        "cve_id": "CVE-2024-0124",
        "cwe_id": "CWE-416",
        "cuda_attack_surface": "Offline fixture",
        "vulnerability_class": "fixture",
        "primitive": "fixture",
        "root_cause_description": "Test data only; no vulnerability claim.",
        "affected_code_path": "fixture",
        "controllability": "fixture",
        "relevant_mitigations": [],
    },
    "verification_strategy": {
        "goal": "Exercise generation without execution",
        "preconditions": [],
        "steps": [{
            "step_id": "S01",
            "description": "Generate a harmless fixture",
            "pseudocode": "print a constant",
            "success_condition": "A candidate file exists",
            "failure_condition": "Candidate generation fails",
            "expected_cuda_behavior": "No CUDA calls",
        }],
        "confidence": 0.5,
        "cuda_version_range": "Not applicable",
        "gpu_arch_range": "Not applicable",
    },
}


class ProviderError(Exception):
    """A synthetic provider response with no real request or credentials."""

    def __init__(self, status_code):
        super().__init__(f"offline provider HTTP {status_code}")
        self.status_code = status_code


class OfflineTestCase(unittest.TestCase):
    """Isolate each test from local secrets, tracing, and project .env loading."""

    def setUp(self):
        preserved = {
            key: value for key, value in os.environ.items()
            if key.upper() in {"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP"}
        }
        self.env_patch = patch.dict(os.environ, preserved, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        import dotenv
        self.real_load_dotenv = dotenv.load_dotenv
        self.dotenv_patch = patch("dotenv.load_dotenv", return_value=False)
        self.dotenv_patch.start()
        self.addCleanup(self.dotenv_patch.stop)
        self.config_module = importlib.import_module("src.config_loader")
        self.config_dotenv_patch = patch.object(self.config_module, "load_dotenv", return_value=False)
        self.config_dotenv_patch.start()
        self.addCleanup(self.config_dotenv_patch.stop)
        self.llm_module = importlib.import_module("src.llm_client")
        self.loader_module = importlib.import_module("src.data_loader")
        self.expert_module = importlib.import_module("src.core_expert")
        self.codegen_module = importlib.import_module("src.code_generator")
        self.library_module = importlib.import_module("src.cuda_library")
        self.pipeline_module = importlib.import_module("src.pipeline")

    def config(self):
        return self.config_module.ConfigLoader(str(DEFAULT_CONFIG))

    def fake_llm(self):
        fake = MagicMock()
        fake.structured_generate.return_value = self.llm_module.StructuredResponse(
            deepcopy(ANALYSIS), raw_response=json.dumps(ANALYSIS),
        )
        fake.chat.return_value = SAFE_CODE
        return fake


class TestConfiguration(OfflineTestCase):
    def test_default_configuration_and_project_paths(self):
        cfg = self.config()
        self.assertEqual(cfg.llm["api_base"], "https://api.deepseek.com")
        self.assertEqual(cfg.llm["api_key_env"], "DEEPSEEK_API_KEY")
        self.assertTrue(cfg.llm["model_name"])
        self.assertEqual(set(cfg.vulnerability["input_files"]), set(INPUT_KEYS))
        self.assertEqual(cfg.resolve_path("data/inputs"), PROJECT_ROOT / "data/inputs")
        self.assertEqual(cfg.get("missing.path", "fallback"), "fallback")

    def test_environment_overrides_are_typed(self):
        os.environ.update({
            "CPG_LLM_MODEL_NAME": "offline-model",
            "CPG_LLM_API_BASE": "https://offline.invalid/v1",
            "CPG_LLM_API_KEY_ENV": "OFFLINE_PROVIDER_KEY",
            "CPG_LLM_TEMPERATURE": "0.25",
            "CPG_LLM_MAX_TOKENS": "512",
            "CPG_LLM_TIMEOUT": "30",
            "CPG_LLM_MAX_RETRIES": "2",
            "CPG_RAG_ENABLED": "false",
        })
        cfg = self.config()
        self.assertEqual(cfg.llm["model_name"], "offline-model")
        self.assertEqual(cfg.llm["api_key_env"], "OFFLINE_PROVIDER_KEY")
        self.assertEqual(cfg.llm["temperature"], 0.25)
        self.assertEqual(cfg.llm["max_tokens"], 512)
        self.assertEqual(cfg.llm["timeout"], 30)
        self.assertEqual(cfg.llm["max_retries"], 2)
        self.assertFalse(cfg.rag["enabled"])

    def test_temporary_dotenv_and_shell_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "CPG_LLM_MODEL_NAME=dotenv-model\n"
                "CPG_RAG_ENABLED=false\n"
                "DEEPSEEK_API_KEY=offline-dotenv-value\n", encoding="utf-8",
            )
            os.environ["CPG_LLM_MODEL_NAME"] = "shell-model"
            with patch.object(self.config_module, "resolve_project_root", return_value=root), \
                    patch.object(self.config_module, "load_dotenv", wraps=self.real_load_dotenv) as loader:
                cfg = self.config()
            self.assertEqual(cfg.llm["model_name"], "shell-model")
            self.assertFalse(cfg.rag["enabled"])
            self.assertEqual(os.environ["DEEPSEEK_API_KEY"], "offline-dotenv-value")
            self.assertEqual(Path(loader.call_args.args[0]), root / ".env")
            self.assertFalse(loader.call_args.kwargs["override"])

    def test_invalid_environment_values_fail_before_generation(self):
        invalid = (
            ("CPG_LLM_MAX_TOKENS", "0"),
            ("CPG_LLM_MAX_TOKENS", "not-a-number"),
            ("CPG_LLM_TIMEOUT", "-1"),
            ("CPG_LLM_MAX_RETRIES", "0"),
            ("CPG_LLM_TEMPERATURE", "nan"),
            ("CPG_RAG_ENABLED", "maybe"),
        )
        for name, value in invalid:
            with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError):
                    self.config()

    def test_invalid_yaml_shapes_and_chunk_settings_are_rejected(self):
        invalid = (
            "[not, a, mapping]\n",
            "llm: []\n",
            "rag: {enabled: 'true'}\n",
            "rag: {chunk_size: 8, chunk_overlap: 8}\n",
            "rag: {chunk_size: 8, chunk_overlap: -1}\n",
            "llm: {max_tokens: true}\n",
            "llm: {api_base: ''}\n",
            "llm: [broken\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "offline.yaml"
            for content in invalid:
                with self.subTest(content=content):
                    target.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        self.config_module.ConfigLoader(str(target))


class TestLLMConfigurationAndRetry(OfflineTestCase):
    def test_truncated_reasoning_completion_reports_the_real_cause(self):
        # The provider returns content and reasoning_content separately; a
        # budget exhausted by reasoning must not surface as "empty_response".
        diagnostic = self.llm_module.empty_completion_diagnostic(
            "", {"finish_reason": "length"}, {"reasoning_content": "thinking..."})
        self.assertEqual(diagnostic[0]["code"], "output_truncated")
        self.assertEqual(diagnostic[0]["finish_reason"], "length")
        self.assertEqual(diagnostic[0]["reasoning_chars"], len("thinking..."))

    def test_empty_content_without_any_hint_stays_an_empty_response(self):
        self.assertIsNone(self.llm_module.empty_completion_diagnostic("", {}, {}))

    def test_non_empty_content_is_never_flagged(self):
        self.assertIsNone(self.llm_module.empty_completion_diagnostic(
            "OK", {"finish_reason": "length"}, {"reasoning_content": "x"}))

    def test_canonical_key_takes_priority_over_legacy_alias(self):
        os.environ.update({"DEEPSEEK_API_KEY": "offline-primary", "DEEPSEEK_KEY": "offline-legacy"})
        with patch.object(self.llm_module, "ChatOpenAI") as constructor:
            self.llm_module.LLMClient(self.config())
        self.assertEqual(constructor.call_args.kwargs["api_key"], "offline-primary")
        constructor.return_value.invoke.assert_not_called()

    def test_legacy_deepseek_key_is_accepted(self):
        os.environ["DEEPSEEK_KEY"] = "offline-legacy"
        with patch.object(self.llm_module, "ChatOpenAI") as constructor:
            self.llm_module.LLMClient(self.config())
        self.assertEqual(constructor.call_args.kwargs["api_key"], "offline-legacy")

    def test_custom_key_and_missing_key_do_not_cross_providers(self):
        cfg = self.config()
        for env_name in ("OFFLINE_PROVIDER_KEY", "NIUBIAPI_KEY"):
            with self.subTest(env_name=env_name):
                cfg.config["llm"]["api_key_env"] = env_name
                cfg.config["llm"]["api_base"] = "https://offline.invalid/v1"
                with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "offline-unrelated", "DEEPSEEK_KEY": "offline-other"}), \
                        patch.object(self.llm_module, "ChatOpenAI") as constructor:
                    with self.assertRaises(ValueError):
                        self.llm_module.LLMClient(cfg)
                    constructor.assert_not_called()
                with patch.dict(os.environ, {env_name: "offline-selected"}), \
                        patch.object(self.llm_module, "ChatOpenAI") as constructor:
                    self.llm_module.LLMClient(cfg)
                    self.assertEqual(constructor.call_args.kwargs["api_key"], "offline-selected")

    def test_missing_key_has_clear_local_failure(self):
        with patch.object(self.llm_module, "ChatOpenAI") as constructor:
            with self.assertRaises(ValueError):
                self.llm_module.LLMClient(self.config())
            constructor.assert_not_called()

    def test_403_and_404_are_not_retried(self):
        os.environ["DEEPSEEK_API_KEY"] = "offline-fixture"
        for status in (403, 404):
            with self.subTest(status=status), patch.object(self.llm_module, "ChatOpenAI") as constructor, \
                    patch.object(self.llm_module.time, "sleep") as sleep:
                constructor.return_value.invoke.side_effect = ProviderError(status)
                client = self.llm_module.LLMClient(self.config())
                with self.assertRaises(RuntimeError):
                    client.chat([{"role": "user", "content": "offline fixture"}])
                self.assertEqual(constructor.return_value.invoke.call_count, 1)
                sleep.assert_not_called()

    def test_429_is_retried_with_bounded_attempts(self):
        os.environ["DEEPSEEK_API_KEY"] = "offline-fixture"
        with patch.object(self.llm_module, "ChatOpenAI") as constructor, \
                patch.object(self.llm_module.time, "sleep") as sleep:
            constructor.return_value.invoke.side_effect = [
                ProviderError(429), SimpleNamespace(content="offline recovery"),
            ]
            client = self.llm_module.LLMClient(self.config())
            output = client.chat([{"role": "user", "content": "offline fixture"}])
        self.assertEqual(output, "offline recovery")
        self.assertEqual(constructor.return_value.invoke.call_count, 2)
        sleep.assert_called_once()

    def test_retry_budget_stops_without_sleeping_after_final_failure(self):
        os.environ["DEEPSEEK_API_KEY"] = "offline-fixture"
        cfg = self.config()
        cfg.config["llm"]["max_retries"] = 2
        with patch.object(self.llm_module, "ChatOpenAI") as constructor, \
                patch.object(self.llm_module.time, "sleep") as sleep:
            constructor.return_value.invoke.side_effect = ProviderError(429)
            client = self.llm_module.LLMClient(cfg)
            with self.assertRaises(RuntimeError):
                client.chat([{"role": "user", "content": "offline fixture"}])
        self.assertEqual(constructor.return_value.invoke.call_count, 2)
        sleep.assert_called_once()

    def test_per_call_override_keeps_other_configured_generation_limits(self):
        os.environ["DEEPSEEK_API_KEY"] = "offline-fixture"
        cfg = self.config()
        for override in ({"temperature": 0.1}, {"max_tokens": 123}):
            with self.subTest(override=override), patch.object(self.llm_module, "ChatOpenAI") as constructor:
                constructor.return_value.invoke.return_value = SimpleNamespace(content="offline fixture")
                client = self.llm_module.LLMClient(cfg)
                result = client.chat([{"role": "user", "content": "offline fixture"}], **override)
                self.assertEqual(result, "offline fixture")
                self.assertEqual(constructor.call_args.kwargs["temperature"],
                                 override.get("temperature", cfg.llm["temperature"]))
                self.assertEqual(constructor.call_args.kwargs["max_tokens"],
                                 override.get("max_tokens", cfg.llm["max_tokens"]))

    def test_generic_json_parsing_is_separate_from_cuda_analysis_validation(self):
        client = object.__new__(self.llm_module.LLMClient)
        with patch.object(client, "chat", return_value='{"unexpected": "valid JSON"}'):
            parsed = client.structured_generate(
                "offline fixture", "offline fixture",
                json_schema={"type": "object", "required": ["required_field"]},
            )
        # Generic JSON parsing is separate from the strict CUDA expert model contract.
        self.assertEqual(parsed, {"unexpected": "valid JSON"})
        self.assertNotIn("required_field", parsed)
        self.assertEqual(self.llm_module.LLMClient._safe_parse_json("unstructured fixture"),
                         {"raw": "unstructured fixture"})


class TestInputsAndGeneration(OfflineTestCase):
    def test_every_case_and_its_seven_json_files_load_without_data_loss(self):
        cases = sorted((PROJECT_ROOT / "data" / "inputs").glob("CVE-*"))
        self.assertTrue(cases, "no CVE input directories found")
        loader = self.loader_module.CudaDataLoader(self.config())
        count = 0
        for case in cases:
            with self.subTest(case=case.name):
                loaded = loader.load_inputs(str(case))
                self.assertEqual(set(loaded), set(INPUT_KEYS))
                for index, key in enumerate(INPUT_KEYS, 1):
                    path = case / f"{index}_{key}.json"
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual(raw["cve_id"], case.name)
                    self.assertEqual(loaded[key], raw)
                    count += 1
        self.assertEqual(count, 7 * len(cases))

    def test_missing_and_malformed_json_have_current_empty_boundary(self):
        loader = self.loader_module.CudaDataLoader(self.config())
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "1_os_environment.json").write_text("{broken", encoding="utf-8")
            loaded = loader.load_inputs(directory)
        self.assertEqual(loaded, dict.fromkeys(INPUT_KEYS, {}))

    def test_rag_missing_optional_package_degrades_without_download(self):
        loader = self.loader_module.CudaDataLoader(self.config())
        loader.rag_enabled = True
        original_import = builtins.__import__

        def without_chroma(name, *args, **kwargs):
            if name == "langchain_chroma":
                raise ImportError("offline missing optional package fixture")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=without_chroma), redirect_stdout(StringIO()):
            loader.build_or_load_knowledge_base()
        self.assertFalse(loader.rag_enabled)
        self.assertEqual(loader.query_knowledge("offline fixture"), "")

    def test_expert_keeps_seven_dimensions_and_passes_schema_to_mock(self):
        context = self.loader_module.CudaDataLoader(self.config()).load_inputs(
            str(PROJECT_ROOT / "data/inputs/CVE-2024-0124"),
        )
        fake = self.fake_llm()
        result = self.expert_module.CudaSecurityExpert(fake).analyze(context, rag_context="offline knowledge")
        self.assertEqual(result, ANALYSIS)
        fake.structured_generate.assert_called_once()
        prompt = fake.structured_generate.call_args.kwargs["user_prompt"]
        self.assertIn("offline knowledge", prompt)
        for label in ("OS Environment", "CUDA Environment", "Affected Component", "Attack Surface",
                      "Vulnerability Type", "Impact & Controllability", "Root Cause"):
            self.assertIn(label, prompt)
        self.assertIn("root_cause_analysis", fake.structured_generate.call_args.kwargs["json_schema"]["required"])

    def test_static_validation_does_not_execute_candidate(self):
        marker = 'raise RuntimeError("candidate execution must never happen")\n'
        ok, error = self.codegen_module.CudaCodeGenerator._validate_code(marker)
        self.assertTrue(ok)
        self.assertEqual(error, "")
        self.assertFalse(self.codegen_module.CudaCodeGenerator._validate_code("def invalid(:\n")[0])

    def test_static_validation_rejects_empty_and_prefix_only_struct_formats(self):
        validate = self.codegen_module.CudaCodeGenerator._validate_code
        for source in ('import struct\nstruct.pack("", 1)\n',
                       "import struct\nstruct.pack('<', 1)\n",
                       'import struct\nstruct.pack_into("", buf, 0, 1)\n',
                       'import struct\nstruct.unpack("", b"")\n'):
            ok, error = validate(source)
            self.assertFalse(ok, source)
            self.assertIn("struct format", error)
        # A complete format string remains statically acceptable.
        self.assertTrue(validate("import struct\nstruct.pack('<I', 1)\n")[0])

    def test_generation_saves_harmless_candidate_and_limits_static_correction(self):
        fake = self.fake_llm()
        fake.chat.side_effect = ["def invalid(:\n", SAFE_CODE]
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            generator = self.codegen_module.CudaCodeGenerator(fake, self.library_module.CudaLibrary(), directory)
            code = generator.generate({}, deepcopy(ANALYSIS))
            saved = (Path(directory) / "cuda_poc_v1.py").read_text(encoding="utf-8")
        self.assertEqual(saved, code)
        ast.parse(saved)
        self.assertIn('print("offline fixture")', saved)
        self.assertEqual(fake.chat.call_count, 2)

    def test_static_failures_remain_candidates_without_execution(self):
        fake = self.fake_llm()
        fake.chat.return_value = "def invalid(:\n"
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            generator = self.codegen_module.CudaCodeGenerator(fake, self.library_module.CudaLibrary(), directory)
            generator.generate({}, deepcopy(ANALYSIS))
            saved = (Path(directory) / "cuda_poc_v1.py").read_text(encoding="utf-8")
        self.assertEqual(fake.chat.call_count, 3)
        with self.assertRaises(SyntaxError):
            ast.parse(saved)

    def test_pipeline_is_single_shot_and_writes_only_mock_artifacts(self):
        fake = self.fake_llm()
        with tempfile.TemporaryDirectory() as directory:
            cfg = self.config()
            cfg.config["paths"]["outputs_dir"] = directory
            cfg.config["rag"]["enabled"] = False
            env = {"gpu": {"gpu_count": 0}, "toolchain": {}, "os": {}}
            with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                    patch.object(self.pipeline_module, "LLMClient", return_value=fake), \
                    patch.object(self.pipeline_module, "probe_environment", return_value=env) as probe, \
                    patch.object(self.pipeline_module.CudaDataLoader, "build_or_load_knowledge_base") as build_kb, \
                    patch.object(self.pipeline_module.CudaPipeline, "_query_web_search", return_value="") as search, \
                    redirect_stdout(StringIO()):
                pipeline = self.pipeline_module.CudaPipeline()
                pipeline.run(input_dir=str(PROJECT_ROOT / "data/inputs/CVE-2024-0124"))
            output = Path(directory) / "CVE-2024-0124"
            self.assertEqual({path.name for path in output.iterdir()},
                             {"cuda_analysis_v1.json", "cuda_poc_v1.py", "input_manifest_v1.json",
                              "cuda_analysis_v1.raw.txt", "cuda_poc_v1.status.json", "cuda_run_v1.json"})
            self.assertEqual(json.loads((output / "cuda_analysis_v1.json").read_text(encoding="utf-8")), ANALYSIS)
            ast.parse((output / "cuda_poc_v1.py").read_text(encoding="utf-8"))
        fake.structured_generate.assert_called_once()
        fake.chat.assert_called_once()
        probe.assert_called_once()
        build_kb.assert_called_once()
        search.assert_called_once()

    def test_core_modules_import_without_rag_or_cuda_extras(self):
        names = ("src.config_loader", "src.llm_client", "src.data_loader", "src.core_expert",
                 "src.code_generator", "src.pipeline", "src.env_probe", "src.cuda_library",
                 "src.models", "src.tools", "src.tools.compile", "src.tools.elf_ops",
                 "src.tools.env", "src.tools.inspect", "src.tools.search")
        for name in names:
            with self.subTest(module=name):
                self.assertIsNotNone(importlib.import_module(name))


class TestDependencyFreeCLI(unittest.TestCase):
    def test_help_works_without_site_packages(self):
        result = subprocess.run(
            [sys.executable, "-S", str(PROJECT_ROOT / "main.py"), "--help"],
            cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--cve-id", result.stdout)
        self.assertIn("--no-rag", result.stdout)


class TestCLIExecutionBoundary(OfflineTestCase):
    def test_cli_routes_config_output_and_no_rag_to_mock_pipeline(self):
        main = importlib.import_module("main")
        with tempfile.TemporaryDirectory() as directory:
            argv = ["main.py", "--input-dir", directory, "--config", "offline.yaml",
                    "--output-dir", str(Path(directory) / "out"), "--no-rag"]
            with patch.object(sys, "argv", argv), patch.object(main, "setup_logging"), \
                    patch.object(self.pipeline_module, "CudaPipeline") as constructor:
                main.main()
            constructor.assert_called_once_with(config_path="offline.yaml")
            constructor.return_value.run.assert_called_once_with(
                input_dir=directory, output_dir=str(Path(directory) / "out"),
            )
            self.assertEqual(os.environ["CPG_RAG_ENABLED"], "false")

    def test_cli_reports_configuration_and_dependency_failures(self):
        main = importlib.import_module("main")
        with tempfile.TemporaryDirectory() as directory:
            for failure in (ValueError("offline invalid configuration"),
                            RuntimeError("offline provider failure"),
                            ImportError("offline missing dependency")):
                with self.subTest(error=type(failure).__name__), \
                        patch.object(sys, "argv", ["main.py", "--input-dir", directory]), \
                        patch.object(main, "setup_logging"), \
                        patch.object(self.pipeline_module, "CudaPipeline", side_effect=failure), \
                        redirect_stdout(StringIO()) as output:
                    with self.assertRaises(SystemExit) as result:
                        main.main()
                    self.assertEqual(result.exception.code, 1)
                    self.assertIn("[ERROR]", output.getvalue())


if __name__ == "__main__":
    unittest.main()
