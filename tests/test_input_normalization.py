"""Offline seven-dimension normalization regression; no providers or CUDA calls."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from src.data_loader import CudaDataLoader
from src.models.normalized_input import (
    FieldState, INPUT_DIMENSIONS, InputValidationError, normalize_input_files,
)


INPUT_ROOT = Path(__file__).resolve().parent.parent / "data" / "inputs"


class InputNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "case"
        shutil.copytree(INPUT_ROOT / "CVE-2024-0124", self.directory)

    def file(self, dimension):
        index = INPUT_DIMENSIONS.index(dimension) + 1
        return self.directory / f"{index}_{dimension}.json"

    def change(self, dimension, update):
        path = self.file(dimension)
        data = json.loads(path.read_text(encoding="utf-8"))
        update(data)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def codes(self, result):
        return {diagnostic.code for diagnostic in result.diagnostics}

    def test_all_six_cases_42_files_normalize_without_changes(self):
        files = sorted(INPUT_ROOT.glob("CVE-*/*.json"))
        self.assertEqual(len(files), 42)
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        cases = sorted(INPUT_ROOT.glob("CVE-*"))
        self.assertEqual(len(cases), 6)
        checked = 0
        for case in cases:
            with self.subTest(case=case.name):
                result = normalize_input_files(case)
                self.assertTrue(result.is_valid, result.diagnostics)
                self.assertIs(result.require_valid(), result)
                self.assertEqual(result.cve_id, case.name)
                self.assertEqual(set(result.dimensions), set(INPUT_DIMENSIONS))
                self.assertEqual(result.verification, "unverified")
                self.assertEqual(result.assertion_kind, "input_assertion")
                for dimension, source in result.sources.items():
                    path = case / source.source_file
                    self.assertEqual(source.sha256, before[path])
                    self.assertEqual(source.size_bytes, len(path.read_bytes()))
                    self.assertFalse(Path(source.source_file).is_absolute())
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual(result.raw_inputs[dimension], raw)
                    self.assertEqual(result.dimensions[dimension]["cve_id"], case.name)
                    self.assertNotIn(dimension, result.dimensions[dimension])
                    checked += 1
                self.assertTrue(result.provenance)
                self.assertTrue(all(item.verification == "unverified" for item in result.provenance))
        self.assertEqual(checked, 42)
        self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files})

    def test_flat_wrapped_equivalence(self):
        wrapped = normalize_input_files(self.directory).require_valid()
        for dimension, payload in wrapped.dimensions.items():
            self.file(dimension).write_text(json.dumps(payload), encoding="utf-8")
        flat = normalize_input_files(self.directory).require_valid()
        self.assertEqual(flat.dimensions, wrapped.dimensions)
        self.assertEqual(flat.cve_id, wrapped.cve_id)
        field = "/dimensions/root_cause/summary"
        self.assertEqual({item.field_path for item in wrapped.provenance if item.normalized_path == field},
                         {"/root_cause/summary"})
        self.assertEqual({item.field_path for item in flat.provenance if item.normalized_path == field}, {"/summary"})

    def test_equal_outer_field_keeps_all_provenance(self):
        self.change("affected_component", lambda data: data.update(name=data["affected_component"]["name"]))
        result = normalize_input_files(self.directory).require_valid()
        self.assertEqual(result.dimensions["affected_component"]["name"], "nvdisasm")
        self.assertEqual({item.field_path for item in result.provenance
                          if item.normalized_path == "/dimensions/affected_component/name"},
                         {"/name", "/affected_component/name"})
        self.assertIn("name", result.raw_inputs["affected_component"])

    def test_outer_conflict_selects_neither_value(self):
        self.change("affected_component", lambda data: data.update(name="private-test-marker"))
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertNotIn("name", result.dimensions["affected_component"])
        self.assertEqual(result.field_states["/dimensions/affected_component/name"], FieldState.CONFLICT)
        self.assertIn("FIELD_CONFLICT", self.codes(result))
        self.assertNotIn("private-test-marker", json.dumps([item.model_dump() for item in result.diagnostics]))
        with self.assertRaises(InputValidationError) as raised:
            result.require_valid()
        self.assertIs(raised.exception.result, result)
        self.assertIs(raised.exception.diagnostics, result.diagnostics)

    def test_recursive_duplicate_mapping_merges_without_dropping_outer_fields(self):
        self.change("impact_controllability", lambda data: data.update(
            impact={"availability": data["impact_controllability"]["impact"]["availability"],
                    "custom_property": "preserved"}, outer_metadata={"review": "pending"}))
        result = normalize_input_files(self.directory).require_valid()
        self.assertEqual(result.dimensions["impact_controllability"]["impact"]["custom_property"], "preserved")
        self.assertIn("confidentiality", result.dimensions["impact_controllability"]["impact"])
        self.assertEqual(result.dimensions["impact_controllability"]["outer_metadata"], {"review": "pending"})

    def test_recursive_duplicate_mapping_conflict(self):
        self.change("impact_controllability", lambda data: data.update(impact={"availability": "conflict"}))
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertNotIn("availability", result.dimensions["impact_controllability"]["impact"])
        self.assertEqual(result.field_states["/dimensions/impact_controllability/impact/availability"], FieldState.CONFLICT)

    def test_all_seven_cve_ids_checked(self):
        for dimension in INPUT_DIMENSIONS:
            with self.subTest(dimension=dimension):
                original = self.file(dimension).read_bytes()
                self.change(dimension, lambda data: data.update(cve_id="CVE-2099-9999"))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIsNone(result.cve_id)
                self.assertIn("CVE_ID_CONFLICT", self.codes(result))
                self.file(dimension).write_bytes(original)

    def test_cve_id_missing_wrong_type_and_bad_format(self):
        for value, expected in [(None, "REQUIRED_FIELD_UNKNOWN"), (12, "FIELD_TYPE_ERROR"),
                                ("../../escape", "CVE_ID_FORMAT_ERROR"), ("CVE-2024-0124 ", "CVE_ID_FORMAT_ERROR")]:
            with self.subTest(value=value):
                self.change("os_environment", lambda data: data.update(cve_id=value))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn(expected, self.codes(result))
        self.change("os_environment", lambda data: data.pop("cve_id"))
        result = normalize_input_files(self.directory)
        self.assertEqual(result.field_states["/dimensions/os_environment/cve_id"], FieldState.MISSING)

    def test_missing_required_fields(self):
        for dimension, field in [("affected_component", "name"), ("attack_surface", "entry_point"),
                                 ("vulnerability_type", "cwe_id"), ("root_cause", "summary")]:
            with self.subTest(dimension=dimension):
                original = self.file(dimension).read_bytes()
                self.change(dimension, lambda data: data[dimension].pop(field))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertEqual(result.field_states[f"/dimensions/{dimension}/{field}"], FieldState.MISSING)
                self.assertIn("REQUIRED_FIELD_MISSING", self.codes(result))
                self.file(dimension).write_bytes(original)

    def test_root_alternative_summary_supported(self):
        self.change("root_cause", lambda data: data["root_cause"].update(
            vulnerable_code_summary=data["root_cause"].pop("summary")))
        self.assertTrue(normalize_input_files(self.directory).is_valid)

    def test_wrong_field_types_not_coerced(self):
        cases = [("affected_component", "name", 7), ("root_cause", "summary", ["not a string"]),
                 ("cuda_environment", "compute_capability", 7.5),
                 ("cuda_environment", "affected_tools", "nvdisasm"),
                 ("vulnerability_type", "related_cwe", [None]),
                 ("impact_controllability", "impact", 42)]
        for dimension, field, value in cases:
            with self.subTest(dimension=dimension, field=field):
                original = self.file(dimension).read_bytes()
                self.change(dimension, lambda data: data[dimension].update({field: value}))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn("FIELD_TYPE_ERROR", self.codes(result))
                self.file(dimension).write_bytes(original)

    def test_unknown_environment_preserved_but_required_unknown_rejected(self):
        self.change("cuda_environment", lambda data: data["cuda_environment"].update(
            cuda_toolkit_version=None, compute_capability="unknown", gpu_architecture=" "))
        result = normalize_input_files(self.directory).require_valid()
        for field in ("cuda_toolkit_version", "compute_capability", "gpu_architecture"):
            self.assertEqual(result.field_states[f"/dimensions/cuda_environment/{field}"], FieldState.UNKNOWN)
        self.assertEqual(result.field_states["/dimensions/cuda_environment/gpu_model"], FieldState.MISSING)
        self.assertIsNone(result.dimensions["cuda_environment"]["cuda_toolkit_version"])
        self.change("root_cause", lambda data: data["root_cause"].update(summary="unknown"))
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.field_states["/dimensions/root_cause/summary"], FieldState.UNKNOWN)

    def test_files_missing_invalid_json_and_nonobject(self):
        path = self.file("os_environment")
        original = path.read_bytes()
        for content, code in [(None, "INPUT_FILE_MISSING"), (b'{"truncated":', "INPUT_JSON_ERROR"),
                              (b'[]', "INPUT_OBJECT_REQUIRED"), (b'{"field":NaN}', "INPUT_JSON_ERROR"),
                              (b'{"field":1e999}', "INPUT_JSON_ERROR"),
                              (b'\xff', "INPUT_JSON_ERROR")]:
            with self.subTest(code=code, content=content):
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn(code, self.codes(result))
                self.assertIsNone(result.raw_inputs["os_environment"])
                if content is not None:
                    self.assertEqual(result.sources["os_environment"].sha256, hashlib.sha256(content).hexdigest())
                path.write_bytes(original)

    def test_json_duplicate_key_conflict_exact_path_and_hash(self):
        content = b'{"cve_id":"CVE-2024-0124","os_environment":{"os_name":"first","os_name":"second"}}'
        self.file("os_environment").write_bytes(content)
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertIn("DUPLICATE_KEY_CONFLICT", self.codes(result))
        diagnostic = next(item for item in result.diagnostics if item.code == "DUPLICATE_KEY_CONFLICT")
        self.assertEqual(diagnostic.field_paths, ["/os_environment/os_name"])
        self.assertEqual(diagnostic.normalized_path, "/dimensions/os_environment/os_name")
        self.assertEqual(result.sources["os_environment"].sha256, hashlib.sha256(content).hexdigest())
        self.assertIsNone(result.raw_inputs["os_environment"])
        self.assertEqual(self.file("os_environment").read_bytes(), content)

    def test_equal_duplicate_json_key_allowed_but_bool_and_int_conflict(self):
        self.file("os_environment").write_text(
            '{"cve_id":"CVE-2024-0124","os_name":"Linux","os_name":"Linux"}', encoding="utf-8")
        self.assertTrue(normalize_input_files(self.directory).is_valid)
        self.file("os_environment").write_text(
            '{"cve_id":"CVE-2024-0124","custom":true,"custom":1}', encoding="utf-8")
        self.assertIn("DUPLICATE_KEY_CONFLICT", self.codes(normalize_input_files(self.directory)))

    def test_wrapped_type_error(self):
        self.change("os_environment", lambda data: data.update(os_environment=["Linux"]))
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertIn("WRAPPER_TYPE_ERROR", self.codes(result))
        self.assertEqual(result.raw_inputs["os_environment"]["os_environment"], ["Linux"])

    def test_explicit_shared_environment_conflict(self):
        self.change("os_environment", lambda data: data["os_environment"].update(cuda_toolkit_version="different"))
        result = normalize_input_files(self.directory)
        self.assertFalse(result.is_valid)
        self.assertIn("SHARED_FIELD_CONFLICT", self.codes(result))
        self.assertEqual(result.field_states["/dimensions/cuda_environment/cuda_toolkit_version"], FieldState.CONFLICT)

    def test_cvss_range_and_cwe_format(self):
        for score in ("11", -1, True, "not numeric", "nan"):
            self.change("vulnerability_type", lambda data: data["vulnerability_type"].update(cvss_score=score))
            self.assertIn("FIELD_RANGE_ERROR", self.codes(normalize_input_files(self.directory)))
        self.change("vulnerability_type", lambda data: data["vulnerability_type"].update(cvss_score="3.3", cwe_id="416"))
        self.assertIn("CWE_ID_FORMAT_ERROR", self.codes(normalize_input_files(self.directory)))

    def test_unicode_digits_are_not_legal_cve_or_cwe_identifiers(self):
        for cve_id in ("CVE-２０２４-０１２４", "CVE-٢٠٢٤-٠١٢٤"):
            with self.subTest(cve_id=cve_id):
                self.change("os_environment", lambda data: data.update(cve_id=cve_id))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn("CVE_ID_FORMAT_ERROR", self.codes(result))
        self.change("os_environment", lambda data: data.update(cve_id="CVE-2024-0124"))
        for cwe_id in ("CWE-４１６", "CWE-٤١٦"):
            with self.subTest(cwe_id=cwe_id):
                self.change("vulnerability_type", lambda data: data["vulnerability_type"].update(cwe_id=cwe_id))
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn("CWE_ID_FORMAT_ERROR", self.codes(result))

    def test_excessive_json_nesting_becomes_input_diagnostic(self):
        path = self.file("os_environment")
        # Include depths that parse but cannot safely serialize in a manifest,
        # plus depths beyond the JSON parser's recursion limit.
        for depth in (129, 300, 600, 5000):
            with self.subTest(depth=depth):
                content = ('{"cve_id":"CVE-2024-0124","custom":' + '[' * depth + '0'
                           + ']' * depth + '}').encode("utf-8")
                path.write_bytes(content)
                result = normalize_input_files(self.directory)
                self.assertFalse(result.is_valid)
                self.assertIn("INPUT_JSON_ERROR", self.codes(result))
                self.assertIsNone(result.raw_inputs["os_environment"])
                self.assertEqual(result.dimensions["os_environment"], {})
                self.assertEqual(result.sources["os_environment"].sha256, hashlib.sha256(content).hexdigest())
                self.assertFalse(any(item.dimension == "os_environment" for item in result.provenance))
                self.assertEqual(result.model_dump(mode="json")["raw_inputs"]["os_environment"], None)

    def test_loader_retains_legacy_interface_and_new_configuration(self):
        cfg = SimpleNamespace(rag={"enabled": False}, paths={"inputs_dir": str(self.directory)},
                              vulnerability={"input_files": {}}, resolve_path=Path)
        loader = CudaDataLoader(cfg)
        legacy = loader.load_inputs()
        normalized = loader.load_normalized_inputs().require_valid()
        self.assertEqual(legacy, normalized.raw_inputs)
        self.assertIn("root_cause", legacy["root_cause"])
        self.assertNotIn("root_cause", normalized.dimensions["root_cause"])
        custom_file = self.directory / "root-custom.json"
        self.file("root_cause").rename(custom_file)
        cfg.vulnerability["input_files"] = {"root_cause": custom_file.name}
        result = loader.load_normalized_inputs().require_valid()
        self.assertEqual(result.sources["root_cause"].source_file, custom_file.name)

    def test_source_hash_exact_bom_bytes_and_json_pointer_escaping(self):
        self.change("os_environment", lambda data: data.update({"custom/a~b": "preserved"}))
        path = self.file("os_environment")
        path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
        result = normalize_input_files(self.directory).require_valid()
        self.assertEqual(result.sources["os_environment"].sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        entry = next(item for item in result.provenance if item.normalized_path == "/dimensions/os_environment/custom~1a~0b")
        self.assertEqual(entry.field_path, "/custom~1a~0b")
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["field_states"][entry.normalized_path], "VALID")


if __name__ == "__main__":
    unittest.main()
