"""CUDA header profile tests use synthetic bytes, never any native parser."""

import hashlib
import struct
import unittest

from src.cuda_registry import validate_smoke_cubin_bytes
from src.tools.elf_ops import CUDA_12_8_PROFILE, validate_elf_structure
from tests.test_cuda_registry import synthetic_cuda_elf


def synthetic_profile():
    raw = bytearray(synthetic_cuda_elf())
    raw[7:9] = bytes((51, 7))
    struct.pack_into("<I", raw, 20, 128)
    return bytes(raw)


class TestExplicitCudaElfProfile(unittest.TestCase):
    def test_default_generic_rules_stay_strict(self):
        raw = synthetic_profile()
        self.assertTrue(validate_elf_structure(raw))
        self.assertEqual(validate_elf_structure(raw, profile=CUDA_12_8_PROFILE), [])

    def test_profile_checks_original_bytes_without_rewriting_header(self):
        raw = synthetic_profile()
        before = hashlib.sha256(raw).hexdigest()
        observed = validate_smoke_cubin_bytes(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), before)
        self.assertEqual(observed["sha256"], before)
        self.assertEqual(observed["elf_version_raw"], 128)
        self.assertEqual(observed["structural_profile"], CUDA_12_8_PROFILE)

    def test_unknown_version_osabi_abi_or_machine_is_not_guessed(self):
        for offset, fmt, value in ((20, "<I", 127), (20, "<I", 129), (7, "<B", 0),
                                    (8, "<B", 8), (18, "<H", 62), (6, "<B", 2)):
            raw = bytearray(synthetic_profile())
            struct.pack_into(fmt, raw, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                validate_smoke_cubin_bytes(bytes(raw))

    def test_existing_section_and_name_boundaries_still_apply(self):
        raw = synthetic_profile()
        for damaged in (raw[:63], raw[:-1], raw[:40] + (len(raw) + 100).to_bytes(8, "little") + raw[48:]):
            with self.assertRaises(ValueError):
                validate_smoke_cubin_bytes(damaged)

    def test_unknown_parser_profile_is_rejected(self):
        self.assertTrue(validate_elf_structure(synthetic_profile(), profile="GUESS_CUDA"))


if __name__ == "__main__":
    unittest.main()
