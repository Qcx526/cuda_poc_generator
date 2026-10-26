# -*- coding: utf-8 -*-
"""Tests for the domain lints, each derived from a real generated-PoC failure."""

import unittest

from src.code_generator import CudaCodeGenerator
from src.quality_lints import run_lints


def _ids(code: str):
    return {lint_id for lint_id, _ in run_lints(code)}


class TestVersionClassifierLint(unittest.TestCase):
    def test_unmapped_major_returning_false_is_flagged(self):
        # The CVE-2024-0090 failure: major 551 missing from the branch table
        # produced a false PATCHED verdict.
        code = '''
FIXED_BRANCHES = {"470": (470, 256, 2), "555": (555, 52, 4)}

def classify_driver_version(installed):
    key = str(installed[0])
    if key not in FIXED_BRANCHES:
        return False, "outside branches"
    return True, "affected"
'''
        self.assertIn("version-classifier-unknown-major", _ids(code))

    def test_unknown_mapped_to_unknown_is_clean(self):
        code = '''
FIXED_BRANCHES = {"470": (470, 256, 2)}

def classify_driver_version(installed):
    key = str(installed[0])
    if key not in FIXED_BRANCHES:
        return None, "UNKNOWN - consult the advisory"
    return True, "affected"
'''
        self.assertEqual(_ids(code), set())


class TestDriverProbeContextLint(unittest.TestCase):
    def test_probe_without_context_is_flagged(self):
        # The CVE-2024-0091 failure: 35 probes, every one vacuous.
        code = '''
import ctypes

def run_single_probe(target, value):
    lib = ctypes.WinDLL("nvcuda.dll")
    out = ctypes.c_void_p()
    return lib.cuModuleLoadData(ctypes.byref(out), value)
'''
        self.assertIn("driver-probe-without-context", _ids(code))

    def test_probe_reachable_from_init_helper_is_clean(self):
        code = '''
import ctypes

def _setup(lib):
    lib.cuInit(0)
    ctx = ctypes.c_void_p()
    lib.cuCtxCreate_v2(ctypes.byref(ctx), 0, 0)
    return ctx

def run_single_probe(target, value):
    lib = ctypes.WinDLL("nvcuda.dll")
    _setup(lib)
    out = ctypes.c_void_p()
    return lib.cuModuleLoadData(ctypes.byref(out), value)
'''
        self.assertNotIn("driver-probe-without-context", _ids(code))


    def test_pointer_resolver_is_not_treated_as_a_probe(self):
        # probe_nvapi_initialize only resolves a function pointer via
        # nvapi_QueryInterface; nothing consumes attacker state yet.
        code = """
def probe_nvapi_initialize(lib):
    lib.nvapi_QueryInterface.restype = None
    return lib.nvapi_QueryInterface(0x0150E828)
"""
        self.assertEqual(_ids(code), set())

    def test_non_probe_code_is_ignored(self):
        code = '''
def submit_shader(device, blob):
    return device.CreatePixelShader(blob)
'''
        self.assertEqual(_ids(code), set())


class TestLegacyTokenLint(unittest.TestCase):
    def test_d3dsio_tokens_with_ps_5_0_are_flagged(self):
        # The CVE-2024-0107 failure: SM2/SM3 tokens searched in an SM4 stream.
        code = '''
TARGET = "ps_5_0"
D3DSIO_SINCOS = 0x25

def find_tokens(dxbc):
    return [i for i, t in enumerate(dxbc) if t == D3DSIO_SINCOS]
'''
        self.assertIn("legacy-token-search-on-modern-profile", _ids(code))

    def test_legacy_profile_is_clean(self):
        code = '''
TARGET = "ps_2_0"
D3DSIO_SINCOS = 0x25

def find_tokens(dxbc):
    return [i for i, t in enumerate(dxbc) if t == D3DSIO_SINCOS]
'''
        self.assertEqual(_ids(code), set())


class TestValidationIntegration(unittest.TestCase):
    def test_validate_code_reports_the_lint_id(self):
        code = '''
import ctypes

def run_single_probe(target, value):
    lib = ctypes.WinDLL("nvcuda.dll")
    out = ctypes.c_void_p()
    return lib.cuModuleLoadData(ctypes.byref(out), value)
'''
        ok, message = CudaCodeGenerator._validate_code(code)
        self.assertFalse(ok)
        self.assertIn("driver-probe-without-context", message)

    def test_clean_code_still_validates(self):
        code = '''
import ctypes

def _setup(lib):
    lib.cuInit(0)
    return 0

def run_single_probe(value):
    lib = ctypes.WinDLL("nvcuda.dll")
    _setup(lib)
    out = ctypes.c_void_p()
    return lib.cuModuleLoadData(ctypes.byref(out), value)
'''
        ok, message = CudaCodeGenerator._validate_code(code)
        self.assertTrue(ok, message)


if __name__ == "__main__":
    unittest.main()


def test_hand_built_elf_layout_is_flagged():
    code = (
        "import struct\n"
        "image = bytearray(open('a.cubin','rb').read())\n"
        "assert image[:4] == b'\\x7fELF'\n"
        "# rebuild shstrtab so the loader sees the new name\n"
        "shstrtab = image[0x100:0x200] + b'.nv_debug_source\\x00'\n"
        "image[0x100:0x200] = shstrtab\n"
    )
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "elf-layout-built-by-hand" in ids


def test_using_cpgkit_clears_the_elf_lint():
    code = (
        "from cpgkit import Elf, check_section_roundtrip\n"
        "e = Elf('a.cubin')\n"
        "e.append_section('.x', b'1')\n"
        "e.save('b.cubin')\n"
        "check_section_roundtrip('b.cubin', '.x', 1)\n"
    )
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "elf-layout-built-by-hand" not in ids


def test_a_script_that_never_touches_elf_is_not_flagged():
    ids = [lint_id for lint_id, _ in run_lints("print('hello')\n")]
    assert "elf-layout-built-by-hand" not in ids


def test_patching_an_existing_field_in_place_is_allowed():
    """The mutation that worked without the helper must keep working."""
    code = (
        "import struct\n"
        "image = bytearray(open('a.cubin','rb').read())\n"
        "shoff = struct.unpack_from('<Q', image, 0x28)[0]\n"
        "struct.pack_into('<Q', image, shoff + 8*64 + 32, 0xffffffffffffffff)\n"
        "open('b.cubin','wb').write(image)\n"
    )
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "elf-layout-built-by-hand" not in ids


def test_importing_project_packages_is_flagged():
    code = "from src.tools.env import find_cuda_tool\nimport tools.helpers\n"
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "project-import-in-poc" in ids


def test_stdlib_and_third_party_imports_are_fine():
    code = "import os\nimport struct\nfrom ctypes import c_void_p\n"
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "project-import-in-poc" not in ids


def test_py38_builtin_generics_in_annotations_are_flagged():
    code = "def f(items: list[str]) -> dict[str, int]:\n    return {}\n"
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "py38-incompatible-syntax" in ids


def test_bitwise_or_outside_annotations_is_not_flagged():
    """Flags and masks are ordinary arithmetic, not union types."""
    code = "flags = 1 | 2\nvalue = (flags | 4) & 0xff\n"
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "py38-incompatible-syntax" not in ids


def test_future_annotations_clears_the_py38_lint():
    code = "from __future__ import annotations\ndef f(x: list[str]) -> None:/n    pass\n"
    ids = [lint_id for lint_id, _ in run_lints(code)]
    assert "py38-incompatible-syntax" not in ids
