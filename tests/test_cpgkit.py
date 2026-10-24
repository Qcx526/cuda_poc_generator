# -*- coding: utf-8 -*-
"""The ELF helper must keep a section visible after a save."""

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.cpgkit.cpgkit import Elf, KitError, check_section_roundtrip, require

SHDR = struct.Struct("<IIQQQQIIQQ")


def _minimal_elf(path: Path) -> None:
    """An ELF64 with a null section and a string table, nothing else."""
    strtab = b"\0.shstrtab\0"
    ehdr = bytearray(64)
    ehdr[:4] = b"\x7fELF"
    ehdr[4] = 2
    ehdr[5] = 1
    ehdr[6] = 1
    data_off = 64
    image = bytearray(ehdr) + bytearray(strtab)
    shoff = len(image)
    image += SHDR.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    image += SHDR.pack(1, 3, 0, 0, data_off, len(strtab), 0, 0, 1, 0)
    struct.pack_into("<Q", image, 0x28, shoff)
    struct.pack_into("<H", image, 0x3A, 64)
    struct.pack_into("<H", image, 0x3C, 2)
    struct.pack_into("<H", image, 0x3E, 1)
    path.write_bytes(bytes(image))


class TestCpgkit(unittest.TestCase):
    def test_appended_section_is_visible_after_save(self):
        with TemporaryDirectory() as tmp:
            src, out = Path(tmp) / "a.cubin", Path(tmp) / "b.cubin"
            _minimal_elf(src)
            blob = b"\xff" * 40
            elf = Elf(str(src))
            elf.append_section(".nv_debug_source", blob)
            elf.save(str(out))
            check_section_roundtrip(str(out), ".nv_debug_source", 40)
            self.assertEqual(Elf(str(out)).section(".nv_debug_source").data, blob)

    def test_adding_the_same_section_twice_is_refused(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "a.cubin"
            _minimal_elf(src)
            elf = Elf(str(src))
            elf.append_section(".x", b"1")
            with self.assertRaises(KitError):
                elf.append_section(".x", b"2")

    def test_require_fails_loudly(self):
        with self.assertRaises(KitError):
            require(False, "size mismatch")

    def test_non_elf_input_is_refused(self):
        with TemporaryDirectory() as tmp:
            bad = Path(tmp) / "not.elf"
            bad.write_bytes(b"hello")
            with self.assertRaises(KitError):
                Elf(str(bad))


if __name__ == "__main__":
    unittest.main()
