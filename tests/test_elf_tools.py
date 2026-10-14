"""Fixed ELF fixtures and bounded mutations; these tests never execute ELF."""

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from src.tools import elf_ops as elf


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "elf64_le_rel.hex"


def legal_elf_fixture(extra_sections=0):
    """Independently specified ELF64LE ET_REL, x86-64, no program headers.

    Contains text, conceptual NOBITS, symbol/string tables and one RELA entry.
    It is fixed research data, not a GPU program or an execution test.
    """
    names = ["", ".shstrtab", ".text", ".bss", ".strtab", ".symtab", ".rela.text"]
    names += [f".fixture.{i}" for i in range(extra_sections)]
    strings = bytearray(b"\x00")
    indexes = [0]
    for name in names[1:]:
        indexes.append(len(strings))
        strings.extend(name.encode("ascii") + b"\x00")
    data = bytearray(64)

    def body(value, alignment=1):
        data.extend(b"\x00" * ((-len(data)) % alignment))
        offset = len(data)
        data.extend(value)
        return offset, len(value)

    name_pos, name_size = body(strings)
    text_pos, text_size = body(b"\x00\x00\x00", 8)
    string_pos, string_size = body(b"\x00symbol\x00")
    symbols = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 2, 0, 3)
    symbol_pos, symbol_size = body(symbols, 8)
    rela_pos, rela_size = body(struct.pack("<QQq", 0, (1 << 32) | 1, 0), 8)
    headers = [
        [0] * 10,
        [indexes[1], 3, 0, 0, name_pos, name_size, 0, 0, 1, 0],
        [indexes[2], 1, 6, 0, text_pos, text_size, 0, 0, 8, 0],
        [indexes[3], 8, 3, 0, 0x100000, 4096, 0, 0, 8, 0],
        [indexes[4], 3, 0, 0, string_pos, string_size, 0, 0, 1, 0],
        [indexes[5], 2, 0, 0, symbol_pos, symbol_size, 4, 1, 8, 24],
        [indexes[6], 4, 0, 0, rela_pos, rela_size, 5, 2, 8, 24],
    ]
    for index in indexes[7:]:
        pos, size = body(b"F")
        headers.append([index, 1, 0, 0, pos, size, 0, 0, 1, 0])
    table, _ = body(b"".join(struct.pack("<IIQQQQIIQQ", *h) for h in headers), 8)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 62, 1,
                         0, 0, table, 0, 64, 0, 0, 64, len(headers), 1)
    data[:64] = header
    return bytes(data)


def fixture():
    return bytes.fromhex(FIXTURE_PATH.read_text(encoding="ascii"))


def change_header(data, offset, format_, value):
    changed = bytearray(data)
    struct.pack_into(format_, changed, offset, value)
    return bytes(changed)


def change_section(data, index, offset, format_, value):
    table = struct.unpack_from("<Q", data, 40)[0]
    return change_header(data, table + index * 64 + offset, format_, value)


class TestLegalFixture(unittest.TestCase):
    def test_fixed_fixture_matches_independent_definition(self):
        self.assertEqual(fixture(), legal_elf_fixture())
        self.assertEqual(elf.validate_elf_structure(fixture()), [])
        self.assertEqual(hashlib.sha256(fixture()).hexdigest(),
                         "fd9119b01caf56fe810d6f1bd79fcbfa20ca8188844d02a3325d092ba6086750")

    def test_read_legal_sections_and_relocation_types(self):
        data = fixture()
        self.assertEqual(len(elf.parse_all_sections(data)), 7)
        idx, header = elf.find_section(data, ".text")
        self.assertEqual(idx, 2)
        self.assertEqual(data[header[4]:header[4] + header[5]], b"\x00\x00\x00")
        self.assertIsNone(elf.find_section(data, ".does-not-exist"))
        self.assertEqual([i for i, _ in elf.find_sections_by_type(data, 4)], [6])
        self.assertEqual(elf.get_section_info(data)[0]["name"], "")

    def test_nobits_conceptual_range_is_not_file_content(self):
        data = fixture()
        _, hdr = elf.find_section(data, ".bss")
        self.assertGreater(hdr[4] + hdr[5], len(data))
        self.assertEqual(elf.validate_elf_structure(data), [])
        with self.assertRaisesRegex(ValueError, "NOBITS"):
            elf.replace_section_content(data, ".bss", b"X")

    def test_validates_every_section_beyond_old_100_header_limit(self):
        data = legal_elf_fixture(110)
        self.assertEqual(len(elf.parse_all_sections(data)), 117)
        broken = change_section(data, 116, 24, "<Q", len(data) + 1)
        self.assertIn("116", elf.validate_elf_structure(broken)[0])

    def test_section_names_can_be_suffix_offsets(self):
        data = fixture()
        name_pos = elf.find_section(data, ".text")[1][0]
        suffix_name = change_section(data, 2, 0, "<I", name_pos + 1)
        self.assertEqual(elf.find_section(suffix_name, "text")[0], 2)

    def test_supported_absent_name_table_has_no_names(self):
        data = fixture()
        data = change_header(data, 62, "<H", 0)
        for index in range(1, 7):
            data = change_section(data, index, 0, "<I", 0)
        self.assertEqual(elf.validate_elf_structure(data), [])
        self.assertIsNone(elf.find_section(data, ".text"))
        with self.assertRaisesRegex(ValueError, "existing name"):
            elf.append_section(data, ".new", b"X")


class TestUnsupportedAndMalformedELF(unittest.TestCase):
    def assert_rejected(self, data, message=None):
        self.assertTrue(elf.validate_elf_structure(data))
        with self.assertRaises(ValueError) as caught:
            elf.parse_all_sections(data)
        if message:
            self.assertIn(message, str(caught.exception))
        with self.assertRaises(ValueError):
            elf.find_section(data, ".text")

    def test_elf32_is_rejected_without_elf64_guessing(self):
        self.assert_rejected(change_header(fixture(), 4, "<B", 1), "class")

    def test_big_endian_and_unknown_byte_order_rejected(self):
        for order in (0, 2, 3):
            with self.subTest(order=order):
                self.assert_rejected(change_header(fixture(), 5, "<B", order), "byte order")

    def test_all_truncation_boundaries_rejected(self):
        data = fixture()
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                self.assert_rejected(data[:cut])

    def test_header_magic_versions_and_size_rejected(self):
        for offset, fmt, value in [(0, "<I", 0), (6, "<B", 0), (20, "<I", 0), (52, "<H", 63)]:
            with self.subTest(offset=offset):
                self.assert_rejected(change_header(fixture(), offset, fmt, value))

    def test_section_table_entry_size_range_alignment(self):
        for offset, fmt, value in [(58, "<H", 0), (58, "<H", 63), (40, "<Q", 0),
                                   (40, "<Q", len(fixture())), (40, "<Q", 65),
                                   (40, "<Q", (1 << 64) - 1)]:
            with self.subTest(offset=offset, value=value):
                self.assert_rejected(change_header(fixture(), offset, fmt, value))

    def test_extended_and_sectionless_numbering_explicitly_unsupported(self):
        for offset, value in [(60, 0), (60, 0xff00), (62, 0xffff), (56, 0xffff)]:
            with self.subTest(offset=offset, value=value):
                self.assert_rejected(change_header(fixture(), offset, "<H", value), "Unsupported")

    def test_section_zero_and_name_table_index_and_type(self):
        self.assert_rejected(change_section(fixture(), 0, 4, "<I", 1), "zero")
        self.assert_rejected(change_header(fixture(), 62, "<H", 7), "string table index")
        self.assert_rejected(change_section(fixture(), 1, 4, "<I", 1), "SHT_STRTAB")
        self.assert_rejected(change_header(fixture(), 62, "<H", 0), "absent string table")

    def test_name_offsets_and_missing_terminators(self):
        data = fixture()
        size = elf.parse_all_sections(data)[1][5]
        self.assert_rejected(change_section(data, 2, 0, "<I", size), "name offset")
        pos = elf.parse_all_sections(data)[1][4]
        for changed_index in [pos, pos + size - 1]:
            changed = bytearray(data)
            changed[changed_index] = 65
            self.assert_rejected(bytes(changed), "NUL")

    def test_section_ranges_and_empty_section_offset(self):
        data = fixture()
        self.assert_rejected(change_section(data, 2, 32, "<Q", (1 << 64) - 1), "range")
        self.assert_rejected(change_section(data, 2, 24, "<Q", len(data) + 1), "range")
        empty = change_section(data, 2, 32, "<Q", 0)
        self.assert_rejected(change_section(empty, 2, 24, "<Q", len(data) + 1), "range")

    def test_overlapping_sections_headers_and_program_table(self):
        data = fixture()
        text_pos = elf.find_section(data, ".text")[1][4]
        self.assert_rejected(change_section(data, 4, 24, "<Q", text_pos), "overlap")
        self.assert_rejected(change_section(data, 2, 24, "<Q", 0), "ELF header")
        table = struct.unpack_from("<Q", data, 40)[0]
        self.assert_rejected(change_section(data, 2, 24, "<Q", table), "section header table")
        ph = change_header(data, 32, "<Q", table)
        ph = change_header(ph, 54, "<H", 56)
        ph = change_header(ph, 56, "<H", 1)
        self.assert_rejected(ph, "header tables overlap")

    def test_invalid_program_table_sizes_and_ranges(self):
        data = change_header(fixture(), 56, "<H", 1)
        self.assert_rejected(data, "program header")
        data = change_header(data, 54, "<H", 56)
        data = change_header(data, 32, "<Q", (1 << 64) - 1)
        self.assert_rejected(data, "program header")

    def test_known_section_link_and_info_index_semantics(self):
        data = fixture()
        self.assert_rejected(change_section(data, 5, 40, "<I", 7), "sh_link")
        self.assert_rejected(change_section(data, 6, 40, "<I", 7), "sh_link")
        self.assert_rejected(change_section(data, 6, 44, "<I", 7), "sh_info")
        flags = change_section(data, 2, 8, "<Q", 0x40)
        self.assert_rejected(change_section(flags, 2, 44, "<I", 7), "sh_info")
        flags = change_section(data, 2, 8, "<Q", 0x80)
        self.assert_rejected(change_section(flags, 2, 40, "<I", 7), "sh_link")

    def test_symbol_info_and_processor_specific_fields_are_not_section_indexes(self):
        data = change_section(fixture(), 5, 44, "<I", 200)
        self.assertEqual(elf.validate_elf_structure(data), [])
        unknown = change_section(fixture(), 6, 4, "<I", 0x70000001)
        unknown = change_section(unknown, 6, 40, "<I", 0xffffffff)
        unknown = change_section(unknown, 6, 44, "<I", 0xffffffff)
        self.assertEqual(elf.validate_elf_structure(unknown), [])

    def test_alignment_and_entry_length(self):
        self.assert_rejected(change_section(fixture(), 2, 48, "<Q", 3), "power of two")
        self.assert_rejected(change_section(fixture(), 2, 16, "<Q", 1), "sh_addr")
        self.assert_rejected(change_section(fixture(), 5, 56, "<Q", 23), "sh_entsize")

    def test_invalid_data_type_is_a_diagnostic(self):
        for data in (None, "ELF", 123):
            with self.subTest(data=data):
                self.assert_rejected(data, "bytes")


class TestPreciseMutations(unittest.TestCase):
    def test_each_field_uses_exact_spec_width_and_preserves_every_other_byte(self):
        data = fixture()
        table = struct.unpack_from("<Q", data, 40)[0]
        # Independently written gABI offsets and widths, not production constants.
        fields = [(0, 4), (4, 4), (8, 8), (16, 8), (24, 8),
                  (32, 8), (40, 4), (44, 4), (48, 8), (56, 8)]
        for index, (offset, width) in enumerate(fields):
            with self.subTest(field=index):
                value = (1 << (8 * width)) - 1
                result = elf.patch_section_field(data, 2, index, value)
                position = table + 2 * 64 + offset
                self.assertEqual(result[:position], data[:position])
                self.assertEqual(result[position:position + width], b"\xff" * width)
                self.assertEqual(result[position + width:], data[position + width:])
                self.assertEqual(len(result), len(data))

    def test_invalid_indices_types_and_uint_overflow_rejected(self):
        cases = [(-1, 0, 0), (7, 0, 0), (True, 0, 0), (1.0, 0, 0),
                 (2, -1, 0), (2, 10, 0), (2, True, 0), (2, "1", 0),
                 (2, 0, -1), (2, 0, 1 << 32), (2, 2, 1 << 64),
                 (2, 0, True), (2, 0, "1")]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                elf.patch_section_field(fixture(), *args)

    def test_invalid_input_not_mutated_and_bad_result_cannot_be_reparsed(self):
        data = fixture()
        invalid = elf.patch_section_field(data, 2, 5, (1 << 64) - 1)
        self.assertTrue(elf.validate_elf_structure(invalid))
        with self.assertRaises(ValueError):
            elf.patch_section_field(invalid, 2, 5, 0)
        self.assertEqual(data, fixture())

    def test_private_compatibility_writes_restrict_offset_width_pairs(self):
        data = bytearray(fixture())
        for args in [(40, 1, 8), (44, 1, 8), (1, 1, 4), (-4, 1, 4), (8, 1, 4), (0, 1, 3)]:
            original = bytes(data)
            with self.subTest(args=args), self.assertRaises(ValueError):
                elf._patch_shdr(data, 2, *args)
            self.assertEqual(bytes(data), original)
        elf._patch_shdr(data, 2, 40, 5, width=4)
        self.assertEqual(elf.parse_all_sections(data)[2][6], 5)

    def test_replace_keeps_other_headers_alignment_and_original_source(self):
        data = fixture()
        result = elf.replace_section_content(data, ".text", b"replacement")
        self.assertEqual(elf.validate_elf_structure(result), [])
        before, after = elf.parse_all_sections(data), elf.parse_all_sections(result)
        self.assertEqual(after[:2], before[:2])
        self.assertEqual(after[3:], before[3:])
        self.assertEqual(after[2][:4], before[2][:4])
        self.assertEqual(after[2][6:], before[2][6:])
        self.assertEqual(after[2][4] % 8, 0)
        self.assertEqual(result[after[2][4]:after[2][4] + after[2][5]], b"replacement")
        self.assertEqual(data, fixture())

    def test_replace_validated_before_output_write(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "modified.elf"
            result = elf.replace_section_content(fixture(), ".text", b"safe", str(output))
            self.assertEqual(output.read_bytes(), result)
            output.write_bytes(b"keep")
            with self.assertRaises(ValueError):
                elf.replace_section_content(fixture(), ".shstrtab", b"invalid", str(output))
            self.assertEqual(output.read_bytes(), b"keep")

    def test_replace_limits_pathological_alignment(self):
        data = change_section(fixture(), 2, 48, "<Q", 1 << 63)
        self.assertEqual(elf.validate_elf_structure(data), [])
        with self.assertRaisesRegex(ValueError, "alignment"):
            elf.replace_section_content(data, ".text", b"X")

    def test_append_preserves_legal_fixture_and_aligned_table(self):
        data = fixture()
        result = elf.append_section(data, ".new", b"NEW")
        self.assertEqual(elf.validate_elf_structure(result), [])
        self.assertEqual(len(elf.parse_all_sections(result)), 8)
        self.assertEqual(struct.unpack_from("<Q", result, 40)[0] % 8, 0)
        idx, hdr = elf.find_section(result, ".new")
        self.assertEqual(idx, 7)
        self.assertEqual(result[hdr[4]:hdr[4] + hdr[5]], b"NEW")
        self.assertEqual(elf.find_section(result, ".text"), elf.find_section(data, ".text"))
        self.assertEqual(data, fixture())

    def test_relocation_type_inference_checks_prefix_order(self):
        for name, kind, body in [(".rel.test", 9, bytes(16)), (".rela.test", 4, bytes(24))]:
            with self.subTest(name=name):
                result = elf.append_section(fixture(), name, body)
                self.assertEqual(elf.find_section(result, name)[1][1], kind)

    def test_invalid_append_names_types_and_content_are_rejected(self):
        for name in ["", "x\x00y", ".text", 3, "\ud800"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                elf.append_section(fixture(), name, b"X")
        for kind in [0, 8, -1, 1 << 32, True]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                elf.append_section(fixture(), ".new", b"X", kind)
        with self.assertRaises(ValueError):
            elf.append_section(fixture(), ".new", None)
        with self.assertRaises(ValueError):
            elf.replace_section_content(fixture(), ".missing", b"X")

    def test_section_name_supported_limit_bounds_scan_and_mutation(self):
        maximum = "N" * elf.MAX_SECTION_NAME_BYTES
        self.assertEqual(elf._section_name(b"\0" + maximum.encode() + b"\0", 1), maximum)
        with self.assertRaisesRegex(ValueError, "4096-byte limit"):
            elf._section_name(b"\0" + maximum.encode() + b"N\0", 1)
        with self.assertRaisesRegex(ValueError, "4096-byte limit"):
            elf.append_section(fixture(), maximum + "N", b"X")
        valid = elf.append_section(fixture(), maximum, b"X")
        self.assertEqual(elf.find_section(valid, maximum)[1][5], 1)


if __name__ == "__main__":
    unittest.main()
