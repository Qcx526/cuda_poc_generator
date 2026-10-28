# -*- coding: utf-8 -*-
"""Read or write decides whether a crash is a denial of service or a primitive."""

from src.fault_site import EXEC, READ, UNKNOWN, WRITE, access_type, classify


def test_a_compare_reads():
    assert access_type("803f00") == READ                 # cmp byte ptr [rdi], 0


def test_a_store_writes():
    assert access_type("488909") == WRITE                # mov [rcx], rcx
    assert access_type("c70000000000") == WRITE          # mov dword ptr [rax], 0


def test_a_load_reads():
    assert access_type("488b01") == READ                 # mov rax, [rcx]


def test_an_instruction_without_memory_is_a_fetch():
    assert access_type("0f0b") == EXEC                   # ud2


def test_undecodable_input_is_unknown_rather_than_a_guess():
    assert access_type("") == UNKNOWN
    assert access_type("zz") == UNKNOWN


def test_severity_separates_a_null_read_from_a_write():
    assert classify("803f00", 0)["severity"] == "null-read"
    assert classify("488909", 0x41414141)["severity"] == "write-to-address"
    assert classify("488b01", 0x2000)["severity"] == "read-out-of-bounds"
