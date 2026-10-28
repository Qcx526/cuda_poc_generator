# -*- coding: utf-8 -*-
"""A fingerprint says where; memcheck says what."""

from src.finding_analysis import parse

NULL_STRCMP = """\
==27== Invalid read of size 1
==27==    at 0x483FED4: strcmp (in vgpreload_memcheck-amd64-linux.so)
==27==    by 0x412DFC: ??? (in /usr/local/cuda-11.2/bin/cuobjdump)
==27==  Address 0x0 is not stack'd, malloc'd or (recently) free'd
"""

NULL_FIELD = """\
==28== Invalid read of size 4
==28==    at 0x414000: ??? (in /usr/local/cuda-11.2/bin/cuobjdump)
==28==  Address 0x4 is not stack'd, malloc'd or (recently) free'd
"""

HEAP_WRITE = """\
==29== Invalid write of size 8
==29==    at 0x415000: ??? (in /usr/local/cuda-11.2/bin/cuobjdump)
==29==  Address 0x5555 is not stack'd, malloc'd or (recently) free'd
"""


def test_a_null_string_is_a_null_dereference():
    report = parse(NULL_STRCMP)
    assert report["verdict"] == "null-dereference"
    assert report["address"] == "0x0"
    assert "strcmp" in report["frames"]


def test_reading_a_field_of_a_null_struct_is_still_a_null_dereference():
    report = parse(NULL_FIELD)
    assert report["verdict"] == "null-dereference"
    assert report["address"] == "0x4"


def test_a_write_to_a_made_up_address_is_its_own_verdict():
    report = parse(HEAP_WRITE)
    assert report["verdict"] == "invalid-write"


def test_no_memcheck_output_is_unknown_rather_than_a_guess():
    assert parse("")["verdict"] == "unknown"
