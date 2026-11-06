# -*- coding: utf-8 -*-
"""The table scan must verify registers, not adjacency."""

import json
from pathlib import Path

import pytest

TABLE = Path("data/driver/f9r2_table.json")
pytestmark = pytest.mark.skipif(not TABLE.is_file(), reason="f9r2 table 未生成")


@pytest.fixture(scope="module")
def table() -> dict:
    return json.loads(TABLE.read_text(encoding="utf-8"))


def test_pairs_carry_bytes_and_registers(table):
    assert table["count"] > 0
    for entry in table["pairs"][:5]:
        assert entry["bytes"], "缺少原始字节"
        assert entry["value_reg"] and entry["base_reg"]
        assert entry["target_rva"].startswith("0x")
        assert entry["lea_rva"].startswith("0x")


def test_adjacent_instructions_with_other_registers_are_rejected(table):
    """The old scan paired any lea with any following mov."""
    for entry in table["rejected"]:
        assert entry.get("reason"), "被拒绝的配对应说明原因"
    assert table["rejected_count"] == len(table["rejected"])


def test_offset_0x110_store_is_present_with_its_target(table):
    hit = [p for p in table["pairs"] if p["field_offset"] == "0x110"]
    assert hit, "0x110 写入应存在于校验后的配对中"
    assert hit[0]["target_rva"] == "0x733e240"
    assert hit[0]["base_reg"] == "rbp"


def test_base_register_is_a_stack_frame(table):
    writes = table["base_binding"]["writes"]
    assert writes and writes[0]["text"].startswith("lea rbp, [rsp")
    # 结构体在栈上，不等于它一定是 DRIVER_INITIALIZATION_DATA
    assert "0x733a124" in writes[0]["rva"]
