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


def test_pairs_are_not_one_table(table):
    """51 rbp-relative and 6 rsp-relative writes are different objects."""
    groups = table["base_groups"]
    assert set(groups) == {"rbp", "rsp"}
    assert groups["rbp"]["count"] + groups["rsp"]["count"] == table["count"]


def test_no_consumer_takes_rbp_as_an_argument(table):
    """Six kilobytes of calls after the fills, none sets an argument from rbp."""
    assert table["consumer"]["calls_after_fill"] > 0
    assert table["consumer"]["argument_from_rbp"] == []


def test_the_candidate_target_is_not_a_function_start(table):
    bounds = table["candidate_bounds"]
    assert bounds["executable"] is True
    assert bounds["section"] == "INIT"
    assert bounds["function_at_rva"] is False
