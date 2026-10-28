# -*- coding: utf-8 -*-
"""The control arm must be a fair, single-change comparison."""

from src.baseline_control import compare, random_variants, summarise
from src.mutation_campaign import CLEAN, NOVEL, SAME, UNKNOWN, Variant


def test_each_random_variant_changes_one_byte_in_a_distinct_place():
    variants = random_variants(size=512, count=20, seed=1)
    assert len(variants) == 20
    assert len({v.offset for v in variants}) == 20
    assert all(v.width == 1 for v in variants)
    assert all(v.offset >= 0x40 for v in variants)   # ELF ident block untouched


def test_the_same_seed_gives_the_same_control():
    a = [v.offset for v in random_variants(256, 5, seed=3)]
    b = [v.offset for v in random_variants(256, 5, seed=3)]
    assert a == b


def test_summary_counts_outcomes_and_distinct_sites():
    variants = [
        Variant("random", "byte", 1, 100, 1, exit_code=139, fingerprint="a+0x1000", outcome=SAME),
        Variant("random", "byte", 2, 200, 1, exit_code=139, fingerprint="a+0x2000", outcome=NOVEL),
        Variant("random", "byte", 3, 300, 1, exit_code=0, outcome=CLEAN),
        Variant("random", "byte", 4, 400, 1, exit_code=1, outcome=UNKNOWN),
    ]
    summary = summarise(variants, "a+0x1000")
    assert summary["counts"][SAME] == 1
    assert summary["counts"][CLEAN] == 1
    assert summary["distinct_sites"] == 2
    assert summary["novel_sites"] == ["a+0x2000"]


def test_the_comparison_prints_both_arms():
    table = compare({"counts": {NOVEL: 2}, "distinct_sites": 3, "novel_sites": ["x", "y"]},
                    {"counts": {NOVEL: 1}, "distinct_sites": 2, "novel_sites": ["z"]})
    assert "语义轴变异" in table and "随机字节变异" in table
    assert "**2**" in table and "**1**" in table
