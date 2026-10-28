# -*- coding: utf-8 -*-
"""Mutation is only useful if each variant differs in exactly one place."""

import pytest

from src.mutation_campaign import (CLEAN, NOVEL, SAME, UNKNOWN, Variant, apply,
                                   classify, missing_axes, plan, verdict)


def spec_with_axes():
    return {
        "mutation": {
            "seed": "poc.cubin",
            "axes": [
                {"name": "boundary", "field": "sh_size", "offset": 32, "width": 8,
                 "values": [0, 12]},
                {"name": "mechanism", "field": "sh_type", "offset": 4, "width": 4,
                 "values": [1, 4]},
            ],
            "required": ["boundary", "mechanism"],
        }
    }


def test_plan_covers_every_declared_value():
    variants = plan(spec_with_axes())
    assert [(v.axis, v.value) for v in variants] == [
        ("boundary", 0), ("boundary", 12), ("mechanism", 1), ("mechanism", 4)]


def test_an_axis_without_an_offset_is_rejected():
    with pytest.raises(ValueError):
        plan({"mutation": {"axes": [{"name": "x", "field": "f", "values": [1]}]}})


def test_apply_changes_one_field_and_nothing_else():
    seed = bytes(range(64))
    mutated = apply(seed, 32, 8, 0x1122334455667788)
    assert mutated[:32] == seed[:32]
    assert mutated[40:] == seed[40:]
    assert mutated[32:40] == bytes.fromhex("8877665544332211")


def test_a_zero_width_write_leaves_the_seed_alone():
    """The seed itself runs as a variant; writing eight zero bytes would make it
    an invalid file and quietly destroy the baseline."""
    seed = bytes(range(32))
    assert apply(seed, 0, 0, 0) == seed


def test_a_field_past_the_end_is_refused():
    with pytest.raises(ValueError):
        apply(b"\x00" * 8, 8, 8, 1)


def test_missing_axes_are_reported():
    assert missing_axes({"mutation": {"required": ["boundary"]}}, [])
    assert not missing_axes(spec_with_axes(), plan(spec_with_axes()))


def test_classify_separates_same_clean_and_new_sites():
    variants = [
        Variant("boundary", "sh_size", 0, 0, 8, exit_code=139,
                fingerprint="nvdisasm+0x28000"),
        Variant("boundary", "sh_size", 24, 0, 8, exit_code=0),
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=139,
                fingerprint="nvdisasm+0x1a000"),
        Variant("mechanism", "sh_type", 2, 0, 4),
    ]
    classify(variants, "nvdisasm+0x28000")
    assert [v.outcome for v in variants] == [SAME, CLEAN, NOVEL, UNKNOWN]


def test_the_verdict_says_when_the_mechanism_does_not_matter():
    variants = [
        Variant("seed", "(unchanged)", 0, 0, 0, exit_code=139,
                fingerprint="nvdisasm+0x28000", outcome=""),
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=139,
                fingerprint="nvdisasm+0x28000", outcome=SAME),
        Variant("mechanism", "sh_type", 4, 0, 4, exit_code=139,
                fingerprint="nvdisasm+0x28000", outcome=SAME),
    ]
    text = " ".join(verdict(variants, "nvdisasm+0x28000"))
    # A field that cannot remove the crash says nothing about attribution; the
    # verdict must not turn it into "not this CVE".
    assert "不区分" in text
    assert "不是该 CVE" not in text


def test_knowledge_entry_states_what_the_axes_proved():
    from src.mutation_campaign import knowledge_markdown

    variants = [
        Variant("seed", "(unchanged)", 0, 0, 0, exit_code=139, fingerprint="nvdisasm+0x28000"),
        Variant("boundary", "sh_size", 0, 0, 8, exit_code=139,
                fingerprint="nvdisasm+0x28000", outcome=SAME),
        Variant("boundary", "sh_size", 24, 0, 8, exit_code=0, outcome=CLEAN),
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=139,
                fingerprint="nvdisasm+0x28000", outcome=SAME),
    ]
    text = knowledge_markdown(variants, "CVE-X", "nvdisasm+0x28000")
    assert "CVE-X" in text
    # The mechanism axis changed nothing, so the entry may describe what was
    # measured but must not present it as the trigger condition.
    assert "未确证归属" in text
    assert "不是 CVE-X 的区分轴" in text


def test_knowledge_is_one_file_per_cve(tmp_path):
    from src.mutation_campaign import write_knowledge

    # Attributed, so it lands in the directory under test rather than in the
    # pending area for unproven conclusions.
    variants = [Variant("mechanism", "sh_type", 1, 0, 4, exit_code=0, outcome=CLEAN)]
    first = write_knowledge(variants, "CVE-X", "a+0x1000", tmp_path)
    second = write_knowledge(variants, "CVE-X", "a+0x1000", tmp_path)
    assert first == second
    assert len(list(tmp_path.glob("*.md"))) == 1


def test_only_novel_variants_reach_the_findings_store():
    """A crash that repeated the seed is not a finding; one somewhere else is."""
    from src.mutation_campaign import novel_lines

    raw = ("[CPG_RUN] a.cubin::cuobjdump exit=139\n"
           "[CPG_CRASH] a.cubin sig=11 code=1 pc=0x1 base=0x0 off=0xb000 "
           "addr=0x0 module=cuobjdump insn=803f00\n"
           "[CPG_RUN] b.cubin::cuobjdump exit=139\n"
           "[CPG_CRASH] b.cubin sig=11 code=1 pc=0x2 base=0x0 off=0x12000 "
           "addr=0x0 module=cuobjdump insn=803f00\n")
    kept = novel_lines(raw, ["b.cubin"])
    assert "b.cubin" in kept
    assert "a.cubin" not in kept


def test_a_nonzero_exit_without_a_fault_site_is_not_a_new_site():
    """The tool rejecting an input is not a crash somewhere else."""
    variants = [
        Variant("seed", "(unchanged)", 0, 0, 0, exit_code=139,
                fingerprint="cuobjdump+0xb000"),
        Variant("structure", "e_shnum", 1, 60, 2, exit_code=1, fingerprint=""),
    ]
    classify(variants, "cuobjdump+0xb000")
    assert variants[1].outcome == UNKNOWN


def test_knowledge_without_attribution_refuses_to_give_instructions():
    """A mechanism axis that changes nothing cannot license a reproduction rule."""
    from src.mutation_campaign import attributed, knowledge_markdown

    unattributed = [
        Variant("seed", "(unchanged)", 0, 0, 0, exit_code=139, fingerprint="a+0x1000"),
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=139, fingerprint="a+0x1000", outcome=SAME),
        Variant("boundary", "sh_size", 0, 0, 8, exit_code=139, fingerprint="a+0x1000", outcome=SAME),
        Variant("boundary", "sh_size", 24, 0, 8, exit_code=0, outcome=CLEAN),
    ]
    assert attributed(unattributed) is False
    text = knowledge_markdown(unattributed, "CVE-X", "a+0x1000")
    assert "未确证归属" in text
    assert "生成时应直接取窗口内的值" not in text

    attributed_arm = [
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=0, outcome=CLEAN),
    ]
    assert attributed(attributed_arm) is True


def test_unattributed_knowledge_goes_outside_the_index(tmp_path):
    """Handing an unproven conclusion to the generator is how a false positive
    gets reproduced on purpose."""
    from src.mutation_campaign import write_knowledge

    variants = [
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=139,
                fingerprint="a+0x1000", outcome=SAME),
    ]
    indexed = tmp_path / "kb" / "mutation"
    path = write_knowledge(variants, "CVE-X", "a+0x1000", indexed)
    assert "pending" in str(path)
    assert not (indexed / "CVE-X.md").exists()


def test_attributed_knowledge_stays_in_the_index(tmp_path):
    from src.mutation_campaign import write_knowledge

    variants = [
        Variant("mechanism", "sh_type", 1, 0, 4, exit_code=0, outcome=CLEAN),
    ]
    indexed = tmp_path / "kb" / "mutation"
    path = write_knowledge(variants, "CVE-X", "a+0x1000", indexed)
    assert path == indexed / "CVE-X.md"
