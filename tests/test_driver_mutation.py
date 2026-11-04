# -*- coding: utf-8 -*-
"""Mutation space invariants.

The value of these tests is mostly negative: they prove the mutator *cannot*
invent a vendor-private Type, a Flags meaning, or a private body. Everything the
project refuses to guess is frozen here as a constraint.
"""

import random

from src import driver_mutation as mut


def test_the_allowed_space_never_invents_a_private_type_or_flags():
    for case in mut.legal_space():
        assert case.type == 0
        assert case.flags == 0
        assert case.body == b""


def test_a_mutation_changes_exactly_one_field():
    rng = random.Random(7)
    before = mut.EscapeInput(context="none")
    change = mut.mutate(before, rng)
    assert len(change.changed) == 1
    assert change.changed[0] == "hContext"
    assert change.case.context != before.context


def test_the_same_seed_produces_the_same_mutation():
    first = mut.mutate(mut.EscapeInput(), random.Random(11))
    second = mut.mutate(mut.EscapeInput(), random.Random(11))
    assert first.case == second.case


def test_mutation_is_exhausted_rather_than_repeated():
    case = mut.EscapeInput(context="own")
    change = mut.mutate(case, random.Random(3), contexts=("own",))
    assert change.changed == []
    assert "穷尽" in change.reason


def test_corpus_deduplicates_on_structure_not_on_notes():
    corpus = mut.Corpus()
    case = mut.EscapeInput(context="own")
    assert corpus.add(case, 0, "first note") is True
    assert corpus.add(case, 0, "a different note") is False
    assert len(corpus) == 1


def test_status_attribution_does_not_pretend_to_know_the_reason():
    assert mut.attribute(0) == "ACCEPTED"
    assert mut.attribute(0xC000000D).startswith("REJECTED")
    assert mut.attribute(None) == "NO_RESULT"


def test_next_round_skips_cases_that_already_ran():
    executed = [(mut.EscapeInput(context="none"), 0xC000000D)]
    pending = mut.next_round(executed, random.Random(5))
    assert pending
    assert all(item.case.context != "none" for item in pending)


def test_diff_lists_the_changed_fields_only():
    before = mut.EscapeInput(context="none")
    after = mut.mutate(before, random.Random(1)).case
    diff = mut.Mutation(after, ["hContext"], "x").diff(before)
    assert diff["changed_fields"] == ["hContext"]
    assert diff["before"]["Type"] == diff["after"]["Type"] == 0


def test_context_block_reports_the_changed_field_by_header_name():
    base = mut.EscapeInput(context="none")
    case = mut.EscapeInput(context="own")
    block = mut.context_block(base, case, rng_seed=1234)
    import json

    payload = json.loads(block)
    assert payload["changed_fields"] == ["hContext"]
    assert payload["seed"]["provenance"] == "synthetic"
    assert payload["unknowns"]
