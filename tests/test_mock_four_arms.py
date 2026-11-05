# -*- coding: utf-8 -*-
"""Four-arm wiring, mutation constraints and facts projection.

These are the properties that make the A/B/C/D comparison mean anything: an arm that
silently receives another arm's context is not a different condition, and a mutation
adapter that encodes the trigger is not a test of reasoning.
"""

import json
import tempfile
from pathlib import Path

import pytest

from mock_native import binding as nb
from src import mock_facts, mock_mutation
from tools.driver import mock_experiment

FACTS = Path("data/driver/mock_facts/mock_gpu_facts.json")

pytestmark = pytest.mark.native_required


class _Stub:
    model_name = "stub"

    def chat(self, messages, temperature=0.1):
        return ("```python\nimport json, mock_gpu\n"
                "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': []}))\n```\n")


def _prompt_for(arm: str, workdir: Path) -> str:
    mock_experiment.run("w" + arm, rounds=1, workdir=workdir, arm=arm,
                        mutation_seed=11, client=_Stub(), facts_path=FACTS)
    return (workdir / ("w" + arm) / "round1" / "prompt.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("arm,facts,mutation", [
    ("A", False, False), ("B", True, False), ("C", False, True), ("D", True, True)])
def test_each_arm_receives_exactly_its_own_context(arm, facts, mutation, tmp_path):
    text = _prompt_for(arm, tmp_path)
    assert ("静态事实" in text) is facts
    assert ("结构化变异" in text) is mutation


def test_no_arm_sees_oracle_wording(tmp_path):
    for arm in "ABCD":
        text = _prompt_for(arm, tmp_path)
        for word in ("oracle", "AUTHZ_BYPASS", "OOB_READ", "flaw", "触发条件"):
            assert word.lower() not in text.lower(), "%s 的 prompt 含 %s" % (arm, word)


def test_facts_projection_drops_analyst_notes():
    raw = mock_facts.load_raw(FACTS)
    projected = mock_facts.project(raw)
    text = json.dumps(projected).lower()
    assert "flaw" not in text and "oracle" not in text
    assert "note" not in projected["artifact"]
    assert projected["artifact"]["sha256"] == raw["artifact"]["sha256"]


def test_facts_are_rejected_when_the_dll_hash_differs(tmp_path):
    facts = json.loads(FACTS.read_text(encoding="utf-8"))
    facts["artifact"]["sha256"] = "0" * 64
    altered = tmp_path / "facts.json"
    altered.write_text(json.dumps(facts), encoding="utf-8")
    with pytest.raises(mock_facts.FactsError):
        mock_facts.verify_artifact(nb.DLL, mock_facts.load_raw(altered))


def test_mutation_space_encodes_no_trigger_formula():
    seeds = mock_mutation.baseline_space()
    candidates = mock_mutation.expand(seeds, __import__("random").Random(3), budget=8)
    blob = json.dumps([c.explain() for c in candidates]) + mock_mutation.context_block(
        candidates, seeds, 3)
    for hint in ("declared", "len(payload) - 4", "len-3", "size+1", "off-by-one"):
        assert hint not in blob.lower()


def test_mutation_is_deterministic_and_deduplicated():
    import random

    first = mock_mutation.expand(mock_mutation.baseline_space(), random.Random(5), 6)
    second = mock_mutation.expand(mock_mutation.baseline_space(), random.Random(5), 6)
    assert [c.key() for c in first] == [c.key() for c in second]
    assert len({c.key() for c in first}) == len(first)


def test_categories_separate_normal_boundary_and_expected_invalid():
    assert mock_mutation.classify(mock_mutation.Candidate(type=3, payload_len=10)) == \
        mock_mutation.NORMAL
    assert mock_mutation.classify(mock_mutation.Candidate(type=7)) == mock_mutation.BOUNDARY
    assert mock_mutation.classify(mock_mutation.Candidate(payload_len=2048)) == \
        mock_mutation.EXPECTED_INVALID


def test_payload_bytes_are_reproducible_for_a_candidate():
    import random

    candidate = mock_mutation.Candidate(payload_len=64, payload_kind="random")
    first = mock_mutation.payload_bytes(candidate, random.Random(1))
    second = mock_mutation.payload_bytes(candidate, random.Random(1))
    assert first == second and len(first) == 64


def test_call_budget_is_enforced_by_the_server(tmp_path):
    """An arm cannot buy more driver calls by enumerating more inputs."""
    from tools.driver import mock_bench

    candidate = tmp_path / "poc.py"
    candidate.write_text(
        "import json, mock_gpu\n"
        "statuses = []\n"
        "for _ in range(10):\n"
        "    s, a = mock_gpu.open_adapter()\n"
        "    statuses.append(s)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': []}))\n",
        encoding="utf-8")
    verdict = mock_bench.run_candidate(candidate, max_calls=4)
    assert verdict["external"]["calls_made"] == 4
    assert verdict["external"]["max_calls"] == 4
