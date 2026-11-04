# -*- coding: utf-8 -*-
"""Seed corpus invariants.

The corpus is only useful if "captured" means it ran and "synthetic" means it did
not. These tests pin that down, plus the snapshot bug that made every earlier
seed inherit later releases.
"""

from src import driver_seeds as seeds


def test_synthetic_seed_is_labelled_and_never_claims_execution():
    sample = seeds.synthetic_escape()
    assert sample.provenance == seeds.SYNTHETIC
    assert sample.params["pPrivateDriverData"] is None
    assert sample.params["PrivateDriverDataSize"] == 0


def test_earlier_snapshots_do_not_inherit_later_releases():
    """Sharing handle objects made correct calls look like use-after-release."""
    hdc = seeds.Handle("hdc", "hdc", "CreateDCW", value=1)
    first = seeds.Seed("a", "CreateDCW", {"hdc": "hdc"}, 0, ["CreateDCW"],
                       seeds.snapshot([hdc]))
    hdc.released_by = "DeleteDC"
    assert first.handles[0].released_by == ""
    assert hdc.released_by == "DeleteDC"


def test_a_destroying_call_is_not_a_lifecycle_violation():
    handle = seeds.Handle("hContext", "hContext", "D3DKMTCreateContext",
                          released_by="D3DKMTDestroyContext", value=7)
    sample = seeds.Seed("d", "D3DKMTDestroyContext", {"hContext": "hContext"}, 0,
                        ["D3DKMTDestroyContext"], [handle])
    assert seeds.lifecycle_problems([sample]) == []


def test_use_after_release_is_reported():
    handle = seeds.Handle("hDevice", "hDevice", "D3DKMTCreateDevice",
                          released_by="D3DKMTDestroyDevice", value=9)
    sample = seeds.Seed("u", "D3DKMTCreateContext", {"hDevice": "hDevice"}, 0,
                        ["D3DKMTCreateContext"], [handle])
    assert seeds.lifecycle_problems([sample])


def test_digest_is_stable_and_order_independent():
    assert seeds.digest({"a": 1, "b": 2}) == seeds.digest({"b": 2, "a": 1})
    assert seeds.digest({"a": 1}) != seeds.digest({"a": 2})
