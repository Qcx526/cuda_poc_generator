# -*- coding: utf-8 -*-
"""Roles come from the candidate's own manifest when it left one."""

import json
from pathlib import Path

from src.run_artifacts import role_for, roles_from_manifest


def test_manifest_roles_win_over_filenames(tmp_path: Path):
    (tmp_path / "artifacts.json").write_text(json.dumps({
        "benign": ["base.bin"], "crafted": ["evil.bin"], "controls": ["fixed.bin"],
    }), encoding="utf-8")
    mapping = roles_from_manifest(tmp_path)
    assert mapping == {"base.bin": "BENIGN", "evil.bin": "MALICIOUS",
                       "fixed.bin": "CONTROL"}


def test_without_a_manifest_the_filename_is_the_only_hint(tmp_path: Path):
    assert roles_from_manifest(tmp_path) == {}
    assert role_for("poc_whatever.cubin") == "MALICIOUS"


def test_a_broken_manifest_falls_back_to_filenames(tmp_path: Path):
    (tmp_path / "artifacts.json").write_text("{not json", encoding="utf-8")
    assert roles_from_manifest(tmp_path) == {}
