# -*- coding: utf-8 -*-
"""New knowledge must not sit behind a stale index."""

import os
from pathlib import Path

from src.data_loader import _index_is_stale


def _touch(path: Path, when: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")
    os.utime(path, (when, when))


def test_no_index_means_rebuild(tmp_path):
    kb = tmp_path / "kb"
    _touch(kb / "a.md", 1000)
    assert _index_is_stale(kb, tmp_path / "index") is True


def test_a_document_newer_than_the_index_means_rebuild(tmp_path):
    kb = tmp_path / "kb"
    index = tmp_path / "index"
    _touch(kb / "a.md", 1000)
    _touch(index / "chroma.sqlite3", 2000)
    _touch(kb / "mutation.md", 3000)          # written after the build
    assert _index_is_stale(kb, index) is True


def test_an_index_newer_than_every_document_is_reused(tmp_path):
    kb = tmp_path / "kb"
    index = tmp_path / "index"
    _touch(kb / "a.md", 1000)
    _touch(index / "chroma.sqlite3", 2000)
    assert _index_is_stale(kb, index) is False
