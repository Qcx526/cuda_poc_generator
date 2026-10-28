# -*- coding: utf-8 -*-
"""New knowledge must not sit behind a stale index.

The first version compared modification times and was defeated by `mv`: moving a
file back into the directory restores its old timestamp, so an index built without
it still looked current. Content is what the index is a function of, so content is
what the check compares.
"""

import json
from pathlib import Path

from src.data_loader import _corpus_fingerprint, _index_is_stale, _write_corpus_stamp


def _doc(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_no_index_means_rebuild(tmp_path):
    _doc(tmp_path / "kb" / "a.md", "hello")
    assert _index_is_stale(tmp_path / "kb", tmp_path / "index") is True


def test_an_index_without_a_stamp_is_not_trusted(tmp_path):
    _doc(tmp_path / "kb" / "a.md", "hello")
    (tmp_path / "index").mkdir()
    assert _index_is_stale(tmp_path / "kb", tmp_path / "index") is True


def test_a_matching_stamp_is_reused(tmp_path):
    _doc(tmp_path / "kb" / "a.md", "hello")
    stamp = tmp_path / "index" / "kb_corpus.json"
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps({"sha256": _corpus_fingerprint(tmp_path / "kb")}),
                     encoding="utf-8")
    assert _index_is_stale(tmp_path / "kb", tmp_path / "index") is False


def test_a_restored_file_invalidates_the_index_even_with_an_old_timestamp(tmp_path):
    """This is the case modification times could not see."""
    _doc(tmp_path / "kb" / "a.md", "hello")
    stamp = tmp_path / "index" / "kb_corpus.json"
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps({"sha256": _corpus_fingerprint(tmp_path / "kb")}),
                     encoding="utf-8")
    _doc(tmp_path / "kb" / "mutation.md", "a conclusion")
    assert _index_is_stale(tmp_path / "kb", tmp_path / "index") is True


def test_building_writes_the_stamp(tmp_path):
    _doc(tmp_path / "kb" / "a.md", "hello")
    _write_corpus_stamp(tmp_path / "kb", tmp_path / "index")
    assert _index_is_stale(tmp_path / "kb", tmp_path / "index") is False
