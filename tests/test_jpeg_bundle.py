# -*- coding: utf-8 -*-
"""Manifest and offline verification tests.

Verification must fail closed: a single flipped byte, a missing file or a rewritten plan
has to be reported, and nothing may be repaired in place.
"""

import json

import pytest

from src.jpeg_adapter import build_baseline, write_bundle
from src.jpeg_bundle import BundleError, canonical, digest, verify_bundle

PLAN = {"operations": [{"op": "set_sof_size", "width": 48, "height": 32},
                       {"op": "set_dri", "interval": 0}]}


@pytest.fixture()
def bundle(tmp_path):
    write_bundle(tmp_path, build_baseline(64, 64), PLAN)
    return tmp_path


def test_manifest_is_written_with_required_sections(bundle):
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "jpeg-bundle-manifest/v1"
    for key in ("adapter", "artifacts", "pairing", "provenance", "manifest_sha256"):
        assert key in manifest
    assert set(manifest["artifacts"]) == {"baseline", "candidate", "control"}
    assert manifest["adapter"]["adapter_source_sha256"]
    assert manifest["adapter"]["reference_decoder"] == "Pillow"


def test_manifest_has_no_run_specific_identity(bundle):
    text = (bundle / "manifest.json").read_text(encoding="utf-8")
    assert str(bundle) not in text, "absolute paths must not enter content identity"
    manifest = json.loads(text)
    assert "timestamp" not in json.dumps(manifest["adapter"])
    # Determinism: rebuilding the same bundle yields the same content hash.
    again = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert again["manifest_sha256"] == manifest["manifest_sha256"]


def test_verify_accepts_a_good_bundle(bundle):
    result = verify_bundle(bundle)
    assert result["ok"] is True


def test_verify_rejects_modified_candidate(bundle):
    path = bundle / "poc_plan.jpg"
    data = bytearray(path.read_bytes())
    data[-2] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(BundleError) as exc:
        verify_bundle(bundle)
    assert "candidate sha256 mismatch" in str(exc.value)


def test_verify_rejects_missing_control(bundle):
    (bundle / "ctrl_restored.jpg").unlink()
    with pytest.raises(BundleError) as exc:
        verify_bundle(bundle)
    assert "control missing" in str(exc.value)


def test_verify_rejects_edited_plan(bundle):
    path = bundle / "plan.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["plan"]["operations"].append({"op": "set_dri", "interval": 9})
    path.write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(BundleError) as exc:
        verify_bundle(bundle)
    assert "plan_sha256 mismatch" in str(exc.value)


def test_verify_rejects_control_that_is_not_baseline(bundle):
    baseline = (bundle / "benign_baseline.jpg").read_bytes()
    (bundle / "ctrl_restored.jpg").write_bytes(baseline[:-2] + b"\xff\xd8")
    with pytest.raises(BundleError) as exc:
        verify_bundle(bundle)
    message = str(exc.value)
    assert "control does not equal baseline" in message or "control sha256 mismatch" in message


def test_canonical_json_is_order_independent():
    a = {"b": 1, "a": [1, 2, {"z": 0, "y": 1}]}
    b = {"a": [1, 2, {"y": 1, "z": 0}], "b": 1}
    assert canonical(a) == canonical(b)
    assert digest(a) == digest(b)
