# -*- coding: utf-8 -*-
"""Bundle manifest and offline verification.

The bundle is the unit of evidence: one baseline, one candidate, one control, plus the
plan and journal that connect them. A manifest that only lists file names is not enough
to re-check anything later, so this records hashes over canonical JSON, the adapter's own
identity, and the structure and reference verdict of each artifact.

Nothing in the manifest depends on when or where the run happened: no timestamps, no
absolute paths, no UUIDs. Those belong in a separate run record, and keeping them out
means the manifest hash is stable across machines.
"""

import hashlib
import json
import sys
from pathlib import Path

from .jpeg_adapter import diff_range, reference_decode, sha256, walk
from .jpeg_parser import summary

MANIFEST_SCHEMA = "jpeg-bundle-manifest/v1"
ADAPTER_VERSION = "1.1.0"
FILES = {"baseline": "benign_baseline.jpg",
         "candidate": "poc_plan.jpg",
         "control": "ctrl_restored.jpg"}


def canonical(payload) -> str:
    """Deterministic JSON: sorted keys, no whitespace, no ASCII escaping surprises."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(payload) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def adapter_identity() -> dict:
    package = Path(__file__).resolve().parent
    source = (package / "jpeg_adapter.py").read_bytes() + (package / "jpeg_parser.py").read_bytes()
    try:
        import PIL
        pillow_version = PIL.__version__
    except Exception:  # noqa: BLE001 - identity must not fail the bundle
        pillow_version = "unknown"
    return {
        "schema": MANIFEST_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "adapter_source_sha256": hashlib.sha256(source).hexdigest(),
        "reference_decoder": "Pillow",
        "reference_decoder_version": pillow_version,
        "python": "%d.%d" % (sys.version_info.major, sys.version_info.minor),
    }


def artifact_record(path: Path, role: str) -> dict:
    data = path.read_bytes()
    ok, error, size, mode = reference_decode(data)
    return {
        "role": role,
        "file": path.name,
        "sha256": sha256(data),
        "bytes": len(data),
        "structure": summary(data),
        "reference": {"ok": ok, "error": error,
                      "size": list(size), "mode": mode},
    }


def build_manifest(directory: Path) -> dict:
    """Describe the bundle that ``write_bundle`` just wrote."""
    paths = {role: directory / name for role, name in FILES.items()}
    baseline = paths["baseline"].read_bytes()
    candidate = paths["candidate"].read_bytes()
    control = paths["control"].read_bytes()
    stored = json.loads((directory / "plan.json").read_text(encoding="utf-8"))

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "adapter": adapter_identity(),
        "artifacts": {role: artifact_record(paths[role], role) for role in FILES},
        "pairing": {
            "control_equals_baseline_bytes": control == baseline,
            "control_sha256_equals_baseline": sha256(control) == sha256(baseline),
            "candidate_differs_from_baseline": candidate != baseline,
            "diff_candidate_baseline": diff_range(candidate, baseline),
            "diff_candidate_control": diff_range(candidate, control),
        },
        "provenance": {
            "plan": stored["plan"],
            "plan_sha256": digest(stored["plan"]),
            "journal": stored["journal"],
            "journal_sha256": digest(stored["journal"]),
        },
    }
    manifest["manifest_sha256"] = digest({k: v for k, v in manifest.items()
                                          if k != "manifest_sha256"})
    return manifest


def write_manifest(directory: Path) -> dict:
    manifest = build_manifest(directory)
    (directory / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
    return manifest


class BundleError(ValueError):
    """The bundle does not verify; never repaired in place."""


def verify_bundle(directory: Path, recheck_reference: bool = True) -> dict:
    """Recompute every claim in the manifest. Raises BundleError on any mismatch."""
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        raise BundleError("manifest.json missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise BundleError("unexpected schema: %r" % manifest.get("schema"))

    problems = []
    stored_manifest_sha = manifest.get("manifest_sha256")
    recomputed = digest({k: v for k, v in manifest.items() if k != "manifest_sha256"})
    if stored_manifest_sha != recomputed:
        problems.append("manifest_sha256 mismatch")

    plan = json.loads((directory / "plan.json").read_text(encoding="utf-8"))
    provenance = manifest.get("provenance", {})
    if digest(plan["plan"]) != provenance.get("plan_sha256"):
        problems.append("plan_sha256 mismatch")
    if digest(plan["journal"]) != provenance.get("journal_sha256"):
        problems.append("journal_sha256 mismatch")
    if provenance.get("plan") != plan["plan"]:
        problems.append("plan content differs from provenance")

    for role, name in FILES.items():
        path = directory / name
        if not path.is_file():
            problems.append("%s missing: %s" % (role, name))
            continue
        data = path.read_bytes()
        record = manifest["artifacts"][role]
        if sha256(data) != record["sha256"]:
            problems.append("%s sha256 mismatch" % role)
        if len(data) != record["bytes"]:
            problems.append("%s size mismatch" % role)
        if recheck_reference:
            ok, error, size, mode = reference_decode(data)
            if ok != record["reference"]["ok"]:
                problems.append("%s reference verdict changed (%s)" % (role, error or "ok"))
            if list(size) != record["reference"]["size"]:
                problems.append("%s reference size changed" % role)

    present = all((directory / name).is_file() for name in FILES.values())
    if present:
        baseline = (directory / FILES["baseline"]).read_bytes()
        candidate = (directory / FILES["candidate"]).read_bytes()
        control = (directory / FILES["control"]).read_bytes()
        if control != baseline:
            problems.append("control does not equal baseline byte for byte")
        if candidate == baseline:
            problems.append("candidate is identical to baseline")
        pairing = manifest.get("pairing", {})
        if pairing.get("control_equals_baseline_bytes") != (control == baseline):
            problems.append("pairing flag disagrees with the bytes")

    if problems:
        raise BundleError("; ".join(problems))
    return {"ok": True, "artifacts": list(FILES), "manifest_sha256": stored_manifest_sha,
            "adapter_source_sha256": manifest["adapter"]["adapter_source_sha256"]}
