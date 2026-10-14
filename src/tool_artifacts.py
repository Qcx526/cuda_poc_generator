"""Private, byte-exact tool evidence with independently checkable file hashes."""

import hashlib
import json
import os
from pathlib import Path

from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory


DEFAULT_TOOL_OUTPUT_ROOT = (
    Path(__file__).resolve().parent.parent / "data" / "outputs" / "tool_runs" if os.name == "nt"
    else Path.home() / ".local" / "state" / "cuda-poc-generator" / "tool_runs"
)


class ToolEvidenceError(OSError):
    """Evidence storage failed; retained process bytes remain available to callers."""

    def __init__(self, message: str, *, tool_result: ToolResult | None = None,
                 evidence_directory: str | None = None):
        super().__init__(message)
        self.tool_result = tool_result
        self.evidence_directory = evidence_directory


def prepare_tool_directory(root: str | Path | None, run_id: str):
    folder = (DEFAULT_TOOL_OUTPUT_ROOT if root is None else Path(root)) / run_id
    folder = folder.resolve()
    try:
        protection = protect_directory(folder)
    except OSError as exc:
        raise ToolEvidenceError("Private tool evidence directory could not be created or protected: " + str(exc),
                                evidence_directory=str(folder)) from exc
    if os.name != "nt" and folder.stat().st_mode & 0o777 != 0o700:
        raise ToolEvidenceError("Private tool evidence requires effective POSIX mode 0700; select a native Linux filesystem artifact_root, not a /mnt drive without permission metadata.",
                                evidence_directory=str(folder))
    return folder, protection


def write_tool_evidence(folder: Path, result: ToolResult, protection: dict) -> dict:
    """Persist retained bytes and a manifest, including failed process observations."""
    # A frozen model still contains Python list fields; revalidate its canonical
    # content before persistence rather than trusting a mutated/model_copy object.
    result = ToolResult.model_validate(result.model_dump(mode="json"))
    folder = folder.resolve()
    if folder != Path(result.evidence_directory).resolve():
        raise ValueError("tool evidence destination does not match result")

    def write(name: str, raw: bytes):
        destination = folder / name
        # Unique protected directory; never overwrite prior records.
        try:
            with destination.open("xb") as stream:
                stream.write(raw)
            if os.name != "nt":
                destination.chmod(0o600)
                if destination.stat().st_mode & 0o777 != 0o600:
                    raise OSError("Tool evidence file mode 0600 could not be applied")
        except OSError as exc:
            raise ToolEvidenceError("Tool evidence artifact could not be saved: " + str(exc),
                                    tool_result=result, evidence_directory=str(folder)) from exc

    write("stdout.bin", result.stdout_bytes())
    write("stderr.bin", result.stderr_bytes())
    write("tool_result.json", (result.model_dump_json(indent=2) + "\n").encode("utf-8"))
    files = {}
    for name in ("stdout.bin", "stderr.bin", "tool_result.json"):
        raw = (folder / name).read_bytes()
        files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    manifest = {"schema_version": "1.0", "run_id": result.run_id, "record_id": result.record_id,
                "access_control": protection, "artifacts": files,
                "capture_complete": not result.truncated and not result.capture_failed,
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    write("evidence_manifest.json", (json.dumps(manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
    return manifest


def _strict_json(raw: bytes):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key in tool evidence JSON")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite constant in tool evidence JSON")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def read_tool_evidence(folder: str | Path, *, expected_run_id: str | None = None,
                       expected_record_id: str | None = None) -> ToolResult:
    """Revalidate saved hashes and model identity without replacing stored digests."""
    directory = Path(folder)
    manifest_path = directory / "evidence_manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("tool evidence manifest must not redirect to another file")
    with manifest_path.open("rb") as stream:
        manifest_raw = stream.read(65537)
    if len(manifest_raw) > 65536:
        raise ValueError("tool evidence manifest exceeds bound")
    manifest = _strict_json(manifest_raw)
    if not isinstance(manifest, dict) or set(manifest.get("artifacts", {})) != {"stdout.bin", "stderr.bin", "tool_result.json"}:
        raise ValueError("tool evidence manifest must describe the fixed artifact set")
    if manifest.get("schema_version") != "1.0":
        raise ValueError("unsupported tool evidence manifest version")
    records = {}
    limits = {"stdout.bin": 16777216, "stderr.bin": 16777216, "tool_result.json": 50000000}
    for name, entry in manifest["artifacts"].items():
        if not isinstance(entry, dict) or set(entry) != {"sha256", "size_bytes"}:
            raise ValueError("invalid tool evidence file entry")
        if type(entry["size_bytes"]) is not int or not 0 <= entry["size_bytes"] <= limits[name]:
            raise ValueError("tool evidence size exceeds declared bound")
        file = directory / name
        if file.is_symlink():
            raise ValueError("tool evidence must not redirect to another file")
        with file.open("rb") as stream:
            raw = stream.read(limits[name] + 1)
        if len(raw) != entry["size_bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("tool evidence artifact integrity mismatch")
        records[name] = raw
    result = ToolResult.model_validate(_strict_json(records["tool_result.json"]))
    if result.run_id != manifest.get("run_id") or result.record_id != manifest.get("record_id"):
        raise ValueError("tool evidence record identity mismatch")
    if result.stdout_bytes() != records["stdout.bin"] or result.stderr_bytes() != records["stderr.bin"]:
        raise ValueError("raw tool evidence differs from recorded process output")
    if expected_run_id is not None and result.run_id != expected_run_id:
        raise ValueError("tool evidence is not the requested run")
    if expected_record_id is not None and result.record_id != expected_record_id:
        raise ValueError("tool evidence is not the requested content identity")
    if manifest.get("capture_complete") != (not result.truncated and not result.capture_failed):
        raise ValueError("tool evidence capture-completeness state mismatch")
    if (manifest.get("candidate_execution_status") != result.candidate_execution_status
            or manifest.get("verification_status") != result.verification_status):
        raise ValueError("tool evidence candidate or verification state mismatch")
    return result
