# -*- coding: utf-8 -*-
"""An index of past runs, built only from what the host actually recorded.

The rule that shapes this module: a string in a prompt is not evidence. Several
files in this repository contain "hDevice=0x..." because the *model* wrote that
text; only a run log carrying a status code for the call that produced the handle
counts. So the scanner reads run logs, never prompts, and a missing status makes
the field UNKNOWN rather than assumed.

Experiment identity is derived from content (cve, source hash, api sequence), not
from the directory it was found in, so re-scanning the same tree in a different
order produces the same ids.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

UNKNOWN = "UNKNOWN"

SETUP_PATH_SUCCESS = "SETUP_PATH_SUCCESS"
# The call happened. That is all it proves: 0xC000000D is returned before any
# vendor dispatch is established, so the interface is *called*, not *reached*.
D3DKMT_ESCAPE_CALL_OBSERVED = "D3DKMT_ESCAPE_CALL_OBSERVED"
DRIVER_INTERFACE_REACHED = "DRIVER_INTERFACE_REACHED"
VULNERABILITY_TRIGGERED = "VULNERABILITY_TRIGGERED"
NO_EVIDENCE = "NO_EVIDENCE"

EXECUTION_RECORD = "EXECUTION_RECORD"
SELF_REPORTED = "SELF_REPORTED"
NONE_EVIDENCE = "NONE"

_HANDLE = re.compile(r"(hAdapter|hDevice|hContext)=0x([0-9a-fA-F]+)")
_CPG_DRIVER = "CPG_DRIVER "
_CPG_CLAIMS = "CPG_CLAIMS "
# Evidence is read from this sidecar only. A CPG_EXTERNAL line inside run.log is
# indistinguishable from the candidate printing it, so text is never consulted.
EXTERNAL_SIDECAR = "external_evidence.json"
_CPG_RESULT = "CPG_RESULT "

# Setup APIs, in the order a working sequence would call them.
_SETUP_APIS = ("EnumDisplayDevices", "OpenAdapter", "CreateDevice", "CreateContext")
_ESCAPE_APIS = ("D3DKMTEscape", "DeviceIoControl")


@dataclass
class HistoricalExperiment:
    experiment_id: str
    cve_id: str
    timestamp: str
    source_directory: str
    source_files: List[str]
    source_hash: str
    api_sequence: List[str] = field(default_factory=list)
    successful_calls: List[Dict[str, object]] = field(default_factory=list)
    failed_calls: List[Dict[str, object]] = field(default_factory=list)
    returned_values: Dict[str, str] = field(default_factory=dict)
    outcome: str = UNKNOWN
    evidence_level: str = NONE_EVIDENCE
    classification: str = NO_EVIDENCE
    platform: str = UNKNOWN
    gpu: str = UNKNOWN
    driver_version: str = UNKNOWN
    os_version: str = UNKNOWN
    environment_match: str = UNKNOWN

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)


def _hash_files(paths: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def _experiment_id(cve: str, source_hash: str, api_sequence: Iterable[str]) -> str:
    raw = "|".join([cve, source_hash, ",".join(api_sequence)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _parse_log(text: str, log_path: Optional[Path] = None) -> Dict[str, object]:
    """Pull the structured record out of a run log, ignoring prose."""
    payload = None
    for line in text.splitlines():
        if line.startswith(_CPG_DRIVER):
            try:
                payload = json.loads(line[len(_CPG_DRIVER):])
            except ValueError:
                payload = None
    calls: List[Dict[str, object]] = []
    if payload:
        result = ((payload.get("detail") or {}).get("result") or {})
        calls = list(result.get("calls") or [])
    # A bare CPG_RESULT line (older candidates) is also a record.
    if not calls:
        for line in text.splitlines():
            if line.startswith(_CPG_RESULT):
                try:
                    calls = list(json.loads(line[len(_CPG_RESULT):]).get("calls") or [])
                except ValueError:
                    pass
    external: List[Dict[str, object]] = []
    sidecar = Path(log_path).parent / EXTERNAL_SIDECAR if log_path else None
    if sidecar is not None and sidecar.is_file():
        try:
            bundle = json.loads(sidecar.read_text(encoding="utf-8"))
        except ValueError:
            bundle = {}
        if isinstance(bundle, dict) and bundle.get("written_by") == "driver_exec":
            external = list(bundle.get("records") or [])
    return {"payload": payload, "calls": calls, "external": external,
            "handles": {name: int(value, 16) for name, value in _HANDLE.findall(text)}}


def has_external_hit(records: Sequence[Dict[str, object]]) -> bool:
    """A hit reported by an outside observer, not by the candidate.

    The producer is checked here as well as at write time: an archived file could
    have been edited, and the index is the last place that can refuse it.
    """
    from .driver_exec import TRUSTED_PRODUCERS

    for record in records or []:
        if isinstance(record, dict) and record.get("hit") \
                and str(record.get("producer", "")) in TRUSTED_PRODUCERS:
            return True
    return False


def _classify(calls: List[Dict[str, object]], handles: Dict[str, int],
              payload: Optional[dict], external: Sequence[Dict[str, object]] = (),) -> str:
    """What the run proved, at the weakest level that is still true.

    Creating a device proves the setup path. An escape that returned
    STATUS_INVALID_PARAMETER proves the call was made and refused - it does not
    prove the vendor dispatcher was entered, and it is not a trigger. Promotion to
    reached requires an external hit record; while no observer is wired into the
    pipeline, that classification is simply unreachable, which is the truth.
    """
    state = (payload or {}).get("state", "")
    if state == "KERNEL_BUGCHECK":
        # A bugcheck without dump-level attribution is not proof either.
        return NO_EVIDENCE
    seen = {str(c.get("api")): c.get("status") for c in calls}
    escaped = [api for api in seen if api.startswith(_ESCAPE_APIS)]
    if escaped:
        if has_external_hit(external):
            return DRIVER_INTERFACE_REACHED
        return D3DKMT_ESCAPE_CALL_OBSERVED
    if handles.get("hDevice") or any("CreateDevice" in str(api) for api in seen):
        return SETUP_PATH_SUCCESS
    return NO_EVIDENCE


def scan(roots: Sequence[Path]) -> List[HistoricalExperiment]:
    """Read-only walk; nothing is written, moved or deleted."""
    found: Dict[str, HistoricalExperiment] = {}
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for log in sorted(root.rglob("run.log")):
            try:
                text = log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            parsed = _parse_log(text, log)
            calls = parsed["calls"]
            if not calls and not parsed["payload"]:
                continue
            source = log.parent / "poc.py"
            files = [log] + ([source] if source.is_file() else [])
            api_sequence = [str(c.get("api")) for c in calls if c.get("api")]
            source_hash = _hash_files(files)
            cve = next((part for part in log.parts if part.startswith("CVE-")), "")
            if not cve:
                # An archive directory can be named after the experiment id; the
                # record next to it still knows which CVE it belonged to.
                record = log.parent / "experiment.json"
                if record.is_file():
                    try:
                        cve = json.loads(record.read_text(encoding="utf-8")).get("cve_id", UNKNOWN)
                    except ValueError:
                        cve = UNKNOWN
                else:
                    cve = UNKNOWN
            identifier = _experiment_id(cve, source_hash, api_sequence)
            found[identifier] = HistoricalExperiment(
                experiment_id=identifier,
                cve_id=cve,
                timestamp=str(int(log.stat().st_mtime)),
                source_directory=str(log.parent),
                source_files=[str(item) for item in files],
                source_hash=source_hash,
                api_sequence=api_sequence,
                successful_calls=[c for c in calls if c.get("status") == 0],
                failed_calls=[c for c in calls if c.get("status") not in (0, None)],
                returned_values={str(c.get("api")): str(c.get("status")) for c in calls},
                outcome=str((parsed["payload"] or {}).get("state") or UNKNOWN),
                evidence_level=EXECUTION_RECORD if calls else SELF_REPORTED,
                classification=_classify(calls, parsed["handles"], parsed["payload"],
                                         parsed["external"]),
                platform="windows" if any("D3DKMT" in a or "gdi32" in a
                                          for a in api_sequence) else UNKNOWN,
                environment_match=UNKNOWN,
            )
    return sorted(found.values(), key=lambda item: (item.cve_id, item.experiment_id))


def default_roots(project_root: Optional[Path] = None) -> List[Path]:
    root = Path(project_root or Path(__file__).resolve().parent.parent)
    return [root / "data" / "driver" / "llm_poc",
            root / "data" / "driver" / "p12f",
            root / "data" / "driver"]


def relevance(experiment: HistoricalExperiment, *, cve: str, api: str = "",
              driver_version: str = UNKNOWN) -> int:
    """How much this experiment is worth showing the model.

    Same CVE first, then a reached interface, then any shared API. A setup-only
    run outranks a bare failure because it contains a sequence that worked.
    """
    score = 0
    if experiment.cve_id == cve:
        score += 8
    if driver_version != UNKNOWN and experiment.driver_version == driver_version:
        score += 4
    if experiment.classification == SETUP_PATH_SUCCESS:
        score += 3
    if experiment.classification == DRIVER_INTERFACE_REACHED:
        score += 2
    if experiment.classification == D3DKMT_ESCAPE_CALL_OBSERVED:
        score += 1
    if api and api in " ".join(experiment.api_sequence):
        score += 2
    return score


def select(experiments: Sequence[HistoricalExperiment], *, cve: str, api: str = "",
           limit: int = 3) -> List[HistoricalExperiment]:
    ranked = sorted(experiments, key=lambda item: (-relevance(item, cve=cve, api=api),
                                                   item.experiment_id))
    return [item for item in ranked if relevance(item, cve=cve, api=api) > 0][:limit]


def render(experiments: Sequence[HistoricalExperiment], *, code_of=None) -> str:
    """The block the analyst and the generator both read."""
    if not experiments:
        return "（没有可用的历史实验记录）"
    blocks = []
    for index, item in enumerate(experiments, 1):
        lines = [
            "[历史实验 %d] id=%s cve=%s 结论=%s 证据=%s"
            % (index, item.experiment_id, item.cve_id, item.classification,
               item.evidence_level),
            "  目录: %s" % item.source_directory,
            "  调用序列: %s" % (" -> ".join(item.api_sequence) or UNKNOWN),
            "  成功调用: %s" % json.dumps(item.successful_calls, ensure_ascii=False),
            "  失败调用: %s" % json.dumps(item.failed_calls, ensure_ascii=False),
            "  环境: platform=%s gpu=%s driver=%s os=%s"
            % (item.platform, item.gpu, item.driver_version, item.os_version),
        ]
        if code_of is not None and item.classification == SETUP_PATH_SUCCESS:
            snippet = code_of(item)
            if snippet:
                lines.append("  可参考代码片段:\n```python\n%s\n```" % snippet[:1500])
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)
