"""Deterministic, offline P3-A reports and immutable integrity bundles.

The manifest is a byte integrity index, not a signature or authorization.
Neither rendering nor rebuilding executes a tool or changes an Oracle verdict.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata
from typing import Literal

from pydantic import Field, model_validator

from .models.lifecycle import LifecycleContract, canonical_sha256
from .models.oracle import OraclePlan, OracleResult, VulnerabilityClaim


MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class OracleReportArtifact(LifecycleContract):
    filename: Literal["plan.json", "result.json", "claim.json", "report.md"]
    size_bytes: int = Field(ge=0, le=MAX_REPORT_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class OracleReportManifest(LifecycleContract):
    manifest_schema_version: Literal["1.0"] = "1.0"
    generator: Literal["p3a-oracle-report-1.0"] = "p3a-oracle-report-1.0"
    cve_id: str
    oracle_id: str
    domain: Literal["OBJECTIVE", "SYNTHETIC"]
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    artifacts: list[OracleReportArtifact] = Field(min_length=3, max_length=4)
    integrity_scope: Literal["UNSIGNED_LOCAL_BYTE_INDEX"] = "UNSIGNED_LOCAL_BYTE_INDEX"

    @model_validator(mode="after")
    def files(self):
        names = [item.filename for item in self.artifacts]
        expected = {"plan.json", "result.json", "report.md"}
        if self.claim_sha256 is not None:
            expected.add("claim.json")
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError("unexpected or duplicate Oracle report artifact")
        return self


def _model(cls, value):
    return cls.model_validate(value)


def _safe(value):
    """Readable JSON scalars, with Markdown/HTML/control characters neutralized."""
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    raw = "".join(
        ("\\u%04x" % ord(char))
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else char
        for char in raw
    )
    escapes = {char: "&#%d;" % ord(char) for char in "&<>|`*_[]()!#~\\"}
    return "".join(escapes.get(char, char) for char in raw)


def _table(items):
    return ["| Field | Value |", "| --- | --- |"] + [
        "| " + _safe(key) + " | " + _safe(value) + " |" for key, value in items
    ]


def _associate(plan, result, claim):
    plan = _model(OraclePlan, plan)
    result = _model(OracleResult, result)
    claim = None if claim is None else _model(VulnerabilityClaim, claim)
    if result.plan_sha256 != canonical_sha256(plan):
        raise ValueError("Oracle result does not bind this plan digest")
    if (plan.cve_id, plan.oracle_id, plan.domain) != (
            result.cve_id, result.oracle_id, result.domain):
        raise ValueError("Oracle report target, oracle or domain mismatch")
    if result.eligibility.cve_id != plan.cve_id:
        raise ValueError("Oracle eligibility target mismatch")
    conditions = {item.condition_id: item for item in plan.conditions}
    evaluations = {item.condition_id: item for item in result.conditions}
    if len(evaluations) != len(result.conditions) or set(evaluations) != set(conditions):
        raise ValueError("Oracle report condition IDs mismatch")
    for key, evaluation in evaluations.items():
        allowed = set(conditions[key].requirement.reference_ids)
        if len(evaluation.reference_ids) != len(set(evaluation.reference_ids)) or not (
                set(evaluation.reference_ids) <= allowed):
            raise ValueError("Oracle evaluation references an unbound evidence source")
    if result.verdict == "VERIFIED" and any(
            item.required and evaluations[item.condition_id].status != "SATISFIED"
            for item in plan.conditions):
        raise ValueError("synthetic VERIFIED requires all necessary conditions")
    if claim is not None:
        if claim.cve_id != plan.cve_id:
            raise ValueError("Oracle claim target mismatch")
        if not set(plan.source_ids) <= {item.source_id for item in claim.sources}:
            raise ValueError("Oracle plan sources are absent from claim")
        bound = plan.bindings.get("claim_sha256")
        if bound is not None and bound != canonical_sha256(claim):
            raise ValueError("Oracle claim digest mismatch")
    return plan, result, claim


def render_oracle_report(plan: OraclePlan, result: OracleResult,
                         claim: VulnerabilityClaim | None = None) -> str:
    """Render already determined results; require exact input associations."""
    plan, result, claim = _associate(plan, result, claim)
    rows = ["# Deterministic CVE Oracle Report — P3-A", ""]
    rows += _table([
        ("Target CVE", plan.cve_id), ("Oracle", plan.oracle_id),
        ("Evidence domain", plan.domain), ("Plan SHA-256", result.plan_sha256),
        ("Corpus manifest SHA-256", result.corpus_manifest_sha256),
        ("Environment eligibility", result.eligibility.status),
        ("Condition aggregate", result.condition_status), ("Oracle verdict", result.verdict),
        ("Real CVE verification", result.real_cve_verification),
        ("Execution authorized by this report", False),
    ])
    rows += ["", "## Interpretation and decision rule", ""]
    rows += _table([
        ("Standard ID", plan.standard_id), ("Predeclared standard", plan.verification_standard),
        ("Review reference", plan.review_reference), ("Eligibility reasons", result.eligibility.reasons),
        ("Decision reasons", result.reasons),
    ])
    if plan.domain == "SYNTHETIC":
        rows += ["", "**SYNTHETIC: any VERIFIED verdict proves only the synthetic Oracle rules.**",
                 "No real CVE reproduction or real vulnerability verification is established.",
                 "Real CVE verification remains NOT_VERIFIED."]
    else:
        rows += ["", "No reviewed production root-cause assessor is registered in P3-A.",
                 "Real CVE verification remains NOT_VERIFIED."]
    rows += ["", "A crash, signal, Sanitizer finding, nonzero exit or exit zero alone does not prove a specific CVE.",
             "The report preserves the Oracle output; it supplies no additional execution observations.",
             "", "## Claim, public sources and unknowns", ""]
    if claim is None:
        rows += ["No VulnerabilityClaim was supplied. Affected versions, fixes and public facts are UNKNOWN."]
    else:
        rows += _table([
            ("Fact status", claim.fact_status), ("CWE classifications", claim.cwe),
            ("Vulnerability type", claim.vulnerability_type), ("Affected component", claim.affected_component),
            ("Affected version ranges", claim.affected_version_ranges), ("Version scheme", claim.version_scheme),
            ("Entry", claim.entry), ("Controlled input", claim.controlled_input),
            ("Prerequisites", claim.prerequisites), ("Mechanism", claim.trigger_mechanism),
            ("Expected objective behavior", claim.expected_objective_behavior),
            ("Fixed releases", claim.fixed_versions), ("Unknown facts and methods", claim.unknowns),
        ])
        for source in sorted(claim.sources, key=lambda item: item.source_id):
            rows += [""] + _table([
                ("Source ID", source.source_id), ("Kind", source.kind), ("URL", source.url),
                ("Retrieved", source.retrieved_at), ("Content SHA-256", source.content_sha256),
                ("Support", source.support), ("Exact source locator", source.locator),
            ])
        for assertion in sorted(claim.input_assertions,
                                key=lambda item: (item.source_file, item.field_path)):
            rows += [""] + _table(list(assertion.model_dump(mode="json").items()))
    rows += ["", "## Bound environment and identities", ""]
    rows += _table(sorted(plan.bindings.items()))
    rows += [""] + _table([("Observed context with original artifact identities", result.observed_context)])
    rows += ["", "Actual tool, driver and platform versions appear only when the following",
             "condition observations contain corresponding measured fields. Missing observations remain UNKNOWN.",
             "", "## Trigger conditions and observed values", ""]
    evaluations = {item.condition_id: item for item in result.conditions}
    for condition in sorted(plan.conditions, key=lambda item: item.condition_id):
        evaluated = evaluations[condition.condition_id]
        rows += ["### " + _safe(condition.condition_id), ""]
        rows += _table([
            ("Category", condition.category), ("Subject", condition.subject),
            ("Required", condition.required), ("Applicability", condition.applicability),
            ("Predicate", condition.predicate_type), ("Expected relation", condition.expected_relation),
            ("Expected value", condition.expected_value), ("Minimum inclusive", condition.minimum_inclusive),
            ("Maximum exclusive", condition.maximum_exclusive),
            ("Evidence requirement", condition.requirement.model_dump(mode="json")),
            ("Provenance source IDs", condition.provenance), ("Status", evaluated.status),
            ("Reason", evaluated.reason), ("Observed values", evaluated.observed_values),
            ("Used reference IDs", evaluated.reference_ids),
        ])
        rows.append("")
    rows += ["## Exact evidence references", ""]
    if not plan.references:
        rows += ["No evidence references were supplied; missing objective evidence is not manufactured by this report.", ""]
    for reference in sorted(plan.references, key=lambda item: item.reference_id):
        rows += _table(list(reference.model_dump(mode="json").items())) + [""]
    rows += ["## Scientific and integrity limitations", ""]
    rows += _table([("Oracle limitations", result.limitations)])
    rows += ["", "Source documents support attributed claims, not execution facts.",
             "Only bound, checked original artifacts can supply objective observations; Markdown and LLM prose cannot.",
             "The local manifest detects byte changes relative to its recorded hashes; it is not a signature,",
             "independent authentication, authorization, GPU isolation, or a claim that the local host is uncompromised.", ""]
    report = "\n".join(rows)
    if len(report.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Oracle report exceeds size limit")
    return report


def _json_bytes(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Oracle JSON exceeds size limit")
    return raw


def _no_links(directory):
    path = Path(directory)
    if ".." in path.parts:
        raise ValueError("Oracle report path traversal is forbidden")
    path = path.absolute()
    for parent in [*reversed(path.parents), path]:
        if not parent.exists() and not parent.is_symlink():
            continue
        observed = parent.lstat()
        if stat.S_ISLNK(observed.st_mode) or getattr(observed, "st_file_attributes", 0) & 0x400:
            raise ValueError("Oracle report symlink/reparse paths are forbidden")
    return path


def _exclusive_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save_oracle_report(directory, plan: OraclePlan, result: OracleResult,
                       claim: VulnerabilityClaim | None = None) -> Path:
    """Reserve a new directory. Any failure retains incomplete files, never overwrites history."""
    plan, result, claim = _associate(plan, result, claim)
    content = {"plan.json": _json_bytes(plan), "result.json": _json_bytes(result),
               "report.md": render_oracle_report(plan, result, claim).encode("utf-8")}
    if claim is not None:
        content["claim.json"] = _json_bytes(claim)
    manifest = OracleReportManifest(
        cve_id=plan.cve_id, oracle_id=plan.oracle_id, domain=plan.domain,
        plan_sha256=canonical_sha256(plan), result_sha256=canonical_sha256(result),
        claim_sha256=None if claim is None else canonical_sha256(claim),
        artifacts=[OracleReportArtifact(filename=name, size_bytes=len(raw),
                                        sha256=hashlib.sha256(raw).hexdigest())
                   for name, raw in sorted(content.items())],
    )
    manifest_raw = _json_bytes(manifest)
    if len(manifest_raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Oracle report manifest exceeds size limit")
    folder = _no_links(directory)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    _no_links(folder)
    for name, raw in sorted(content.items()):
        _exclusive_write(folder / name, raw)
    # Published last: absence means persistence never completed.
    _exclusive_write(folder / "oracle_manifest.json", manifest_raw)
    return folder


def _read(path, maximum):
    _no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("Oracle artifact is not a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Oracle artifact changed during open")
        raw = stream.read(maximum + 1)
    _no_links(path)
    if len(raw) > maximum or len(raw) != before.st_size:
        raise ValueError("Oracle artifact length changed or exceeds limit")
    return raw


def _load(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate Oracle JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("nonfinite Oracle JSON number: " + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def rebuild_oracle_report(directory) -> str:
    """Read only: validate stored hashes/models/associations, then independently render."""
    folder = _no_links(directory)
    if not folder.is_dir():
        raise ValueError("Oracle report bundle must be a directory")
    manifest = OracleReportManifest.model_validate(
        _load(_read(folder / "oracle_manifest.json", MAX_MANIFEST_BYTES)))
    expected = {item.filename for item in manifest.artifacts} | {"oracle_manifest.json"}
    if {item.name for item in folder.iterdir()} != expected:
        raise ValueError("Oracle report bundle contains missing or unexpected files")
    raw = {}
    for item in manifest.artifacts:
        maximum = MAX_REPORT_BYTES if item.filename == "report.md" else MAX_JSON_BYTES
        value = _read(folder / item.filename, maximum)
        if len(value) != item.size_bytes or hashlib.sha256(value).hexdigest() != item.sha256:
            raise ValueError("Oracle report artifact hash/length mismatch: " + item.filename)
        raw[item.filename] = value
    plan = OraclePlan.model_validate(_load(raw["plan.json"]))
    result = OracleResult.model_validate(_load(raw["result.json"]))
    claim = VulnerabilityClaim.model_validate(_load(raw["claim.json"])) if "claim.json" in raw else None
    if (manifest.cve_id, manifest.oracle_id, manifest.domain, manifest.plan_sha256,
            manifest.result_sha256, manifest.claim_sha256) != (
            plan.cve_id, plan.oracle_id, plan.domain, canonical_sha256(plan),
            canonical_sha256(result), None if claim is None else canonical_sha256(claim)):
        raise ValueError("Oracle report manifest association mismatch")
    rendered = render_oracle_report(plan, result, claim)
    if rendered.encode("utf-8") != raw["report.md"]:
        raise ValueError("Stored report is not the deterministic Oracle rendering")
    return rendered
