"""Reviewed source assertions and P1-A provenance, without promoting either to measurements."""

import hashlib
import json
from pathlib import Path

from .models.normalized_input import normalize_input_files
from .models.lifecycle import canonical_sha256
from .oracle_evidence import _strict_json
from .models.oracle import (EvidenceReference, EvidenceRequirement, InputAssertion, OraclePlan,
                            SourceDocument, TriggerCondition, VulnerabilityClaim)

ROOT = Path(__file__).resolve().parent.parent
REVIEW_FILES = ("cve_review_a.json", "cve_review_b.json")
# Reviewed release-family upper bounds are NECESSARY ONLY. They deliberately
# cannot decide Update 1/2 boundaries, exact builds, or WSL path applicability.
COARSE_UPPER = {"CVE-2022-21821": "11.7", "CVE-2023-0196": "12.1",
                "CVE-2024-0076": "12.5", "CVE-2024-0124": "12.7",
                "CVE-2025-23308": "13.0", "CVE-2025-23339": "13.0"}
ROLE = {"CVE-2022-21821": "cuobjdump", "CVE-2023-0196": "cuobjdump",
        "CVE-2024-0076": "cuobjdump", "CVE-2024-0124": "nvdisasm",
        "CVE-2025-23308": "nvdisasm", "CVE-2025-23339": "cuobjdump"}


def load_reviewed_claim(cve_id: str, *, input_root=None) -> VulnerabilityClaim:
    """Only the six source-controlled desk reviews are supported, not LLM facts.

    The caller still independently pins a derived plan before evaluation.
    Source content hashes are retrieval integrity, never authentication.
    """
    if cve_id not in COARSE_UPPER:
        raise ValueError("CVE has no reviewed catalog entry")
    rows = []
    for filename in REVIEW_FILES:
        rows.extend(_strict_json((ROOT / "docs" / "examples" / "p3_a" / filename).read_bytes()))
    matches = [x for x in rows if x["cve_id"] == cve_id]
    if len(matches) != 1:
        raise ValueError("catalog target is missing or duplicated")
    row = matches[0]
    normalized = normalize_input_files(Path(input_root or ROOT / "data" / "inputs") / cve_id)
    normalized.require_valid()
    if normalized.cve_id != cve_id:
        raise ValueError("input target and reviewed claim conflict")
    assertions = []
    for p in normalized.provenance:
        source = normalized.sources[p.dimension]
        if source.sha256 is None:
            raise ValueError("input source has no original byte hash")
        source_file = ((Path(input_root) / cve_id / p.source_file) if input_root is not None
                       else (Path("data") / "inputs" / cve_id / p.source_file)).as_posix()
        assertions.append(InputAssertion(dimension=p.dimension, source_file=source_file,
            source_sha256=source.sha256, field_path=p.field_path, normalized_path=p.normalized_path,
            field_state=p.state.value))
    sources = []
    for index, source in enumerate(row["sources"]):
        sources.append(SourceDocument(source_id=source.get("source_id", cve_id + "-source-" + str(index)),
            kind=source["kind"], url=source["url"], retrieved_at=source["retrieved_at"],
            content_sha256=source.get("content_sha256"), support="DOCUMENTED",
            locator=("/containers/cna/affected/0; /containers/cna/problemTypes; /containers/cna/descriptions"
                     if source["kind"] == "CNA_RECORD" else
                     ("CVE details row " + cve_id + "; Security Updates table"
                      if source["kind"] == "VENDOR_ADVISORY" and "custhelp" in source["url"]
                      else str(source.get("support", "reviewed source section"))))))
    component = row["component"]
    if isinstance(component, list):
        component = "; ".join(component)
    return VulnerabilityClaim(cve_id=cve_id, cwe=row["cwe"], vulnerability_type=row["mechanism"],
        affected_component=component, affected_version_ranges=[row["affected_release_text"]],
        version_scheme="VENDOR_RELEASE_LABEL", entry=row["entry"],
        controlled_input="Externally supplied binary input; exact constraints remain source-scoped/unknown.",
        prerequisites=["Exact affected tool identity and input path must be independently established.",
                       "WSL applicability is not demonstrated by a vendor Windows/Linux label alone."],
        trigger_mechanism=row["mechanism"], expected_objective_behavior=row["expected_behavior"],
        fixed_versions=[row["fix_release_text"]], sources=sources, unknowns=row["unknowns"],
        input_assertions=assertions,
        fact_status="CONFLICT" if row.get("source_conflicts") else "DOCUMENTED_NOT_REPRODUCED")


def smoke_review_plan(claim: VulnerabilityClaim, corpus) -> OraclePlan:
    """Draft a conservative, inspectable plan; this does not approve its digest.

    A numeric release-family exclusion can rule a target out. Exact Update/build
    applicability, trigger and root cause stay unknown. A smoke is not a CVE run.
    """
    claim = VulnerabilityClaim.model_validate(claim)
    if corpus.domain != "OBJECTIVE" or corpus.scope != "TOOLCHAIN_SMOKE":
        raise ValueError("requires pinned original P2-C harmless smoke evidence")
    cve = claim.cve_id
    role = ROLE[cve]
    binding = {key: corpus.binding[key] for key in ("request_id", "run_id", "platform_environment_id",
               "platform_probe_id", "snapshot_sha256", "candidate_sha256")}
    binding["tool_sha256"] = dict(corpus.binding["tool_sha256"])
    binding["claim_sha256"] = canonical_sha256(claim)
    source_ids = [x.source_id for x in claim.sources]
    refs = []

    def ref(ref_id, file, pointer, kind, tool_role=None):
        reference_role = tool_role or role
        metadata = corpus.provenance[file]
        value = EvidenceReference(reference_id=ref_id, domain="OBJECTIVE", cve_id=None,
            artifact_file=file, artifact_sha256=corpus.artifact_sha256[file], json_pointer=pointer,
            original_source=metadata["original_source"], collection_method=metadata["collector"],
            scope="TOOLCHAIN_SMOKE", evidence_type=kind, tool_role=reference_role,
            tool_sha256=binding["tool_sha256"][reference_role], **{k: binding[k] for k in (
                "request_id", "run_id", "platform_environment_id", "platform_probe_id", "snapshot_sha256", "candidate_sha256")})
        refs.append(value)
        return ref_id

    version_ref = ref("toolkit-release", "platform_snapshot.json", "/cuda_toolkit_version/value", "PLATFORM")
    source_ref = ref("registered-source", "execution_record.json", "/cuda_smoke/source_sha256", "IDENTITY", "nvcc")
    # A measured Toolkit/nvcc family does not identify another parser binary.
    # Exclude a target only when each affected role has a bound, parsed version
    # from that same release family. Unknown banner/build remains UNKNOWN.
    needed_roles = ("cuobjdump", "nvdisasm") if cve == "CVE-2024-0076" else (role,)
    try:
        family = corpus.resolve("platform_snapshot.json", corpus.artifact_sha256["platform_snapshot.json"],
                                "/cuda_toolkit_version/value")
        versions = corpus.binding.get("tool_versions", {})
        family_bound = all(versions.get(r) is not None and versions[r]["release"] == family for r in needed_roles)
    except (ValueError, KeyError, TypeError):
        family_bound = False
    conditions = [TriggerCondition(condition_id="release-family-guard", category="ENVIRONMENT",
        predicate_type="NUMERIC_RANGE" if family_bound else "UNIMPLEMENTED",
        subject="Toolkit numeric release family with measured affected tool build (necessary exclusion only)",
        expected_relation="GTE_LT" if family_bound else "UNKNOWN",
        minimum_inclusive="0.0", maximum_exclusive=COARSE_UPPER[cve],
        applicability="APPLICABLE", required=True, provenance=source_ids,
        requirement=EvidenceRequirement(evidence_type="PLATFORM", evidence_source="OBJECTIVE",
            method="NUMERIC_VERSION" if family_bound else "UNIMPLEMENTED",
            scope="TOOLCHAIN_SMOKE", reference_ids=[version_ref])),
        TriggerCondition(condition_id="registered-source-identity", category="IDENTITY", predicate_type="EQUALS",
            subject="fixed harmless smoke input identity; not an exploit identity", expected_relation="EQUALS",
            expected_value="50e0b1c170424527056a2343443be06475e500dd19ef6186e4d3aaca1a8c5931",
            applicability="APPLICABLE", required=True, provenance=source_ids,
            requirement=EvidenceRequirement(evidence_type="IDENTITY", evidence_source="OBJECTIVE",
                method="EXACT_FIELD", scope="TOOLCHAIN_SMOKE", reference_ids=[source_ref]))]
    for cid, category, subject, evidence_type in (
        ("exact-target-applicability", "ENVIRONMENT", "Exact component build, Toolkit Update and WSL path applicability", "PLATFORM"),
        ("target-entry", "ENTRY_BEHAVIOR", claim.entry, "PROCESS"),
        ("target-anomaly", "ANOMALY", claim.expected_objective_behavior, "PROCESS"),
        ("target-root-cause", "ROOT_CAUSE", claim.trigger_mechanism, "ROOT_CAUSE")):
        conditions.append(TriggerCondition(condition_id=cid, category=category, predicate_type="UNIMPLEMENTED",
            subject=subject, expected_relation="UNKNOWN", applicability="APPLICABLE", required=True,
            provenance=source_ids, requirement=EvidenceRequirement(evidence_type=evidence_type,
                evidence_source="OBJECTIVE", method="UNIMPLEMENTED", scope="CVE_TRIGGER", reference_ids=[])))
    return OraclePlan(oracle_id="p3a-desk-review-" + cve.lower(), cve_id=cve, domain="OBJECTIVE",
        standard_id="CVE_METHOD_NOT_IMPLEMENTED_V1", verification_standard="All required conditions and an independently reviewed target-specific root-cause method; method unavailable in P3-A.",
        review_reference="docs/P3_A_CVE_REVIEW_A.md; docs/P3_A_CVE_REVIEW_B.md", bindings=binding,
        conditions=conditions, references=refs, source_ids=source_ids)
