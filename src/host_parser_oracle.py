"""Read-only host observations projected onto fixed A-F requirements and P3-A."""

import hashlib
import json

from .host_parser_evidence import reassess_host_parser_evidence
from .models.host_parser import (HostObjectiveRequirement, HostOracleAssessment,
                                 HostParserEvidence)
from .models.lifecycle import canonical_sha256
from .models.oracle import EvidenceReference, OraclePlan, TriggerCondition
from .oracle_evidence import EvidenceCorpus


def evaluate_host_parser_requirements(evidence: HostParserEvidence, *, expected_collection_sha256: str,
                                     expected_cve_id: str) -> HostOracleAssessment:
    """Fixed preparation criteria; no execution authorization or real VERIFIED."""
    evidence = reassess_host_parser_evidence(evidence,
                                             expected_collection_sha256=expected_collection_sha256)
    collection = evidence.collection
    if expected_cve_id != collection.cve_id:
        raise ValueError("host evidence cannot be rebound to another CVE")
    parsed = evidence.parse_status == "PARSED"
    observed_write = [x for x in evidence.observations if x.classification == "INVALID_WRITE"]
    definitions = [
        ("a_exact_build", "A_EXACT_BUILD", "精确受影响 build 与实测宿主二进制身份", "UNKNOWN", "UNKNOWN",
         "EXACT_AFFECTED_BUILD_AND_TRUSTED_VERSION_RECORD_REQUIRED", []),
        ("b_input_identity_format", "B_INPUT_IDENTITY_FORMAT", "输入原始字节身份、容器格式与相关调试或重定位数据",
         "UNKNOWN", "UNKNOWN", "INPUT_BYTES_AND_FORMAT_PROFILE_NOT_INDEPENDENTLY_VERIFIED", []),
        ("c_execution_path", "C_EXECUTION_PATH", "诊断记录中的目标工具和输入调用路径",
         "SATISFIED" if parsed else "UNKNOWN", "OBSERVED" if parsed else "UNKNOWN",
         "XML_ARGUMENTS_MATCH_PINNED_COLLECTION_ONLY" if parsed else "QUALIFIED_XML_ARGUMENTS_UNAVAILABLE", []),
        ("d_memory_anomaly", "D_MEMORY_ANOMALY", "结构化诊断观测到无效写；不据此推断堆、栈或根因",
         "SATISFIED" if parsed and observed_write else "UNKNOWN",
         "OBSERVED" if parsed and observed_write else "UNKNOWN",
         "INVALID_WRITE_OBSERVED_WITH_REGION_AND_ROOT_CAUSE_UNKNOWN" if parsed and observed_write else "NO_QUALIFIED_INVALID_WRITE_OBSERVATION",
         [x.kind_locator for x in observed_write] if parsed else []),
        ("e_mechanism_location", "E_MECHANISM_LOCATION", "异常位置与公开堆或栈越界机制的独立关联",
         "UNKNOWN", "UNIMPLEMENTED", "REGION_ACCESS_SIZE_AND_PUBLIC_ROOT_CAUSE_BINDING_UNIMPLEMENTED", []),
        ("f_root_cause_differential", "F_ROOT_CAUSE_DIFFERENTIAL", "相同根因以及可信受影响与修复 build 的充分差分",
         "UNKNOWN", "UNIMPLEMENTED", "ROOT_CAUSE_AND_FIXED_BUILD_DIFFERENTIAL_UNIMPLEMENTED", []),
    ]
    requirements = [HostObjectiveRequirement(requirement_id=rid, category=category, description=text,
        status=status, method_status=method, reason_code=reason, evidence_locators=locators)
        for rid, category, text, status, method, reason, locators in definitions]
    return HostOracleAssessment(cve_id=collection.cve_id, collection_sha256=evidence.collection_sha256,
        evidence_sha256=canonical_sha256(evidence), domain=collection.domain, requirements=requirements,
        reasons=["HOST_DIAGNOSTIC_OBSERVATION_IS_NOT_TARGET_CVE_PROOF",
                 "PRODUCTION_HOST_PARSER_COLLECTOR_UNSUPPORTED",
                 "EXACT_AFFECTED_BUILD_AND_ROOT_CAUSE_UNKNOWN",
                 "SYNTHETIC_IS_RULE_TEST_ONLY" if collection.domain == "SYNTHETIC"
                 else "IMPORTED_OBSERVATION_IS_NOT_AUTHENTICATED_EXECUTION_ATTESTATION"])


def project_host_parser_to_p3a(evidence: HostParserEvidence, *, expected_collection_sha256: str,
                              expected_cve_id: str):
    """Return (plan, corpus) for the existing SYNTHETIC P3-A evaluator only.

    The old objective allowlist and frozen P3-A semantics are unchanged. P3-B
    has no production collector, so an imported XML file cannot be converted
    into an objective P3-A EvidenceCorpus by declaring a JSON flag.
    """
    assessment = evaluate_host_parser_requirements(evidence,
        expected_collection_sha256=expected_collection_sha256, expected_cve_id=expected_cve_id)
    evidence = HostParserEvidence.model_validate(evidence)
    if evidence.collection.domain != "SYNTHETIC":
        raise ValueError("objective host-parser Oracle projection is UNSUPPORTED in P3-B")
    collection = evidence.collection
    binding = {"request_id": collection.request_id, "run_id": collection.run_id,
        "platform_environment_id": collection.platform_environment_id,
        "platform_probe_id": collection.platform_probe_id, "snapshot_sha256": collection.snapshot_sha256,
        "candidate_sha256": collection.input.file.sha256,
        "tool_sha256": {collection.target.component: collection.target.executable.file_sha256}}
    document = {"label": "SYNTHETIC", "host_evidence_sha256": canonical_sha256(evidence),
        "collection_sha256": evidence.collection_sha256,
        "requirements": [item.model_dump(mode="json") for item in assessment.requirements],
        "raw_references": [x.model_dump(mode="json") for item in evidence.observations
                           for x in [item.kind_locator]],
        "raw_diagnostic_sha256": collection.diagnostic_artifact.sha256,
        "real_cve_verification": "NOT_VERIFIED"}
    raw = json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    corpus = EvidenceCorpus.from_synthetic(artifacts={"host_parser_projection.json": raw},
        binding=binding, label="SYNTHETIC")
    references, conditions = [], []
    categories = ["ENVIRONMENT", "IDENTITY", "ENTRY_BEHAVIOR", "ANOMALY", "ROOT_CAUSE", "ROOT_CAUSE"]
    for index, (requirement, category) in enumerate(zip(assessment.requirements, categories)):
        ref_id = requirement.requirement_id + "-evidence"
        evidence_type = "PLATFORM" if category == "ENVIRONMENT" else "IDENTITY" if category == "IDENTITY" else "ROOT_CAUSE" if category == "ROOT_CAUSE" else "PROCESS"
        references.append(EvidenceReference(reference_id=ref_id, domain="SYNTHETIC", cve_id=collection.cve_id,
            **{key: value for key, value in binding.items() if key != "tool_sha256"},
            artifact_file="host_parser_projection.json", artifact_sha256=hashlib.sha256(raw).hexdigest(),
            json_pointer=f"/requirements/{index}/status", original_source="SYNTHETIC_FIXTURE",
            tool_role=collection.target.component, tool_sha256=collection.target.executable.file_sha256,
            collection_method="p3a-synthetic-1.0", scope="SYNTHETIC", evidence_type=evidence_type))
        # UNKNOWN observations must not become a negative environment match.
        # There is no objective numeric affected-build rule in this adapter.
        unimplemented = requirement.status == "UNKNOWN"
        conditions.append(TriggerCondition(condition_id=requirement.requirement_id, category=category,
            predicate_type="UNIMPLEMENTED" if unimplemented else "EQUALS",
            subject="host_parser." + requirement.requirement_id,
            expected_value=None if unimplemented else "SATISFIED",
            expected_relation="UNKNOWN" if unimplemented else "EQUALS", applicability="APPLICABLE", required=True,
            requirement={"evidence_type": evidence_type, "evidence_source": "SYNTHETIC",
                         "method": "UNIMPLEMENTED" if unimplemented else "SYNTHETIC_FACT", "scope": "SYNTHETIC",
                         "reference_ids": [ref_id]}, provenance=["p3b-host-preparation-v1"]))
    plan = OraclePlan(oracle_id="p3b-host-parser-preparation-v1", cve_id=collection.cve_id,
        domain="SYNTHETIC", standard_id="SYNTHETIC_ALL_REQUIRED_V1",
        verification_standard="SYNTHETIC: A-F preparation only; E/F unimplemented, never real CVE proof.",
        review_reference="P3_B_HOST_PARSER_EVIDENCE.md", bindings=binding,
        conditions=conditions, references=references, source_ids=["p3b-host-preparation-v1"])
    return plan, corpus
