"""Deterministic, fail-closed predicate evaluation. No LLM or process calls."""

from .models.lifecycle import canonical_sha256
from .models.oracle import (CVEEligibility, ConditionEvaluation, OraclePlan, OracleResult,
                            version_tuple)
from .oracle_evidence import EvidenceCorpus


_BINDING_KEYS = frozenset({"request_id", "run_id", "platform_environment_id", "platform_probe_id",
                           "snapshot_sha256", "candidate_sha256"})
_CATEGORIES = frozenset({"ENVIRONMENT", "IDENTITY", "ENTRY_BEHAVIOR", "ANOMALY", "ROOT_CAUSE"})


def _typed_equal(left, right):
    return type(left) is type(right) and left == right


def _binding_error(plan, corpus):
    if plan.domain != corpus.domain:
        return "evidence domain conflict"
    if not _BINDING_KEYS <= set(plan.bindings):
        return "plan lacks mandatory request/run/platform/probe/snapshot/input bindings"
    for key in _BINDING_KEYS:
        if not _typed_equal(plan.bindings[key], corpus.binding.get(key)):
            return "identity conflict: " + key
    tools = plan.bindings.get("tool_sha256")
    actual = corpus.binding.get("tool_sha256", {})
    if not isinstance(tools, dict) or not tools or set(tools) != set(actual) or any(
            not _typed_equal(value, actual.get(role)) for role, value in tools.items()):
        return "identity conflict: tool_sha256"
    return None


def _reference_value(plan, condition, ref, corpus):
    if ref.domain != plan.domain or ref.cve_id not in (None, plan.cve_id):
        raise ValueError("CVE or evidence domain conflict")
    for key in _BINDING_KEYS:
        if not _typed_equal(getattr(ref, key), corpus.binding.get(key)):
            raise ValueError("reference identity conflict: " + key)
    if ref.tool_sha256 != corpus.binding.get("tool_sha256", {}).get(ref.tool_role):
        raise ValueError("tool identity conflict")
    corpus.validate_tool_binding(ref.artifact_file, ref.json_pointer, ref.tool_role, ref.tool_sha256)
    metadata = corpus.provenance.get(ref.artifact_file, {})
    if (ref.original_source != metadata.get("original_source") or
            ref.collection_method != metadata.get("collector") or
            ref.scope != metadata.get("scope") or ref.scope != condition.requirement.scope or
            ref.evidence_type != condition.requirement.evidence_type or
            ref.domain != condition.requirement.evidence_source):
        raise ValueError("evidence source, method, type or scope conflict")
    if condition.requirement.scope == "CVE_TRIGGER" and ref.cve_id != plan.cve_id:
        raise ValueError("target-specific evidence lacks explicit CVE binding")
    # The existing production collector can attest toolchain observations only.
    if plan.domain == "OBJECTIVE" and (condition.category == "ROOT_CAUSE" or
            ref.scope == "CVE_TRIGGER" or ref.evidence_type in {"ROOT_CAUSE", "DIFFERENTIAL"}):
        raise NotImplementedError("no reviewed objective CVE root-cause/differential collector in P3-A")
    return corpus.resolve(ref.artifact_file, ref.artifact_sha256, ref.json_pointer)


def _condition(plan, condition, corpus, refs):
    values, used = [], []
    status, reason = "UNKNOWN", "no qualified evidence"
    if condition.applicability != "APPLICABLE":
        reason = "applicability is " + condition.applicability + "; necessary conditions are not waived"
    elif condition.predicate_type == "UNIMPLEMENTED" or condition.requirement.method == "UNIMPLEMENTED":
        reason = "objective verification method is not implemented"
    elif (condition.required or condition.requirement.completeness_required) and not corpus.qualified:
        reason = "evidence capture/integrity/cleanup is not complete"
    elif condition.requirement.method == "SYNTHETIC_FACT" and plan.domain != "SYNTHETIC":
        reason = "synthetic method cannot assess objective evidence"
    elif not condition.requirement.reference_ids:
        reason = "required evidence reference is missing"
    else:
        try:
            for reference_id in condition.requirement.reference_ids:
                ref = refs[reference_id]
                value = _reference_value(plan, condition, ref, corpus)
                values.append(value)
                used.append(reference_id)
            if any(not _typed_equal(x, values[0]) for x in values[1:]):
                status, reason = "CONFLICT", "evidence observations disagree for the same predicate"
            elif condition.predicate_type == "EQUALS":
                status = "SATISFIED" if _typed_equal(values[0], condition.expected_value) else "NOT_SATISFIED"
                reason = "typed equality against original structured field"
            else:
                observed = version_tuple(values[0])
                matched = version_tuple(condition.minimum_inclusive) <= observed < version_tuple(condition.maximum_exclusive)
                status = "SATISFIED" if matched else "NOT_SATISFIED"
                reason = "numeric component build in explicit [minimum, maximum) range"
        except NotImplementedError as exc:
            reason = str(exc)
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            status, reason = "CONFLICT", str(exc)
    return ConditionEvaluation(condition_id=condition.condition_id, status=status, reason=reason,
                               reference_ids=used, observed_values=values)


def evaluate_oracle(plan: OraclePlan, corpus: EvidenceCorpus, *, trusted_plan_sha256: str | None) -> OracleResult:
    """The caller supplies an independently approved plan digest, never an LLM flag.

    This API cannot authorize execution. Production root-cause methods are not
    registered in P3-A. SYNTHETIC VERIFIED is only a regression rule result.
    """
    plan = OraclePlan.model_validate(plan)
    plan_hash = canonical_sha256(plan)
    conflict = None
    if trusted_plan_sha256 != plan_hash:
        conflict = "plan is not pinned by the operator/trusted policy"
    else:
        conflict = _binding_error(plan, corpus)
    refs = {x.reference_id: x for x in plan.references}
    if conflict:
        results = [ConditionEvaluation(condition_id=x.condition_id, status="CONFLICT", reason=conflict,
                                       reference_ids=[], observed_values=[]) for x in plan.conditions]
    else:
        results = [_condition(plan, x, corpus, refs) for x in plan.conditions]
    # Contradictory necessary predicates cannot be hidden by separate IDs.
    by_subject = {}
    for condition, result in zip(plan.conditions, results):
        if condition.required and condition.applicability == "APPLICABLE":
            by_subject.setdefault(condition.subject, []).append((condition, result))
    for group in by_subject.values():
        signatures = {(x.predicate_type, repr(x.expected_value), x.minimum_inclusive,
                       x.maximum_exclusive, x.expected_relation) for x, _ in group}
        if len(signatures) > 1:
            conflicting = {x.condition_id for x, _ in group}
            results = [ConditionEvaluation(condition_id=x.condition_id, status="CONFLICT",
                         reason="contradictory necessary predicates for the same subject",
                         reference_ids=x.reference_ids, observed_values=x.observed_values)
                       if x.condition_id in conflicting else x for x in results]
    required = [r for c, r in zip(plan.conditions, results) if c.required]
    environment = [r for c, r in zip(plan.conditions, results) if c.required and c.category == "ENVIRONMENT"]
    if not environment or any(r.status == "CONFLICT" for r in environment):
        eligibility = "UNKNOWN"
    elif any(r.status == "NOT_SATISFIED" for r in environment):
        eligibility = "INELIGIBLE"
    elif any(r.status == "UNKNOWN" for r in environment):
        eligibility = "UNKNOWN"
    else:
        eligibility = "ELIGIBLE"
    statuses = {r.status for r in required}
    if "CONFLICT" in {r.status for r in results}:
        combined = "CONFLICT"
    elif "NOT_SATISFIED" in statuses:
        combined = "NOT_SATISFIED"
    elif not required or "UNKNOWN" in statuses:
        combined = "UNKNOWN"
    else:
        combined = "SATISFIED"
    covered = {c.category for c in plan.conditions if c.required and c.applicability == "APPLICABLE"}
    reasons = []
    if combined == "CONFLICT":
        verdict, reasons = "UNKNOWN", ["conflicting/untrusted identity, provenance or necessary conditions; fail closed"]
    elif eligibility == "INELIGIBLE":
        verdict, reasons = "NOT_VERIFIED", ["affected-environment prerequisite is not satisfied; this is not a failed CVE reproduction"]
    elif combined == "NOT_SATISFIED":
        verdict, reasons = "NOT_VERIFIED", ["at least one necessary trigger condition is not satisfied"]
    elif corpus.scope == "TOOLCHAIN_SMOKE":
        verdict, reasons = "NOT_VERIFIED", ["fixed harmless CUDA toolchain smoke has no CVE trigger/root-cause scope"]
    elif (combined == "SATISFIED" and eligibility == "ELIGIBLE" and covered == _CATEGORIES
          and plan.domain == "SYNTHETIC"):
        verdict, reasons = "VERIFIED", ["SYNTHETIC: all predeclared necessary conditions in all five categories satisfy the test rule only"]
    elif eligibility == "ELIGIBLE" and any(r.status == "SATISFIED" and c.category not in {"ENVIRONMENT", "IDENTITY"}
                                          for c, r in zip(plan.conditions, results)):
        verdict, reasons = "SUPPORTED", ["some relevant observations are supported; complete CVE/root-cause standard is not met"]
    else:
        verdict, reasons = "UNKNOWN", ["insufficient eligibility or necessary objective evidence"]
    if covered != _CATEGORIES:
        reasons.append("verification profile lacks necessary categories: " + ", ".join(sorted(_CATEGORIES - covered)))
    observed_context = {}
    if corpus.domain == "OBJECTIVE" and not conflict:
        for field in ("host_os", "kernel", "driver_release", "cuda_toolkit_version", "nvcc_version"):
            filename, pointer = "platform_snapshot.json", "/" + field + "/value"
            try:
                digest = corpus.artifact_sha256[filename]
                observed_context[field] = {"value": corpus.resolve(filename, digest, pointer),
                    "artifact_file": filename, "artifact_sha256": digest, "json_pointer": pointer}
            except (KeyError, ValueError, TypeError):
                observed_context[field] = {"status": "UNKNOWN"}
        # Convert the immutable mappings to ordinary JSON values for the strict
        # result model. These versions come only from the fixed banner parser.
        def plain(item):
            if hasattr(item, "items"):
                return {k: plain(v) for k, v in item.items()}
            if isinstance(item, tuple):
                return [plain(v) for v in item]
            return item
        observed_context["tool_versions"] = plain(corpus.binding.get("tool_versions", {}))
        observed_context["tool_version_provenance"] = plain(corpus.binding.get("tool_version_provenance", {}))
        observed_context["tool_sha256"] = plain(corpus.binding.get("tool_sha256", {}))
        observed_context["target_environment"] = corpus.binding.get("target_environment")
        observed_context["capture_qualified"] = corpus.qualified
        observed_context["diagnostics"] = list(corpus.diagnostics)
    return OracleResult(oracle_id=plan.oracle_id, cve_id=plan.cve_id, domain=plan.domain, plan_sha256=plan_hash,
        corpus_manifest_sha256=corpus.binding.get("manifest_sha256"),
        eligibility=CVEEligibility(cve_id=plan.cve_id, status=eligibility,
                                   reasons=[r.condition_id + ": " + r.reason for r in environment] or ["no environment prerequisite"]),
        conditions=results, condition_status=combined, verdict=verdict, reasons=reasons, observed_context=observed_context,
        limitations=["No generated candidate or real CVE is executed by this Oracle.",
                     "Exit zero, crash, signal and Sanitizer messages alone never establish a specific CVE.",
                     "Integrity hashes are not signatures or proof of a trustworthy collector/host.",
                     "SYNTHETIC VERIFIED proves only offline rule behavior; real CVE remains NOT_VERIFIED.",
                     "Production root-cause assessors and affected/fixed differential standards are not implemented."])
