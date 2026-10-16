"""Bound, byte-preserving Memcheck XML v4 parsing. No subprocess or LLM calls."""

import base64
import re
import xml.etree.ElementTree as ET

from .models.host_parser import (HostEvidenceLocator, HostMemoryObservation,
                                 HostParserCollection, HostParserEvidence,
                                 HostRawArtifact, HostStackFrame)
from .models.lifecycle import canonical_sha256


_MAX_XML = 2 * 1024 * 1024
_CLASSIFY = {
    "InvalidRead": ("INVALID_READ", "READ"),
    "InvalidWrite": ("INVALID_WRITE", "WRITE"),
    "InvalidFree": ("INVALID_FREE", "UNKNOWN"),
    "MismatchedFree": ("INVALID_FREE", "UNKNOWN"),
    "UninitValue": ("UNINITIALIZED_VALUE", "UNKNOWN"),
    "UninitCondition": ("UNINITIALIZED_VALUE", "UNKNOWN"),
    "Overlap": ("OTHER", "UNKNOWN"),
    "SyscallParam": ("OTHER", "UNKNOWN"),
    "ClientCheck": ("OTHER", "UNKNOWN"),
    "Leak_DefinitelyLost": ("OTHER", "UNKNOWN"),
    "Leak_IndirectlyLost": ("OTHER", "UNKNOWN"),
    "Leak_PossiblyLost": ("OTHER", "UNKNOWN"),
    "Leak_StillReachable": ("OTHER", "UNKNOWN"),
}


class _InvalidXML(ValueError):
    pass


def _one(parent, tag, *, required=True):
    items = parent.findall(tag)
    if len(items) > 1 or (required and len(items) != 1):
        raise _InvalidXML("XML_REQUIRED_OR_DUPLICATE_NODE:" + tag)
    if not items:
        return None
    item = items[0]
    if len(item) or item.attrib or item.text is None or not item.text.strip():
        raise _InvalidXML("XML_INVALID_SCALAR_NODE:" + tag)
    return item.text


def _locator(collection, node):
    source = collection.diagnostic_artifact
    return HostEvidenceLocator(artifact_file=source.artifact_file, artifact_sha256=source.sha256,
                               xml_node=node)


def _frames(error, collection, error_node):
    result = []
    mapping = {"ip": "instruction_pointer", "obj": "object_file", "fn": "function",
               "dir": "directory", "file": "file", "line": "line"}
    # Each stack is preserved in its own indexed node; partial frames remain partial.
    for stack_index, stack in enumerate(error.findall("stack"), 1):
        for frame_index, frame in enumerate(stack.findall("frame"), 1):
            if len(result) >= 256:
                raise _InvalidXML("XML_FRAME_LIMIT")
            path = error_node + f"/stack[{stack_index}]/frame[{frame_index}]"
            values, locations = {}, {}
            for tag, field in mapping.items():
                value = _one(frame, tag, required=False)
                if value is None:
                    continue
                if tag == "line":
                    if not re.fullmatch(r"[0-9]{1,9}", value):
                        raise _InvalidXML("XML_INVALID_FRAME_LINE")
                    value = int(value)
                if tag == "ip" and not re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
                    raise _InvalidXML("XML_INVALID_INSTRUCTION_POINTER")
                values[field] = value
                locations[field] = _locator(collection, path + "/" + tag + "[1]")
            result.append(HostStackFrame(**values, locator=_locator(collection, path),
                                         field_locators=locations))
    return result


def _parse(raw, collection):
    if len(raw) > _MAX_XML:
        raise _InvalidXML("XML_SIZE_LIMIT")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise _InvalidXML("XML_UTF8_REQUIRED") from exc
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise _InvalidXML("XML_DTD_OR_ENTITY_FORBIDDEN")
    declaration = re.match(r"\ufeff?\s*<\?xml\b(.*?)\?>", text, re.DOTALL)
    if declaration:
        encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration[1])
        if encoding and encoding[1].lower() not in {"utf-8", "utf8"}:
            raise _InvalidXML("XML_UTF8_REQUIRED")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise _InvalidXML("XML_MALFORMED_OR_TRUNCATED") from exc
    if root.tag != "valgrindoutput" or root.attrib:
        raise _InvalidXML("XML_UNSUPPORTED_ROOT")
    todo, count = [(root, 1)], 0
    while todo:
        node, depth = todo.pop()
        count += 1
        if depth > 32 or count > 20000:
            raise _InvalidXML("XML_STRUCTURE_LIMIT")
        if not isinstance(node.tag, str) or not re.fullmatch(r"[a-z_]+", node.tag) or node.attrib:
            raise _InvalidXML("XML_UNSUPPORTED_NODE_PROFILE")
        todo.extend((child, depth + 1) for child in node)
    if _one(root, "protocolversion") != "4" or _one(root, "protocoltool") != "memcheck":
        raise _InvalidXML("XML_UNSUPPORTED_PROTOCOL")
    pid = _one(root, "pid")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", pid) or int(pid) != collection.observed_pid:
        raise _InvalidXML("XML_PROCESS_ID_CONFLICT")
    statuses = root.findall("status")
    if not statuses or _one(statuses[-1], "state") != "FINISHED":
        raise _InvalidXML("XML_MISSING_FINISHED")
    if any(_one(status, "state") not in {"RUNNING", "FINISHED"} for status in statuses):
        raise _InvalidXML("XML_UNSUPPORTED_PROCESS_STATE")
    if sum(_one(status, "state") == "FINISHED" for status in statuses) != 1:
        raise _InvalidXML("XML_DUPLICATE_FINISHED")
    args = root.findall("args")
    if len(args) != 1:
        raise _InvalidXML("XML_REQUIRED_OR_DUPLICATE_ARGS")
    argv = args[0].findall("argv")
    vargv = args[0].findall("vargv")
    if len(argv) != 1 or len(vargv) != 1:
        raise _InvalidXML("XML_REQUIRED_OR_DUPLICATE_ARGV")
    def vector(node):
        values = [_one(node, "exe")]
        for arg in node.findall("arg"):
            if len(arg) or arg.attrib or arg.text is None:
                raise _InvalidXML("XML_INVALID_ARGUMENT")
            values.append(arg.text)
        if len(values) > 68:
            raise _InvalidXML("XML_ARGUMENT_LIMIT")
        return values
    if vector(argv[0]) != collection.target_argv or vector(vargv[0]) != collection.process.argv[:4]:
        raise _InvalidXML("XML_TOOL_OR_INPUT_IDENTITY_CONFLICT")
    errors = root.findall("error")
    if len(errors) > 128:
        raise _InvalidXML("XML_ERROR_LIMIT")
    result, seen = [], set()
    for index, error in enumerate(errors, 1):
        kind = _one(error, "kind")
        unique = _one(error, "unique")
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", unique) or unique in seen:
            raise _InvalidXML("XML_INVALID_OR_DUPLICATE_ERROR_ID")
        seen.add(unique)
        node = f"/valgrindoutput/error[{index}]"
        classification, direction = _CLASSIFY.get(kind, ("UNSUPPORTED", "UNKNOWN"))
        description = _one(error, "what", required=False)
        if description is None:
            xwhat = error.findall("xwhat")
            if len(xwhat) > 1:
                raise _InvalidXML("XML_DUPLICATE_XWHAT")
            if xwhat:
                description = _one(xwhat[0], "text", required=False)
        result.append(HostMemoryObservation(observation_id=unique, source_kind=kind,
            classification=classification, access_type=direction, description_original=description,
            locator=_locator(collection, node), kind_locator=_locator(collection, node + "/kind[1]"),
            frames=_frames(error, collection, node)))
    return result


def parse_host_parser_evidence(collection: HostParserCollection, *, diagnostic_bytes: bytes,
                               stdout_bytes: bytes, stderr_bytes: bytes,
                               expected_collection_sha256: str) -> HostParserEvidence:
    """Parse pinned original bytes; an external operator/policy provides the pin.

    The pin prevents accidental re-binding, not a forged host or collector. No
    production host-parser attestation/collector is registered in P3-B. Imported
    observations are therefore unqualified for production CVE determination.
    """
    collection = HostParserCollection.model_validate(collection)
    pin = canonical_sha256(collection)
    if expected_collection_sha256 != pin:
        raise ValueError("independent host collection identity pin mismatch")
    artifacts = []
    for name, raw in (("diagnostic", diagnostic_bytes), ("stdout", stdout_bytes), ("stderr", stderr_bytes)):
        if type(raw) is not bytes:
            raise ValueError("original raw artifacts must be bytes")
        identity = getattr(collection, name + "_artifact")
        artifacts.append(HostRawArtifact(identity=identity, raw_b64=base64.b64encode(raw).decode("ascii")))
    if stdout_bytes != collection.process.stdout_bytes() or stderr_bytes != collection.process.stderr_bytes():
        raise ValueError("raw streams differ from the bound process observation")
    codes, observations = [], []
    missing = ["REVIEWED_PRODUCTION_COLLECTOR_UNIMPLEMENTED", "EXACT_AFFECTED_BUILD_ELIGIBILITY_UNKNOWN",
               "HEAP_STACK_LIFETIME_LOCATION_UNKNOWN", "ROOT_CAUSE_BINDING_UNIMPLEMENTED",
               "AFFECTED_FIXED_DIFFERENTIAL_UNIMPLEMENTED", "CVE_EXECUTION_NOT_AUTHORIZED"]
    if collection.diagnostic_format != "VALGRIND_MEMCHECK_XML_V4":
        status, observation_status = "UNSUPPORTED", "UNSUPPORTED"
        codes.append("DIAGNOSTIC_FORMAT_NOT_IMPLEMENTED")
    elif (not collection.capture_complete or collection.process.truncated or collection.process.capture_failed
          or collection.process.timed_out or collection.cleanup_status != "CONFIRMED"):
        status, observation_status = "REJECTED", "UNKNOWN"
        codes.append("CAPTURE_OR_CLEANUP_INCOMPLETE")
    else:
        try:
            observations = _parse(diagnostic_bytes, collection)
            status, observation_status = "PARSED", "OBSERVED"
            codes.append("STRUCTURED_MEMCHECK_OBSERVATIONS_ONLY")
            if collection.process.linux_signal is not None:
                codes.append("LINUX_SIGNAL_IS_NOT_CVE_PROOF")
            if not observations:
                codes.append("NO_STRUCTURED_MEMORY_ERROR_OBSERVED")
        except _InvalidXML as exc:
            status, observation_status = "REJECTED", "UNKNOWN"
            codes.append(str(exc))
    return HostParserEvidence(collection=collection, collection_sha256=pin, raw_artifacts=artifacts,
        parse_status=status, observation_status=observation_status, diagnostic_codes=codes,
        observations=observations, missing_evidence=missing)


def reassess_host_parser_evidence(evidence: HostParserEvidence, *, expected_collection_sha256: str) -> HostParserEvidence:
    """Reparse original XML offline and reject changed derived fields as well."""
    evidence = HostParserEvidence.model_validate(evidence)
    original = {item.identity.artifact_file: item.raw_bytes() for item in evidence.raw_artifacts}
    collection = evidence.collection
    if len(original) != 3:
        raise ValueError("duplicate host raw artifact")
    try:
        rebuilt = parse_host_parser_evidence(collection,
            diagnostic_bytes=original[collection.diagnostic_artifact.artifact_file],
            stdout_bytes=original[collection.stdout_artifact.artifact_file],
            stderr_bytes=original[collection.stderr_artifact.artifact_file],
            expected_collection_sha256=expected_collection_sha256)
    except KeyError as exc:
        raise ValueError("bound raw host artifact is missing") from exc
    if canonical_sha256(evidence) != canonical_sha256(rebuilt):
        raise ValueError("host parsed result differs from deterministic original-byte reevaluation")
    return rebuilt


def host_evidence_digest(evidence: HostParserEvidence) -> str:
    """Digest of the versioned structured result, independent of report locale."""
    return canonical_sha256(HostParserEvidence.model_validate(evidence))
