# -*- coding: utf-8 -*-
"""Match functions between two builds of the same driver, honestly.

What this can and cannot claim:

* A byte-identical body is strong evidence the function did not change.
* A body that differs only in call/jump displacements is *probably* unchanged
  code moved by layout, so it is reported as ``relocated`` rather than matched.
* Equal size alone proves nothing. It is recorded as a feature and explicitly
  never used as a match on its own.

The output is a correspondence plus the set of functions that could not be
paired, because "we could not align this function" is a result worth keeping.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .driver_binary import Function, PEImage

# x86 branch opcodes whose operand is a displacement that shifts with layout.
_REL32 = (0xE8, 0xE9)


def body_bytes(image: PEImage, function: Function) -> bytes:
    start = image.offset_of(function.rva)
    if start is None:
        return b""
    return image.data[start:start + function.size]


def mask_displacements(code: bytes) -> bytes:
    """Blank branch displacements so a moved function compares equal to itself.

    Only the four bytes after a call/jump opcode are cleared; everything else,
    including immediates a fix would change, stays comparable.
    """
    out = bytearray(code)
    index = 0
    while index < len(out) - 4:
        if out[index] in _REL32:
            out[index + 1:index + 5] = b"\x00\x00\x00\x00"
            index += 5
            continue
        # RIP-relative addressing (ModRM mod=00, rm=101) carries a disp32 that
        # shifts with layout just like a branch target. Without masking it, most
        # moved-but-unchanged functions look rewritten.
        if out[index] & 0xC7 == 0x05:
            out[index + 1:index + 5] = b"\x00\x00\x00\x00"
            index += 5
            continue
        index += 1
    return bytes(out)


@dataclass
class FunctionFeature:
    rva: int
    size: int
    digest: str
    masked_digest: str


@dataclass
class Match:
    old_rva: int
    new_rva: int
    matching_features: List[str]
    status: str          # identical | relocated | changed
    limitations: List[str] = field(default_factory=list)


@dataclass
class MatchResult:
    pairs: List[Match] = field(default_factory=list)
    unmatched_old: List[FunctionFeature] = field(default_factory=list)
    unmatched_new: List[FunctionFeature] = field(default_factory=list)
    totals: Dict[str, int] = field(default_factory=dict)


def features_of(image: PEImage) -> List[FunctionFeature]:
    out = []
    for function in image.functions():
        code = body_bytes(image, function)
        if not code:
            continue
        out.append(FunctionFeature(
            rva=function.rva, size=function.size,
            digest=hashlib.sha1(code).hexdigest(),
            masked_digest=hashlib.sha1(mask_displacements(code)).hexdigest()))
    return out


def _group(features: List[FunctionFeature], key) -> Dict[object, List[FunctionFeature]]:
    buckets: Dict[object, List[FunctionFeature]] = {}
    for item in features:
        buckets.setdefault(key(item), []).append(item)
    return buckets


def match(old: List[FunctionFeature], new: List[FunctionFeature]) -> MatchResult:
    """Pair by content first, then by masked content; never by size alone."""
    result = MatchResult()
    new_by_digest = _group(new, lambda f: f.digest)
    new_by_masked = _group(new, lambda f: (f.masked_digest, f.size))
    used_new = set()

    for item in old:
        bucket = [c for c in new_by_digest.get(item.digest, []) if c.rva not in used_new]
        if bucket:
            pick = bucket[0]
            used_new.add(pick.rva)
            result.pairs.append(Match(item.rva, pick.rva, ["identical_bytes"], "identical"))
            continue
        bucket = [c for c in new_by_masked.get((item.masked_digest, item.size), [])
                  if c.rva not in used_new]
        if bucket:
            pick = bucket[0]
            used_new.add(pick.rva)
            result.pairs.append(Match(
                item.rva, pick.rva, ["masked_bytes", "same_size"], "relocated",
                ["差异只在 call/jmp 位移，不能据此判断逻辑未变"]))
            continue
        result.unmatched_old.append(item)

    matched_new = {pair.new_rva for pair in result.pairs}
    result.unmatched_new = [item for item in new if item.rva not in matched_new]
    result.totals = {"old": len(old), "new": len(new), "pairs": len(result.pairs),
                     "identical": sum(1 for p in result.pairs if p.status == "identical"),
                     "relocated": sum(1 for p in result.pairs if p.status == "relocated"),
                     "unmatched_old": len(result.unmatched_old),
                     "unmatched_new": len(result.unmatched_new)}
    return result


def candidate_changes(result: MatchResult, limit: int = 20) -> List[Dict[str, object]]:
    """Functions with no counterpart, ordered by size.

    These are the places a fix could live - and equally places where a build
    difference moved something. Both readings stay open in the output.
    """
    ordered = sorted(result.unmatched_old, key=lambda f: -f.size)[:limit]
    return [{"old_rva": "0x%x" % f.rva, "size": f.size,
             "reason": "no identical or relocated counterpart in the new build",
             "limitation": "可能为删除、重命名或大幅改写，需人工确认"}
            for f in ordered]


def to_json(result: MatchResult, path: Optional[Path] = None) -> Dict[str, object]:
    payload = {
        "totals": result.totals,
        "pairs_sample": [
            {"old_rva": "0x%x" % p.old_rva, "new_rva": "0x%x" % p.new_rva,
             "status": p.status, "matching_features": p.matching_features,
             "limitations": p.limitations}
            for p in result.pairs[:50]],
        "unmatched_old": [{"old_rva": "0x%x" % f.rva, "size": f.size}
                          for f in result.unmatched_old[:50]],
        "unmatched_new": [{"new_rva": "0x%x" % f.rva, "size": f.size}
                          for f in result.unmatched_new[:50]],
    }
    if path is not None:
        import json
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                              encoding="utf-8")
    return payload


# ---------------------------------------------------------------------------
# decoded matching
# ---------------------------------------------------------------------------

@dataclass
class DecodedFeature:
    rva: int
    size: int
    byte_digest: str
    shape_digest: str
    structure: object = None


def features_decoded(image: PEImage) -> List[DecodedFeature]:
    """Same idea as ``features_of``, but the normalisation is done on decoded
    instructions instead of on arbitrary byte offsets."""
    from . import driver_structdiff

    out: List[DecodedFeature] = []
    for function in image.functions():
        code = body_bytes(image, function)
        if not code:
            continue
        structure = driver_structdiff.analyze(code, function.rva)
        out.append(DecodedFeature(
            rva=function.rva, size=function.size,
            byte_digest=hashlib.sha1(code).hexdigest(),
            shape_digest=structure.shape_digest, structure=structure))
    return out


def match_decoded(old: List[DecodedFeature], new: List[DecodedFeature]) -> MatchResult:
    """Pair by bytes, then by decoded shape; equal size is still not a match."""
    result = MatchResult()
    by_bytes: Dict[str, List[DecodedFeature]] = {}
    by_shape: Dict[Tuple[str, int], List[DecodedFeature]] = {}
    for item in new:
        by_bytes.setdefault(item.byte_digest, []).append(item)
        by_shape.setdefault((item.shape_digest, item.size), []).append(item)

    used = set()
    for item in old:
        bucket = [c for c in by_bytes.get(item.byte_digest, []) if c.rva not in used]
        if bucket:
            used.add(bucket[0].rva)
            result.pairs.append(Match(item.rva, bucket[0].rva, ["identical_bytes"],
                                      "identical"))
            continue
        bucket = [c for c in by_shape.get((item.shape_digest, item.size), [])
                  if c.rva not in used]
        if bucket:
            used.add(bucket[0].rva)
            result.pairs.append(Match(
                item.rva, bucket[0].rva, ["decoded_shape", "same_size"], "relocated",
                ["形状一致说明控制流与操作数结构未变，不代表数据内容未变"]))
            continue
        result.unmatched_old.append(
            FunctionFeature(item.rva, item.size, item.byte_digest, item.shape_digest))

    matched = {pair.new_rva for pair in result.pairs}
    result.unmatched_new = [
        FunctionFeature(f.rva, f.size, f.byte_digest, f.shape_digest)
        for f in new if f.rva not in matched]
    result.totals = {"old": len(old), "new": len(new), "pairs": len(result.pairs),
                     "identical": sum(1 for p in result.pairs if p.status == "identical"),
                     "relocated": sum(1 for p in result.pairs if p.status == "relocated"),
                     "unmatched_old": len(result.unmatched_old),
                     "unmatched_new": len(result.unmatched_new)}
    return result
