# -*- coding: utf-8 -*-
"""Mutate a seed PoC along the axes its specification declares.

The point is not to fuzz. A fuzzer asks "can I make it crash"; this asks "is the
crash I just made the same one, a different one, or no crash at all" - and for
that the axes have to be chosen deliberately, one field at a time, so the answer
can be attributed.

Two rules make the result readable:

* one field changes per variant, so a difference in outcome has one candidate
  cause;
* the outcome is a fingerprint (where it died), not an exit code, so ten inputs
  reaching the same instruction collapse into one line.

  python -m src.mutation_campaign --cve CVE-2025-23340 --workdir data/mutation/a
"""

import argparse
import json
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import novel_findings
from .grader_matrix import parse_invocations, tool_name

DEFAULT_IMAGE = "cpg/cuda112-py3:1.0"

# Outcome classes, in the order the report reads them.
SAME = "SAME_SITE"
CLEAN = "CLEAN"
NOVEL = "NOVEL_SITE"
UNKNOWN = "NO_SIGNAL"


@dataclass
class Variant:
    axis: str
    field: str
    value: int
    offset: int
    width: int
    path: str = ""
    exit_code: Optional[int] = None
    fingerprint: str = ""
    fault_address: int = 0
    access: str = ""
    severity: str = ""
    tool: str = ""
    outcome: str = ""


def widen(value: int, width: int) -> bytes:
    """Little-endian encoding at the width the field actually occupies."""
    if width <= 0:
        return b""          # the seed is written unchanged, not with zero bytes
    if width == 1:
        return struct.pack("<B", value & 0xFF)
    if width == 2:
        return struct.pack("<H", value & 0xFFFF)
    if width == 4:
        return struct.pack("<I", value & 0xFFFFFFFF)
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def apply(seed: bytes, offset: int, width: int, value: int) -> bytes:
    """One field, one value, everything else byte-identical."""
    if offset + width > len(seed):
        raise ValueError("field at %d+%d runs past the %d-byte seed"
                         % (offset, width, len(seed)))
    out = bytearray(seed)
    encoded = widen(value, width)
    if encoded:
        out[offset:offset + width] = encoded
    return bytes(out)


def plan(spec: dict) -> List[Variant]:
    """Every variant the spec asks for, before anything is executed."""
    block = spec.get("mutation") or {}
    axes = block.get("axes") or []
    if not axes:
        raise ValueError("spec has no mutation.axes")
    variants: List[Variant] = []
    for axis in axes:
        name = str(axis.get("name", axis.get("field", "axis")))
        field = str(axis.get("field", ""))
        offset = int(axis.get("offset", -1))
        width = int(axis.get("width", 8))
        if not field or offset < 0:
            raise ValueError("axis %r needs field and offset" % name)
        for value in axis.get("values", []):
            variants.append(Variant(axis=name, field=field, value=int(value),
                                    offset=offset, width=width))
    return variants


def missing_axes(spec: dict, variants: Sequence[Variant]) -> List[str]:
    """Required axes the spec never produced a variant for."""
    block = spec.get("mutation") or {}
    required = list(block.get("required") or [])
    present = {variant.axis for variant in variants}
    return [name for name in required if name not in present]


def classify(variants: Sequence[Variant], baseline: str) -> List[Variant]:
    """Same fault, no fault, or a fault somewhere new."""
    for variant in variants:
        if variant.exit_code is None:
            variant.outcome = UNKNOWN
        elif variant.exit_code == 0:
            variant.outcome = CLEAN
        elif not variant.fingerprint or variant.fingerprint.startswith("exit:"):
            # Non-zero exit without a recorded fault site is the tool refusing
            # the input, not a crash somewhere new. This must be checked before
            # comparing to the baseline: when the seed does not crash, the
            # baseline is empty and every rejection would equal it.
            variant.outcome = UNKNOWN
        elif variant.fingerprint == baseline:
            variant.outcome = SAME
        else:
            variant.outcome = NOVEL
    return list(variants)


def tool_label(invocation: Sequence[str]) -> str:
    """The binary's own name, as the grader writes it.

    Using the variant's filename here puts parentheses into the protocol line,
    and the grader's pattern for a tool name does not accept them - the line then
    reads as a crash with no exit code.
    """
    for part in invocation:
        text = str(part)
        if text and not text.startswith("-") and "{" not in text:
            return Path(text).name
    return "tool"


def _matrix_script(variants: Sequence[Variant],
                   invocations: Sequence[Sequence[str]]) -> str:
    """One container pass for every variant, mirroring the grader's protocol."""
    lines = ["#!/bin/sh", "crashcap=''",
             "if [ ! -f ./crashcap.so ] && [ -f ./crashcap.c ] && command -v gcc >/dev/null 2>&1; then",
             "  gcc -shared -fPIC -O1 -o ./crashcap.so ./crashcap.c -ldl >/dev/null 2>&1 || true",
             "fi",
             "[ -f ./crashcap.so ] && crashcap='./crashcap.so'"]
    for variant in variants:
        name = Path(variant.path).name
        lines.append("f='%s'" % name)
        for invocation in invocations:
            parts = []
            for part in invocation:
                # Specs spell the input either way; both mean the same file.
                parts.append('"$f"' if str(part) in ("{artifact}", "{candidate}")
                             else str(part))
            command = " ".join(parts)
            lines.append('rm -f ".cc.$f"')
            # A hostile input can make the tool run for minutes; without a bound
            # one such variant stalls the whole pass and the campaign looks hung.
            lines.append('CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" '
                         'timeout 10 %s >/dev/null 2>&1' % command)
            lines.append("rc=$?")
            lines.append('echo "[CPG_RUN] $f::%s exit=$rc"' % tool_name(invocation))
            lines.append('if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi')
    lines.append("true")
    return "\n".join(lines) + "\n"


def _worse(candidate: int, current: int) -> bool:
    """A crash outranks a plain error, which outranks success."""
    def rank(code: int) -> int:
        if code < 0 or code in (134, 136, 137, 139, 143):
            return 2
        return 1 if code else 0
    return rank(candidate) > rank(current)


def run(variants: Sequence[Variant], seed: bytes, invocations: Sequence[Sequence[str]],
        workdir: Path, image: str = DEFAULT_IMAGE,
        timeout: int = 600) -> str:
    """Materialise the variants, run them once, and read back where they died."""
    # Absolute: a relative path is read by docker as a *named volume*, and the
    # mount silently fails to appear, which looks exactly like "nothing ran".
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    for variant in variants:
        variant.path = str(workdir / ("%s_%s_%d.cubin"
                                      % (variant.axis, variant.field, variant.value)))
        Path(variant.path).write_bytes(
            apply(seed, variant.offset, variant.width, variant.value))

    source = Path(__file__).resolve().parent.parent / "tools" / "driver" / "crashcap.c"
    if source.is_file():
        shutil.copy2(source, workdir / "crashcap.c")
    script = workdir / "_mutation.sh"
    script.write_bytes(_matrix_script(variants, invocations).encode("utf-8"))

    command = ["docker", "run", "--rm", "--network", "none",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--read-only", "--tmpfs", "/tmp:size=512m",
               "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
               "-v", "%s:/work:rw" % workdir.as_posix(),
               image, "bash", "-c", "cd /work && sh ./_mutation.sh"]
    completed = subprocess.run(command, capture_output=True, text=True,
                               timeout=timeout, encoding="utf-8", errors="replace")
    observed = novel_findings.parse_crashes(completed.stdout or "")
    by_name: Dict[str, object] = {crash.artifact: crash for crash in observed}
    # Every declared tool runs the same file. Keep the worst result and the tool
    # that produced it: a spec often lists a second tool because only that one
    # reaches the vulnerable parser, and averaging the two would hide it.
    codes: Dict[str, tuple] = {}
    for line in (completed.stdout or "").splitlines():
        if not line.startswith("[CPG_RUN]"):
            continue
        parts = line.split()
        name, _, tool = parts[1].partition("::")
        code = int(parts[-1].split("=")[1])
        previous = codes.get(name)
        if previous is None or _worse(code, previous[0]):
            codes[name] = (code, tool)

    for variant in variants:
        name = Path(variant.path).name
        crash = by_name.get(name)
        recorded = codes.get(name)
        if recorded is not None:
            variant.exit_code, variant.tool = recorded
        if crash is not None:
            variant.fingerprint = crash.fingerprint
            variant.fault_address = crash.address
            variant.access = crash.access
            variant.severity = crash.severity
    return completed.stdout or ""


def novel_lines(raw: str, names: Sequence[str]) -> str:
    """Only the protocol lines belonging to variants that landed somewhere new.

    The findings store is where a human looks for things worth a second look; a
    crash that merely repeated the seed does not belong in it.
    """
    keep = set(names)
    lines = []
    for line in (raw or "").splitlines():
        if "CPG_CRASH" in line or "CPG_RUN" in line:
            parts = line.split()
            if len(parts) > 1 and parts[1].split("::")[0] in keep:
                lines.append(line)
    return "\n".join(lines) + "\n"


def verdict(variants: Sequence[Variant], baseline: str) -> List[str]:
    """What the table means, stated before the table is read.

    Two questions decide whether a crash belongs to the CVE: does the mechanism
    axis move the crash, and does the boundary axis behave as the oracle claims.
    Both are answered here from the measurements, not from the specification.
    """
    findings: List[str] = []
    by_axis: Dict[str, List[Variant]] = {}
    for variant in variants:
        by_axis.setdefault(variant.axis, []).append(variant)

    mechanism = by_axis.get("mechanism", [])
    if mechanism and baseline:
        moved = [v for v in mechanism if v.outcome == NOVEL]
        same = [v for v in mechanism if v.outcome == SAME]
        if same and not moved:
            # Not the same claim as "the mechanism is refuted". If changing the
            # field cannot remove the crash, the axis simply does not separate
            # the bug from the noise, and another axis has to be chosen; saying
            # "not this CVE" from a non-discriminating axis would be a verdict
            # built on a badly chosen question.
            findings.append(
                "机制轴不区分：把 `%s` 改成 %s 都不改变崩溃位置，"
                "因此无法用这个轴证明归属——需要换一个**能让崩溃消失**的机制轴"
                "（例如条目大小、偏移是否落在文件内），而不是据此否定。"
                % (mechanism[0].field, [v.value for v in same]))
        elif moved:
            findings.append(
                "机制轴改变了崩溃点：%s 崩在别处，可能是独立缺陷，需单独判定。"
                % [(v.field, v.value, v.fingerprint) for v in moved])

    boundary = by_axis.get("boundary", [])
    if boundary:
        clean = [v.value for v in boundary if v.outcome == CLEAN]
        crash = [v.value for v in boundary if v.outcome in (SAME, NOVEL)]
        if crash and clean:
            findings.append("边界轴：%s 崩溃，%s 不崩溃。" % (crash, clean))
            if 0 in crash and 11 in clean:
                findings.append(
                    "注意：公告声称 0..11 都应触发，但实测只有 0 触发——"
                    "该构建的有效窗口比文档更窄。")
    if not findings:
        findings.append("本轮没有产生可判读的差异。")
    return findings


def attributed(variants: Sequence[Variant]) -> bool:
    """Whether the axes separated the bug from everything else.

    A mechanism axis that changes nothing cannot support attribution, and a
    campaign without one may well be describing a side effect rather than the
    CVE. Knowledge written from such a campaign must not read as instructions.
    """
    seed = next((v for v in variants if v.axis == "seed"), None)
    if seed is not None and not seed.fingerprint:
        # The seed never crashed: this is an exploratory sweep, not a
        # reproduction, and nothing in it can be called attributed.
        return False
    mechanism = [v for v in variants if v.axis.startswith("mechanism")]
    if not mechanism:
        return False
    return any(v.outcome in (NOVEL, CLEAN) for v in mechanism)


def knowledge_markdown(variants: Sequence[Variant], cve_id: str,
                       baseline: str) -> str:
    """What the campaign learned, written for retrieval rather than for reading.

    Short paragraphs, each headed by the CVE and the axis it is about: the loader
    splits at about a thousand characters, so a conclusion that only makes sense
    inside a longer argument would be retrieved as a fragment.
    """
    by_axis: Dict[str, List[Variant]] = {}
    for variant in variants:
        by_axis.setdefault(variant.axis, []).append(variant)

    ok = attributed(variants)
    parts = ["# %s 变异实测结论" % cve_id, ""]
    parts.append("归属状态：%s" % ("机制轴可区分，结论可用于复现指引"
                                  if ok else
                                  "**未确证归属**——机制轴不区分，本条只描述实测现象，"
                                  "不得当作该 CVE 的复现指引"))
    parts.append("")
    parts.append("## 种子（%s）" % cve_id)
    parts.append("%s 的种子样本崩溃于 `%s`。" % (cve_id, baseline or "未记录"))
    parts.append("")

    for axis_name, items in by_axis.items():
        if axis_name == "seed" or not items:
            continue
        field = items[0].field
        same = [v.value for v in items if v.outcome == SAME]
        clean = [v.value for v in items if v.outcome == CLEAN]
        novel = [v for v in items if v.outcome == NOVEL]
        parts.append("## %s 的 %s 轴（%s）" % (cve_id, axis_name, field))
        facts = []
        if same:
            facts.append("取值 %s 仍崩溃在同一处 `%s`" % (same, baseline))
        if clean:
            facts.append("取值 %s 不崩溃" % clean)
        if novel:
            facts.append("取值 %s 崩溃在别处（%s）"
                         % ([v.value for v in novel],
                            [v.fingerprint for v in novel]))
        parts.append("%s：%s。" % (cve_id, "；".join(facts)))

        if axis_name.startswith("mechanism") and same and not novel:
            parts.append(
                "因此 `%s` 不是 %s 的区分轴：改它不改变崩溃点，"
                "用它既不能证明也不能否定归属。" % (field, cve_id))
        elif clean and same and ok:
            parts.append(
                "因此 %s 的触发窗口是 `%s` ∈ %s；%s 不触发。"
                "生成时应直接取窗口内的值，不要靠试探。"
                % (cve_id, field, [v.value for v in items if v.outcome in (SAME, NOVEL)],
                   clean))
        elif clean and same:
            parts.append(
                "取值 %s 能让崩溃消失、%s 不能，但机制轴不区分，"
                "所以这只能说明该字段影响了某个崩溃，**不能**说明它就是 %s 的触发条件。"
                % (clean, [v.value for v in items if v.outcome in (SAME, NOVEL)], cve_id))
        elif clean and not same:
            parts.append(
                "因此 %s 的 `%s` 在本轮取值中都不触发，窗口尚未定位。"
                % (cve_id, field))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def write_knowledge(variants: Sequence[Variant], cve_id: str, baseline: str,
                    directory: Path, pending_dir: Optional[Path] = None) -> Path:
    """One file per CVE, overwritten rather than appended.

    A campaign that runs twice must not leave two versions of the same conclusion
    in the index - retrieval would then answer with whichever chunk it matched
    first.

    An unattributed campaign writes outside the indexed directory: its结论 is a
    measured fact, but handing it to the generator as guidance is how a false
    positive gets reproduced on purpose.
    """
    directory = Path(directory)
    if not attributed(variants):
        directory = Path(pending_dir) if pending_dir else \
            directory.parent.parent / "knowledge_bases_pending" / "mutation"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ("%s.md" % cve_id)
    target.write_text(knowledge_markdown(variants, cve_id, baseline),
                      encoding="utf-8")
    return target


def report(variants: Sequence[Variant], cve_id: str, baseline: str,
           required_missing: Sequence[str]) -> str:
    counts: Dict[str, int] = {}
    for variant in variants:
        counts[variant.outcome] = counts.get(variant.outcome, 0) + 1

    lines = ["# %s 变异战役" % cve_id, "",
             "种子基线指纹：`%s`" % (baseline or "（未记录）"), "",
             "| 类别 | 数量 | 含义 |", "|---|---|---|",
             "| `%s` | %d | 与种子同一处崩溃 |" % (SAME, counts.get(SAME, 0)),
             "| `%s` | %d | 不崩溃 |" % (CLEAN, counts.get(CLEAN, 0)),
             "| `%s` | %d | **崩溃在别处，候选新发现** |" % (NOVEL, counts.get(NOVEL, 0)),
             "| `%s` | %d | 非零退出但无崩溃点（多为工具拒绝），或无结果 |"
             % (UNKNOWN, counts.get(UNKNOWN, 0)),
             ""]
    if required_missing:
        lines += ["**缺少必需变异轴：%s**，本轮结论不可用于归属。"
                  % ", ".join(required_missing), ""]

    lines += ["## 结论", ""]
    lines += ["- " + item for item in verdict(variants, baseline)]
    lines += ["", "## 明细", "",
              "| 轴 | 字段 | 取值 | 退出码 | 指纹 | 访问 | 判定 |", "|---|---|---|---|---|---|---|"]
    for variant in variants:
        lines.append("| %s | %s | %d | %s | `%s` | %s | `%s` |"
                     % (variant.axis, variant.field, variant.value,
                        "-" if variant.exit_code is None else variant.exit_code,
                        variant.fingerprint or "-", variant.severity or "-",
                        variant.outcome))
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="mutate a seed along declared axes")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--spec", default="")
    parser.add_argument("--workdir", default="")
    parser.add_argument("--tool", default="",
                        help='single tool to exercise, e.g. "nvdisasm {artifact}"')
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--seed", default="",
                        help="path to the seed artifact; overrides mutation.seed")
    parser.add_argument("--knowledge-dir", default="data/knowledge_bases/mutation")
    parser.add_argument("--no-knowledge", action="store_true", default=False)
    args = parser.parse_args(argv)

    spec_path = Path(args.spec) if args.spec else Path("specs") / args.cve / "spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    block = spec.get("mutation") or {}
    workdir = Path(args.workdir) if args.workdir else Path("data/mutation") / args.cve

    seed_dir = Path("data/outputs") / args.cve
    seed_path = Path(args.seed) if args.seed else seed_dir / str(block.get("seed", ""))
    if not seed_path.is_file():
        print("seed not found: %s" % seed_path)
        return 2

    variants = plan(spec)
    missing = missing_axes(spec, variants)
    # The seed runs too: its fingerprint is the baseline everything else is
    # compared against, and guessing it from the spec would be a second chance
    # to be wrong about which instruction matters.
    seed_variant = Variant(axis="seed", field="(unchanged)", value=0,
                           offset=0, width=0)
    anchor = spec.get("anchor") or {}
    invocations = ([args.tool.split()] if args.tool else
                   parse_invocations(anchor.get("invocations"),
                                     anchor.get("invocation")))
    if not invocations:
        print("spec declares no anchor invocation")
        return 2
    raw = run([seed_variant] + variants, seed_path.read_bytes(), invocations,
              workdir, args.image)

    baseline = seed_variant.fingerprint
    variants = classify(variants, baseline)
    variants = [seed_variant] + variants
    text = report(variants, args.cve, baseline, missing)
    (workdir / "report.md").write_text(text, encoding="utf-8")
    (workdir / "variants.json").write_text(
        json.dumps([variant.__dict__ for variant in variants],
                   ensure_ascii=False, indent=2), encoding="utf-8")
    novel = [v for v in variants if v.outcome == NOVEL]
    if novel:
        from . import novel_findings
        saved = novel_findings.record(
            workdir, args.cve,
            novel_lines(raw, [Path(v.path).name for v in novel]),
            "NOT_VERIFIED", ["变异落在与种子不同的崩溃点，归属未定"])
        for path in saved:
            print("novel finding: %s" % path)

    print(text)
    if not args.no_knowledge:
        target = write_knowledge(variants, args.cve, baseline,
                                 Path(args.knowledge_dir))
        indexed = Path(args.knowledge_dir) in target.parents
        print("knowledge entry: %s%s" % (target,
                                         "" if indexed else "（未确证归属，不进索引）"))
    print("written to %s" % workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
