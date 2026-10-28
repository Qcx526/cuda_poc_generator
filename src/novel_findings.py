# -*- coding: utf-8 -*-
"""Keep crashes that the CVE could not claim.

A sample that segfaults the target but cannot be attributed to the CVE under
test is not noise. It is either a bad PoC or a different bug, and the second case
is worth more than the first - it is the only way this pipeline can find
something nobody has reported.

Three conditions make a crash attributable to the CVE: baseline clean, crafted
crashes, controls clean. When that fails but something still crashed, the crash
is recorded here with the evidence that made the verdict fail, so the file, the
exit code and the reason survive the run.

Nothing here decides whether it is a real bug. It records, and leaves triage to a
human who can afford to look.

  python -m src.novel_findings list
  python -m src.novel_findings list --cve CVE-2025-23340
"""

import argparse
import hashlib
import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

_RUN = re.compile(
    r"\[CPG_RUN\]\s+(?P<artifact>[^\s:]+)(?:::(?P<tool>[\w.-]+))?\s+exit=(?P<code>-?\d+)")
_CRASH = re.compile(
    r"\[CPG_CRASH\]\s+(?P<artifact>[^\s:]+)\s+sig=(?P<sig>-?\d+)"
    r"(?:\s+code=(?P<code>-?\d+))?\s+pc=0x(?P<pc>[0-9a-fA-F]+)"
    r"\s+base=0x(?P<base>[0-9a-fA-F]+)\s+off=0x(?P<off>[0-9a-fA-F]+)"
    r"\s+addr=0x(?P<addr>[0-9a-fA-F]+)\s+module=(?P<module>\S+)"
    r"(?:\s+insn=(?P<insn>[0-9a-fA-F]*))?")
BUCKET = 0x1000
_CRASH_EXITS = {134, 136, 137, 139, 143, -6, -11, -4}


@dataclass
class Crash:
    artifact: str
    exit_code: int
    tool: str = ""
    module: str = ""
    offset: int = 0
    address: int = 0
    insn: str = ""
    access: str = ""
    instruction: str = ""
    severity: str = ""

    @property
    def crashed(self) -> bool:
        return self.exit_code in _CRASH_EXITS

    @property
    def fingerprint(self) -> str:
        """Where it died, not which input killed it.

        Offsets are bucketed to 4 KB: the same function faulting at two nearby
        instructions is one bug far more often than it is two, and an exact
        offset would split one root cause across a dozen findings.
        """
        if not self.module:
            return "exit:%d" % self.exit_code
        return "%s+0x%x" % (self.module, self.offset & ~(BUCKET - 1))


@dataclass
class Finding:
    cve_id: str
    artifact: str
    exit_code: int
    tool: str
    verdict: str
    reasons: List[str] = field(default_factory=list)
    note: str = ""
    fingerprint: str = ""
    fault_address: int = 0
    access: str = ""
    instruction: str = ""
    severity: str = ""
    sha256: str = ""
    recorded_at: str = ""
    triage: str = "UNTRIAGED"

    def as_dict(self) -> dict:
        return asdict(self)


def disclosure_markdown(finding: dict) -> str:
    """The finding registered the way a CVE entry is written.

    Component, effect, trigger, the versions it was measured on, the inferred
    affected range, and the disclosure search. The point of the document is that
    someone can read it without our tooling and decide whether they have seen
    this bug before.
    """
    disclosure = finding.get("disclosure") or {}
    versions = finding.get("versions") or []
    measured = "; ".join(
        "%s %s" % (str(row.get("image", "")).split(":")[-1].split("-")[0],
                   "崩溃" if row.get("crashed") else "不崩溃")
        for row in versions) or "未测"
    matches = disclosure.get("matches") or []
    match_lines = "\n".join("- %s" % item for item in matches) or "- 未检索到已发布的相似描述"
    verdict = disclosure.get("verdict", "待查重")
    return "\n".join([
        "# 候选漏洞登记：%s" % finding.get("artifact", ""),
        "",
        "| 项目 | 内容 |",
        "|---|---|",
        "| 组件 | %s |" % disclosure.get("component", finding.get("fingerprint", "")),
        "| 现象 | %s |" % disclosure.get("effect", finding.get("severity", "崩溃")),
        "| 触发条件 | %s |" % disclosure.get("trigger", ""),
        "| 崩溃点 | `%s` |" % finding.get("fingerprint", ""),
        "| 故障地址 | %s |" % ("0x%x" % finding["fault_address"] if finding.get("fault_address") else "—"),
        "| 实测版本 | %s |" % measured,
        "| 推断受影响范围 | %s |" % disclosure.get("affected_statement", "以实测为准"),
        "",
        "## 查重结果（%s）" % verdict,
        "",
        match_lines,
        "",
        "## 结论",
        "",
        disclosure.get("conclusion", ""),
        "",
    ]) + "\n"


def write_disclosure(directory: Path) -> Path:
    """Render the finding's CVE-like registration beside its evidence."""
    directory = Path(directory)
    meta = json.loads((directory / "finding.json").read_text(encoding="utf-8"))
    target = directory / "disclosure.md"
    target.write_text(disclosure_markdown(meta), encoding="utf-8")
    return target


def parse_sites(text: str) -> dict:
    """Fault sites recorded by the shim, keyed by artifact."""
    sites = {}
    for match in _CRASH.finditer(text or ""):
        sites[match.group("artifact")] = {
            "module": match.group("module"),
            "offset": int(match.group("off"), 16),
            "address": int(match.group("addr"), 16),
            "insn": match.group("insn") or "",
        }
    return sites


def parse_crashes(text: str) -> List[Crash]:
    """Every crashing run in a log, from either [CPG_RUN] spelling."""
    sites = parse_sites(text)
    crashes: List[Crash] = []
    seen = set()
    for match in _RUN.finditer(text or ""):
        code = int(match.group("code"))
        artifact = match.group("artifact")
        key = (artifact, code)
        if key in seen:
            continue
        seen.add(key)
        site = sites.get(artifact, {})
        crash = Crash(artifact=artifact, exit_code=code,
                      tool=(match.group("tool") or "").strip(),
                      module=site.get("module", ""),
                      offset=site.get("offset", 0),
                      address=site.get("address", 0),
                      insn=site.get("insn", ""))
        if crash.insn:
            from . import fault_site
            detail = fault_site.classify(crash.insn, crash.address)
            crash.access = detail["access"]
            crash.instruction = detail["instruction"]
            crash.severity = detail["severity"]
        if crash.crashed:
            crashes.append(crash)
    return crashes


def _excerpt(text: str, artifact: str, span: int = 12) -> str:
    """The lines around one artifact's run, so the record explains itself."""
    lines = (text or "").splitlines()
    for index, line in enumerate(lines):
        if artifact in line and "CPG_RUN" in line:
            start = max(0, index - span // 2)
            return "\n".join(lines[start:index + span // 2])
    return ""


def record(directory: Path, cve_id: str, observation: str, verdict: str,
           reasons: Optional[List[str]] = None,
           root: Path = Path("data/findings/novel")) -> List[Path]:
    """Save each unattributed crash; returns the directories created.

    Called only when the verdict is not SUPPORTED: a crash that helped prove the
    CVE is already preserved by the run itself and needs no separate copy.
    """
    if verdict == "SUPPORTED":
        return []
    written: List[Path] = []
    directory = Path(directory)
    known = {row.get("fingerprint") for row in load_all(Path(root) / cve_id)}
    # One record per artifact: the candidate's own run and the grader's run both
    # report the same crash, and two directories named after it collide.
    by_artifact = {}
    for crash in parse_crashes(observation):
        previous = by_artifact.get(crash.artifact)
        if previous is None or (not previous.tool and crash.tool):
            by_artifact[crash.artifact] = crash
    for crash in by_artifact.values():
        if crash.fingerprint in known:
            continue          # same place, same bug: already on file
        known.add(crash.fingerprint)
        source = directory / crash.artifact
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = Path(root) / cve_id / ("%s_%s_exit%d" % (stamp, crash.artifact, crash.exit_code))
        target.mkdir(parents=True, exist_ok=True)

        digest = ""
        if source.is_file():
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            shutil.copy2(source, target / crash.artifact)
        (target / "observation.txt").write_text(
            _excerpt(observation, crash.artifact) or observation[:2000],
            encoding="utf-8")

        finding = Finding(
            cve_id=cve_id, artifact=crash.artifact, exit_code=crash.exit_code,
            tool=crash.tool, verdict=verdict, reasons=list(reasons or []),
            note=("Crash present but the CVE is not attributable: the baseline or "
                  "a control did not behave, so this may be a different bug."),
            fingerprint=crash.fingerprint, fault_address=crash.address,
            access=crash.access, instruction=crash.instruction,
            severity=crash.severity,
            sha256=digest, recorded_at=stamp)
        (target / "finding.json").write_text(
            json.dumps(finding.as_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8")
        written.append(target)
    return written


def load_all(root: Path = Path("data/findings/novel")) -> List[dict]:
    rows = []
    for path in sorted(Path(root).rglob("finding.json")):
        try:
            rows.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return rows


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="crashes the CVE could not claim")
    parser.add_argument("action", choices=["list"])
    parser.add_argument("--cve", default="")
    parser.add_argument("--root", default="data/findings/novel")
    args = parser.parse_args(argv)

    rows = [row for row in load_all(Path(args.root))
            if not args.cve or row.get("cve_id") == args.cve]
    if not rows:
        print("no novel crashes recorded")
        return 0
    print("%-16s %-34s %-8s %-12s %s" % ("CVE", "ARTIFACT", "EXIT", "VERDICT", "TRIAGE"))
    for row in rows:
        print("%-16s %-34s %-8s %-12s %s" % (row.get("cve_id", ""),
                                             row.get("artifact", ""),
                                             row.get("exit_code", ""),
                                             row.get("verdict", ""),
                                             row.get("triage", "")))
    print("\n%d recorded; triage is manual by design" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
