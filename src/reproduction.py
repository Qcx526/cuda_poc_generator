"""Turn a recorded CUDA-step run log into structured reproduction evidence.

The generated PoCs print ``[CUDA_STEP:Sxx] <description> — START|OK|FAIL`` and,
for toolchain targets, one ``<artifact> -> exit=<code> (crash)`` line per run.
This module parses exactly that vocabulary so a finished run can be evaluated
offline, without re-executing anything and without trusting a narrative.

It deliberately does not emit a CVE-level ``VERIFIED``. A crash plus a clean
control supports the observation that the crafted input crashes this build; it
does not prove the specific root cause. That stronger claim stays with the
dedicated verifier described in the P3-A contract.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

StepStatus = Literal["START", "OK", "FAIL"]
RunLabel = Literal["MALICIOUS", "BENIGN", "CONTROL", "UNKNOWN"]
Verdict = Literal["SUPPORTED", "NOT_VERIFIED", "UNKNOWN"]

_STEP = re.compile(
    r"\[CUDA_STEP:(?P<step>S\d+)\]\s*(?P<description>.+?)\s*[—–-]+\s*(?P<status>START|OK|FAIL)"
    r"(?:\s*[:\-]\s*(?P<detail>.*))?$",
    re.MULTILINE,
)
_EXIT = re.compile(
    r"(?P<artifact>[^\s\\/]+\.(?:cubin|fatbin|elf|bin))\s*->\s*exit=(?P<code>[0-9]+)"
    r"(?:\s*\((?P<kind>[^)]*)\))?",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>|]*|/(?:home|mnt|tmp|var)/[^\s\"'<>|]*)")

# Windows NTSTATUS values produced by a fatal access/illegal instruction fault.
_CRASH_CODES = {0xC0000005, 0xC000001D, 0xC0000094, 0xC00000FD, 0xC0000409, 0xC0000374}
# Shell-style signal exits on POSIX (128 + signal).
_CRASH_SIGNAL_EXITS = {134, 136, 137, 139, 143}
# subprocess reports the same faults as -signal: SIGILL/SIGABRT/SIGBUS/SIGFPE/SIGSEGV.
_FATAL_SIGNALS = {4, 6, 7, 8, 11}


class StepEvent(BaseModel):
    """One ``[CUDA_STEP]`` transition; the detail keeps the operator-facing text."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    step_id: str = Field(pattern=r"^S[0-9]{2,}$")
    description: str = Field(min_length=1)
    status: StepStatus
    detail: str = ""


class ArtifactRun(BaseModel):
    """One tool invocation recorded by the PoC, classified by artifact name."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    artifact: str = Field(min_length=1)
    exit_code: int
    crashed: bool
    label: RunLabel
    recorded_kind: str = ""


class ReproductionEvidence(BaseModel):
    """Everything the verdict may use, bound to the exact log bytes."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source_log_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    steps: List[StepEvent]
    runs: List[ArtifactRun]
    target_version_in_range: Optional[bool] = None
    root_cause_proof_recorded: bool = False


class ReproductionResult(BaseModel):
    """A verdict plus the reasons that produced it, never a bare label."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    verdict: Verdict
    reasons: List[str] = Field(min_length=1)
    failed_steps: List[str]
    malicious_runs: int
    malicious_crashes: int
    benign_runs: int
    benign_crashes: int
    control_runs: int = 0
    control_crashes: int = 0


def redact_paths(text: str) -> str:
    """Remove absolute host paths before text reaches a report or a fixture."""
    return _ABSOLUTE_PATH.sub("<path>", text)


def _normalise_newlines(text: str) -> str:
    """Windows logs end lines with CRLF; the trailing CR breaks anchored regexes."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def is_crash_exit(code: int) -> bool:
    """Recognise a fatal fault exit, not a normal error return.

    Two conventions reach this function: a shell reports ``128 + signal`` while
    ``subprocess`` reports ``-signal``. Both must be recognised, otherwise a
    Linux segfault (-11) would look like an ordinary failure.
    """
    if code < 0:
        return -code in _FATAL_SIGNALS
    if code in _CRASH_SIGNAL_EXITS:
        return True
    return (code & 0xFFFFFFFF) in _CRASH_CODES


def label_for(artifact: str) -> RunLabel:
    """Public entry point for the naming rule; callers must not re-implement it."""
    return _label(artifact)


def _label(artifact: str) -> RunLabel:
    """Classify by what the artifact contains, then by what the run probes.

    Precedence is content first: ``_ctrl_size_restored_malicious_*`` still holds
    the malicious payload and must count as a malicious sample, not as a
    mechanism control. A pure ``benign*`` name is the baseline; otherwise a
    ``ctrl*`` name is a one-variable probe. ``benign`` inside a control name
    (``_ctrlD_benign_content_at_eof``) does not make it the baseline.
    """
    lowered = artifact.lower()
    # "payload" is deliberately not a malicious marker: "_ctrlE_zero_payload"
    # is a control whose payload is empty.
    # "poc" and "crafted" are how most candidates name the thing they built;
    # without them a perfectly good crafted artifact classified as UNKNOWN and
    # the run reported "no controlled sample recorded" while it sat right there.
    if re.search(r"(^|[^a-z])(malicious|exploit|poc|crafted|trigger)", lowered):
        return "MALICIOUS"
    if "benign" in lowered and "ctrl" not in lowered and "control" not in lowered:
        return "BENIGN"
    if "ctrl" in lowered or "control" in lowered:
        return "CONTROL"
    return "UNKNOWN"


def parse_step_events(text: str) -> List[StepEvent]:
    """Return events in recorded order; Windows CRLF logs are supported."""
    events: List[StepEvent] = []
    for match in _STEP.finditer(_normalise_newlines(text)):
        events.append(StepEvent(
            step_id=match.group("step"),
            description=redact_paths(match.group("description").strip()),
            status=match.group("status"),
            detail=redact_paths((match.group("detail") or "").strip()),
        ))
    return events


def parse_artifact_runs(text: str) -> List[ArtifactRun]:
    runs: List[ArtifactRun] = []
    for match in _EXIT.finditer(text):
        code = int(match.group("code"))
        runs.append(ArtifactRun(
            artifact=match.group("artifact"),
            exit_code=code,
            crashed=is_crash_exit(code),
            label=_label(match.group("artifact")),
            recorded_kind=(match.group("kind") or "").strip(),
        ))
    return runs


def parse_log(text: str, *, target_version_in_range: Optional[bool] = None,
              root_cause_proof_recorded: bool = False) -> ReproductionEvidence:
    """Parse a log's text; the digest must be computed by the caller's source bytes."""
    if not isinstance(text, str):
        raise ValueError("run log must be text")
    return ReproductionEvidence(
        source_log_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        steps=parse_step_events(text),
        runs=parse_artifact_runs(text),
        target_version_in_range=target_version_in_range,
        root_cause_proof_recorded=root_cause_proof_recorded,
    )


def parse_log_file(path: str, **kwargs: Any) -> ReproductionEvidence:
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8", errors="replace")
    evidence = parse_log(text, **kwargs)
    # Bind the digest to the bytes actually read, not to a re-encoded copy.
    return evidence.model_copy(update={"source_log_sha256": hashlib.sha256(raw).hexdigest()})


def evidence_from_runs(*, runs: List[Dict[str, Any]], source_sha256: str,
                       steps: Optional[List[StepEvent]] = None,
                       target_version_in_range: Optional[bool] = None,
                       root_cause_proof_recorded: bool = False) -> ReproductionEvidence:
    """Build evidence from structured runs when there is no ``[CUDA_STEP]`` log.

    A container harness reports ``artifact -> exit=N`` lines rather than PoC step
    events. The digest must still cover the raw harness output, so the caller
    passes it in; no observation is inferred from a summary.
    """
    base = ReproductionEvidence(
        source_log_sha256=source_sha256,
        steps=[] if steps is None else list(steps),
        runs=[],
        target_version_in_range=target_version_in_range,
        root_cause_proof_recorded=root_cause_proof_recorded,
    )
    return attach_runs(base, runs)


def attach_runs(evidence: ReproductionEvidence,
                runs: List[Dict[str, Any]]) -> ReproductionEvidence:
    """Attach runs recorded outside the log, e.g. controls run separately.

    Each item needs ``artifact`` and ``exit_code``. The label is derived from the
    artifact name with the same rule as the log parser, so a control cannot be
    relabelled as a malicious sample by its caller.
    """
    extra: List[ArtifactRun] = []
    for item in runs:
        if not isinstance(item, dict) or "artifact" not in item or "exit_code" not in item:
            raise ValueError("external runs need artifact and exit_code")
        artifact = item["artifact"]
        code = item["exit_code"]
        if not isinstance(artifact, str) or not artifact.strip():
            raise ValueError("external run artifact must be a non-blank string")
        if type(code) is not int:
            raise ValueError("external run exit_code must be an int")
        derived = _label(artifact)
        explicit = item.get("label")
        if explicit is not None:
            # A harness may know the role of an artifact whose name carries no
            # marker (e.g. "poc_shsize_12.cubin"). It may only supply a label
            # when the name itself does not already resolve to one, so a
            # recognised benign file can never be relabelled as malicious.
            if explicit not in ("MALICIOUS", "BENIGN", "CONTROL"):
                raise ValueError("external label must be MALICIOUS, BENIGN or CONTROL")
            if derived != "UNKNOWN" and derived != explicit:
                raise ValueError("cannot override a recognisable artifact label")
            # Agreement is not an override: a candidate may restate the role
            # its file name already implies.
            label = explicit
        else:
            label = derived
        extra.append(ArtifactRun(artifact=artifact, exit_code=code,
                                 crashed=is_crash_exit(code), label=label))
    return evidence.model_copy(update={"runs": list(evidence.runs) + extra})


def decide(evidence: ReproductionEvidence) -> ReproductionResult:
    """Apply ordered rules; a benign baseline and version eligibility are mandatory.

    The order matters: an out-of-range target must never be reported as a
    failed reproduction, and a benign baseline that crashes removes
    discriminating power even when the malicious sample crashed as intended.

    A crashing ``_ctrl*`` mechanism probe is reported but does not by itself
    disqualify the observation: it shows the crash is not exclusive to the
    payload, which is exactly why the verdict stays at SUPPORTED.
    """
    steps = evidence.steps
    runs = evidence.runs
    failed = [event.step_id for event in steps if event.status == "FAIL"]
    malicious = [run for run in runs if run.label == "MALICIOUS"]
    benign = [run for run in runs if run.label == "BENIGN"]
    control = [run for run in runs if run.label == "CONTROL"]
    malicious_crashes = sum(1 for run in malicious if run.crashed)
    benign_crashes = sum(1 for run in benign if run.crashed)
    control_crashes = sum(1 for run in control if run.crashed)

    def result(verdict: Verdict, reasons: List[str]) -> ReproductionResult:
        return ReproductionResult(
            verdict=verdict, reasons=reasons, failed_steps=failed,
            malicious_runs=len(malicious), malicious_crashes=malicious_crashes,
            benign_runs=len(benign), benign_crashes=benign_crashes,
            control_runs=len(control), control_crashes=control_crashes,
        )

    if not steps and not runs:
        return result("UNKNOWN", ["日志中既没有 CUDA_STEP 事件，也没有样本执行记录；无法判定"])
    if evidence.target_version_in_range is False:
        return result("NOT_VERIFIED", [
            "目标工具/驱动不在受影响区间；这是环境前提不满足，不是复现失败"])
    if not malicious:
        return result("UNKNOWN", ["没有可识别的受控样本执行记录；无法判定复现"])
    if malicious_crashes == 0:
        detail = f"失败步骤 {', '.join(failed)}" if failed else "所有步骤均报告 OK"
        return result("NOT_VERIFIED", [f"受控样本未产生崩溃退出码（{detail}）"])
    if not benign:
        return result("UNKNOWN", [
            "缺少良性基线（benign.cubin），无法排除工具对任意输入崩溃；"
            "补跑基线并用 --controls 附加结果后重新评估"])
    if benign_crashes:
        return result("UNKNOWN", [
            f"良性基线中有 {benign_crashes} 个样本同样崩溃；样本不具区分力"])
    if control and control_crashes:
        # A one-variable control crashing means the crash is not tied to the
        # controlled variable, so the differential has not isolated anything -
        # whether one control or all of them crashed. Counting that as support
        # would credit the tool with a trigger it did not demonstrate.
        return result("UNKNOWN", [
            f"机制对照 {control_crashes}/{len(control)} 个同样崩溃；"
            "所声称的触发条件未得到支持，崩溃不可归因于受控变量"])
    reasons = [
        f"受控样本 {malicious_crashes}/{len(malicious)} 个产生崩溃退出码",
        f"良性基线 {len(benign)} 个全部未崩溃",
        "目标工具版本处于受影响区间" if evidence.target_version_in_range else "目标版本区间未提供，按未知处理",
    ]
    if control:
        reasons.append(f"机制对照 {len(control)} 个全部未崩溃")
    if evidence.root_cause_proof_recorded:
        reasons.append("已记录根因级证据；CVE 级 VERIFIED 仍须独立验证器与人工复核")
    else:
        reasons.append("未采集寄存器/根因级证据；结论停留在“支持”而不是“已验证”")
    return result("SUPPORTED", reasons)


def render_report(evidence: ReproductionEvidence, result: ReproductionResult) -> str:
    """Render a deterministic zh-CN report; raw log text is never embedded."""
    lines = [
        "# CVE 复现证据报告",
        "",
        "报告语言：`zh-CN`。本报告由结构化记录确定性渲染，不执行任何样本。",
        "",
        "## 结论",
        "",
        f"- 判定：`{result.verdict}`",
        f"- 受控样本：{result.malicious_runs} 个，其中崩溃 {result.malicious_crashes} 个",
        f"- 良性基线：{result.benign_runs} 个，其中崩溃 {result.benign_crashes} 个",
        f"- 机制对照：{result.control_runs} 个，其中崩溃 {result.control_crashes} 个",
        f"- 失败步骤：{', '.join(result.failed_steps) if result.failed_steps else '无'}",
        "",
        "## 判定理由",
        "",
    ]
    lines.extend(f"{index}. {reason}" for index, reason in enumerate(result.reasons, 1))
    lines.extend(["", "## 步骤", "", "| 步骤 | 状态 | 描述 |", "|---|---|---|"])
    # A step may emit START and then OK; the last event is its outcome.
    latest: Dict[str, StepEvent] = {}
    for event in evidence.steps:
        latest[event.step_id] = event
    for step_id in sorted(latest):
        event = latest[step_id]
        lines.append(f"| {step_id} | {event.status} | {event.description} |")
    lines.extend(["", "## 样本", "", "| 样本 | 标签 | 退出码 | 崩溃 |", "|---|---|---|---|"])
    for run in evidence.runs:
        lines.append(
            f"| {run.artifact} | {run.label} | {run.exit_code} | {'是' if run.crashed else '否'} |")
    lines.extend([
        "",
        "## 证据绑定",
        "",
        f"- 原始日志 SHA-256：`{evidence.source_log_sha256}`",
        f"- 目标版本区间：{'在区间内' if evidence.target_version_in_range else ('不在区间' if evidence.target_version_in_range is False else '未提供')}",
        f"- 根因级证据：{'已记录' if evidence.root_cause_proof_recorded else '未记录'}",
        "",
        "## 边界",
        "",
        "`SUPPORTED` 表示受控样本在该构建上崩溃、且良性基线 `benign*` 未崩溃，可排除“任意输入都崩”。",
        "`_ctrl*` 是单变量机制对照：它崩溃**不代表**复现失败，但说明该崩溃不独属于恶意载荷，",
        "单一变量的隔离结论没有成立。",
        "它**不等同于** CVE 级 `VERIFIED`：后者要求针对该缺陷的必要条件集合与独立复核。",
        "本报告不产生、也不允许把复现观测升级为漏洞验证结论。",
        "",
    ])
    return "\n".join(lines)


def write_report(directory: str, evidence: ReproductionEvidence, result: ReproductionResult) -> Path:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "reproduction_evidence.json").write_text(
        json.dumps(evidence.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (folder / "reproduction_result.json").write_text(
        json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    report = folder / "report.zh-CN.md"
    report.write_text(render_report(evidence, result), encoding="utf-8")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="离线解析 CUDA_STEP 运行日志并渲染复现证据报告；不执行任何样本")
    parser.add_argument("--log", required=True, help="已保存的运行日志路径")
    parser.add_argument("--out", default=None, help="报告输出目录")
    parser.add_argument("--version-in-range", choices=["yes", "no", "unknown"], default="unknown",
                        help="目标工具版本是否处于受影响区间")
    parser.add_argument("--root-cause-proof", action="store_true", help="日志外另有根因级证据")
    parser.add_argument("--controls", default=None,
                        help="另行记录的对照执行结果 JSON：[{\"artifact\":..., \"exit_code\":...}]")
    args = parser.parse_args(argv)

    version = {"yes": True, "no": False, "unknown": None}[args.version_in_range]
    evidence = parse_log_file(args.log, target_version_in_range=version,
                              root_cause_proof_recorded=args.root_cause_proof)
    if args.controls:
        controls = json.loads(Path(args.controls).read_text(encoding="utf-8"))
        if not isinstance(controls, list):
            raise ValueError("controls file must contain a JSON array")
        evidence = attach_runs(evidence, controls)
    result = decide(evidence)
    if args.out:
        path = write_report(args.out, evidence, result)
        print(f"报告: {path}")
        print(f"判定: {result.verdict}（stage/samples: {len(evidence.steps)}/{len(evidence.runs)}）")
    else:
        print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
