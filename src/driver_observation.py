# -*- coding: utf-8 -*-
"""One record shape for every observation, whatever produced it.

Rules encoded here:

* ``confidence`` never rises on its own. An ETW event that cannot be tied to a
  call stays ``INDIRECT``; a user-mode NTSTATUS stays ``DIRECT`` for that call and
  says nothing about the kernel.
* ``UNAVAILABLE`` is a value, not an absence to be filled in later.
* ``source`` is required, because "we observed it" is meaningless without knowing
  what observed it.
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

DIRECT = "DIRECT"          # the process itself returned this
INDIRECT = "INDIRECT"      # a side channel consistent with it
UNAVAILABLE = "UNAVAILABLE"

SOURCE_USERLAND = "userland_log"
SOURCE_ETW = "etw:DxgKrnl"
SOURCE_MOCK = "mock_driver"

STORE = Path("data/driver/observations")


@dataclass
class Observation:
    source: str
    event_type: str
    timestamp: str
    experiment: str
    round: int
    input_signature: str
    observed: Dict[str, object] = field(default_factory=dict)
    evidence_path: str = ""
    confidence: str = DIRECT
    limitations: str = ""
    pid: Optional[int] = None
    tid: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def from_run_log(experiment: str, round_index: int, log_path: Path,
                 input_signature: str = "") -> List[Observation]:
    """Turn one CPG_CLAIMS line into per-call observations."""
    if not Path(log_path).is_file():
        return []
    text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    claims = next((l for l in text.splitlines() if l.startswith("CPG_CLAIMS ")), "")
    if not claims:
        return []
    payload = json.loads(claims[len("CPG_CLAIMS "):])
    stamp = _mtime(log_path)
    out: List[Observation] = []
    for call in payload.get("calls") or []:
        out.append(Observation(
            source=SOURCE_USERLAND, event_type="api_call", timestamp=stamp,
            experiment=experiment, round=round_index,
            input_signature=input_signature or str(call.get("api"))[:80],
            observed={"api": call.get("api"), "status": call.get("status")},
            evidence_path=str(log_path), confidence=DIRECT,
            limitations="仅证明用户态返回值，不证明内核函数执行"))
    return out


def from_etw(experiment: str, round_index: int, summary_path: Path,
             input_signature: str = "") -> Observation:
    """Aggregate ETW counts as one observation, with its limits attached."""
    if not Path(summary_path).is_file():
        return Observation(SOURCE_ETW, "etw_summary", _mtime(summary_path),
                           experiment, round_index, input_signature, {},
                           str(summary_path), UNAVAILABLE,
                           "无 ETL/无法解码；无法归因到具体调用")
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    return Observation(
        source=SOURCE_ETW, event_type="etw_summary", timestamp=_mtime(summary_path),
        experiment=experiment, round=round_index, input_signature=input_signature,
        observed={"total_events": summary.get("total"),
                  "top_tasks": dict(list(summary.get("by_task", {}).items())[:5])},
        evidence_path=str(summary_path), confidence=INDIRECT,
        limitations=("DxgKrnl 事件只有数字 task id；对比 base/escape 两次采集无超出噪声的差异，"
                     "不能证明 Escape 处理函数或授权分支执行"))


def _mtime(path: Path) -> str:
    try:
        import datetime

        return datetime.datetime.fromtimestamp(Path(path).stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return ""


def save(observations: Iterable[Observation], name: str) -> Path:
    STORE.mkdir(parents=True, exist_ok=True)
    target = STORE / ("%s.jsonl" % name)
    with target.open("w", encoding="utf-8") as handle:
        for item in observations:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
    return target


def load(name: str) -> List[dict]:
    path = STORE / ("%s.jsonl" % name)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def prompt_block(observations: List[dict]) -> str:
    """Compact, non-upgraded summary for the analyst prompt."""
    if not observations:
        return "（本轮无运行观测）"
    lines = ["来源 | 事件 | 观测 | 置信度 | 限制"]
    for item in observations[-12:]:
        lines.append("%s | %s | %s | %s | %s" % (
            item["source"], item["event_type"],
            json.dumps(item["observed"], ensure_ascii=False)[:120],
            item["confidence"], item["limitations"][:60]))
    lines.append("说明：INDIRECT 与 UNAVAILABLE 不得当作已证明的内核行为。")
    return "\n".join(lines)
