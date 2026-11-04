# -*- coding: utf-8 -*-
"""Audit escape calls for precondition validity.

A rejected escape only tells you something if the objects it referenced were
actually alive. In the F2 runs several escapes were issued after CreateDevice had
already failed, so counting them as "input exploration" inflated the numbers.

Rules:

* an escape counts as exploration only when the adapter opened, the device was
  created, and no handle used by the call had been destroyed earlier;
* the raw NTSTATUS is preserved untouched;
* a call made on a handle that was never created is ``INVALID_SETUP``, not
  ``INPUT_REJECTED``.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

INVALID_SETUP = "INVALID_SETUP"
INPUT_REJECTED = "INPUT_REJECTED"
ACCEPTED = "ACCEPTED"
NO_ESCAPE = "NO_ESCAPE"

_CREATE = {"D3DKMTOpenAdapterFromHdc": "adapter", "D3DKMTOpenAdapterFromLuid": "adapter",
           "D3DKMT_CREATE_DEVICE": "device", "D3DKMTCreateDevice": "device",
           "D3DKMT_CREATE_CONTEXT": "context", "D3DKMTCreateContext": "context"}
_DESTROY = {"D3DKMTDestroyDevice": "device", "D3DKMTDestroyContext": "context",
            "D3DKMTCloseAdapter": "adapter"}


def _status(value: object) -> int:
    if isinstance(value, int):
        return value
    text = str(value)
    if text.startswith("0x"):
        return int(text, 16)
    try:
        return int(text)
    except ValueError:
        return 0


def _ok(status: int) -> bool:
    return status == 0


@dataclass
class EscapeVerdict:
    round_name: str
    api: str
    status: int
    setup_valid: bool
    reasons: List[str] = field(default_factory=list)
    handles: Dict[str, object] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        if not self.setup_valid:
            return INVALID_SETUP
        return ACCEPTED if self.status == 0 else INPUT_REJECTED

    def to_dict(self) -> dict:
        return {"round": self.round_name, "api": self.api, "status": self.status,
                "kind": self.kind, "setup_valid": self.setup_valid,
                "reasons": self.reasons, "handles": self.handles}


def _handles_in(api: str) -> Dict[str, str]:
    found = {}
    for name in ("hAdapter", "hDevice", "hContext"):
        match = re.search(r"%s=(0x[0-9a-fA-F]+|\d+|none|ctx|null)" % name, api)
        if match:
            found[name] = match.group(1)
    return found


def audit_round(log_path: Path, round_name: str = "") -> List[EscapeVerdict]:
    if not Path(log_path).is_file():
        return []
    text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    claims = next((l for l in text.splitlines() if l.startswith("CPG_CLAIMS ")), "")
    if not claims:
        return []
    calls = json.loads(claims[len("CPG_CLAIMS "):]).get("calls") or []

    alive = {"adapter": True, "device": False, "context": False}
    verdicts: List[EscapeVerdict] = []
    for call in calls:
        api = str(call.get("api") or "")
        status = _status(call.get("status"))
        name = api.split("(")[0]
        if name in _CREATE:
            alive[_CREATE[name]] = _ok(status)
            if _CREATE[name] == "adapter" and not _ok(status):
                alive["device"] = alive["context"] = False
        elif name in _DESTROY:
            alive[_DESTROY[name]] = False
        elif name.startswith("D3DKMTEscape"):
            handles = _handles_in(api)
            reasons = []
            if not alive["adapter"]:
                reasons.append("adapter 未成功打开")
            if not alive["device"]:
                reasons.append("device 未成功创建")
            zero = [k for k, v in handles.items()
                    if str(v).lower() in ("0", "0x0", "none", "null")]
            if zero:
                reasons.append("句柄为空: %s" % ",".join(zero))
            verdicts.append(EscapeVerdict(round_name or Path(log_path).parent.name, api,
                                          status, not reasons, reasons, handles))
    return verdicts


def summarise(verdicts: List[EscapeVerdict]) -> dict:
    counts = {INVALID_SETUP: 0, INPUT_REJECTED: 0, ACCEPTED: 0}
    for item in verdicts:
        counts[item.kind] += 1
    return {"escapes": len(verdicts), **counts,
            "valid_explorations": len(verdicts) - counts[INVALID_SETUP]}


def audit_experiment(workdir: Path, cve: str) -> dict:
    root = Path(workdir) / cve
    verdicts: List[EscapeVerdict] = []
    for round_dir in sorted(root.glob("round*")):
        verdicts += audit_round(round_dir / "run.log", round_dir.name)
    return {"workdir": str(workdir), **summarise(verdicts),
            "detail": [v.to_dict() for v in verdicts]}
