# -*- coding: utf-8 -*-
"""Independent evaluation: replay the recorded calls and judge there.

The candidate process only produces a *call trace* - parameters, no verdicts. The
verdict is computed here, in the runner's process, by executing that trace against
a fresh instance with the oracle enabled.

Forging is therefore not useful: a trace that claims a trigger still has to trigger
when replayed, which means the calls had to actually be made.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import List

from . import _oracle, api


def replay(trace: List[dict]) -> dict:
    api.reset()
    handle, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(handle)
    previous = os.environ.get(_oracle.PATH_ENV)
    os.environ[_oracle.PATH_ENV] = path
    os.environ["MOCK_GPU_JUDGE"] = "1"
    try:
        for step in trace:
            op = step.get("op")
            if op == "open_adapter":
                api.open_adapter(step.get("hint", ""))
            elif op == "create_device":
                api.create_device(int(step.get("hAdapter", 0)))
            elif op == "create_context":
                api.create_context(int(step.get("hDevice", 0)), int(step.get("node", 0)))
            elif op == "escape":
                api.escape(int(step.get("hAdapter", 0)), int(step.get("hDevice", 0)),
                           int(step.get("hContext", 0)), int(step.get("type_", 0)),
                           int(step.get("flags", 0)),
                           bytes.fromhex(step.get("payload", "")))
            elif op == "destroy_context":
                api.destroy_context(int(step.get("hContext", 0)))
            elif op == "destroy_device":
                api.destroy_device(int(step.get("hDevice", 0)))
            elif op == "close_adapter":
                api.close_adapter(int(step.get("hAdapter", 0)))
        verdict = _oracle.verdict(path)
    finally:
        os.environ.pop("MOCK_GPU_JUDGE", None)
        if previous is None:
            os.environ.pop(_oracle.PATH_ENV, None)
        else:
            os.environ[_oracle.PATH_ENV] = previous
        Path(path).unlink(missing_ok=True)
    verdict["replayed_steps"] = len(trace)
    return verdict


def load_trace(path: Path) -> List[dict]:
    path = Path(path)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
    return data if isinstance(data, list) else []
