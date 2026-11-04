# -*- coding: utf-8 -*-
"""Ground truth, kept away from the model.

The harness sets ``MOCK_GPU_ORACLE`` to a file; every planted flaw appends a record
there. Nothing in the contract or in the generated program reads this path, and the
program is never told which behaviours count as a trigger.

Keeping the oracle in a separate module is not decoration: it is the only reason a
"trigger" claim can be checked instead of believed.
"""

import json
import os
from pathlib import Path

PATH_ENV = "MOCK_GPU_ORACLE"


def record(kind: str, detail: dict) -> None:
    target = os.environ.get(PATH_ENV)
    if not target:
        return
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"flaw": kind, "detail": detail}, ensure_ascii=False) + "\n")


def read(path: Path) -> list:
    path = Path(path)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def verdict(path: Path) -> dict:
    records = read(path)
    kinds = sorted({item["flaw"] for item in records})
    return {"triggered": bool(records), "flaws": kinds, "records": records}
