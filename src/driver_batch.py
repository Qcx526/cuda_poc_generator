# -*- coding: utf-8 -*-
"""Run a list of driver probes so that a bugcheck costs one probe, not the batch.

Every probe is written to disk before it runs, and its result is appended as soon
as it returns. If the machine goes down mid-probe, the next start sees a probe
with no result and knows exactly which one took it - no guessing from timestamps,
and no re-running the probes that already answered.

The probe itself runs in a child process. A driver call can fault the user-mode
caller as easily as the kernel, and a fault inside this process would take the
batch with it.

  python -m src.driver_batch --plan data/driver/plans/profile-fields.json
  python -m src.driver_batch --plan ... --resume        # after a reboot
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "tools" / "driver" / "drs_probe.py"
DEFAULT_RUNS = ROOT / "data" / "driver" / "runs"

# Field offsets inside NVDRS_PROFILE, from the published layout:
# version(4) profileName[2048] wchars(4096) gpuSupport(4) isPredefined(4)
# numOfApps(4) numOfSettings(4) = 4116 bytes.
PROFILE = {"size": 4116, "version": 1,
           "fn_get": "0x61CD6FD6", "fn_set": "0x16ABD3A9"}
PROFILE_FIELDS = {"gpuSupport": 4100, "isPredefined": 4104,
                  "numOfApps": 4108, "numOfSettings": 4112}
BOUNDARIES = (0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF)


def build_profile_plan(write_path: bool = True) -> List[dict]:
    """Counter-like fields of the profile struct, one boundary value each.

    The driver reads these when it copies the struct into driver state, so a count
    it trusts without checking is where an out-of-bounds write would come from.
    """
    plan = []
    for name, offset in PROFILE_FIELDS.items():
        for value in BOUNDARIES:
            plan.append({
                "label": "%s.%s=0x%x" % ("set" if write_path else "get", name, value),
                "fn": PROFILE["fn_set"] if write_path else PROFILE["fn_get"],
                "size": PROFILE["size"], "version": PROFILE["version"],
                "offset": offset, "value": value,
            })
    return plan


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, payload) -> None:
    """Write-then-rename: a bugcheck mid-write must not leave a truncated marker."""
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def probe_once(spec: dict, timeout: int = 60) -> Dict[str, object]:
    command = [sys.executable, "-B", str(PROBE), "--fn", spec["fn"],
               "--at", str(spec["offset"]), "--value", str(spec["value"]),
               "--bytes", str(spec["size"]), "--version", str(spec["version"])]
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              errors="replace", timeout=timeout, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout", "exit": None, "output": ""}
    return {"outcome": "returned" if done.returncode == 0 else "faulted",
            "exit": done.returncode,
            "output": ((done.stdout or "") + (done.stderr or ""))[-400:]}


def status_of(result: Dict[str, object]) -> Optional[int]:
    text = str(result.get("output") or "")
    for line in text.splitlines():
        if "-> " in line:
            tail = line.split("-> ", 1)[1].strip().split()[0]
            try:
                return int(tail)
            except ValueError:
                continue
    return None


def run_plan(plan: List[dict], run_dir: Path, resume: bool) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    results_path = run_dir / "results.jsonl"
    armed_path = run_dir / "armed.json"

    done = set()
    if results_path.is_file():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["label"])
            except (ValueError, KeyError):
                continue

    # A probe that was armed and never answered means the machine went down on it.
    armed = load_json(armed_path, None)
    crashed_on = None
    if resume and armed and armed.get("label") not in done:
        crashed_on = armed.get("label")
        with results_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"label": crashed_on, "outcome": "machine_died",
                                     "armed_at": armed.get("armed_at"),
                                     "spec": armed.get("spec")},
                                    ensure_ascii=False) + "\n")
        done.add(crashed_on)
        print("[!] 上一次停在 %s —— 按蓝屏记录" % crashed_on, flush=True)

    summary = {"ran": 0, "crashed_on": crashed_on, "statuses": {}}
    for spec in plan:
        label = spec["label"]
        if label in done:
            continue
        write_json(armed_path, {"label": label, "spec": spec,
                                "armed_at": datetime.now(timezone.utc).isoformat()})
        result = probe_once(spec)
        status = status_of(result)
        record = {"label": label, "spec": spec, "outcome": result["outcome"],
                  "exit": result["exit"], "status": status,
                  "output": result["output"],
                  "at": datetime.now(timezone.utc).isoformat()}
        with results_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        summary["ran"] += 1
        summary["statuses"][label] = status
        print("%-28s %-8s exit=%s status=%s"
              % (label, result["outcome"], result["exit"], status), flush=True)
        if result["outcome"] == "faulted":
            # A fault in the caller is still a finding about the driver's input
            # handling, but it is not the batch's job to keep going through it.
            print("[!] 探测体在新驱动上崩了，停在 %s" % label, flush=True)
            break
        armed_path.unlink(missing_ok=True)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="batch driver probes with resume")
    parser.add_argument("--plan", default="",
                        help="plan json; default is the profile struct plan")
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    if args.plan and Path(args.plan).is_file():
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    else:
        plan = build_profile_plan()

    run_dir = Path(args.run_dir) if args.run_dir else \
        DEFAULT_RUNS / datetime.now().strftime("%Y%m%dT%H%M%S")
    print("plan: %d probes -> %s" % (len(plan), run_dir), flush=True)
    summary = run_plan(plan, run_dir, args.resume)
    write_json(run_dir / "summary.json", summary)
    print("\n跑完 %d 个；蓝屏点：%s" % (summary["ran"], summary["crashed_on"] or "无"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
