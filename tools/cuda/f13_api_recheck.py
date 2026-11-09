# -*- coding: utf-8 -*-
"""Re-run the four API experiments from their stored sources, without new generation.

Two questions: did the FILE_INPUT grading change break the API path, and how much of
an API verdict is actually observable by the harness? The exit code and any signal are
the transport's; the "API cuInit = 0" and "DATA=OK" lines are printed by the program
and stay CANDIDATE_REPORTED.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.cuda_api_backend import parse_api_lines        # noqa: E402
from src.cuda_transport import save_record, transport_for  # noqa: E402

SOURCE = ROOT / "data" / "driver" / "f12-api"
OUT = ROOT / "data" / "driver" / "f13-api-recheck"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for platform in ("windows", "linux"):
        for task in ("normal", "boundary"):
            work = SOURCE / platform / task
            source = work / "candidate.c"
            if not source.is_file():
                rows.append({"platform": platform, "task": task,
                             "status": "NO_SOURCE"})
                continue
            previous = json.loads((work / "result.json").read_text(encoding="utf-8")) \
                if (work / "result.json").is_file() else {}
            run_dir = OUT / platform / task
            run_dir.mkdir(parents=True, exist_ok=True)
            # The transport builds by file name inside its working directory, so the
            # source has to be there; pointing at f12's copy silently failed on Windows.
            staged = run_dir / "candidate.c"
            staged.write_bytes(source.read_bytes())
            build = transport_for(platform).build(staged, run_dir)
            if not build.ok:
                rows.append({"platform": platform, "task": task,
                             "status": "BUILD_FAILED", "rc": build.returncode,
                             "log": build.log[-600:]})
                continue
            invocation = transport_for(platform).run(
                build.artifact, "%s-%s-recheck" % (platform, task))
            save_record(run_dir, build, invocation)
            api = parse_api_lines(invocation.stdout)
            same_api = [r["meaning"] for r in api] == \
                       [r["meaning"] for r in previous.get("api", [])]
            rows.append({"platform": platform, "task": task, "status": "RAN",
                         "exit": invocation.exit_code,
                         "signal": invocation.signal,
                         "api_calls": len(api),
                         "api_matches_previous": same_api,
                         "data_ok": "DATA=OK" in invocation.stdout,
                         "boundary_done": "BOUNDARY=DONE" in invocation.stdout,
                         "trust": {"exit_and_signal": "HARNESS_OBSERVED",
                                   "api_lines_and_data": "CANDIDATE_REPORTED"}})
            print("%-8s %-9s exit=%s api=%d matches_prev=%s data_ok=%s"
                  % (platform, task, invocation.exit_code, len(api), same_api,
                     rows[-1]["data_ok"]))
    (OUT / "recheck.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
