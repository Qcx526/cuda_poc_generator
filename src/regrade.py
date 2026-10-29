# -*- coding: utf-8 -*-
"""Re-grade a set of recorded artifacts, deterministically.

The generation stage needs a model and an API key; the verdict does not. Given the
artifacts and the observation log a run produced, this replays the three
conditions - benign clean, crafted crashes, controls clean - and prints what the
grader would have said. It is the honest way to show the judging logic without
asking anyone to trust a screenshot.

  python -m src.regrade --cve CVE-2024-0076 --samples demo/CVE-2024-0076/artifacts \
      --log demo/CVE-2024-0076/artifacts/observation.txt
"""

import argparse
from pathlib import Path
from typing import List, Optional

from .closed_loop import LoopConfig, LoopState
from .loop_stages import make_grader


def regrade(cve_id: str, samples: Path, log: Path,
            project_root: Optional[Path] = None):
    config = LoopConfig(cve_id=cve_id, samples_dir=str(samples),
                        project_root=str(project_root or Path(".").resolve()))
    state = LoopState(iteration=1, observation_file=str(log))
    return make_grader(config, version_in_range=None)(state)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="replay a verdict from artifacts")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--samples", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args(argv)

    result = regrade(args.cve, Path(args.samples), Path(args.log))
    print("verdict: %s" % result.verdict)
    for reason in result.reasons:
        print("  - %s" % reason)
    print("runs: malicious %d/%d crashed, benign %d/%d crashed"
          % (result.malicious_crashes, result.malicious_runs,
             result.benign_crashes, result.benign_runs))
    return 0 if result.verdict == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
