# -*- coding: utf-8 -*-
"""Read what happened while a kernel probe was armed.

Run this after the machine comes back: it compares the moment the probe was
armed with the current boot time and, if the machine restarted, reports the
bugcheck the OS recorded. Exit code 0 means the machine went down.

  python -m tools.harvest_probe data/loop/<workdir>/<CVE>
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.driver_probe import harvest, summarise  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="harvest an armed kernel probe")
    parser.add_argument("workdir")
    args = parser.parse_args()

    result = harvest(Path(args.workdir))
    print(summarise(result))
    for key in ("candidate", "started_at", "exit_code"):
        if result.get(key) is not None:
            print("  %-12s %s" % (key, result[key]))
    bug = result.get("bugcheck") or {}
    if bug:
        print("  %-12s %s (%s)" % ("bugcheck", bug.get("name"), bug.get("code")))
        if bug.get("params"):
            print("  %-12s %s" % ("params", ", ".join(bug["params"])))
    return 0 if result.get("outcome") == "crashed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
