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


def scan(root: Path) -> int:
    """Harvest every armed probe under a directory; what a boot task runs."""
    markers = sorted(root.rglob("probe_armed.json"))
    if not markers:
        print("no armed probes under %s" % root)
        return 1
    crashed = 0
    for marker in markers:
        workdir = marker.parent
        result = harvest(workdir)
        line = "%s | %s | %s" % (workdir, result.get("outcome"), summarise(result))
        print(line)
        with (root / "harvest.log").open("a", encoding="utf-8") as log:
            log.write(line + "\n")
        if result.get("outcome") == "crashed":
            crashed += 1
    print("%d armed probe(s), %d crashed" % (len(markers), crashed))
    return 0 if crashed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="harvest an armed kernel probe")
    parser.add_argument("workdir", nargs="?")
    parser.add_argument("--scan", metavar="ROOT", default=None,
                        help="harvest every armed probe under ROOT (boot task)")
    args = parser.parse_args()

    if args.scan:
        return scan(Path(args.scan))
    if not args.workdir:
        parser.error("give a workdir or --scan ROOT")

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
