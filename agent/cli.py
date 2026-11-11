# -*- coding: utf-8 -*-
"""Command line entry: python -m agent.cli --goal "..." --turns 12"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from agent.runtime import AgentRuntime                 # noqa: E402
from src.config_loader import ConfigLoader             # noqa: E402
from src.llm_client import LLMClient                   # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--goal", default="")
    parser.add_argument("--goal-file", default="")
    parser.add_argument("--root", default="data/agent/runs/p17_1")
    parser.add_argument("--turns", type=int, default=12)
    parser.add_argument("--legacy", action="store_true",
                        help="also register adapters that legacy src modules expose")
    parser.add_argument("--no-search", action="store_true",
                        help="do not register web search providers even when configured")
    parser.add_argument("--resume", action="store_true",
                        help="continue the run already present in --root")
    args = parser.parse_args()

    goal = Path(args.goal_file).read_text(encoding="utf-8") if args.goal_file else args.goal
    sys.path.insert(0, str(Path.cwd()))
    runtime = AgentRuntime(goal=goal, root=Path(args.root),
                           client=LLMClient(ConfigLoader()), max_turns=args.turns,
                           legacy=args.legacy, search=not args.no_search,
                           resume=args.resume)
    for provider in runtime.provider_status:
        print("[provider] %s available=%s (%s)"
              % (provider["provider"], provider["available"], provider["reason"]))
    result = runtime.run()
    print(json.dumps({"stopped": result.stopped, "turns": len(result.turns),
                      "final": result.final[:2000]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
