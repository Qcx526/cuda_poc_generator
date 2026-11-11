# -*- coding: utf-8 -*-
"""Real Tavily acceptance: search, pick an official source, extract, read deeper.

No model is involved: this exercises the tool contract against the live API and leaves a
run directory with evidence, artifacts and hashes. It is a search-tool acceptance, not a
vulnerability reproduction, and nothing here counts as a PoC result.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.evidence import ArtifactStore, EvidenceLog, Runner       # noqa: E402
from agent.memory import ResearchMemory                             # noqa: E402
from agent.registry import build_registry                           # noqa: E402
from agent.workspace import Workspace                               # noqa: E402
from src.config_loader import ConfigLoader                          # noqa: E402

OUT = ROOT / "data" / "agent" / "r2_acceptance"
PREFERRED = ("nvidia.com", "github.com/nvidia", "docs.nvidia.com")


def main() -> int:
    ConfigLoader()  # load the project .env; the key is read from there, nowhere else
    OUT.mkdir(parents=True, exist_ok=True)
    log = EvidenceLog(OUT / "evidence.jsonl", ArtifactStore(OUT / "artifacts"),
                      run_id="run-tavily-acceptance")
    registry, _, providers = build_registry(Workspace(OUT / "workspace"),
                                            Runner(OUT / "workspace", log), log,
                                            ResearchMemory(OUT / "memory.jsonl"),
                                            search=True)
    summary = {"providers": providers, "steps": []}
    if not providers or not providers[0]["available"]:
        summary["verdict"] = "BLOCKED_CONFIG"
        (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
        print("BLOCKED_CONFIG:", providers[0]["reason"] if providers else "no provider")
        return 2

    search = registry.call("web_search", {"query": "NVIDIA CUDA security bulletin nvJPEG",
                                          "max_results": 5, "search_depth": "advanced"})
    summary["steps"].append({"step": "search", "ok": search["ok"], "status": search["status"]})
    items = (search.get("summary") or {}).get("items", [])
    print("search:", search["status"], "results:", len(items))
    for item in items:
        print("  -", item["score"], item["url"][:80], "|", item["content"][:60].replace("\n", " "))

    chosen = next((i for i in items
                   if any(host in i["url"].lower() for host in PREFERRED)), None)
    if chosen is None:
        summary["verdict"] = "NO_OFFICIAL_SOURCE"
        (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
        print("no official source among results")
        return 3
    print("chosen:", chosen["url"])

    extract = registry.call("web_extract", {"url": chosen["url"]})
    summary["steps"].append({"step": "extract", "ok": extract["ok"],
                             "status": extract["status"],
                             "chars": (extract.get("summary") or {}).get("chars")})
    print("extract:", extract["status"], "chars:", (extract.get("summary") or {}).get("chars"))

    artifact = None
    if extract.get("artifacts"):
        artifact = extract["artifacts"][0]
        read = registry.call("artifact_read", {"artifact": artifact["artifact"],
                                               "offset": 4000, "limit": 4000})
        summary["steps"].append({"step": "artifact_read", "ok": read["ok"],
                                 "status": read["status"],
                                 "has_more": (read.get("summary") or {}).get("has_more"),
                                 "read_bytes": (read.get("summary") or {}).get("read_bytes")})
        print("artifact_read:", read["status"], "read:", read["summary"]["read_bytes"],
              "has_more:", read["summary"]["has_more"])

    # Negative controls: the same tool must report failure, not success.
    bad = registry.call("web_search", {"query": "x", "max_results": 0})
    empty = registry.call("web_extract", {"url": "https://invalid.invalid/nothing-here"})
    summary["steps"].append({"step": "invalid_max_results", "ok": bad["ok"],
                             "status": bad["status"]})
    summary["steps"].append({"step": "invalid_url", "ok": empty["ok"],
                             "status": empty["status"]})
    print("negative controls:", bad["status"], empty["status"])

    summary["verdict"] = ("ACCEPTED" if search["ok"] and extract["ok"] and artifact
                          and not bad["ok"] and not empty["ok"] else "PARTIAL")
    summary["artifact"] = artifact
    summary["evidence"] = str(log.path.relative_to(ROOT)).replace("\\", "/")
    summary["records"] = log.verify()
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    print("verdict:", summary["verdict"], "| evidence ok:", summary["records"]["ok"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
