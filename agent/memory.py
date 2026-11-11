# -*- coding: utf-8 -*-
"""Research memory: what was tried, what it produced, what is still open.

Every entry carries an id, the run it came from, a type and the evidence it points at.
The runtime searches this before each turn, so a dead end recorded in turn 3 is visible
in turn 9 without the model re-reading its own transcript.

Types have meaning enforced here: only ``finding`` may claim support, and it must name at
least one evidence id. A model opinion is a ``hypothesis`` and stays one.
"""

import hashlib
import json
import time
from pathlib import Path

TYPES = {"attempt", "finding", "hypothesis", "failed", "open"}


class MemoryError(ValueError):
    """An entry would misrepresent what is known."""


class ResearchMemory:
    def __init__(self, path: Path, run_id: str = ""):
        self.path = Path(path)
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def add(self, kind: str, text: str, tags: list = None,
            evidence: list = None, source: str = "agent") -> dict:
        if kind not in TYPES:
            raise MemoryError("unknown memory type %r (allowed: %s)"
                              % (kind, ", ".join(sorted(TYPES))))
        if kind == "finding" and not evidence:
            raise MemoryError("a finding must cite evidence ids; use 'hypothesis' instead")
        entry = {
            "id": hashlib.sha256(("%s|%s|%s" % (self.run_id, kind, text)).encode("utf-8")
                                 ).hexdigest()[:16],
            "run_id": self.run_id,
            "type": kind,
            "content": text,
            "tags": list(tags or []),
            "evidence": list(evidence or []),
            "source": source,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def entries(self) -> list:
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def search(self, query: str, limit: int = 5) -> list:
        """Rank by term overlap, then prefer failures and open questions."""
        words = [w.lower() for w in query.replace("\n", " ").split() if len(w) > 2]
        scored = []
        for entry in self.entries():
            haystack = (entry["content"] + " " + " ".join(entry["tags"])).lower()
            score = sum(haystack.count(word) for word in words)
            if not score:
                continue
            priority = {"failed": 3, "open": 2, "finding": 1}.get(entry["type"], 0)
            scored.append((score + priority * 0.5, entry))
        scored.sort(key=lambda pair: -pair[0])
        return [entry for _, entry in scored[:limit]]

    def digest(self, goal: str = "", limit: int = 8) -> str:
        """Bounded recap: what matched the goal, the last few, and every open item."""
        seen, lines = set(), []
        candidates = self.search(goal, limit=limit) if goal else []
        candidates += self.entries()[-limit:]
        candidates += [e for e in self.entries() if e["type"] == "open"][-4:]
        for entry in candidates:
            if entry["id"] in seen:
                continue
            seen.add(entry["id"])
            lines.append("- [%s] %s" % (entry["type"], entry["content"][:200]))
            if len(lines) >= limit + 4:
                break
        return "\n".join(lines)
