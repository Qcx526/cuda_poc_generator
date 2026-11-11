# -*- coding: utf-8 -*-
"""Research memory: what was tried, what it produced, and what is still open.

The previous project kept this in prose reports that only a human could search. Here it
is a JSONL file the agent can query at the start of every turn, so a dead end recorded
in turn 3 is available in turn 9 without re-reading the transcript.
"""

import json
import time
from pathlib import Path


class ResearchMemory:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def add(self, kind: str, text: str, tags: list = None) -> dict:
        entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind,
                 "text": text, "tags": tags or []}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def entries(self) -> list:
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def search(self, query: str, limit: int = 5) -> list:
        words = [w.lower() for w in query.split() if w]
        scored = []
        for entry in self.entries():
            haystack = (entry["text"] + " " + " ".join(entry["tags"])).lower()
            score = sum(haystack.count(word) for word in words)
            if score:
                scored.append((score, entry))
        scored.sort(key=lambda pair: -pair[0])
        return [entry for _, entry in scored[:limit]]

    def digest(self, limit: int = 8) -> str:
        """A short recap for the prompt: last few findings and every open question."""
        entries = self.entries()
        open_items = [e for e in entries if e["kind"] == "open"]
        recent = entries[-limit:]
        lines = []
        for entry in recent:
            lines.append("- [%s] %s" % (entry["kind"], entry["text"][:220]))
        for entry in open_items[-4:]:
            line = "- [open] %s" % entry["text"][:220]
            if line not in lines:
                lines.append(line)
        return "\n".join(lines)
