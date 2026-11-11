# -*- coding: utf-8 -*-
"""Workspace: the one directory an agent may write to, and a guard for everything else.

Path containment is not a formality. An agent that can rewrite its own environment can
also destroy evidence of what it did, so writes are refused outside the workspace and
the refusal is recorded rather than silently retried.
"""

from pathlib import Path


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        if self.root not in candidate.parents and candidate != self.root:
            raise PermissionError("path escapes workspace: %s" % relative)
        return candidate

    def write(self, relative: str, content: str) -> dict:
        path = self.resolve(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        path.write_bytes(data)
        return {"path": str(path.relative_to(self.root)), "bytes": len(data)}

    def read(self, relative: str, limit: int = 20000) -> dict:
        path = self.resolve(relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"path": str(path.relative_to(self.root)), "bytes": len(text),
                "truncated": len(text) > limit, "content": text[:limit]}

    def listdir(self, relative: str = ".") -> dict:
        path = self.resolve(relative)
        entries = []
        for child in sorted(path.iterdir()):
            entries.append({"name": child.name, "dir": child.is_dir(),
                            "bytes": child.stat().st_size if child.is_file() else None})
        return {"path": str(path.relative_to(self.root)), "entries": entries[:200]}
