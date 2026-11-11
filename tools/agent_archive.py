# -*- coding: utf-8 -*-
"""Archive a run directory for publication, with redaction and a hash manifest.

Two rules matter here. The archive copy is what gets redacted, never the original: the
original stays byte-identical so a later audit can compare. And every file records both
its pre- and post-redaction hash, so "this file was modified before publication" is a
fact in the record rather than something a reader has to guess.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "sk-***REDACTED***"),
    (re.compile(r"(api[_-]?key\s*[=:]\s*[\"']?)[A-Za-z0-9\-_]{12,}", re.I), r"\1***REDACTED***"),
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_.]{12,}", re.I), r"\1***REDACTED***"),
    (re.compile(r"C:\\\\Users\\\\[A-Za-z0-9_.-]+"), r"C:\\Users\\<user>"),
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redact(text: str) -> tuple:
    hits = 0
    for pattern, replacement in SECRET_PATTERNS:
        text, count = pattern.subn(replacement, text)
        hits += count
    return text, hits


def archive(source: Path, destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    entries = []
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        is_binary = False
        try:
            text = raw.decode("utf-8")
            cleaned, hits = redact(text)
            target.write_text(cleaned, encoding="utf-8")
        except UnicodeDecodeError:
            hits = 0
            is_binary = True
            target.write_bytes(raw)
        entries.append({"path": str(relative).replace("\\", "/"),
                        "bytes": target.stat().st_size,
                        "sha256_original": before,
                        "sha256_archived": sha256_file(target),
                        "redactions": hits,
                        "binary": is_binary})
    manifest = {"source": str(source).replace("\\", "/"),
                "files": entries,
                "file_count": len(entries),
                "redacted_files": sum(1 for e in entries if e["redactions"])}
    (destination / "archive.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return manifest


def _is_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:2048]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    manifest = archive(Path(args.source), Path(args.destination))
    print(json.dumps({"files": manifest["file_count"],
                      "redacted": manifest["redacted_files"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
