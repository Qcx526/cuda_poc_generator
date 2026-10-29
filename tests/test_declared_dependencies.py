# -*- coding: utf-8 -*-
"""Anything imported behind a try/except must actually be declared.

The code degrades gracefully when an optional import fails - that is right, an
instruction decoder that is missing should not crash a campaign. The problem is
that "graceful" hides the difference between "this install does not need it" and
"nobody declared it, so every install lacks it". capstone was in the second
category: fault_site.py called it a declared dependency, and reproducing the demo
on a fresh venv produced a table of `unknown` access types instead of read/write.

This walks every try-block import in src/ and requires a matching entry in
pyproject.toml, so the next one fails a test instead of a demo.
"""

import ast
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Import name -> distribution name, for the cases where they differ.
DISTRIBUTIONS = {
    "dotenv": "python-dotenv",
    "langchain_chroma": "langchain-chroma",
    "langchain_huggingface": "langchain-huggingface",
    "langchain_openai": "langchain-openai",
    "langchain_core": "langchain-core",
    "sentence_transformers": "sentence-transformers",
    "yaml": "pyyaml",
}


def _declared() -> set:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = set()
    for spec in data.get("project", {}).get("dependencies", []):
        names.add(_normal(spec))
    for extra in data.get("project", {}).get("optional-dependencies", {}).values():
        for spec in extra:
            names.add(_normal(spec))
    return names


def _normal(spec: str) -> str:
    """Distribution name out of a requirement string, normalised."""
    for sep in (" ;", " ", ">=", "==", "<", "~=", "!=", "["):
        spec = spec.split(sep)[0]
    return spec.strip().lower().replace("-", "_")


def _guarded_imports(path: Path) -> set:
    """Module roots imported inside a try block."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(child, ast.ImportFrom) and child.module:
                found.add(child.module.split(".")[0])
    return found


def _is_local(module: str) -> bool:
    """A sibling module or package inside src/ is not a distribution."""
    src = ROOT / "src"
    return (src / ("%s.py" % module)).is_file() or (src / module).is_dir()


def test_every_degraded_import_is_declared():
    declared = _declared()
    undeclared = {}
    for path in sorted((ROOT / "src").glob("*.py")):
        for module in _guarded_imports(path):
            if module in sys.stdlib_module_names or module == "__future__":
                continue
            if _is_local(module):
                continue
            name = _normal(DISTRIBUTIONS.get(module, module))
            if name not in declared:
                undeclared.setdefault(module, []).append(path.name)

    assert not undeclared, (
        "这些模块在 try/except 里被导入，但 pyproject.toml 没有声明，"
        "装不上时只会静默降级：%s" % undeclared)
