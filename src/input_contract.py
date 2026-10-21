# -*- coding: utf-8 -*-
"""Turn the input's optional operational blocks into a generation contract.

The seven descriptive layers explain what the vulnerability is; they do not
say what the parser consumes. When an input also carries ``parser_model``,
``executable_anchor`` and ``observable_signal``, those blocks are rendered as a
specification the generator must satisfy, and the sufficiency score picks the
search strategy.

Nothing here invents data: only fields present in the input are rendered.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .input_sufficiency import assess

_LAYER_FILES = {
    "component": "3_affected_component.json",
    "surface": "4_attack_surface.json",
    "root": "7_root_cause.json",
}
_WRAPPERS = {"component": "affected_component", "surface": "attack_surface",
             "root": "root_cause"}


@dataclass(frozen=True)
class ExecutableContract:
    """Rendered contract plus the strategy the input quality justifies."""

    cve_id: str
    strategy: str
    text: str
    has_operational: bool


def _load_layer(input_dir: Path, layer: str) -> Dict[str, object]:
    path = input_dir / _LAYER_FILES[layer]
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    wrapper = _WRAPPERS[layer]
    body = payload.get(wrapper)
    return body if isinstance(body, dict) else payload


def _render_fields(fields: object) -> List[str]:
    lines: List[str] = []
    if not isinstance(fields, list):
        return lines
    for item in fields:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "?")
        parts = ["%s:" % name]
        for key in ("offset", "size", "bound_check", "semantics"):
            value = item.get(key)
            if value not in (None, "", []):
                parts.append("%s=%s" % (key, value))
        lines.append("  - " + " ".join(parts))
    return lines


def render_contract(input_dir: Path) -> ExecutableContract:
    """Build the prompt block; empty sections are omitted, never faked."""
    sufficiency = assess(input_dir)
    root = _load_layer(input_dir, "root")
    component = _load_layer(input_dir, "component")
    surface = _load_layer(input_dir, "surface")

    parser = root.get("parser_model") if isinstance(root.get("parser_model"), dict) else {}
    anchor = (component.get("executable_anchor")
              if isinstance(component.get("executable_anchor"), dict) else {})
    signal = surface.get("observable_signal")
    invocation = surface.get("invocation")

    lines: List[str] = ["[EXECUTABLE CONTRACT — SPECIFICATION, NOT BACKGROUND]",
                        "STRATEGY: %s" % sufficiency.strategy]
    has_operational = False

    entry = parser.get("entry_function")
    if isinstance(entry, dict) and entry:
        has_operational = True
        lines.append("PARSER ENTRY: %s @ %s" % (entry.get("name", "?"),
                                                entry.get("rva", "?")))
    pseudocode = parser.get("loop_pseudocode")
    if isinstance(pseudocode, str) and pseudocode.strip():
        has_operational = True
        lines.append("PARSER LOOP:\n%s" % pseudocode.strip())
    field_lines = _render_fields(parser.get("consumed_fields"))
    if field_lines:
        has_operational = True
        lines.append("FIELDS THE PARSER CONSUMES (mutate these, not random bytes):")
        lines.extend(field_lines)

    if anchor:
        has_operational = True
        if anchor.get("binary"):
            lines.append("TARGET BINARY: %s" % anchor["binary"])
        fmt = anchor.get("input_format")
        if isinstance(fmt, dict) and fmt:
            lines.append("INPUT FORMAT: %s" % json.dumps(fmt, ensure_ascii=False))
        if anchor.get("baseline_recipe"):
            lines.append("BASELINE RECIPE (use it; do not invent a baseline): %s"
                         % anchor["baseline_recipe"])
        versions = anchor.get("affected_versions")
        if isinstance(versions, dict) and versions:
            lines.append("AFFECTED VERSIONS: %s" % json.dumps(versions, ensure_ascii=False))

    if isinstance(invocation, dict) and invocation:
        has_operational = True
        lines.append("INVOCATION: %s" % json.dumps(invocation, ensure_ascii=False))
    if isinstance(signal, dict) and signal:
        has_operational = True
        lines.append("SUCCESS SIGNAL: %s" % json.dumps(signal, ensure_ascii=False))

    if sufficiency.strategy == "RECON_FIRST":
        lines.append("This input is thin: spend the first step confirming the "
                     "parser entry and the file layout before mutating anything.")
    elif sufficiency.strategy == "PROBE_THEN_MUTATE":
        lines.append("The parser entry is known but its field layout is not: "
                     "probe the tool with one benign and one slightly malformed "
                     "input, then mutate the field the probe reacts to.")

    return ExecutableContract(cve_id=input_dir.name, strategy=sufficiency.strategy,
                              text="\n".join(lines),
                              has_operational=has_operational)


def contract_for(input_dir: Optional[Path]) -> Optional[ExecutableContract]:
    """Convenience wrapper: None when the directory cannot be read."""
    if input_dir is None or not Path(input_dir).is_dir():
        return None
    return render_contract(Path(input_dir))
