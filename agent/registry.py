# -*- coding: utf-8 -*-
"""Tool registry: tools are discovered, described and called, never imported as policy.

A tool here is a name, a description the model can read, an argument schema, and a
callable. The registry records where each tool came from and whether it is available,
so the agent can see the menu without the runtime deciding for it. Legacy modules are
registered as adapters rather than called directly - if an adapter is useless the model
can ignore it and write its own tool through the shell.
"""

import importlib
import inspect
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional


@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict[str, str]
    fn: Callable
    category: str = "general"
    requires: List[str] = field(default_factory=list)
    source: str = "builtin"

    def available(self) -> tuple:
        missing = [item for item in self.requires if shutil.which(item) is None]
        return (not missing), missing

    def describe(self) -> dict:
        ok, missing = self.available()
        return {"name": self.name, "description": self.description,
                "parameters": self.parameters, "category": self.category,
                "available": ok, "missing": missing, "source": self.source}


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool, allow_override: bool = False) -> None:
        if tool.name in self._tools and not allow_override:
            raise ValueError("tool %r is already registered (source=%s); refusing to "
                             "silently replace it" % (tool.name, self._tools[tool.name].source))
        self._tools[tool.name] = tool

    def register_many(self, specs: List[dict], allow_override: bool = False) -> List[str]:
        added = []
        for spec in specs:
            self.register(Tool(**spec), allow_override=allow_override)
            added.append(spec["name"])
        return added

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def describe(self, only_available: bool = False) -> List[dict]:
        items = [t.describe() for t in self._tools.values()]
        if only_available:
            items = [i for i in items if i["available"]]
        return sorted(items, key=lambda i: i["name"])

    def call(self, name: str, arguments: dict) -> dict:
        """Dispatch a tool and normalise the outcome.

        Two different facts were being merged into one "ok": whether the call could be
        dispatched at all, and whether the operation the tool performed succeeded. A
        shell command exiting 1, an HTTP 500 and a 401 were all reported as success
        because the call itself returned without raising.

        The envelope keeps them apart:

            dispatched  the tool exists, its dependencies are present and the arguments
                        were accepted - i.e. the function actually ran
            ok          the operation succeeded, according to the tool's own report

        Builtin tools already answer with {"ok", "summary", "artifacts"}; a legacy tool
        returning a plain object is treated as a successful operation with that object as
        its result, because it has no way to say otherwise.
        """
        tool = self._tools.get(name)
        if tool is None:
            return envelope(False, False, None,
                            "unknown tool %r; known: %s" % (name, ", ".join(self.names())))
        available, missing = tool.available()
        if not available:
            return envelope(False, False, None,
                            "tool %r needs %s on PATH" % (name, missing))
        try:
            payload = tool.fn(**(arguments or {}))
        except TypeError as exc:
            return envelope(False, False, None, "bad arguments for %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001 - a tool failure is data, not a crash
            return envelope(True, False, None, "%s: %s" % (type(exc).__name__, exc))
        return envelope(True, True, payload, None)

    def discover_legacy(self, package: str = "src", prefix: str = "") -> List[str]:
        """Register optional adapters that wrap existing project modules.

        Discovery is explicit and shallow: a module must expose ``AGENT_TOOLS`` to be
        picked up. Nothing is imported implicitly, so a broken legacy module cannot take
        the runtime down with it.
        """
        added = []
        module_path = Path(package.replace(".", "/"))
        if not module_path.is_dir():
            return added
        for path in sorted(module_path.glob(prefix + "*.py")):
            if path.stem.startswith("_"):
                continue
            name = "%s.%s" % (package, path.stem)
            try:
                module = importlib.import_module(name)
            except Exception:  # noqa: BLE001 - optional dependency or side effect
                continue
            for entry in getattr(module, "AGENT_TOOLS", []):
                self.register(Tool(**entry))
                added.append(entry["name"])
        return added


def envelope(dispatched: bool, operation_ok: bool, payload, error) -> dict:
    """Normalise a tool payload into the call envelope used by runtime and evidence."""
    result = payload if isinstance(payload, dict) else {"value": payload}
    reported = result.get("ok") if isinstance(payload, dict) and "ok" in result else None
    ok = bool(reported) if reported is not None else bool(operation_ok)
    if error:
        status = "dispatch_error" if not dispatched else "failed"
    elif ok:
        status = result.get("status", "success") if isinstance(payload, dict) else "success"
    else:
        status = "failed"
    return {
        "dispatched": dispatched,
        "ok": ok,
        "status": status,
        "result": payload,
        "summary": result.get("summary") if isinstance(payload, dict) else None,
        "artifacts": result.get("artifacts", []) if isinstance(payload, dict) else [],
        "error": error or (result.get("error") if isinstance(payload, dict) else None),
    }


def build_registry(workspace, runner, log, memory, legacy: bool = False,
                   search: bool = True) -> tuple:
    """Builtins first and always; legacy adapters only add, never replace.

    The earlier CLI could end up with a registry that had only legacy tools, because the
    builtin set was installed only when no legacy tool was found. This function makes the
    order irrelevant: builtins are unconditional, legacy is additive, and a name clash is
    reported instead of resolved by import order.
    """
    from .tools_builtin import build_tools

    registry = ToolRegistry()
    registry.register_many(build_tools(workspace, runner, log, memory))
    conflicts = []
    providers = []
    if search:
        from .tavily_provider import build_tools as provider_tools, status as provider_status
        state = provider_status()
        providers.append(state)
        for spec in provider_tools(log):
            if registry.get(spec["name"]) is not None:
                conflicts.append(spec["name"])
                continue
            registry.register(Tool(**spec))
    if legacy:
        for spec in _legacy_specs():
            if registry.get(spec["name"]) is not None:
                conflicts.append(spec["name"])
                continue
            registry.register(Tool(**spec))
    return registry, conflicts, providers


def _legacy_specs() -> List[dict]:
    specs: List[dict] = []
    module_path = Path("src")
    if not module_path.is_dir():
        return specs
    for path in sorted(module_path.glob("*.py")):
        if path.stem.startswith("_"):
            continue
        try:
            module = importlib.import_module("src.%s" % path.stem)
        except Exception:  # noqa: BLE001 - an optional module must not break startup
            continue
        for entry in getattr(module, "AGENT_TOOLS", []):
            specs.append(entry)
    return specs


def fn_signature(fn: Callable) -> Dict[str, str]:
    return {name: "str" for name, _ in inspect.signature(fn).parameters.items()}


def describe_result(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:4000]
    return str(value)[:4000]
