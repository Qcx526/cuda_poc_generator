# -*- coding: utf-8 -*-
"""Provider-neutral tool calling: native tool_calls when available, JSON otherwise.

The runtime's action protocol is a dict: {"thought", "tool", "args"} or {"thought",
"final"}. Native function calling produces the same thing through a different channel,
so it is adapted here instead of being wired into the loop.

A provider that returns ``tool_calls`` is used in native mode; one that returns prose is
used in JSON mode. The caller decides which, and the mode used is recorded, because
"the model supports tools" is a claim that has to be true of the endpoint, not of the
prompt.
"""

import json

from .registry import ToolRegistry


def to_openai_tools(registry: ToolRegistry) -> list:
    """Describe registered tools in the shape the OpenAI-compatible API expects."""
    tools = []
    for item in registry.describe():
        properties = {name: {"type": "string", "description": spec}
                      for name, spec in item["parameters"].items()}
        tools.append({"type": "function", "function": {
            "name": item["name"], "description": item["description"],
            "parameters": {"type": "object", "properties": properties,
                           "required": list(properties)}}})
    return tools


class NativeActionModel:
    """Wrap a LangChain chat model so it yields the runtime's action dicts."""

    def __init__(self, chat_model, registry: ToolRegistry):
        self.model = chat_model.bind_tools(to_openai_tools(registry))
        self.registry = registry

    def act(self, messages: list) -> tuple:
        """Return (action, error, mode). Falls back to JSON mode when no tool was called."""
        response = self.model.invoke(messages)
        calls = getattr(response, "tool_calls", None) or []
        if calls:
            call = calls[0]
            return ({"thought": (response.content or "")[:300],
                     "tool": call.get("name"),
                     "args": call.get("args") or {}}, "", "native")
        text = response.content or ""
        from .runtime import parse_action
        action, error = parse_action(text, self.registry.names())
        return action, error, "json_fallback"


def describe_mode(mode: str) -> str:
    return {"native": "provider returned tool_calls",
            "json_fallback": "provider returned text; parsed as JSON"}.get(mode, mode)
