# -*- coding: utf-8 -*-
"""How a kernel-tier probe reaches the driver.

A userland toolchain CVE is triggered by one file handed to one command. A
driver CVE is triggered by a conversation: open a device, ask the driver to
allocate or map something, then ask it to act on a structure the previous call
created. This module gives that conversation a shape the generator can follow
and the harness can check, without pretending to know each driver's ABI.

Two access paths cover the NVIDIA display driver in practice:

  device_ioctl    DeviceIoControl against a named device object
  d3dkmt_escape   D3DKMTEscape, the documented kernel-mode escape hatch, which
                  is how most published GPU driver PoCs reach nvlddmkm

Steps carry their own buffers, so a crafted size and a sane size differ in one
field - which is what makes a control run a control rather than a guess.
"""

import re
from typing import Any, Dict, List, Optional

OP_KINDS = {"open_device", "device_ioctl", "d3dkmt_escape", "close_device",
            "sleep"}

# A step's buffers are described symbolically; the candidate renders them as an
# actual byte layout, because the ABI belongs to the driver, not to the spec.
FIELD_KINDS = {"u8", "u16", "u32", "u64", "ptr", "buffer", "filler"}


class TriggerError(ValueError):
    """The trigger cannot be executed as written."""


def _hex(value: Any) -> str:
    if isinstance(value, str):
        return value
    return "0x%x" % int(value)


def parse_steps(raw: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Validate the step list, keeping the order the spec wrote."""
    if not raw:
        return []
    steps: List[Dict[str, Any]] = []
    for index, step in enumerate(raw):
        if not isinstance(step, dict):
            raise TriggerError("step %d is not an object" % index)
        op = str(step.get("op", "")).strip()
        if op not in OP_KINDS:
            raise TriggerError("step %d: unknown op %r (expected one of %s)"
                               % (index, op, ", ".join(sorted(OP_KINDS))))
        if op in {"device_ioctl", "d3dkmt_escape"} and not step.get("code"):
            raise TriggerError("step %d: %s needs a code" % (index, op))
        if op == "open_device" and not step.get("device"):
            raise TriggerError("step %d: open_device needs a device path" % index)
        steps.append(dict(step, op=op))
    return steps


def fields_are_typed(buffer_spec: Optional[Dict[str, Any]]) -> List[str]:
    """Problems with a buffer description, empty when it is well formed."""
    if not buffer_spec:
        return []
    problems: List[str] = []
    for name, spec in (buffer_spec.get("fields") or {}).items():
        if not isinstance(spec, dict) or "kind" not in spec:
            problems.append("%s has no kind" % name)
        elif spec["kind"] not in FIELD_KINDS:
            problems.append("%s: unknown kind %r" % (name, spec["kind"]))
    return problems


def describe(trigger: Dict[str, Any]) -> str:
    """A compact rendering for the generation prompt."""
    steps = parse_steps(trigger.get("steps"))
    if not steps:
        return ""
    lines = []
    if trigger.get("device"):
        lines.append("device: %s (open as %s)"
                     % (trigger["device"], trigger.get("open_as", "unprivileged")))
    for index, step in enumerate(steps, 1):
        op = step["op"]
        if op == "open_device":
            lines.append("%d. open %s" % (index, step["device"]))
        elif op in {"device_ioctl", "d3dkmt_escape"}:
            detail = "%d. %s code=%s" % (index, op, _hex(step["code"]))
            if step.get("in_size") is not None:
                detail += " in=%s bytes" % _hex(step["in_size"])
            if step.get("out_size") is not None:
                detail += " out=%s bytes" % _hex(step["out_size"])
            if step.get("fields"):
                detail += " fields=%s" % ",".join(step["fields"])
            lines.append(detail)
        elif op == "sleep":
            lines.append("%d. sleep %sms" % (index, step.get("ms", 0)))
        else:
            lines.append("%d. %s" % (index, op))
    if trigger.get("repeat"):
        lines.append("repeat the sequence %s times" % trigger["repeat"])
    return "\n".join(lines)


def variant(trigger: Dict[str, Any], field: str, value: Any) -> Dict[str, Any]:
    """A copy with one field changed - the control for a crafted value.

    Every control must differ in exactly one variable, otherwise a crash cannot
    be attributed to the change that caused it.
    """
    import copy
    clone = copy.deepcopy(trigger)
    for step in clone.get("steps") or []:
        values = step.get("values") or {}
        if field in values:
            values[field] = value
            return clone
    raise TriggerError("no step carries the field %r" % field)


NUMERIC = re.compile(r"^[0-9]+$")


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)
