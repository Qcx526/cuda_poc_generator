"""A tiny user-mode GPU driver stand-in with two planted, harmless flaws.

This is a *benchmark*, not a GPU driver: no kernel, no hardware, no real escape
protocol. Its only job is to give the PoC generator a target whose behaviour is
knowable, so "did the model reach and trigger the bug" can be answered objectively.

The state machine mirrors the shapes already used against the real driver
(adapter -> device -> context -> escape), so the generated programs stay
structurally similar to the NVIDIA ones.

Ground truth lives in ``_oracle`` and is written to a file the harness reads; the
contract the model receives (``CONTRACT``) says nothing about where the flaws are.
"""

import os as _os

from .api import (CONTRACT, STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES,
                  STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
                  STATUS_SUCCESS)
from .api import close_adapter as _local_close_adapter
from .api import create_context as _local_create_context
from .api import create_device as _local_create_device
from .api import destroy_context as _local_destroy_context
from .api import destroy_device as _local_destroy_device
from .api import escape as _local_escape
from .api import open_adapter as _local_open_adapter
from .api import reset as _local_reset
from .client import ENDPOINT_ENV as _ENDPOINT_ENV
from .client import call as _rpc


def _remote() -> bool:
    """True when a trusted service is configured; then nothing runs locally."""
    return bool(_os.environ.get(_ENDPOINT_ENV))


def open_adapter(hint: str = ""):
    if _remote():
        reply = _rpc("open_adapter", {"hint": hint})
        return reply["status"], reply.get("handle") or 0
    return _local_open_adapter(hint)


def create_device(hAdapter: int):
    if _remote():
        reply = _rpc("create_device", {"hAdapter": int(hAdapter)})
        return reply["status"], reply.get("handle") or 0
    return _local_create_device(hAdapter)


def create_context(hDevice: int, node: int = 0):
    if _remote():
        reply = _rpc("create_context", {"hDevice": int(hDevice), "node": int(node)})
        return reply["status"], reply.get("handle") or 0
    return _local_create_context(hDevice, node)


def escape(hAdapter: int, hDevice: int, hContext: int, type_: int, flags: int,
           payload: bytes) -> int:
    if _remote():
        return _rpc("escape", {"hAdapter": int(hAdapter), "hDevice": int(hDevice),
                               "hContext": int(hContext), "type": int(type_),
                               "flags": int(flags), "payload": bytes(payload).hex()})["status"]
    return _local_escape(hAdapter, hDevice, hContext, type_, flags, payload)


def destroy_context(hContext: int) -> int:
    if _remote():
        return _rpc("destroy_context", {"hContext": int(hContext)})["status"]
    return _local_destroy_context(hContext)


def destroy_device(hDevice: int) -> int:
    if _remote():
        return _rpc("destroy_device", {"hDevice": int(hDevice)})["status"]
    return _local_destroy_device(hDevice)


def close_adapter(hAdapter: int) -> int:
    if _remote():
        return _rpc("close_adapter", {"hAdapter": int(hAdapter)})["status"]
    return _local_close_adapter(hAdapter)


def reset() -> None:
    if _remote():
        return None
    return _local_reset()

__all__ = ["CONTRACT", "STATUS_SUCCESS", "STATUS_INVALID_PARAMETER",
           "STATUS_INVALID_DEVICE_REQUEST", "STATUS_ACCESS_DENIED",
           "STATUS_INSUFFICIENT_RESOURCES", "open_adapter", "create_device",
           "create_context", "escape", "destroy_context", "destroy_device",
           "close_adapter", "reset"]
