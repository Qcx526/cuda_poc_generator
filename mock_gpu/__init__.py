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

from .api import (CONTRACT, STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES,
                  STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
                  STATUS_SUCCESS, close_adapter, create_context, create_device,
                  destroy_context, destroy_device, escape, open_adapter, reset)

__all__ = ["CONTRACT", "STATUS_SUCCESS", "STATUS_INVALID_PARAMETER",
           "STATUS_INVALID_DEVICE_REQUEST", "STATUS_ACCESS_DENIED",
           "STATUS_INSUFFICIENT_RESOURCES", "open_adapter", "create_device",
           "create_context", "escape", "destroy_context", "destroy_device",
           "close_adapter", "reset"]
