# -*- coding: utf-8 -*-
"""ctypes binding for the native twin, and a parity check against the Python mock.

Parity is not a formality here: if the two implementations disagree, every metric
collected on either one is meaningless. The check runs the same call scripts on
both and compares statuses *and* which flaw fired.
"""

import ctypes
import os
from ctypes import POINTER, c_char_p, c_int, c_ubyte
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

DLL = Path(__file__).resolve().parent / "mock_gpu.dll"

TRIGGER_AUTHZ = 1
TRIGGER_OOB = 2


class _Binding:
    def __init__(self, path: Path = DLL):
        if not Path(path).is_file():
            raise FileNotFoundError("mock_gpu.dll 未构建: %s" % path)
        self.lib = ctypes.CDLL(str(path))
        self.lib.MockOpenAdapter.argtypes = [POINTER(c_int)]
        self.lib.MockOpenAdapter.restype = c_int
        self.lib.MockCreateDevice.argtypes = [c_int, POINTER(c_int)]
        self.lib.MockCreateDevice.restype = c_int
        self.lib.MockCreateContext.argtypes = [c_int, c_int, POINTER(c_int)]
        self.lib.MockCreateContext.restype = c_int
        self.lib.MockEscape.argtypes = [c_int, c_int, c_int, c_int, c_int, c_char_p, c_int]
        self.lib.MockEscape.restype = c_int
        for name in ("MockDestroyContext", "MockDestroyDevice", "MockCloseAdapter"):
            getattr(self.lib, name).argtypes = [c_int]
            getattr(self.lib, name).restype = c_int
        self.lib.MockReset.argtypes = []
        self.lib.MockReset.restype = None
        self.lib.MockTriggerCount.argtypes = []
        self.lib.MockTriggerCount.restype = c_int
        self.lib.MockTriggerAt.argtypes = [c_int]
        self.lib.MockTriggerAt.restype = c_int

    def reset(self) -> None:
        self.lib.MockReset()

    def open_adapter(self) -> Tuple[int, int]:
        out = c_int(0)
        status = self.lib.MockOpenAdapter(ctypes.byref(out))
        return status, out.value

    def create_device(self, adapter: int) -> Tuple[int, int]:
        out = c_int(0)
        status = self.lib.MockCreateDevice(adapter, ctypes.byref(out))
        return status, out.value

    def create_context(self, device: int, node: int = 0) -> Tuple[int, int]:
        out = c_int(0)
        status = self.lib.MockCreateContext(device, node, ctypes.byref(out))
        return status, out.value

    def escape(self, adapter: int, device: int, context: int, type_: int,
               flags: int, payload: bytes) -> int:
        return self.lib.MockEscape(adapter, device, context, type_, flags,
                                   payload, len(payload))

    def triggers(self) -> List[int]:
        count = self.lib.MockTriggerCount()
        return [self.lib.MockTriggerAt(i) for i in range(count)]


def load(path: Path = DLL) -> _Binding:
    return _Binding(path)


@dataclass
class Step:
    name: str
    args: tuple


def script_authz_bypass() -> List[Step]:
    return [Step("open", ()), Step("device", (0,)), Step("context", (0,)),
            Step("device", (0,)), Step("escape_cross", ())]


def run_script(binding, steps: List[Step]) -> Tuple[List[int], List[int]]:
    """Execute a script, returning statuses and the flaw kinds that fired."""
    binding.reset()
    handles = {"adapter": 0, "device": 0, "context": 0, "device2": 0}
    statuses: List[int] = []
    for step in steps:
        if step.name == "open":
            status, handles["adapter"] = binding.open_adapter()
        elif step.name == "device":
            status, handles["device"] = binding.create_device(handles["adapter"])
        elif step.name == "device2":
            status, handles["device2"] = binding.create_device(handles["adapter"])
        elif step.name == "context":
            status, handles["context"] = binding.create_context(handles["device"])
        elif step.name == "escape_cross":
            status = binding.escape(handles["adapter"], handles["device2"],
                                    handles["context"], 0, 0x2, b"")
        elif step.name == "escape_normal":
            status = binding.escape(handles["adapter"], handles["device"],
                                    handles["context"], 0, 0, b"")
        elif step.name == "escape_oob":
            body = b"\x00" * 4
            payload = (len(body) + 1).to_bytes(4, "little") + body
            status = binding.escape(handles["adapter"], handles["device"],
                                    handles["context"], 3, 0, payload)
        else:
            raise ValueError("unknown step %s" % step.name)
        statuses.append(status)
    return statuses, binding.triggers()


def python_triggers(steps: List[Step]) -> Tuple[List[int], List[int]]:
    """Same script against the Python mock, with triggers read from its oracle."""
    import tempfile

    import mock_gpu as gpu
    from mock_gpu import _oracle

    handle, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(handle)
    previous = os.environ.get(_oracle.PATH_ENV)
    os.environ[_oracle.PATH_ENV] = path
    try:
        gpu.reset()
        handles = {"adapter": 0, "device": 0, "context": 0, "device2": 0}
        statuses: List[int] = []
        for step in steps:
            if step.name == "open":
                status, handles["adapter"] = gpu.open_adapter()
            elif step.name == "device":
                status, handles["device"] = gpu.create_device(handles["adapter"])
            elif step.name == "device2":
                status, handles["device2"] = gpu.create_device(handles["adapter"])
            elif step.name == "context":
                status, handles["context"] = gpu.create_context(handles["device"])
            elif step.name == "escape_cross":
                status = gpu.escape(handles["adapter"], handles["device2"],
                                    handles["context"], 0, 0x2, b"")
            elif step.name == "escape_normal":
                status = gpu.escape(handles["adapter"], handles["device"],
                                    handles["context"], 0, 0, b"")
            elif step.name == "escape_oob":
                body = b"\x00" * 4
                payload = (len(body) + 1).to_bytes(4, "little") + body
                status = gpu.escape(handles["adapter"], handles["device"],
                                    handles["context"], 3, 0, payload)
            else:
                raise ValueError("unknown step %s" % step.name)
            statuses.append(status)
        kinds = [TRIGGER_AUTHZ if item["flaw"] == "AUTHZ_BYPASS" else TRIGGER_OOB
                 for item in _oracle.read(path)]
    finally:
        if previous is None:
            os.environ.pop(_oracle.PATH_ENV, None)
        else:
            os.environ[_oracle.PATH_ENV] = previous
        Path(path).unlink(missing_ok=True)
    return statuses, kinds
