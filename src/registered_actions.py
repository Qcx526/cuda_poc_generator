"""Reviewed harmless programs only; no request can supply source or argv.

Registry changes require a source-code review and normal repository change.
The control socket is private to the trusted parent and never an LLM channel.
"""

from dataclasses import dataclass
import hashlib
from types import MappingProxyType


_GUARD = b'''"""Fixed harmless P2-B resource-gated test program; no CUDA/network."""
import ctypes
import json
import os
import resource
import signal
import socket
import sys
import time

config = json.loads(sys.stdin.buffer.read(4097))
if set(config) != {"request_id", "nonce", "cpu_seconds", "memory_bytes", "control_fd", "parent_pid"}:
    raise ValueError("invalid fixed action configuration")
if (type(config["cpu_seconds"]) is not int or not 1 <= config["cpu_seconds"] <= 30
        or type(config["memory_bytes"]) is not int
        or not 67108864 <= config["memory_bytes"] <= 1073741824
        or type(config["control_fd"]) is not int or config["control_fd"] < 3
        or type(config["parent_pid"]) is not int or config["parent_pid"] < 1):
    raise ValueError("invalid fixed action resource bounds")
for name in ("request_id", "nonce"):
    if (not isinstance(config[name], str) or len(config[name]) != 32
            or any(char not in "0123456789abcdef" for char in config[name])):
        raise ValueError("invalid fixed action identity")

def arm_parent_death_signal(expected_parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")
    actual = ctypes.c_int()
    if libc.prctl(2, ctypes.byref(actual), 0, 0, 0) != 0 or actual.value != signal.SIGKILL:
        raise RuntimeError("parent-death signal could not be confirmed")
    if os.getppid() != expected_parent:
        raise RuntimeError("trusted parent changed before parent-death signal was armed")
    return actual.value

parent_death_signal = arm_parent_death_signal(config["parent_pid"])
resource.setrlimit(resource.RLIMIT_CPU, (config["cpu_seconds"],) * 2)
resource.setrlimit(resource.RLIMIT_AS, (config["memory_bytes"],) * 2)
if (resource.getrlimit(resource.RLIMIT_CPU) != (config["cpu_seconds"],) * 2
        or resource.getrlimit(resource.RLIMIT_AS) != (config["memory_bytes"],) * 2):
    raise RuntimeError("resource bounds were not applied")
control = socket.socket(fileno=config["control_fd"])
def notify(message):
    message.update(request_id=config["request_id"], nonce=config["nonce"])
    control.sendall((json.dumps(message, sort_keys=True, separators=(",", ":")) + "\\n").encode("utf-8"))
with open("/proc/self/stat", "r", encoding="ascii") as stream:
    start_ticks = int(stream.read().rsplit(") ", 1)[1].split()[19])
notify({"event": "RESOURCE_READY", "pid": os.getpid(), "pgid": os.getpgrp(),
        "session_id": os.getsid(0), "start_ticks": start_ticks,
        "cpu_seconds": config["cpu_seconds"], "memory_bytes": config["memory_bytes"],
        "parent_pid": config["parent_pid"], "parent_death_signal": parent_death_signal})
control.settimeout(5)
gate = b""
while len(gate) < 3:
    block = control.recv(3 - len(gate))
    if not block:
        break
    gate += block
if gate != b"GO\\n":
    raise RuntimeError("trusted parent did not authorize the action gate")
control.settimeout(None)
'''


@dataclass(frozen=True)
class RegisteredAction:
    fixture_id: str
    source: bytes
    relative_path: str
    description: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source).hexdigest()


_SPECS = (
    ("p2b-normal-v1", "normal.py", "fixed harmless normal exit",
     b'print("P2-B harmless normal exit", flush=True)\ncontrol.close()\n'),
    ("p2b-nonzero-v1", "nonzero.py", "fixed harmless exit code seven",
     b'print("P2-B harmless nonzero exit", flush=True)\ncontrol.close()\nsys.exit(7)\n'),
    ("p2b-timeout-v1", "timeout.py", "fixed harmless thirty-second sleep",
     b'print("P2-B harmless timeout wait", flush=True)\ncontrol.close()\ntime.sleep(30)\n'),
    ("p2b-output-v1", "output.py", "fixed bounded eight-MiB output producer",
     b'control.close()\nfor _ in range(1024):\n    sys.stdout.buffer.write(b"x" * 8192)\n    sys.stdout.buffer.flush()\n'),
    ("p2b-child-cleanup-v1", "child_cleanup.py", "fixed same-process-group child sleep",
     b'fork_parent = os.getpid()\nchild = os.fork()\nif child == 0:\n    arm_parent_death_signal(fork_parent)\n    control.close()\n    time.sleep(30)\n    os._exit(0)\nnotify({"event": "CHILD_CREATED", "pid": child})\nprint("P2-B harmless child created", flush=True)\ncontrol.close()\ntime.sleep(30)\n'),
    ("p2b-cpu-limit-v1", "cpu_limit.py", "fixed harmless CPU-bound integer loop",
     b'print("P2-B harmless CPU limit loop", flush=True)\ncontrol.close()\nwhile True:\n    value = 1 + 1\n'),
)

REGISTERED_ACTIONS = MappingProxyType({
    fixture_id: RegisteredAction(fixture_id, _GUARD + body,
                                 "tests/fixtures/lifecycle/" + filename, description)
    for fixture_id, filename, description, body in _SPECS
})


def get_registered_action(fixture_id: str) -> RegisteredAction:
    """Exact immutable lookup; no aliases, file loading or untrusted fallback."""
    if type(fixture_id) is not str or fixture_id not in REGISTERED_ACTIONS:
        raise ValueError("unregistered harmless action")
    return REGISTERED_ACTIONS[fixture_id]
