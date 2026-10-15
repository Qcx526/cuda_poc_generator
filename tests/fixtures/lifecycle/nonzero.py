"""Fixed harmless P2-B resource-gated test program; no CUDA/network."""
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
    control.sendall((json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
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
if gate != b"GO\n":
    raise RuntimeError("trusted parent did not authorize the action gate")
control.settimeout(None)
print("P2-B harmless nonzero exit", flush=True)
control.close()
sys.exit(7)
