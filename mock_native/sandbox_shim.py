"""Remote-only mock_gpu shim, copied into the candidate sandbox by the runner.

It contains no driver logic and no local fallback: if the service is unreachable the
call fails, rather than quietly running a Python implementation behind the scenes.

``__CONTRACT__`` is replaced with the public contract text at copy time.
"""

import json
import os
import socket

CONTRACT = __CONTRACT__

STATUS_SUCCESS = 0
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
STATUS_ACCESS_DENIED = 0xC0000022

ENDPOINT_ENV = "MOCK_GPU_ENDPOINT"
TOKEN_ENV = "MOCK_GPU_CLIENT_TOKEN"


def _rpc(op, args):
    endpoint = os.environ[ENDPOINT_ENV]
    host, _, port = endpoint.rpartition(":")
    request = {"action": "call", "op": op, "args": args,
               "token": os.environ[TOKEN_ENV]}
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        stream = sock.makefile("rwb")
        stream.write((json.dumps(request) + "\n").encode("utf-8"))
        stream.flush()
        line = stream.readline()
    reply = json.loads(line.decode("utf-8") or "{}")
    if "error" in reply:
        raise RuntimeError(reply["error"])
    return reply


def open_adapter(hint=""):
    reply = _rpc("open_adapter", {"hint": hint})
    return reply["status"], reply.get("handle") or 0


def create_device(hAdapter):
    reply = _rpc("create_device", {"hAdapter": int(hAdapter)})
    return reply["status"], reply.get("handle") or 0


def create_context(hDevice, node=0):
    reply = _rpc("create_context", {"hDevice": int(hDevice), "node": int(node)})
    return reply["status"], reply.get("handle") or 0


def escape(hAdapter, hDevice, hContext, type_, flags, payload):
    reply = _rpc("escape", {"hAdapter": int(hAdapter), "hDevice": int(hDevice),
                            "hContext": int(hContext), "type": int(type_),
                            "flags": int(flags),
                            "payload": bytes(payload).hex()})
    return reply["status"]


def destroy_context(hContext):
    return _rpc("destroy_context", {"hContext": int(hContext)})["status"]


def destroy_device(hDevice):
    return _rpc("destroy_device", {"hDevice": int(hDevice)})["status"]


def close_adapter(hAdapter):
    return _rpc("close_adapter", {"hAdapter": int(hAdapter)})["status"]


def reset():
    return None
