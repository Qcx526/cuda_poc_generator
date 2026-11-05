# -*- coding: utf-8 -*-
"""Candidate-facing client for the trusted service.

The candidate can issue API calls and see their statuses - nothing else. It cannot
read the authoritative trace, and it does not receive the judge token.
"""

import json
import os
import socket

ENDPOINT_ENV = "MOCK_GPU_ENDPOINT"
TOKEN_ENV = "MOCK_GPU_CLIENT_TOKEN"


class RemoteError(RuntimeError):
    pass


def _rpc(payload: dict) -> dict:
    endpoint = os.environ.get(ENDPOINT_ENV)
    token = os.environ.get(TOKEN_ENV)
    if not endpoint or not token:
        raise RemoteError("未配置 MOCK_GPU_ENDPOINT/MOCK_GPU_CLIENT_TOKEN")
    host, _, port = endpoint.rpartition(":")
    request = dict(payload)
    request["token"] = token
    with socket.create_connection((host or "127.0.0.1", int(port)), timeout=10) as sock:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    reply = json.loads(data.decode("utf-8") or "{}")
    if "error" in reply:
        raise RemoteError(reply["error"])
    return reply


def call(op: str, args: dict) -> dict:
    return _rpc({"action": "call", "op": op, "args": args})
