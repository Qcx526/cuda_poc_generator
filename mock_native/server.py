# -*- coding: utf-8 -*-
"""Trusted execution service: the only process that touches the DLL.

Why a separate process: the candidate must be able to *call* the API without being
able to *write* the authoritative record. A thread inside the candidate's process
cannot offer that, because the candidate could import the recorder and lie.

Two tokens, deliberately different:

* client token - lets the candidate issue API calls;
* judge token  - lets the runner read the trace and the verdict.

Neither token is ever written to disk. Both are printed once on stdout, which the
runner captures through a pipe; a sibling process cannot read another process's
pipe buffer. This removes the previous secrets.json, which was readable by the
candidate because it ran under the same identity.

Residual limitation, stated rather than hidden: the candidate still runs as the
same OS user, so it can read the repository (including mock_gpu.c) and the DLL
itself. Strong isolation needs a separate user or a sandboxed container.
"""

import argparse
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from binding import TRIGGER_AUTHZ, TRIGGER_OOB, _Binding  # noqa: E402


class Session:
    """Owns the loaded DLL, the authoritative trace and the trigger list."""

    def __init__(self, dll_source: Path):
        self.workdir = Path(tempfile.mkdtemp(prefix="mockrun_"))
        self.dll_path = self.workdir / ("m_%s.dll" % secrets.token_hex(8))
        shutil.copy2(dll_source, self.dll_path)
        self.binding = _Binding(self.dll_path)
        self.binding.reset()
        self.trace = []
        # Shadow bookkeeping, so the verdict can say whether the objects an escape
        # referenced were actually alive - not just that some call happened.
        self.adapters = set()
        self.devices = {}
        self.contexts = {}
        self.lock = threading.Lock()
        self.sha256 = hashlib.sha256(self.dll_path.read_bytes()).hexdigest()

    def call(self, op: str, args: dict) -> dict:
        with self.lock:
            return self._call(op, args)

    def _call(self, op: str, args: dict) -> dict:
        b = self.binding
        if op == "open_adapter":
            status, handle = b.open_adapter()
            if status == 0:
                self.adapters.add(handle)
            record = {"op": op, "status": status, "handle": handle}
        elif op == "create_device":
            parent = int(args["hAdapter"])
            status, handle = b.create_device(parent)
            if status == 0:
                self.devices[handle] = parent
            record = {"op": op, "args": {"hAdapter": parent},
                      "status": status, "handle": handle}
        elif op == "create_context":
            device = int(args["hDevice"])
            status, handle = b.create_context(device, int(args.get("node", 0)))
            if status == 0:
                self.contexts[handle] = device
            record = {"op": op, "args": {"hDevice": device,
                                         "node": int(args.get("node", 0))},
                      "status": status, "handle": handle}
        elif op == "escape":
            payload = bytes.fromhex(args.get("payload", ""))
            adapter, device = int(args["hAdapter"]), int(args["hDevice"])
            context = int(args["hContext"])
            # Liveness only. Ownership mismatch is the planted flaw, not an invalid
            # setup: a triggering call is *expected* to use a foreign context.
            objects_valid = (adapter in self.adapters and device in self.devices
                             and context in self.contexts)
            status = b.escape(adapter, device, context, int(args["type"]),
                              int(args["flags"]), payload)
            record = {"op": op, "args": {"hAdapter": adapter, "hDevice": device,
                                         "hContext": context,
                                         "type": int(args["type"]),
                                         "flags": int(args["flags"]),
                                         "payload_len": len(payload)},
                      "status": status, "objects_valid": objects_valid}
        elif op == "destroy_context":
            status = b.lib.MockDestroyContext(int(args["hContext"]))
            self.contexts.pop(int(args["hContext"]), None)
            record = {"op": op, "args": {"hContext": int(args["hContext"])}, "status": status}
        elif op == "destroy_device":
            status = b.lib.MockDestroyDevice(int(args["hDevice"]))
            self.devices.pop(int(args["hDevice"]), None)
            record = {"op": op, "args": {"hDevice": int(args["hDevice"])}, "status": status}
        elif op == "close_adapter":
            status = b.lib.MockCloseAdapter(int(args["hAdapter"]))
            self.adapters.discard(int(args["hAdapter"]))
            record = {"op": op, "args": {"hAdapter": int(args["hAdapter"])}, "status": status}
        else:
            return {"error": "unknown_op", "status": 0xC000000D}

        self.trace.append(record)
        return {"status": status, "handle": record.get("handle")}

    def verdict(self) -> dict:
        with self.lock:
            kinds = self.binding.triggers()
        names = [("AUTHZ_BYPASS" if kind == TRIGGER_AUTHZ else "OOB_READ") for kind in kinds]
        return {"triggered": bool(kinds), "flaws": sorted(set(names)),
                "trigger_count": len(kinds), "dll_sha256": self.sha256,
                "trace_len": len(self.trace),
                "facts": self.facts(),
                "trace": self.trace[-500:]}

    def facts(self) -> dict:
        """Five separate facts, so 'some call happened' cannot pass as a full PoC."""
        escapes = [item for item in self.trace if item["op"] == "escape"]
        return {
            "native_api_called": len(self.trace) > 0,
            "valid_objects_built": bool(self.contexts) or any(
                item.get("status") == 0 for item in self.trace
                if item["op"] == "create_context"),
            "escape_called": bool(escapes),
            "escape_with_valid_objects": any(e.get("objects_valid") for e in escapes),
            "oracle_confirmed": bool(self.binding.triggers()),
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for line in self.rfile:
            try:
                request = json.loads(line.decode("utf-8"))
            except ValueError:
                self.wfile.write(b'{"error":"bad_json"}\n')
                continue
            reply = self.dispatch(request)
            self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))

    def dispatch(self, request: dict) -> dict:
        server = self.server
        token = request.get("token", "")
        if request.get("action") == "verdict":
            if not secrets.compare_digest(token, server.judge_token):
                return {"error": "forbidden"}
            return server.session.verdict()
        if not secrets.compare_digest(token, server.client_token):
            return {"error": "forbidden"}
        if request.get("action") == "trace":
            # Clients may not read the authoritative trace; only the judge can.
            return {"error": "forbidden"}
        return server.session.call(request.get("op", ""), request.get("args", {}) or {})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(dll: Path) -> None:
    session = Session(dll)
    server = Server(("127.0.0.1", 0), Handler)
    server.session = session
    server.client_token = secrets.token_hex(16)
    server.judge_token = secrets.token_hex(16)
    port = server.server_address[1]
    # One line, once, to the runner's pipe. Never to a file.
    print(json.dumps({"port": port, "client_token": server.client_token,
                      "judge_token": server.judge_token,
                      "dll_sha256": session.sha256}), flush=True)
    try:
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        session.cleanup()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dll", required=True)
    args = parser.parse_args(argv)
    serve(Path(args.dll))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
