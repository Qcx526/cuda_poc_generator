# -*- coding: utf-8 -*-
"""Reach the kernel driver through a real DRS session, from Python.

The C caller existed because ctypes turns an access violation into an exception.
That matters when the interesting result is a crash; it does not matter when the
interesting result is a status code, and most of the work here is establishing
that a call is reachable at all. A batch that returns NvAPI_OK for benign input
is the prerequisite for every mutation after it.

The handle chain is the point: initialize, create a session, load settings, take
the base profile, and only then call the target. A placeholder handle is rejected
before any struct is parsed, which is why earlier surveys were all rejections.

  python -m tools.driver.drs_probe --fn 0x61cd6fd6            # benign baseline
  python -m tools.driver.drs_probe --fn 0x61cd6fd6 --at 0 --value 0xff
"""

import argparse
import ctypes
from typing import Optional

NVAPI_INITIALIZE = 0x0150E828
DRS_CREATE_SESSION = 0x0694D52E
DRS_LOAD_SETTINGS = 0x375DBD6B
DRS_GET_BASE_PROFILE = 0xDA8466A0
DRS_GET_CURRENT_GLOBAL_PROFILE = 0x617BFF9F


class Nvapi:
    """A driver session, and the ability to call one function with a struct."""

    def __init__(self) -> None:
        self.dll = ctypes.WinDLL("nvapi64.dll")
        self.query = self.dll.nvapi_QueryInterface
        self.query.argtypes = [ctypes.c_uint]
        self.query.restype = ctypes.c_void_p
        self.session: Optional[int] = None
        self.profile: Optional[int] = None
        self.steps = {}

    def _fn(self, ident: int, argtypes):
        address = self.query(ident)
        if not address:
            return None
        proto = ctypes.WINFUNCTYPE(ctypes.c_int, *argtypes)
        return proto(address)

    def open(self) -> dict:
        """Establish the chain; every step's status is kept for the report."""
        init = self._fn(NVAPI_INITIALIZE, [])
        self.steps["init"] = init() if init else None

        handle = ctypes.c_void_p()
        create = self._fn(DRS_CREATE_SESSION, [ctypes.POINTER(ctypes.c_void_p)])
        self.steps["session"] = create(ctypes.byref(handle)) if create else None
        self.session = handle.value

        load = self._fn(DRS_LOAD_SETTINGS, [ctypes.c_void_p])
        self.steps["load"] = load(self.session) if (load and self.session) else None

        prof = ctypes.c_void_p()
        base = self._fn(DRS_GET_BASE_PROFILE,
                        [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
        self.steps["profile"] = base(self.session, ctypes.byref(prof)) \
            if (base and self.session) else None
        if not self.steps.get("profile") and self.session:
            current = self._fn(DRS_GET_CURRENT_GLOBAL_PROFILE,
                               [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
            if current:
                self.steps["profile"] = current(self.session, ctypes.byref(prof))
        self.profile = prof.value
        return self.steps

    def probe_version(self, ident: int, version: int, claim: int, size: int = 4096) -> Optional[int]:
        """Call with an explicit size|version dword, to find the one accepted.

        Every NVAPI struct opens with a packed dword the driver validates before
        it reads anything else, so a wrong guess is rejected cheaply. Searching it
        is therefore safe and fast - unlike guessing at the fields behind it.
        """
        if not (self.session and self.profile):
            return None
        buf = (ctypes.c_ubyte * size)()
        header = ctypes.c_uint32((claim & 0xFFFF) | ((version & 0xFFFF) << 16))
        ctypes.memmove(buf, ctypes.byref(header), 4)
        fn = self._fn(ident, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
        if not fn:
            return None
        return fn(self.session, self.profile, buf)

    def call(self, ident: int, offset: int, value: int, size: int = 4096) -> dict:
        """One struct-taking call, with one dword optionally overwritten."""
        if not (self.session and self.profile):
            return {"call": None, "reason": "handle chain incomplete"}
        buf = (ctypes.c_ubyte * size)()
        # NVAPI packs size and version into the first dword of most structs.
        ctypes.memmove(buf, ctypes.byref(ctypes.c_uint32((size & 0xFFFF) | (1 << 16))), 4)
        if 0 <= offset <= size - 4:
            ctypes.memmove(ctypes.byref(buf, offset),
                           ctypes.byref(ctypes.c_uint32(value & 0xFFFFFFFF)), 4)
        fn = self._fn(ident, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
        if not fn:
            return {"call": None, "reason": "not exported by this driver"}
        return {"call": fn(self.session, self.profile, buf)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="one DRS probe through a real session")
    parser.add_argument("--fn", required=True, help="target function id, hex")
    parser.add_argument("--at", type=int, default=-1, help="offset of the dword to set")
    parser.add_argument("--value", type=lambda text: int(text, 0), default=0)
    parser.add_argument("--bytes", type=int, default=4096)
    parser.add_argument("--calibrate", action="store_true",
                        help="search the size|version dword the driver accepts")
    args = parser.parse_args(argv)

    nv = Nvapi()
    steps = nv.open()
    if args.calibrate:
        print("chain init=%(init)s session=%(session)s load=%(load)s profile=%(profile)s"
              % {"init": steps.get("init"), "session": steps.get("session"),
                 "load": steps.get("load"), "profile": steps.get("profile")})
        target = int(args.fn, 0)
        claims = (128, 256, 260, 264, 400, 404, 408, 412, 512, 1024, 4096)
        for version in (1, 2, 3, 4):
            row = []
            for claim in claims:
                status = nv.probe_version(target, version, claim, args.bytes)
                row.append("%d:%d" % (claim, status) if status is not None else "?")
            print("ver=%d  %s" % (version, "  ".join(row)))
        return 0
    result = nv.call(int(args.fn, 0), args.at, args.value, args.bytes)
    print("chain init=%(init)s session=%(session)s load=%(load)s profile=%(profile)s"
          % {"init": steps.get("init"), "session": steps.get("session"),
             "load": steps.get("load"), "profile": steps.get("profile")})
    print("call  fn=%s at=%d value=0x%x -> %s%s"
          % (args.fn, args.at, args.value, result.get("call"),
             (" (%s)" % result["reason"]) if result.get("reason") else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
