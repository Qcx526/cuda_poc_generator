# -*- coding: utf-8 -*-
"""Seed corpus of legal GPU API calls.

Every entry records what was actually executed: the call, its arguments, the
status it returned, and the handle it created or consumed. Two provenances are
kept apart on purpose:

* ``captured`` - produced by running :func:`capture_baseline` on this machine
* ``synthetic`` - written by hand from the headers, never executed

A corpus that mixes the two without saying so is worthless for measuring
coverage, because "we have 20 seeds" would then include seeds that never ran.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

CAPTURED = "captured"
SYNTHETIC = "synthetic"

CORPUS = Path("data/driver/seeds/corpus.json")


@dataclass
class Handle:
    name: str
    kind: str                      # hdc | hAdapter | hDevice | hContext
    created_by: str                # api name
    released_by: str = ""
    value: Optional[int] = None

    @property
    def live(self) -> bool:
        return self.value is not None and not self.released_by


@dataclass
class Seed:
    """One legal call and the state it depends on."""

    seed_id: str
    api: str
    params: Dict[str, object]
    status: Optional[int]
    sequence: List[str] = field(default_factory=list)
    handles: List[Handle] = field(default_factory=list)
    input_digest: str = ""
    provenance: str = CAPTURED
    environment: str = "windows-10 x64 / nvlddmkm 610.47"
    note: str = ""

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["handles"] = [asdict(h) for h in self.handles]
        return payload


def snapshot(handles: List[Handle]) -> List[Handle]:
    """A copy per seed, not a shared list.

    Sharing the objects made every earlier seed inherit later releases, so the
    corpus reported use-after-release on calls that were correct when they ran.
    """
    return [Handle(**asdict(h)) for h in handles]


def digest(payload: object) -> str:
    return hashlib.sha1(json.dumps(payload, sort_keys=True,
                                   ensure_ascii=False).encode("utf-8")).hexdigest()[:16]


def capture_baseline() -> List[Seed]:
    """Run the harmless R0 path and record it as seeds.

    Nothing here sends a private escape body; the point is a reproducible
    baseline, not a trigger attempt.
    """
    import ctypes

    from . import driver_abi as abi

    seeds: List[Seed] = []
    sequence: List[str] = []
    handles: List[Handle] = []

    user32, gdi32 = abi.bind_user32(), abi.bind_gdi32()
    device = abi.DISPLAY_DEVICEW()
    device.cb = ctypes.sizeof(abi.DISPLAY_DEVICEW)
    ok = user32.EnumDisplayDevicesW(None, 0, ctypes.byref(device), 0)
    sequence.append("EnumDisplayDevicesW")
    seeds.append(Seed("display0", "EnumDisplayDevicesW",
                      {"iDevNum": 0, "cb": device.cb}, int(ok == 1),
                      list(sequence), snapshot(handles),
                      digest({"device": device.DeviceName if ok else ""}),
                      CAPTURED, note="device=%s" % (device.DeviceName if ok else "none")))

    gdi = abi.bind_gdi_dc()
    hdc = gdi.CreateDCW("DISPLAY", device.DeviceName, None, None)
    sequence.append("CreateDCW")
    hdc_handle = Handle("hdc", "hdc", "CreateDCW", value=hdc if hdc else None)
    handles.append(hdc_handle)
    seeds.append(Seed("dc0", "CreateDCW", {"driver": "DISPLAY",
                                           "device": device.DeviceName},
                      0 if hdc else -1, list(sequence), snapshot(handles),
                      digest({"device": device.DeviceName}), CAPTURED))
    if not hdc:
        return seeds

    opened = abi.D3DKMT_OPENADAPTERFROMHDC()
    opened.hDc = hdc
    status = gdi32.D3DKMTOpenAdapterFromHdc(ctypes.byref(opened))
    sequence.append("D3DKMTOpenAdapterFromHdc")
    adapter = Handle("hAdapter", "hAdapter", "D3DKMTOpenAdapterFromHdc",
                     value=opened.hAdapter or None)
    handles.append(adapter)
    seeds.append(Seed("adapter_hdc", "D3DKMTOpenAdapterFromHdc",
                      {"hDc": "hdc"}, status, list(sequence), snapshot(handles),
                      digest({"device": device.DeviceName}), CAPTURED,
                      note="luid=%08x:%08x" % (opened.AdapterLuid.LowPart,
                                                opened.AdapterLuid.HighPart & 0xFFFFFFFF)))
    if status != 0:
        gdi.DeleteDC(hdc)
        return seeds

    created = abi.D3DKMT_CREATEDEVICE()
    created.Adapter.hAdapter = opened.hAdapter
    status = gdi32.D3DKMTCreateDevice(ctypes.byref(created))
    sequence.append("D3DKMTCreateDevice")
    dev = Handle("hDevice", "hDevice", "D3DKMTCreateDevice", value=created.hDevice or None)
    handles.append(dev)
    seeds.append(Seed("device0", "D3DKMTCreateDevice", {"hAdapter": "hAdapter"},
                      status, list(sequence), snapshot(handles),
                      digest({"hAdapter": opened.hAdapter}), CAPTURED))

    if status == 0:
        context = abi.D3DKMT_CREATECONTEXT()
        context.hDevice = created.hDevice
        context.NodeOrdinal = 0
        context.EngineAffinity = 0
        status_ctx = gdi32.D3DKMTCreateContext(ctypes.byref(context))
        sequence.append("D3DKMTCreateContext")
        ctx = Handle("hContext", "hContext", "D3DKMTCreateContext",
                     value=context.hContext or None)
        handles.append(ctx)
        seeds.append(Seed("context0", "D3DKMTCreateContext",
                          {"hDevice": "hDevice", "NodeOrdinal": 0, "EngineAffinity": 0},
                          status_ctx, list(sequence), snapshot(handles),
                          digest({"hDevice": created.hDevice}), CAPTURED))

        if status_ctx == 0:
            destroyed = gdi32.D3DKMTDestroyContext(
                ctypes.byref(abi.D3DKMT_DESTROYCONTEXT(context.hContext)))
            ctx.released_by = "D3DKMTDestroyContext"
            sequence.append("D3DKMTDestroyContext")
            seeds.append(Seed("destroy_context0", "D3DKMTDestroyContext",
                              {"hContext": "hContext"}, destroyed, list(sequence),
                              snapshot(handles), digest({"hContext": context.hContext}), CAPTURED))

    destroyed = gdi32.D3DKMTDestroyDevice(
        ctypes.byref(abi.D3DKMT_DESTROYDEVICE(created.hDevice)))
    dev.released_by = "D3DKMTDestroyDevice"
    sequence.append("D3DKMTDestroyDevice")
    seeds.append(Seed("destroy_device0", "D3DKMTDestroyDevice", {"hDevice": "hDevice"},
                      destroyed, list(sequence), snapshot(handles),
                      digest({"hDevice": created.hDevice}), CAPTURED))

    gdi32.D3DKMTCloseAdapter(ctypes.byref(abi.D3DKMT_CLOSEADAPTER(opened.hAdapter)))
    adapter.released_by = "D3DKMTCloseAdapter"
    delete_status = gdi.DeleteDC(hdc)
    hdc_handle.released_by = "DeleteDC"
    sequence += ["D3DKMTCloseAdapter", "DeleteDC"]
    seeds.append(Seed("teardown0", "DeleteDC", {"hdc": "hdc"}, delete_status, list(sequence),
                      snapshot(handles), digest({"hdc": hdc}), CAPTURED))
    return seeds


def synthetic_escape() -> Seed:
    """A legal escape call shape, never executed.

    It is listed separately so nobody mistakes it for captured behaviour: the
    private body is deliberately empty, because inventing one is exactly what
    this project forbids.
    """
    # status is None, not 0: a seed that never ran must not look like a success.
    return Seed("escape_shape", "D3DKMTEscape",
                {"Type": 0, "Flags": 0, "pPrivateDriverData": None,
                 "PrivateDriverDataSize": 0, "hContext": 0},
                None, ["D3DKMTEscape"], [], digest({"Type": 0, "Flags": 0}),
                SYNTHETIC, note="shape only, not executed")


VERIFIED_LEGAL = "VERIFIED_LEGAL"            # ran here, returned success
STRUCTURE_ONLY = "STRUCTURE_CHECKED_ONLY"    # type/layout checked, never run
SYNTHETIC_UNVERIFIED = "SYNTHETIC_UNVERIFIED"  # written by hand, unknown validity
OFFLINE_ONLY = "OFFLINE_EVALUATION_ONLY"     # must not run on this host


# Win32 BOOL APIs succeed on non-zero; D3DKMT ones succeed on STATUS_SUCCESS (0).
BOOL_APIS = {"EnumDisplayDevicesW", "DeleteDC"}


def succeeded(seed: Seed) -> bool:
    if seed.status is None:
        return False
    if seed.api in BOOL_APIS:
        return seed.status != 0
    return seed.status == 0


def eligibility(seed: Seed, runnable_on_host: bool = True) -> str:
    """Which of the five states a seed is in.

    The distinction that matters: entering the mutation context does not grant a
    seed the right to be executed. A synthetic shape stays synthetic.
    """
    if seed.provenance == SYNTHETIC:
        return SYNTHETIC_UNVERIFIED if runnable_on_host else OFFLINE_ONLY
    if succeeded(seed) and seed.handles:
        return VERIFIED_LEGAL
    if succeeded(seed):
        return STRUCTURE_ONLY
    return OFFLINE_ONLY


def save(seeds: List[Seed], path: Path = CORPUS) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for seed in seeds:
        record = seed.to_dict()
        record["eligibility"] = eligibility(seed)
        record["executed"] = seed.status is not None
        records.append(record)
    payload = {"seeds": records,
               "counts": {CAPTURED: sum(1 for s in seeds if s.provenance == CAPTURED),
                          SYNTHETIC: sum(1 for s in seeds if s.provenance == SYNTHETIC)}}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load(path: Path = CORPUS) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lifecycle_problems(seeds: List[Seed]) -> List[str]:
    """Flag use-after-release, but not the calls that do the releasing.

    ``D3DKMTDestroyContext`` takes a context as input and releases it in the same
    call; counting that as a violation would make every teardown seed a defect.
    """
    problems: List[str] = []
    for seed in seeds:
        for handle in seed.handles:
            used = any(value == handle.name for value in seed.params.values())
            if used and handle.released_by and handle.released_by != seed.api:
                problems.append("%s used after release in %s" % (handle.name, seed.seed_id))
    # Release counts only make sense on the final timeline; per-seed snapshots
    # were taken at different moments and would each report the same release.
    if seeds:
        final: Dict[str, str] = {}
        for handle in seeds[-1].handles:
            if not handle.released_by:
                continue
            if handle.name in final:
                problems.append("%s released twice" % handle.name)
            final[handle.name] = handle.released_by
    return problems


if __name__ == "__main__":
    import sys

    if "--capture" in sys.argv:
        captured = capture_baseline() + [synthetic_escape()]
        target = save(captured)
        print("saved %d seeds -> %s" % (len(captured), target))
        issues = lifecycle_problems(captured)
        print("lifecycle issues:", issues or "none")
    else:
        data = load()
        print(json.dumps(data["counts"], ensure_ascii=False))
