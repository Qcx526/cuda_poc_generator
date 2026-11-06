# -*- coding: utf-8 -*-
"""Collect the Step 2 baseline evidence in one file.

Runs the normal D3D11 workload, then asks D3DKMT to open the same adapter by LUID and
by HDC, so the two identities can be compared instead of assumed equal.
"""

import ctypes
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src import driver_abi as abi          # noqa: E402
from tools.driver.f8s2r1_revalidate import close_adapter, loaded_kernel_module  # noqa: E402

EXE = ROOT / "tools" / "driver" / "d3d11_baseline.exe"
DRIVER = Path("C:/Windows/System32/DriverStore/FileRepository/"
              "nv_dispi.inf_amd64_c8bc842500fab35b/nvlddmkm.sys")


class D3DKMT_OPENADAPTERFROMLUID(ctypes.Structure):
    _fields_ = [("Luid", ctypes.c_uint64), ("hAdapter", ctypes.c_uint32)]


def _gdi32():
    lib = ctypes.WinDLL("gdi32", use_last_error=True)
    lib.D3DKMTOpenAdapterFromLuid.argtypes = [ctypes.POINTER(D3DKMT_OPENADAPTERFROMLUID)]
    lib.D3DKMTOpenAdapterFromLuid.restype = ctypes.c_int32
    return lib


def open_by_luid(low: int, high: int) -> dict:
    lib = _gdi32()
    request = D3DKMT_OPENADAPTERFROMLUID(Luid=(high << 32) | (low & 0xFFFFFFFF))
    status = lib.D3DKMTOpenAdapterFromLuid(ctypes.byref(request))
    return {"api": "OpenAdapterFromLuid", "luid": "%08x:%08x" % (high, low),
            "status": status & 0xFFFFFFFF, "hAdapter": request.hAdapter}


def open_by_hdc() -> dict:
    gdi32 = abi.bind_gdi32()
    user32 = abi.bind_user32()
    display = abi.DISPLAY_DEVICEW()
    display.cb = ctypes.sizeof(abi.DISPLAY_DEVICEW)
    if not user32.EnumDisplayDevicesW(None, 0, ctypes.byref(display), 0):
        return {"api": "OpenAdapterFromHdc", "status": None, "hAdapter": 0}
    gdi = abi.bind_gdi_dc()
    hdc = gdi.CreateDCW("DISPLAY", display.DeviceName, None, None)
    request = abi.D3DKMT_OPENADAPTERFROMHDC()
    request.hDc = hdc
    status = gdi32.D3DKMTOpenAdapterFromHdc(ctypes.byref(request))
    return {"api": "OpenAdapterFromHdc", "hAdapter": request.hAdapter,
            "status": status & 0xFFFFFFFF}


def loaded_module() -> dict:
    return loaded_kernel_module()


def _parse(output: str) -> dict:
    facts = {"adapters": [], "raw_lines": output.splitlines()}
    for line in output.splitlines():
        if line.startswith("ADAPTER "):
            parts = dict(item.split("=", 1) for item in line.split()[1:] if "=" in item)
            facts["adapters"].append(parts)
        elif "=" in line and line.split()[0] in {
                "DXGI_FACTORY", "CHOSEN", "D3D11_DEVICE", "DEVICE_ADAPTER",
                "SWAPCHAIN", "RTV", "RENDER", "PRESENT", "DEVICE_REMOVED", "RELEASED"}:
            key, _, value = line.partition(" ")
            facts[key] = value.strip()
    return facts


def main() -> int:
    if not EXE.is_file():
        raise SystemExit("d3d11_baseline.exe 未构建")
    run = subprocess.run([str(EXE)], capture_output=True, text=True, errors="replace")
    if run.returncode != 0:
        raise SystemExit("d3d11_baseline 退出码 %d: %s" % (run.returncode, run.stderr[-300:]))
    parsed = _parse(run.stdout)
    parsed["exit_code"] = run.returncode
    parsed["stderr"] = run.stderr[-400:]

    nvidia = [a for a in parsed["adapters"] if a.get("vendor") == "0x10de"]
    first = nvidia[0] if nvidia else {}
    high, _, low = (first.get("luid") or "0:0").partition(":")
    luid = open_by_luid(int(low, 16), int(high, 16)) if first else {}
    hdc = open_by_hdc()
    # Handles are allocated per open, so comparing them is meaningless; identity is
    # carried by the LUID, and the HDC path cannot report one.
    luid["note"] = "句柄值每次 Open 都会变，不能用相等判断是同一个适配器"

    # Leave no adapter handles behind: each open consumed one.
    lib = _gdi32()
    if luid.get("hAdapter"):
        close_adapter(lib, luid["hAdapter"])
    if hdc.get("hAdapter"):
        close_adapter(lib, hdc["hAdapter"])

    evidence = {
        "host": {"os": platform.platform(), "python": platform.python_version()},
        "driver": {"path": str(DRIVER), "sha256_note": "see docs/F8S1_HANDLE_VALIDITY.md"},
        "d3d11": parsed,
        "logical_adapters_note": "%d 个 NVIDIA DXGI 条目，属逻辑适配器，不等于物理卡数量"
                                 % len(nvidia),
        "d3dkmt": {"by_luid": luid, "by_hdc": hdc,
                   "identity_basis": "LUID only; handle values are per-open",
                   "hdc_identity": "UNKNOWN (HDC 路径不返回 LUID)"},
        "driver": {"file_sha256": __import__("hashlib").sha256(DRIVER.read_bytes()).hexdigest()
                   if DRIVER.is_file() else None,
                   "loaded_module": loaded_module(),
                   "note": "磁盘文件与内核已加载模块是两条独立线索"},
    }
    target = ROOT / "data" / "driver" / "f8s2_baseline.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(evidence["d3dkmt"], ensure_ascii=False, indent=1))
    print("written", target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
