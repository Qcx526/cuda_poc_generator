# -*- coding: utf-8 -*-
"""Run the handle-validity controls on this host.

Only documented, read-only or normal-lifecycle calls are used: QueryAdapterInfo,
CreateDevice, GetDeviceState, DestroyDevice, CloseAdapter. No escape is sent.
"""

import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src import driver_abi as abi          # noqa: E402
from tools.driver import handle_validity   # noqa: E402


def open_adapter() -> int:
    gdi32 = abi.bind_gdi32()
    user32 = abi.bind_user32()
    display = abi.DISPLAY_DEVICEW()
    display.cb = ctypes.sizeof(abi.DISPLAY_DEVICEW)
    if not user32.EnumDisplayDevicesW(None, 0, ctypes.byref(display), 0):
        raise RuntimeError("no display device")
    gdi = abi.bind_gdi_dc()
    hdc = gdi.CreateDCW("DISPLAY", display.DeviceName, None, None)
    request = abi.D3DKMT_OPENADAPTERFROMHDC()
    request.hDc = hdc
    status = gdi32.D3DKMTOpenAdapterFromHdc(ctypes.byref(request))
    if status != 0:
        raise RuntimeError("OpenAdapterFromHdc failed: 0x%08x" % (status & 0xFFFFFFFF))
    return request.hAdapter


def main() -> int:
    adapter = open_adapter()
    result = handle_validity.run(adapter)
    result["adapter"] = adapter
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
