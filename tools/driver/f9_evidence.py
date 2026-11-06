# -*- coding: utf-8 -*-
"""Re-extract the static facts this project relies on, from the file on disk.

Every fact used in the F9 reasoning chain has to be reproducible by someone else on
the same image, so this script prints the number and the command that produced it
rather than quoting a document.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import capstone                                    # noqa: E402
from src.driver_binary import PEImage              # noqa: E402

DRIVER = Path("C:/Windows/System32/DriverStore/FileRepository/"
              "nv_dispi.inf_amd64_c8bc842500fab35b/nvlddmkm.sys")
# A function the earlier recon singled out; here only to prove disassembly still works.
PROBE_RVA = 0x6912F0
PROBE_COUNT = 8


def pe_facts(path: Path) -> dict:
    data = path.read_bytes()
    image = PEImage(path)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    machine, sections = struct.unpack_from("<HH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else 0

    pdata = 0
    try:
        rva, size = image.directories[3]      # IMAGE_DIRECTORY_ENTRY_EXCEPTION
        pdata = size // 12
    except (IndexError, AttributeError):
        pass

    # The image has two sections named ".text" (index 0 and 8); taking the last one
    # silently replaced a 13.8 MB value with a 91-byte one.
    text_sections = [{"index": i, "name": s.name, "rva": "0x%x" % s.vaddr,
                      "vsize": s.vsize, "raw_size": s.raw_size}
                     for i, s in enumerate(image.sections) if s.name == ".text"]
    return {"path": str(path), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "machine": "0x%04x" % machine, "pe32plus": magic == 0x20B,
            "image_base": "0x%x" % image_base, "sections": sections,
            "entry_rva": "0x%x" % entry_rva,
            "entry_va": "0x%x" % (image_base + entry_rva),
            # Count of .pdata records, not a count of proven functions: a record
            # describes a code range with unwind data, which is not the same thing.
            "pdata_records": pdata,
            "text_sections": text_sections,
            # Negative evidence for the callback binding: the image never names the
            # DDI, so no RVA can be tied to it by symbol search.
            "ddi_name_scan": {"dxgk_ascii": data.count(b"Dxgk"),
                              "dxgk_utf16": data.count(b"D\x00x\x00g\x00k\x00"),
                              "dxgkrnl_string": data.count(b"dxgkrnl"),
                              "import_dlls": image.imports()}}


def disassemble(path: Path, rva: int, count: int) -> list:
    image = PEImage(path)
    offset = image.offset_of(rva)
    code = Path(path).read_bytes()[offset:offset + 64]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    rows = []
    for i, insn in enumerate(md.disasm(code, rva)):
        if i >= count:
            break
        rows.append({"va": "0x%x" % (0x140000000 + insn.address),
                     "rva": "0x%x" % insn.address,
                     "text": "%s %s" % (insn.mnemonic, insn.op_str)})
    return rows


def main() -> int:
    if not DRIVER.is_file():
        raise SystemExit("驱动文件不存在: %s" % DRIVER)
    facts = {"driver": pe_facts(DRIVER),
             "probe": {"rva": "0x%x" % PROBE_RVA,
                       "instructions": disassemble(DRIVER, PROBE_RVA, PROBE_COUNT)},
             "tools": {"pe": "src.driver_binary.PEImage", "disasm": "capstone 5.x"}}
    target = ROOT / "data" / "driver" / "f9_evidence.json"
    target.write_text(json.dumps(facts, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(facts["driver"], ensure_ascii=False, indent=1))
    print(json.dumps(facts["probe"], ensure_ascii=False, indent=1)[:600])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
