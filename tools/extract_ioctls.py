# -*- coding: utf-8 -*-
r"""Read the ioctl codes straight out of nvapi64.dll.

Tracing would need a capture session and an interpreter for what comes back.
The codes are already in the binary: DeviceIoControl takes its code as an
immediate argument, so the immediate sits two instructions before the call.
Disassembling finds them without running anything and without administrator
rights - and unlike a trace, the result is the same on every run.

The second argument is the code (rcx is the handle, rdx the code, r8/r9 the
input buffer and its size), so a `mov edx, imm32` near a call through the
DeviceIoControl import slot is the code that call will use.

  python -m tools.extract_ioctls
  python -m tools.extract_ioctls --dll C:\Windows\System32\nvapi64.dll
"""

import argparse
import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import capstone

TARGET_IMPORT = "DeviceIoControl"


class Image:
    """Just enough PE parsing to map an RVA to a file offset and back."""

    def __init__(self, data: bytes):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("not a PE image")
        coff = pe + 4
        sections = struct.unpack_from("<H", data, coff + 2)[0]
        self.optional = coff + 20
        magic = struct.unpack_from("<H", data, self.optional)[0]
        self.is_64 = magic == 0x20B
        self.image_base = struct.unpack_from("<Q" if self.is_64 else "<I",
                                             data, self.optional + 24)[0]
        self.directories = self.optional + (112 if self.is_64 else 96)
        self.sections: List[Tuple[int, int, int, int, str]] = []
        table = self.optional + struct.unpack_from("<H", data, coff + 16)[0]
        for index in range(sections):
            entry = table + index * 40
            name = data[entry:entry + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, raw_size, raw = struct.unpack_from("<IIII", data, entry + 8)
            self.sections.append((vaddr, max(vsize, raw_size), raw, raw_size, name))

    def to_offset(self, rva: int) -> Optional[int]:
        for vaddr, size, raw, raw_size, _ in self.sections:
            if vaddr <= rva < vaddr + size:
                delta = rva - vaddr
                if delta >= raw_size:
                    return None
                return raw + delta
        return None

    def directory(self, index: int) -> Tuple[int, int]:
        return struct.unpack_from("<II", self.data, self.directories + index * 8)


def import_slots(image: Image, wanted: str) -> List[int]:
    """Virtual addresses of the IAT slots that hold the import's pointer."""
    rva, size = image.directory(1)
    if not rva:
        return []
    slots: List[int] = []
    offset = image.to_offset(rva)
    if offset is None:
        return []
    while True:
        # IMAGE_IMPORT_DESCRIPTOR is OriginalFirstThunk, TimeDateStamp,
        # ForwarderChain, Name, FirstThunk - read at the descriptor itself.
        original, _stamp, _chain, _name_rva, first_thunk = struct.unpack_from(
            "<IIIII", image.data, offset)
        if first_thunk == 0:
            break
        names_rva = original or first_thunk
        names_offset = image.to_offset(names_rva)
        if names_offset is not None:
            index = 0
            while True:
                entry = struct.unpack_from("<Q" if image.is_64 else "<I",
                                           image.data, names_offset + index * (8 if image.is_64 else 4))[0]
                if entry == 0:
                    break
                if not (entry >> (63 if image.is_64 else 31)):
                    name_offset = image.to_offset(entry + 2)
                    if name_offset is not None:
                        end = image.data.index(b"\x00", name_offset)
                        if image.data[name_offset:end].decode("ascii", "replace") == wanted:
                            slots.append(image.image_base + first_thunk
                                         + index * (8 if image.is_64 else 4))
                index += 1
        offset += 20
    return slots


def sweep(image: Image, slots: List[int], window: int = 12):
    """Every call through a slot, with the code moved into edx just before it.

    The decoder stops at the first byte it cannot read, which in a multi-megabyte
    section means losing everything after that byte. Advancing one byte and
    resuming keeps the sweep going across data tables embedded in .text.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if image.is_64 else capstone.CS_MODE_32)
    md.detail = True
    text = next(section for section in image.sections if section[4] == ".text")
    vaddr, _size, raw, raw_size, _ = text
    code = image.data[raw:raw + raw_size]
    base = image.image_base + vaddr

    history: List[capstone.CsInsn] = []
    found: List[Dict[str, object]] = []
    offset = 0
    while offset < len(code):
        progressed = False
        for insn in md.disasm(code[offset:], base + offset):
            progressed = True
            offset = insn.address - base + insn.size
            history.append(insn)
            if len(history) > window:
                history.pop(0)
            if insn.mnemonic == "call":
                item = _code_before_call(insn, history, slots, image)
                if item:
                    found.append(item)
        if not progressed:
            # Undecodable byte: step over it and keep sweeping.
            offset += 1
    return found


def _code_before_call(insn, history, slots, image):
    """Resolve the callee to an IAT slot, then find the immediate in edx."""
    target = None
    if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
        memory = insn.operands[0].mem
        if memory.base == capstone.x86.X86_REG_RIP:
            target = insn.address + insn.size + memory.disp
        elif image.is_64 and memory.base == 0:
            target = memory.disp
    if target not in slots:
        return None
    for earlier in reversed(history[:-1]):
        written = getattr(earlier, "regs_access", lambda: ([], []))()[1]
        if not any(register in written for register in
                   (capstone.x86.X86_REG_EDX, capstone.x86.X86_REG_RDX,
                    capstone.x86.X86_REG_DX)):
            continue
        for operand in earlier.operands:
            if operand.type == capstone.x86.X86_OP_IMM:
                return {"code": operand.imm & 0xFFFFFFFF,
                        "call_va": "0x%x" % insn.address,
                        "setter": earlier.mnemonic + " " + earlier.op_str}
    return None


METHODS = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}


def decode(code: int) -> Dict[str, object]:
    """CTL_CODE split: type, function, method, required access."""
    return {"device_type": (code >> 16) & 0xFFFF,
            "function": (code >> 2) & 0xFFF,
            "method": METHODS[code & 0x3],
            "access": (code >> 14) & 0x3}


def main() -> int:
    parser = argparse.ArgumentParser(description="extract ioctl codes from a DLL")
    parser.add_argument("--dll", default=os.path.join(os.environ.get("WINDIR",
                                                                   r"C:\Windows"),
                                                     "System32", "nvapi64.dll"))
    parser.add_argument("--json", default="data/probe/nvapi_ioctls.json")
    args = parser.parse_args()

    image = Image(Path(args.dll).read_bytes())
    slots = import_slots(image, TARGET_IMPORT)
    print("%s: %d IAT slot(s) for %s" % (Path(args.dll).name, len(slots),
                                         TARGET_IMPORT))
    if not slots:
        print("this image does not call %s directly" % TARGET_IMPORT)
        return 1

    found = sweep(image, slots)
    unique: Dict[int, Dict[str, object]] = {}
    for item in found:
        unique.setdefault(item["code"], item)
    print("%d call site(s), %d distinct code(s)\n" % (len(found), len(unique)))
    for code in sorted(unique):
        item = unique[code]
        parts = decode(code)
        print("  0x%08x  type=0x%04x func=0x%03x %-8s access=%d  at %s"
              % (code, parts["device_type"], parts["function"], parts["method"],
                 parts["access"], item["call_va"]))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"dll": args.dll, "total_calls": len(found),
                                  "codes": sorted(unique)},
                                 ensure_ascii=False, indent=2), encoding="utf-8")
    print("\nwritten to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
