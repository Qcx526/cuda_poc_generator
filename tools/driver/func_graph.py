# -*- coding: utf-8 -*-
"""Recover function boundaries from .pdata and walk callers by address.

A driver ships no symbols, but it does ship an exception directory: one
RUNTIME_FUNCTION per function, with its start and end RVA. That is enough to say
which function contains a given instruction, and therefore which function calls a
given wrapper.

Direct calls are E8 rel32, so finding callers is a byte scan rather than a
disassembly of 13 MB of code. Indirect calls (FF 15) are counted separately: they
usually mean "through a function pointer" and cannot be attributed this cheaply.

  python -m tools.driver.func_graph --at 0x1400dd4c8
  python -m tools.driver.func_graph --at 0x1400dd4c8 --callers
"""

import argparse
import struct
from bisect import bisect_right
from pathlib import Path
from typing import List, Optional, Tuple

DEFAULT_IMAGE = Path("data/driver/binary/nvlddmkm.sys")


class Image:
    def __init__(self, data: bytes) -> None:
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        self.sections = []
        count = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        self.base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
        for index in range(count):
            off = pe + 24 + opt_size + index * 40
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append((name, vaddr, max(vsize, rsize), raw, rsize))
        pdata = self.section(".pdata")
        self.functions: List[Tuple[int, int]] = []
        if pdata:
            _, vaddr, _, raw, rsize = pdata
            for off in range(raw, raw + rsize - 12, 12):
                begin, end, _ = struct.unpack_from("<III", data, off)
                if begin and end > begin:
                    self.functions.append((begin, end))
            self.functions.sort()
        self._starts = [item[0] for item in self.functions]

    def section(self, name: str) -> Optional[Tuple]:
        for item in self.sections:
            if item[0] == name:
                return item
        return None

    def function_at(self, va: int) -> Optional[Tuple[int, int]]:
        """The function whose range contains this virtual address."""
        rva = va - self.base
        index = bisect_right(self._starts, rva) - 1
        if index < 0:
            return None
        begin, end = self.functions[index]
        return (begin, end) if begin <= rva < end else None

    def callers_of(self, function_va: int, limit: int = 40) -> List[int]:
        """Direct E8 calls that land on the function's first byte."""
        target = function_va - self.base
        text = self.section(".text")
        if not text:
            return []
        _, vaddr, _, raw, rsize = text
        hits = []
        end = min(raw + rsize, len(self.data)) - 5
        for off in range(raw, end):
            if self.data[off] != 0xE8:
                continue
            rel = struct.unpack_from("<i", self.data, off + 1)[0]
            here = vaddr + (off - raw)
            if here + 5 + rel == target:
                hits.append(self.base + here)
                if len(hits) >= limit:
                    break
        return hits

    def indirect_calls(self) -> int:
        text = self.section(".text")
        if not text:
            return 0
        _, _, _, raw, rsize = text
        body = self.data[raw:raw + rsize]
        return sum(1 for i in range(len(body) - 2) if body[i] == 0xFF and body[i + 1] == 0x15)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="function boundaries and callers")
    parser.add_argument("--image", default=str(DEFAULT_IMAGE))
    parser.add_argument("--at", action="append", default=[],
                        help="virtual address to attribute (hex), repeatable")
    parser.add_argument("--callers", action="store_true")
    args = parser.parse_args(argv)

    image = Image(Path(args.image).read_bytes())
    print("functions in .pdata: %d | indirect call sites: %d"
          % (len(image.functions), image.indirect_calls()))
    for text in args.at:
        va = int(text, 0)
        span = image.function_at(va)
        if not span:
            print("%s: not inside a known function" % text)
            continue
        begin, end = span
        print("%s -> function 0x%x .. 0x%x (%d bytes)"
              % (text, image.base + begin, image.base + end, end - begin))
        if args.callers:
            hits = image.callers_of(image.base + begin)
            print("   direct callers: %d %s"
                  % (len(hits), [hex(h) for h in hits[:12]]))
            for hit in hits[:12]:
                caller = image.function_at(hit)
                if caller:
                    print("     caller function 0x%x (%d bytes)"
                          % (image.base + caller[0], caller[1] - caller[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
