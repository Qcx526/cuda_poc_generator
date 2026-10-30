# -*- coding: utf-8 -*-
"""Mutation stages, one per layer of the artifact.

A stage turns the seed into variants. They are kept separate rather than merged
into one big set because their yields are not comparable: a stage that produces
forty variants and no crash says something different from one that produces four
and crashes.

Two stages are implemented:

- ``value``    substitutes boundary values into every numeric field. The cheap
               baseline: it needs no knowledge of what the fields mean.
- ``relation`` picks a value from another field, so the mutation keeps the file
               plausible while breaking an agreement: a size that no longer
               matches the data it describes, an index one past the last entry, a
               stride that is not the size of the record it strides over.

The remaining layers - layout (adding and removing sections), container (fatbin
wrapping), payload (records inside a section) and naming (string table contents) -
are named in STAGES so a report can say they were skipped and why, rather than
leaving the impression that they were tried.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import elf_fields
from .mutation_campaign import Variant

# Layers, in the order they should be tried: cost rises fast after the first two.
STAGES = ("value", "relation", "layout", "payload", "naming", "container")
IMPLEMENTED = ("value", "relation", "layout")

SKIP_REASON = {
    "payload": "尚未实现：需要按节类型解析并重写记录（符号表项、nv.info、重定位项）",
    "naming": "尚未实现：需要字符串表内容级写入",
    "container": "尚未实现：需要 fatbin / 目标文件包装",
}


@dataclass
class Stages:
    variants: List[Variant] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)


def _variant(name: str, value: int, width: int, offset: int,
             note: str = "") -> Variant:
    return Variant(axis="relation", field=name, value=value,
                   offset=offset, width=width)


def value_stage(seed: bytes) -> List[Variant]:
    """Boundary values everywhere. No model, no assumptions about meaning."""
    table = elf_fields.table(seed)
    length = len(seed)
    # The 64-bit all-ones pattern is kept: it is the value that turns a length
    # into an address-sized number, and dropping it loses a real crash path on
    # the releases that are still vulnerable.
    values = list(elf_fields.COMMON_VALUES[:7]) + [length, length + 1,
                                                   0xFFFFFFFFFFFFFFFF]
    out = []
    for name, item in table.items():
        limit = 1 << (8 * item["width"])
        for value in values:
            if value < limit and value != item["value"]:
                out.append(Variant(axis="value", field=name, value=value,
                                   offset=item["offset"], width=item["width"]))
    return out


def _shape(seed: bytes) -> Dict[str, int]:
    """Sizes the relation stage needs: file length and the name table."""
    table = elf_fields.table(seed)
    length = len(seed)
    shstrndx = table.get("e_shstrndx", {}).get("value", 0)
    names = table.get("sec%d.sh_size" % shstrndx, {}).get("value", 0)
    count = table.get("e_shnum", {}).get("value", 0)
    return {"length": length, "shstrtab": names, "sections": count}


def relation_stage(seed: bytes) -> List[Variant]:
    """Values taken from other fields, so the file stays plausible.

    Each variant answers a question a single-field substitution cannot ask: what
    if the size is exactly right for the data, or one past the last index, or
    smaller than the record it describes?
    """
    table = elf_fields.table(seed)
    shape = _shape(seed)
    length = shape["length"]
    out: List[Variant] = []

    for index in range(shape["sections"]):
        prefix = "sec%d." % index
        offset_field = table.get(prefix + "sh_offset")
        size_field = table.get(prefix + "sh_size")
        if not offset_field or not size_field:
            continue
        start = offset_field["value"]
        limit = 1 << (8 * size_field["width"])

        # The size that exactly covers the rest of the file, and the same idea
        # eight bytes too far: "fits" versus "almost fits".
        for delta, label in ((0, "exact"), (8, "overrun")):
            if 0 <= start < length:
                value = length - start + delta
                if value < limit and value != size_field["value"]:
                    out.append(_variant(prefix + "sh_size", value,
                                        size_field["width"], size_field["offset"]))

        # A stride that is not the size of the record it strides over. Twelve is
        # the alignment a relocation entry needs, so it is the value a check is
        # likely to be written against.
        stride = table.get(prefix + "sh_entsize")
        if stride and stride["value"]:
            for value in (12, 16, 24, max(1, stride["value"] // 2)):
                if value < (1 << (8 * stride["width"])) and value != stride["value"]:
                    out.append(_variant(prefix + "sh_entsize", value,
                                        stride["width"], stride["offset"]))

        # An index one past the last entry, and the last entry itself.
        for field_name in ("sh_link", "sh_info"):
            item = table.get(prefix + field_name)
            if not item:
                continue
            for value in (shape["sections"], max(0, shape["sections"] - 1)):
                if value < (1 << (8 * item["width"])) and value != item["value"]:
                    out.append(_variant(prefix + field_name, value,
                                        item["width"], item["offset"]))

        # A name offset at, and just past, the end of the string table.
        name_field = table.get(prefix + "sh_name")
        if name_field and shape["shstrtab"]:
            for value in (shape["shstrtab"] - 1, shape["shstrtab"],
                          shape["shstrtab"] + 1):
                if value < (1 << (8 * name_field["width"])) \
                        and value != name_field["value"]:
                    out.append(_variant(prefix + "sh_name", value,
                                        name_field["width"], name_field["offset"]))
    return out


# ---- layout: the shape of the file, not the value of a field ----------------

def rebuild_layout(seed: bytes, op: str, params: dict) -> bytes:
    """Produce the artifact a layout mutation describes.

    Every layout variant must be describable from the seed alone, because that is
    what the ledger stores: an operation and its parameters, not a file. A recipe
    that cannot be replayed is a claim nobody can check later.
    """
    import struct

    if op == "truncate":
        return seed[:int(params["at"])]
    if op == "pad":
        return seed + b"\x00" * int(params["bytes"])
    if op == "prepend":
        return b"\x00" * int(params["bytes"]) + seed
    if op == "copy_table_to_end":
        shoff = struct.unpack_from("<Q", seed, 0x28)[0]
        entsize = struct.unpack_from("<H", seed, 0x3A)[0]
        count = struct.unpack_from("<H", seed, 0x3C)[0]
        table = seed[shoff:shoff + entsize * count]
        if not table:
            return seed
        out = bytearray(seed + table)
        struct.pack_into("<Q", out, 0x28, len(seed))
        return bytes(out)
    if op == "relocate_and_grow":
        shoff = struct.unpack_from("<Q", seed, 0x28)[0]
        entsize = struct.unpack_from("<H", seed, 0x3A)[0]
        count = struct.unpack_from("<H", seed, 0x3C)[0]
        extra = int(params["extra"])
        table = seed[shoff:shoff + entsize * count]
        if not table or entsize <= 0:
            return seed
        # Copy the table to the end, then extend it there: a table that really is
        # longer than the one the writer produced, in a place it can grow.
        out = bytearray(seed + table + b"\x00" * (entsize * extra))
        struct.pack_into("<Q", out, 0x28, len(seed))
        struct.pack_into("<H", out, 0x3C, count + extra)
        return bytes(out)
    if op == "grow_table":
        shoff = struct.unpack_from("<Q", seed, 0x28)[0]
        entsize = struct.unpack_from("<H", seed, 0x3A)[0]
        extra = int(params["extra"])
        # The table has to end the file for growth to add entries rather than
        # overwrite whatever follows it.
        if shoff + entsize * struct.unpack_from("<H", seed, 0x3C)[0] != len(seed):
            return seed
        out = bytearray(seed + b"\x00" * (entsize * extra))
        struct.pack_into("<H", out, 0x3C, struct.unpack_from("<H", seed, 0x3C)[0] + extra)
        return bytes(out)
    raise ValueError("unknown layout op %s" % op)


def layout_stage(seed: bytes) -> List[Variant]:
    """Cut the file, pad it, move the table - things a field edit cannot say.

    These are the mutations that answer "what if the file is not the shape the
    parser expects" rather than "what if a number is wrong". A parser that has
    hardened every boundary value can still assume the table it read is inside the
    file, or that the file ends where the last section says it does.
    """
    table = elf_fields.table(seed)
    length = len(seed)
    shoff = table.get("e_shoff", {}).get("value", 0)
    entsize = table.get("e_shentsize", {}).get("value", 0)
    out: List[Variant] = []

    def add(op: str, label: str, params: dict) -> None:
        payload = rebuild_layout(seed, op, params)
        if payload == seed or not payload:
            return
        variant = Variant(axis="layout", field=label, value=0, offset=0, width=0)
        variant.payload = payload
        variant.meta = {"op": op, "params": params}
        out.append(variant)

    # Cut at meaningful places: inside the table, exactly at it, inside the last
    # section, and at boundaries a length check is usually written against.
    for at in sorted({length - 1, length // 2, shoff + 1, shoff,
                      max(0, shoff - 1), 64, 63}):
        if 0 < at < length:
            add("truncate", "truncate@%d" % at, {"at": at})

    # Padding shifts nothing but changes what "the end of the file" means.
    for size in (1, 64, 4096):
        add("pad", "pad@%d" % size, {"bytes": size})

    # A table at a new address: parseable, but not where the writer put it.
    add("copy_table_to_end", "table@eof", {})

    # A table that really is longer than the one the file shipped with. Growing in
    # place only works when the table ends the file; otherwise it is moved to the
    # end first, which is also what a linker would have to do.
    for extra in (1, 8):
        if entsize and shoff + entsize * table.get("e_shnum", {}).get("value", 0) == length:
            add("grow_table", "table+%d" % extra, {"extra": extra})
        else:
            add("relocate_and_grow", "table@eof+%d" % extra, {"extra": extra})

    return out


def variant_key(variant) -> tuple:
    """Identity of a mutation, for deduplication across stages.

    Field variants are identified by where they write and what they write. Layout
    variants write nowhere in particular - their offset, width and value are all
    zero - so keying them the same way collapsed thirteen distinct files into one.
    The payload's digest is what distinguishes them.
    """
    if variant.payload:
        return ("payload", hashlib.sha256(variant.payload).hexdigest()[:16])
    if variant.edits:
        return ("edits", tuple(tuple(edit) for edit in variant.edits))
    return ("field", variant.offset, variant.width, variant.value)


BUILDERS = {"value": value_stage, "relation": relation_stage,
            "layout": layout_stage}


def build(seed: bytes, selected: Optional[List[str]] = None) -> Stages:
    """Every requested stage that exists; the rest are reported as skipped."""
    wanted = list(selected or IMPLEMENTED)
    result = Stages()
    seen = set()
    for name in STAGES:
        if name in wanted and name in BUILDERS:
            for variant in BUILDERS[name](seed):
                key = variant_key(variant)
                if key in seen:
                    continue
                seen.add(key)
                result.variants.append(variant)
        elif name in wanted:
            result.skipped.append(name)
    return result
