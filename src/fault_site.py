# -*- coding: utf-8 -*-
"""Read or write, from the instruction that faulted.

The shim carries out the bytes at the faulting instruction pointer; this decodes
them. Two crashes at the same instruction with different access types would be
surprising, but the access type is what separates a null read (a denial of
service) from a write to an attacker-chosen address (potentially much more), and
that distinction is the whole of "exploitation potential" at this level.

Nothing here guesses when it does not know: an instruction capstone cannot decode
returns "unknown", and a caller must treat that as such.
"""

from typing import Optional

try:                                  # capstone is a declared dependency
    import capstone
    from capstone import x86 as cs_x86

    _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _MD.detail = True
except Exception:                     # noqa: BLE001 - decoding is best-effort
    _MD = None

READ = "read"
WRITE = "write"
EXEC = "exec"
UNKNOWN = "unknown"

# Instructions that never write their memory operand, whatever the operand order
# says. Compared with `cmp [rdi], 0`, which reads a pointer to decide a branch.
_READ_ONLY = {
    "cmp", "test", "push", "call", "jmp", "lea", "movzx", "movsx", "movsxd",
    "bt", "div", "idiv", "mul", "imul", "cvtsi2sd", "ucomisd", "comisd",
}


def access_type(insn_hex: str) -> str:
    """Classify one instruction's memory access; 'unknown' when undecidable."""
    if not insn_hex or _MD is None:
        return UNKNOWN
    try:
        raw = bytes.fromhex(insn_hex)
    except ValueError:
        return UNKNOWN
    for insn in _MD.disasm(raw, 0):
        memory = [op for op in insn.operands
                  if op.type == cs_x86.X86_OP_MEM]
        if not memory:
            # No memory operand: the fault came from fetching this instruction.
            return EXEC
        mnemonic = insn.mnemonic.split()[0]
        if mnemonic in _READ_ONLY:
            return READ
        for index, op in enumerate(insn.operands):
            if op.type != cs_x86.X86_OP_MEM:
                continue
            written = bool(getattr(op, "access", 0) & capstone.CS_AC_WRITE)
            # Destination is operand 0 for the shapes that matter here; an
            # `access` flag from capstone outranks that when it is present.
            if written or (index == 0 and not mnemonic.startswith("movs")):
                return WRITE
            return READ
    return UNKNOWN


def describe(insn_hex: str) -> str:
    """The instruction as text, for reports; empty when it cannot be decoded."""
    if not insn_hex or _MD is None:
        return ""
    try:
        for insn in _MD.disasm(bytes.fromhex(insn_hex), 0):
            return "%s %s" % (insn.mnemonic, insn.op_str)
    except ValueError:
        return ""
    return ""


def severity(access: str, address: int) -> str:
    """How much the fault suggests, stated without overclaiming.

    A write to a controlled address is the interesting case; a read at or near
    zero is almost always a missed null check.
    """
    if access == WRITE and address > 0x1000:
        return "write-to-address"
    if access == WRITE:
        return "null-write"
    if access == READ and address < 0x1000:
        return "null-read"
    if access == READ:
        return "read-out-of-bounds"
    if access == EXEC:
        return "execute-non-executable"
    return "unknown"


def classify(insn_hex: str, address: int) -> dict:
    """Everything a caller needs, in one call."""
    access = access_type(insn_hex)
    return {"access": access,
            "instruction": describe(insn_hex),
            "severity": severity(access, address)}
