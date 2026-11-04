# -*- coding: utf-8 -*-
"""Structural comparison of one function pair, decoded rather than byte-masked.

The previous matcher blanked four bytes after every `E8`/`E9` at arbitrary byte
offsets. That is fast and wrong in a predictable way: a `0xE8` inside an
immediate or a string looks like a call, and masking it hides real differences.

This module decodes with Capstone and compares instruction *shapes*:

* registers keep their names, immediates and displacements collapse to a marker
* the shape sequence identifies logic independent of where the function sits
* call targets are recorded separately, so a target that merely moved can be
  distinguished from a target that changed

The five labels are descriptions of a difference, never a claim that a fix lives
here.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:  # pragma: no cover - capstone is a declared dependency
    Cs = None

RELOCATION_ONLY = "RELOCATION_ONLY"
STRUCTURAL_CHANGE = "STRUCTURAL_CHANGE"
CALL_GRAPH_CHANGE = "CALL_GRAPH_CHANGE"
CONSTANT_CHANGE = "CONSTANT_CHANGE"
INSTRUCTION_CHANGE_UNRESOLVED = "INSTRUCTION_CHANGE_UNRESOLVED"
MATCH_UNCERTAIN = "MATCH_UNCERTAIN"

_COND = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
         "jp", "jnp", "jl", "jge", "jle", "jg", "jcxz", "jecxz", "jrcxz")


@dataclass
class Shape:
    """What one instruction does, with addresses and constants abstracted."""
    text: str
    is_call: bool = False
    is_cond_branch: bool = False
    is_return: bool = False
    direct_target: Optional[int] = None
    indirect: bool = False


@dataclass
class Structure:
    instructions: int = 0
    shape_digest: str = ""          # constants preserved
    reloc_digest: str = ""          # addresses and constants normalised
    shapes: List[str] = field(default_factory=list)
    basic_blocks: int = 0
    branches: int = 0
    cond_branches: int = 0
    returns: int = 0
    direct_calls: List[int] = field(default_factory=list)
    indirect_calls: int = 0
    call_targets: List[str] = field(default_factory=list)
    branch_digest: str = ""
    decoded_bytes: int = 0
    undecodable: bool = False


def _engine() -> Optional["Cs"]:
    if Cs is None:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def analyze(code: bytes, base_rva: int) -> Structure:
    """Decode a function body and describe it without committing to addresses."""
    md = _engine()
    structure = Structure()
    if md is None or not code:
        structure.undecodable = True
        return structure

    md.skipdata = True
    targets = set()
    shapes: List[str] = []
    reloc_parts: List[str] = []
    branch_kinds: List[str] = []
    for insn in md.disasm(code, base_rva):
        # Every operand is rendered twice: once keeping constants (shape) and once
        # normalising them (reloc). A jump target is an address in both, a small
        # immediate is a constant in the shape, and a struct offset stays too.
        is_branch = insn.mnemonic.lower().startswith(("j", "call"))
        shape_parts = [insn.mnemonic]
        reloc_parts_here = [insn.mnemonic]
        if insn.id == 0:
            shapes.append(".byte")
            reloc_parts.append(".byte")
            structure.instructions += 1
            structure.decoded_bytes += insn.size
            structure.undecodable = True
            continue
        for operand in insn.operands:
            if operand.type == X86_OP_REG:
                name = insn.reg_name(operand.reg)
                shape_parts.append(name)
                reloc_parts_here.append(name)
            elif operand.type == X86_OP_IMM:
                if is_branch:
                    shape_parts.append("ADDR")
                    reloc_parts_here.append("ADDR")
                elif -0x10000 <= operand.imm <= 0x10000:
                    shape_parts.append("I:%d" % operand.imm)
                    reloc_parts_here.append("I:*")
                else:
                    shape_parts.append("ADDR")
                    reloc_parts_here.append("ADDR")
            elif operand.type == X86_OP_MEM:
                mem = operand.mem
                base = insn.reg_name(mem.base) or ""
                index = insn.reg_name(mem.index) or ""
                rip_relative = base in ("rip", "eip")
                is_offset = (not rip_relative) and -0x10000 <= mem.disp <= 0x10000
                shape_disp = ("%d" % mem.disp) if is_offset else "ADDR"
                shape_parts.append("M[%s+%s*%d+%s]" % (base, index, mem.scale, shape_disp))
                # In the relocation digest every displacement is normalised: a
                # struct offset is a constant, and a constant that changed is a
                # constant change, not a relocation.
                reloc_parts_here.append(
                    "M[%s+%s*%d+%s]" % (base, index, mem.scale, "*"))
            else:
                shape_parts.append("?")
                reloc_parts_here.append("?")
        shapes.append(" ".join(shape_parts))
        reloc_parts.append(" ".join(reloc_parts_here))

        structure.instructions += 1

        structure.instructions += 1
        structure.decoded_bytes += insn.size
        mnemonic = insn.mnemonic.lower()
        if mnemonic.startswith("call"):
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                structure.direct_calls.append(insn.operands[0].imm)
                structure.call_targets.append("direct:0x%x" % insn.operands[0].imm)
            else:
                structure.indirect_calls += 1
                structure.call_targets.append("indirect")
            structure.branches += 1
            targets.add(insn.address + insn.size)
        elif mnemonic.startswith("j"):
            branch_kinds.append(mnemonic)
            structure.branches += 1
            if mnemonic in _COND:
                structure.cond_branches += 1
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                targets.add(insn.operands[0].imm)
            targets.add(insn.address + insn.size)
        elif mnemonic.startswith("ret"):
            structure.returns += 1

    structure.shapes = shapes
    # A function has one entry block; every branch target that lands inside the
    # body starts another. Counting these is a cheap CFG proxy that does not need
    # a full graph library.
    inside = {address for address in targets if base_rva <= address < base_rva + len(code)}
    structure.basic_blocks = 1 + len({a for a in inside if a != base_rva})
    structure.shape_digest = hashlib.sha1("\n".join(shapes).encode("utf-8")).hexdigest()
    structure.reloc_digest = hashlib.sha1(
        "\n".join(reloc_parts).encode("utf-8")).hexdigest()
    # je -> jne keeps every count identical yet changes which way the code goes,
    # so the kind of each branch is part of the structural fingerprint.
    structure.branch_digest = hashlib.sha1(
        "\n".join(branch_kinds).encode("utf-8")).hexdigest()
    structure.undecodable = structure.undecodable or structure.instructions == 0
    return structure


def classify(old: Structure, new: Structure, old_size: int, new_size: int,
             old_to_new: Optional[Dict[int, int]] = None,
             old_body: Optional[int] = None,
             new_body: Optional[int] = None) -> Tuple[str, List[str]]:
    """``old_body``/``new_body`` are Ghidra's function-body sizes when known.

    A .pdata entry can cover only a fragment of the function Ghidra sees; in that
    case the two sides are not comparable and the pair is uncertain, not changed.
    """
    """Guard the comparison with an identity check before labelling anything.

    A function can keep its RVA while being split, merged or replaced wholesale.
    Calling that a structural change would dress an alignment failure up as a
    finding, so an implausible size ratio stops the comparison here.
    """
    for size, body in ((old_size, old_body), (new_size, new_body)):
        if size and body and abs(body - size) / float(max(size, 1)) > 0.25:
            return MATCH_UNCERTAIN, [
                ".pdata 范围（%d）与 Ghidra 函数体（%d）不一致，可能只是片段"
                % (size, body)]
    if old_size and new_size:
        ratio = new_size / float(old_size)
        if ratio < 0.5 or ratio > 2.0:
            return MATCH_UNCERTAIN, [
                "尺寸比例异常（%d→%d，%.2fx），可能是函数拆分/合并而非同一函数"
                % (old_size, new_size, ratio)]
    return compare(old, new, old_to_new)


def compare(old: Structure, new: Structure,
            old_to_new: Optional[Dict[int, int]] = None) -> Tuple[str, List[str]]:
    """Label the difference, weakest claim first.

    ``old_to_new`` maps function RVAs between builds; with it, a call whose target
    merely moved is not reported as a call-graph change.
    """
    if old.undecodable or new.undecodable:
        return MATCH_UNCERTAIN, ["至少一侧无法解码"]

    evidence: List[str] = []
    if old.reloc_digest == new.reloc_digest:
        if old.shape_digest == new.shape_digest:
            evidence.append("指令形状与常量完全一致，差异只在地址")
            if old.call_targets != new.call_targets:
                evidence.append("直接调用目标不同，但已映射到同一函数")
            return RELOCATION_ONLY, evidence
        evidence.append("控制流结构一致，但立即数/偏移不同：常量变化")
        return CONSTANT_CHANGE, evidence

    cfg_changed = (old.basic_blocks != new.basic_blocks
                   or old.cond_branches != new.cond_branches
                   or old.returns != new.returns
                   or old.branch_digest != new.branch_digest)
    if cfg_changed:
        evidence.append("基本块 %d→%d，条件分支 %d→%d，返回 %d→%d"
                        % (old.basic_blocks, new.basic_blocks, old.cond_branches,
                           new.cond_branches, old.returns, new.returns))

    calls_changed = False
    if old_to_new:
        mapped_old = [old_to_new.get(target, target) for target in old.direct_calls]
        mapped_old.sort()
        current = sorted(new.direct_calls)
        calls_changed = mapped_old != current
    else:
        calls_changed = (len(old.direct_calls) != len(new.direct_calls)
                         or old.indirect_calls != new.indirect_calls)
    if calls_changed:
        evidence.append("直接调用 %d→%d，间接调用 %d→%d"
                        % (len(old.direct_calls), len(new.direct_calls),
                           old.indirect_calls, new.indirect_calls))

    if cfg_changed:
        return STRUCTURAL_CHANGE, evidence
    if calls_changed:
        return CALL_GRAPH_CHANGE, evidence
    evidence.append("指令形状不同，但控制流与调用关系一致：可能是常量或数据流变化")
    return INSTRUCTION_CHANGE_UNRESOLVED, evidence
