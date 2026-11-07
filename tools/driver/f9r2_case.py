# -*- coding: utf-8 -*-
"""Build the Windows driver case and run one bounded data-flow check.

Scope is deliberately small: the DriverEntry body plus the handful of instructions
that reference offset 0x110. If a store is found, the report says which register was
used and whether its base could be tied to the initialization structure - a store to
[reg+0x110] alone proves nothing.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import capstone                                              # noqa: E402
from src.case_v2 import (SCHEMA_VERSION, CaseIdentity, ConstraintKnowledge,  # noqa: E402
                         EntrySurface, Evidence, EvidenceKind, ExperimentContract,
                         GPUCase, PlatformExtension, TargetProfile,
                         VerificationStatus, Visibility, VulnerabilityDescription)
from src.driver_binary import PEImage                        # noqa: E402

DRIVER = Path("C:/Windows/System32/DriverStore/FileRepository/"
              "nv_dispi.inf_amd64_c8bc842500fab35b/nvlddmkm.sys")
ENTRY_WINDOW = 0x600          # bounded: 1.5 KB around the entry point


def scan_entry(image: PEImage, entry_rva: int) -> dict:
    offset = image.offset_of(entry_rva)
    code = image.data[offset:offset + ENTRY_WINDOW]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    stores, calls = [], []
    for insn in md.disasm(code, entry_rva):
        text = "%s %s" % (insn.mnemonic, insn.op_str)
        if insn.mnemonic == "mov" and "[r" in insn.op_str and "0x110]" in insn.op_str:
            stores.append({"rva": "0x%x" % insn.address, "text": text})
        elif insn.mnemonic == "call":
            calls.append({"rva": "0x%x" % insn.address, "text": text})
    return {"window_bytes": ENTRY_WINDOW, "stores_to_0x110": stores,
            "calls": calls[:20], "scanned_instructions": len(calls) + len(stores)}


def scan_table(image: PEImage, entry_rva: int, window: int = 0x400) -> dict:
    """Pair lea/mov fills, checking that the registers actually match.

    The first version only looked at adjacent instructions. "lea rax,[rip+X]" followed
    by "mov [rbp+0x110],rax" is a pair only if the mov really uses rax; otherwise the
    stored value came from somewhere else and the pairing is fiction.
    """
    offset = image.offset_of(entry_rva)
    blob = image.data[offset:offset + window]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(blob, entry_rva))
    pairs, rejected = [], []

    for i, insn in enumerate(ins):
        if insn.mnemonic != "lea" or i + 1 >= len(ins):
            continue
        ops = insn.operands
        if len(ops) < 2 or ops[0].type != capstone.x86.X86_OP_REG:
            continue
        src = ops[1]
        if src.type != capstone.x86.X86_OP_MEM or src.mem.base != capstone.x86.X86_REG_RIP:
            continue
        nxt = ins[i + 1]
        if nxt.mnemonic != "mov" or len(nxt.operands) < 2:
            continue
        dst, val = nxt.operands[0], nxt.operands[1]
        if dst.type != capstone.x86.X86_OP_MEM or val.type != capstone.x86.X86_OP_REG:
            continue
        lea_reg = insn.reg_name(ops[0].reg)
        val_reg = nxt.reg_name(val.reg)
        base_reg = nxt.reg_name(dst.mem.base)
        entry = {
            "store_rva": "0x%x" % nxt.address,
            "lea_rva": "0x%x" % insn.address,
            "field_offset": "0x%x" % dst.mem.disp if dst.mem.disp >= 0 else str(dst.mem.disp),
            "base_reg": base_reg,
            "value_reg": val_reg,
            "target_rva": "0x%x" % (insn.address + insn.size + src.mem.disp),
            "bytes": blob[nxt.address - entry_rva: nxt.address - entry_rva + nxt.size].hex(),
        }
        if lea_reg == val_reg:
            pairs.append(entry)
        else:
            entry["reason"] = "lea 写入 %s，mov 读取 %s" % (lea_reg, val_reg)
            rejected.append(entry)
    return {"window_bytes": window, "pairs": pairs, "rejected": rejected,
            "count": len(pairs), "rejected_count": len(rejected)}


def classify_pairs(table: dict) -> dict:
    """Group the pairs by base register instead of calling them one table."""
    groups = {}
    for entry in table["pairs"]:
        groups.setdefault(entry["base_reg"], []).append(entry["field_offset"])
    return {reg: {"count": len(offs), "offsets": sorted(set(offs))[:20]}
            for reg, offs in groups.items()}


def trace_consumer(image: PEImage, entry_rva: int, start_rva: int,
                   window: int = 0x1800) -> dict:
    """Look for a call that receives rbp (or a copy) as an argument, after the fills."""
    offset = image.offset_of(entry_rva)
    blob = image.data[offset:offset + window]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins = list(md.disasm(blob, entry_rva))
    hits = []
    for i, insn in enumerate(ins):
        if insn.address < start_rva or insn.mnemonic != "call":
            continue
        # window of 8 instructions before the call
        for prev in ins[max(0, i - 8):i]:
            if prev.mnemonic == "mov" and prev.op_str.startswith(("rcx", "rdx", "r8")):
                reg, _, src = prev.op_str.partition(",")
                if src.strip().startswith("rbp"):
                    hits.append({"call_rva": "0x%x" % insn.address,
                                 "setup_rva": "0x%x" % prev.address,
                                 "text": "%s %s" % (prev.mnemonic, prev.op_str)})
    return {"calls_after_fill": sum(1 for x in ins if x.address >= start_rva
                                    and x.mnemonic == "call"),
            "argument_from_rbp": hits,
            "scanned_bytes": window}


def scan_block_copy(image: PEImage, entry_rva: int, window: int = 0x1800) -> dict:
    """Any wholesale copy of the stack object (rep movs / movs / stos)?"""
    blob = image.data[image.offset_of(entry_rva):image.offset_of(entry_rva) + window]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    hits = []
    for insn in md.disasm(blob, entry_rva):
        text = "%s %s" % (insn.mnemonic, insn.op_str)
        if "movs" in insn.mnemonic or "stos" in insn.mnemonic or insn.mnemonic == "rep":
            hits.append({"rva": "0x%x" % insn.address, "text": text})
    return {"window_bytes": window, "block_copies": hits, "count": len(hits)}


def function_bounds(image: PEImage, rva: int) -> dict:
    """Is the candidate inside an executable section and a .pdata function?"""
    section = next((s for s in image.sections
                    if s.vaddr <= rva < s.vaddr + s.vsize), None)
    fn = image.function_at(rva) if hasattr(image, "function_at") else None
    return {"section": section.name if section else None,
            "executable": bool(section and section.executable),
            "function_at_rva": bool(fn),
            "function_size": getattr(fn, "size", 0)}


def bound_base_register(image: PEImage, entry_rva: int, reg: str = "rbp",
                        window: int = 0x200) -> dict:
    """Where does rbp come from before the table is written?"""
    offset = image.offset_of(entry_rva)
    blob = image.data[offset:offset + window]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    writes = []
    for insn in md.disasm(blob, entry_rva):
        text = "%s %s" % (insn.mnemonic, insn.op_str)
        if insn.mnemonic in ("lea", "mov") and insn.op_str.startswith(reg + ","):
            writes.append({"rva": "0x%x" % insn.address, "text": text})
    return {"register": reg, "writes": writes, "found": bool(writes)}


def build_case(facts: dict, offsets: dict, flow: dict, table: dict = None) -> GPUCase:
    sha = facts["driver"]["sha256"]
    knowledge = ConstraintKnowledge(evidence=[
        Evidence(id="S1", kind=EvidenceKind.STATIC_FACT,
                 statement="镜像 SHA256 与 PE 身份", source="data/driver/f9_evidence.json",
                 target_identity=sha, digest=sha, status=VerificationStatus.SUPPORTED,
                 visible_in=Visibility.FACT),
        Evidence(id="S2", kind=EvidenceKind.STATIC_FACT,
                 statement="入口 RVA %s（VA %s）" % (facts["driver"]["entry_rva"],
                                                    facts["driver"]["entry_va"]),
                 source="PE 可选头 EntryPoint", target_identity=sha,
                 status=VerificationStatus.SUPPORTED, visible_in=Visibility.FACT),
        Evidence(id="S3", kind=EvidenceKind.STATIC_FACT,
                 statement=".pdata 异常记录 %d 条（记录数，不是函数数）"
                           % facts["driver"]["pdata_records"],
                 source="异常目录大小/12", target_identity=sha,
                 status=VerificationStatus.SUPPORTED, visible_in=Visibility.FACT),
        Evidence(id="S4", kind=EvidenceKind.STATIC_FACT,
                 statement="两个 .text 节：index 0 rva=%s size=%d；index 8 rva=%s size=%d"
                           % (facts["driver"]["text_sections"][0]["rva"],
                              facts["driver"]["text_sections"][0]["vsize"],
                              facts["driver"]["text_sections"][1]["rva"],
                              facts["driver"]["text_sections"][1]["vsize"]),
                 source="节表", target_identity=sha,
                 status=VerificationStatus.SUPPORTED, visible_in=Visibility.FACT),
        Evidence(id="S5", kind=EvidenceKind.STATIC_FACT,
                 statement="WDK 头文件：DRIVER_INITIALIZATION_DATA 的 DxgkDdiEscape 位于 %s"
                           % offsets["offset_DxgkDdiEscape"],
                 source="km_offsetof.c 编译期 FIELD_OFFSET（负控制 C2338）",
                 target_identity="WDK 10.0.26100.0",
                 status=VerificationStatus.SUPPORTED, visible_in=Visibility.FACT),
        Evidence(id="R1", kind=EvidenceKind.EVIDENCE_REQUEST,
                 statement="结构体 +0x110 在运行期是否存放有效函数指针",
                 source="F9-R1 结论", status=VerificationStatus.UNKNOWN,
                 visible_in=Visibility.EVAL,
                 notes="含 +0x110 字段名，默认不进盲测；需内核读内存，本机不可执行"),
        Evidence(id="R2", kind=EvidenceKind.EVIDENCE_REQUEST,
                 statement="该指针指向的函数是否在 Escape 调用时被执行",
                 source="F9-R1 结论", status=VerificationStatus.UNKNOWN,
                 visible_in=Visibility.EVAL,
                 notes="需断点命中+栈回溯；本机不可执行"),
        Evidence(id="S6", kind=EvidenceKind.STATIC_FACT,
                 statement="Entry 窗口内有 %d 条 lea/mov 对在填充同一结构；其中字段偏移 0x110 "
                           "处写入的地址为 %s（store 位于 %s）"
                           % ((table or {}).get("count", 0),
                              next((r["target_rva"] for r in (table or {}).get("pairs", [])
                                    if r["field_offset"] == "0x110"), "未找到"),
                              next((r["store_rva"] for r in (table or {}).get("pairs", [])
                                    if r["field_offset"] == "0x110"), "未找到")),
                 source="tools/driver/f9r2_case.py scan_table（Capstone 线性反汇编）",
                 target_identity=sha, status=VerificationStatus.SUPPORTED,
                 visible_in=Visibility.FACT),
        Evidence(id="S7", kind=EvidenceKind.STATIC_FACT,
                 statement="表基址来自栈帧：%s；操作数级校验后真正成立的 lea/mov 对为 %d 组，"
                           "被拒绝 %d 组（寄存器不一致）"
                           % (", ".join("%s @%s" % (w["text"], w["rva"])
                                        for w in (table or {}).get("base_binding", {})
                                        .get("writes", [])[:1]) or "未找到",
                              (table or {}).get("count", 0),
                              (table or {}).get("rejected_count", 0)),
                 source="tools/driver/f9r2_case.py（Capstone operand detail）",
                 target_identity=sha, status=VerificationStatus.SUPPORTED,
                 visible_in=Visibility.FACT),
        Evidence(id="O1", kind=EvidenceKind.EVALUATION_ONLY,
                 statement="[rbp+0x110] 写入被解释为 DxgkDdiEscape 注册：未证实",
                 source="f9r2_case 推断", status=VerificationStatus.UNKNOWN,
                 visible_in=Visibility.EVAL,
                 notes="偏移与 WDK 布局一致只是必要条件；未证明 rbp 即初始化结构基址，"
                       "也未证明该表用于 Escape 注册"),
    ], missing=["Escape 回调 RVA", "私有请求结构布局", "运行期初始化结构内容"])

    return GPUCase(
        schema_version=SCHEMA_VERSION,
        identity=CaseIdentity(case_id="case:nvlddmkm-610.47-escape",
                              cve_id=None,
                              title="NVIDIA Windows 显示驱动 D3DKMTEscape 请求合法性",
                              sources=["data/driver/f9_evidence.json",
                                       "data/driver/f9_offsets.json"]),
        target=TargetProfile(vendor="NVIDIA", component="nvlddmkm.sys",
                             platform="windows", execution_tier="kernel_driver",
                             versions={"driver": "610.47", "wddm": "2.7"}),
        entry_surface=EntrySurface(medium="api_call", interface="D3DKMTEscape",
                                   trust_boundary="user_mode -> kernel_mode",
                                   constraints=["需有效 Adapter/Device 句柄"]),
        description=VulnerabilityDescription(
            public_summary="D3DKMTEscape 请求合法性由驱动内部判定，具体条件未公开",
            cwe=None, impact="unknown", root_cause_status=VerificationStatus.UNKNOWN),
        knowledge=knowledge,
        contract=ExperimentContract(goal="确定请求合法性的前置条件",
                                    authorized_fact_ids=["S1", "S2", "S3", "S4", "S5", "S6", "S7"],
                                    backend="windows_userland",
                                    allowed_operations=["query_device_state",
                                                        "query_adapter_info"],
                                    risk_level="low"),
        extension=PlatformExtension(name="windows_gpu_driver", version="1",
                                    payload={"driver": "nvlddmkm.sys",
                                             "image_sha256": sha,
                                             "luid": "00000000:b33b765e"}),
    )


def main() -> int:
    facts = json.loads((ROOT / "data" / "driver" / "f9_evidence.json").read_text(encoding="utf-8"))
    offsets = json.loads((ROOT / "data" / "driver" / "f9_offsets.json").read_text(encoding="utf-8"))
    image = PEImage(DRIVER)
    flow = scan_entry(image, int(facts["driver"]["entry_rva"], 16))
    table = scan_table(image, int(facts["driver"]["entry_rva"], 16))
    entry = int(facts["driver"]["entry_rva"], 16)
    table["base_binding"] = bound_base_register(image, entry)
    table["base_groups"] = classify_pairs(table)
    last_store = max((int(p["store_rva"], 16) for p in table["pairs"]), default=entry)
    table["consumer"] = trace_consumer(image, entry, last_store)
    table["candidate_bounds"] = function_bounds(image, 0x733e240)
    table["block_copy"] = scan_block_copy(image, entry)
    case = build_case(facts, offsets, flow, table)

    out = ROOT / "data" / "cases" / "nvlddmkm-610-47-escape.v2.json"
    out.write_text(case.model_dump_json(indent=1), encoding="utf-8")
    flow_out = ROOT / "data" / "driver" / "f9r2_entry_scan.json"
    flow_out.write_text(json.dumps(flow, ensure_ascii=False, indent=1), encoding="utf-8")
    (ROOT / "data" / "driver" / "f9r2_table.json").write_text(
        json.dumps(table, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"stores": len(flow["stores_to_0x110"]),
                      "table_pairs": table["count"],
                      "rejected": table["rejected_count"],
                      "rbp_writes": table["base_binding"]["writes"][:3],
                      "offset_0x110_target": next(
                          (r["target_rva"] for r in table["pairs"]
                           if r["field_offset"] == "0x110"), None)},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
