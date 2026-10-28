# -*- coding: utf-8 -*-
"""A crash the CVE cannot claim is kept, not discarded."""

import json
from pathlib import Path

from src import novel_findings


LOG = """\
[CPG_LABEL] benign.cubin BENIGN
[CPG_RUN] benign.cubin exit=0
[CPG_LABEL] poc.cubin MALICIOUS
[CPG_RUN] poc.cubin exit=-11
[CPG_RUN] poc.cubin::nvdisasm exit=139
[CPG_LABEL] ctrl.cubin CONTROL
[CPG_RUN] ctrl.cubin::nvdisasm exit=0
"""


def test_both_spellings_are_parsed():
    crashes = novel_findings.parse_crashes(LOG)
    assert [crash.exit_code for crash in crashes] == [-11, 139]


def test_clean_runs_are_not_crashes():
    assert novel_findings.parse_crashes("[CPG_RUN] benign.cubin exit=0") == []


def test_supported_verdict_records_nothing(tmp_path):
    assert novel_findings.record(tmp_path, "CVE-X", LOG, "SUPPORTED", [], root=tmp_path / "n") == []


def test_one_record_per_artifact_even_with_two_exit_codes(tmp_path):
    (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
    written = novel_findings.record(tmp_path, "CVE-X", LOG, "NOT_VERIFIED",
                                    ["controls crashed"], root=tmp_path / "n")
    assert len(written) == 1
    finding = json.loads((written[0] / "finding.json").read_text(encoding="utf-8"))
    assert finding["artifact"] == "poc.cubin"
    assert finding["exit_code"] == 139          # the grader's run wins
    assert finding["tool"] == "nvdisasm"
    assert finding["triage"] == "UNTRIAGED"
    assert finding["sha256"]


def test_the_artifact_is_copied_next_to_its_record(tmp_path):
    (tmp_path / "poc.cubin").write_bytes(b"\x7fELF-payload")
    written = novel_findings.record(tmp_path, "CVE-X", LOG, "NOT_VERIFIED", [],
                                    root=tmp_path / "n")
    assert (written[0] / "poc.cubin").read_bytes() == b"\x7fELF-payload"
    assert "CPG_RUN" in (written[0] / "observation.txt").read_text(encoding="utf-8")


def test_listing_reads_every_record(tmp_path):
    (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
    novel_findings.record(tmp_path, "CVE-X", LOG, "NOT_VERIFIED", [], root=tmp_path / "n")
    rows = novel_findings.load_all(tmp_path / "n")
    assert len(rows) == 1 and rows[0]["cve_id"] == "CVE-X"


SITE_LOG = """\
[CPG_RUN] poc.cubin::nvdisasm exit=139
[CPG_CRASH] poc.cubin sig=11 pc=0x428b80 base=0x400000 off=0x28b80 addr=0x0 module=nvdisasm
"""


def test_the_fault_site_becomes_the_fingerprint():
    crash = novel_findings.parse_crashes(SITE_LOG)[0]
    assert crash.module == "nvdisasm"
    assert crash.offset == 0x28B80
    assert crash.address == 0
    assert crash.fingerprint == "nvdisasm+0x28000"      # 4 KB bucket


def test_nearby_offsets_share_a_fingerprint():
    """Two instructions in one function are one bug far more often than two."""
    a = novel_findings.Crash("x.cubin", 139, module="nvdisasm", offset=0x28010)
    b = novel_findings.Crash("y.cubin", 139, module="nvdisasm", offset=0x28FF0)
    assert a.fingerprint == b.fingerprint


def test_without_a_site_the_exit_code_is_the_fingerprint():
    crash = novel_findings.parse_crashes(LOG)[1]
    assert crash.fingerprint.startswith("exit:")


def test_the_same_fault_is_not_recorded_twice(tmp_path):
    (tmp_path / "poc.cubin").write_bytes(b"\x7fELF")
    first = novel_findings.record(tmp_path, "CVE-X", SITE_LOG, "NOT_VERIFIED", [],
                                  root=tmp_path / "n")
    second = novel_findings.record(tmp_path, "CVE-X", SITE_LOG, "NOT_VERIFIED", [],
                                   root=tmp_path / "n")
    assert len(first) == 1
    assert second == []                                  # same place, same bug


def test_the_faulting_instruction_is_read_and_classified():
    line = ("[CPG_RUN] p.cubin::nvdisasm exit=139\n"
            "[CPG_CRASH] p.cubin sig=11 code=1 pc=0x428b80 base=0x400000 "
            "off=0x28b80 addr=0x0 module=nvdisasm insn=803f00744b\n")
    crash = novel_findings.parse_crashes(line)[0]
    assert crash.insn == "803f00744b"
    assert crash.access == "read"
    assert crash.severity == "null-read"
    assert "cmp" in crash.instruction
