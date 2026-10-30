# -*- coding: utf-8 -*-
"""Attribution must refuse to guess when several advisories fit."""

from src.attribute import KNOWN, NEW, UNPUBLISHED, UNRESOLVED, attribute, short

CATALOG = {
    "CVE-2024-0076": {"component": "NVIDIA CUDA cuobjdump + nvdisasm", "fixed_in": "12.4"},
    "CVE-2025-23339": {"component": "cuobjdump DWARF", "fixed_in": "13.0"},
    "CVE-2025-23247": {"component": "cuobjdump .nv_debug_source", "fixed_in": "13.0"},
    "CVE-2025-23340": {"component": "nvdisasm SHT_RELA", "fixed_in": "13.0"},
}


def _site(crashed, clean):
    versions = {}
    for image in crashed:
        versions["nvidia/cuda:%s.0-devel-ubuntu24.04" % image] = True
    for image in clean:
        versions["nvidia/cuda:%s.0-devel-ubuntu24.04" % image] = False
    return {"versions": versions}


def test_release_labels_compare_by_major_minor():
    assert short("nvidia/cuda:13.0.0-devel-ubuntu24.04") == "13.0"
    assert short("cpg/cuda112-py3:1.0") == "11.2"


def test_one_matching_advisory_is_attributed():
    """12.4 崩 / 13.0 不崩 - only 23339 and 23247 fit, so not unique."""
    verdict = attribute("cuobjdump+0x68000", _site(["12.4"], ["13.0"]), CATALOG)
    assert verdict["verdict"] == UNRESOLVED
    assert "23339" in verdict["cve"] and "23247" in verdict["cve"]


def test_a_unique_fit_attributes_to_its_cve():
    """A site that stops crashing at 12.4 matches only 0076."""
    verdict = attribute("cuobjdump+0xb000", _site(["11.2"], ["12.4"]), CATALOG)
    assert verdict["verdict"] == KNOWN and verdict["cve"] == "CVE-2024-0076"


def test_a_component_with_no_advisory_is_reported_as_new():
    verdict = attribute("libc.so.6+0x183000", _site(["12.4"], ["13.0"]), CATALOG)
    assert verdict["verdict"] == NEW


def test_an_advisory_without_a_fix_version_cannot_be_used():
    catalog = {"CVE-XXXX": {"component": "cuobjdump", "fixed_in": ""}}
    verdict = attribute("cuobjdump+0x1", _site(["12.4"], ["13.0"]), catalog)
    assert verdict["verdict"] in (UNPUBLISHED, "无法判定（缺版本数据）")


def test_a_site_that_never_stops_crashing_is_not_attributed():
    verdict = attribute("cuobjdump+0x1", _site(["12.4"], []), CATALOG)
    assert verdict["verdict"] == UNPUBLISHED
