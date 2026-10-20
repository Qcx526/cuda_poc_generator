# -*- coding: utf-8 -*-
"""Sample discovery with explicit labels.

Artifact names are the only labelling channel in this project, so discovery
must apply the same rules as the grader. A file whose name carries no marker
gets no label: guessing would let a control masquerade as a trigger.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .reproduction import label_for

SUFFIXES = (".cubin", ".elf", ".bin", ".ptx", ".dxbc", ".fatbin")


@dataclass(frozen=True)
class Sample:
    """One artifact on disk plus the role its name declares."""

    name: str
    path: Path
    label: str  # MALICIOUS | BENIGN | CONTROL | UNKNOWN


def discover(directory: Path) -> List[Sample]:
    """List candidate artifacts in ``directory``, labels derived from names."""
    if not directory.is_dir():
        return []
    found: List[Sample] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_file() or entry.suffix.lower() not in SUFFIXES:
            continue
        found.append(Sample(name=entry.name, path=entry,
                            label=label_for(entry.name)))
    return found


def apply_manifest(samples: List[Sample], manifest: dict) -> List[Sample]:
    """Override labels for names that resolve to UNKNOWN.

    ``manifest`` maps file name to one of MALICIOUS/BENIGN/CONTROL. Overriding a
    recognisable name is refused, for the same reason the grader refuses it.
    """
    allowed = {"MALICIOUS", "BENIGN", "CONTROL"}
    resolved: List[Sample] = []
    for sample in samples:
        override: Optional[str] = manifest.get(sample.name)
        if override is None:
            resolved.append(sample)
            continue
        if override not in allowed:
            raise ValueError("manifest label must be MALICIOUS, BENIGN or CONTROL")
        if sample.label != "UNKNOWN":
            raise ValueError("cannot override the label of %r" % sample.name)
        resolved.append(Sample(name=sample.name, path=sample.path,
                               label=override))
    return resolved


def summarise(samples: List[Sample]) -> dict:
    """Counts per role; used in the loop report."""
    counts = {"MALICIOUS": 0, "BENIGN": 0, "CONTROL": 0, "UNKNOWN": 0}
    for sample in samples:
        counts[sample.label] = counts.get(sample.label, 0) + 1
    return counts
