"""Standard-library content identity for platform observations, not attestation.

This module is also shipped to the fixed read-only Linux worker. Operational
metadata, provenance identifiers and executable paths are deliberately excluded.
"""

import hashlib
import json
from collections.abc import Mapping


SCIENTIFIC_FIELDS = (
    "schema_version", "platform_type", "execution_backend", "host_os", "kernel",
    "architecture", "python_version", "gpu_devices", "driver_release",
    "cuda_driver_api_version", "driver_reported_cuda_version",
    "cuda_toolkit_version", "nvcc_version", "supported_architectures",
    "compute_sanitizer_version", "host_compiler",
)


def _scientific_value(value):
    """Keep values and epistemic states; discard discovery/run bookkeeping."""
    if isinstance(value, Mapping):
        if "status" in value and "value" in value:
            return {"status": value["status"], "value": _scientific_value(value["value"])}
        return {
            key: _scientific_value(item)
            for key, item in value.items()
            if key not in {"source_ids", "method", "path", "command_id"}
            and not key.endswith("_path")
        }
    if isinstance(value, (list, tuple)):
        return [_scientific_value(item) for item in value]
    return value


def scientific_content(payload):
    """Return the canonical scientific subset of a snapshot mapping.

    Missing fields remain missing: this helper does not invent observations or
    validate the schema. Consumers validate with ``PlatformSnapshot`` separately.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("platform identity requires a snapshot mapping")
    result = {
        key: _scientific_value(payload[key])
        for key in SCIENTIFIC_FIELDS if key in payload
    }
    architectures = result.get("supported_architectures", {})
    if isinstance(architectures, dict) and isinstance(architectures.get("value"), list):
        architectures["value"] = sorted(architectures["value"])
    return result


def compute_environment_id(payload):
    """SHA-256 of scientific content; a local integrity identity, not proof."""
    canonical = json.dumps(
        scientific_content(payload), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
