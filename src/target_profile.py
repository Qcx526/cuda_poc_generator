"""Derive a target-environment profile from normalized CVE input dimensions.

The profile answers one question before any sandbox exists: which execution
prerequisites does this CVE actually impose? It is a read-only derivation from
the seven input dimensions. It never launches a process, never inspects the
host and never grants a candidate execution authority.

Keeping the profile host-independent matters: a CVE "needs a pinned cuobjdump
11.2" regardless of whether the current machine happens to have one. Whether
the host can supply that is a separate, later admission question.
"""

import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .models.normalized_input import normalize_input_files

EnvironmentClass = Literal["USERLAND_TOOL", "GPU_LIBRARY", "NETWORK_SERVICE", "DRIVER", "UNKNOWN"]
IsolationTier = Literal["CONTAINER_CPU", "CONTAINER_GPU", "CONTAINER_SERVICE", "DEDICATED_HOST",
                        "UNCLASSIFIED"]
AutomationTier = Literal["FULL_AUTO", "SUPERVISED", "GPU_WATCHDOG", "MANUAL_ONLY", "NOT_ALLOWED"]
InputKind = Literal["FILE", "NETWORK_REQUEST", "API_CALL", "UNKNOWN"]

# An explicit "not needed / not involved" statement is evidence; silence is not.
_NO_GPU = re.compile(
    r"纯\s*CPU|CPU[- ]only|not\s+required|不依赖|无需\s*GPU|不涉及\s*GPU|不参与|无关|^n/?a\b",
    re.IGNORECASE,
)
_NETWORK = re.compile(r"https?://|grpc|网络请求|服务端|远程", re.IGNORECASE)
# Only components that live in the display/compiler driver stack are DRIVER
# targets. A bare "驱动" substring is not enough: inputs routinely say
# "非驱动" to rule that out.
_DRIVER_TOKENS = ("nvgpucomp", "nvlddmkm", "nvwgf2um", "display driver", "compiler driver",
                  "显示驱动")
# Libraries whose defect sits above the GPU API layer but still need a device.
# A bare "cuda" token is deliberately absent: it matches "CUDA Toolkit" in the
# labels of CPU-only tools and would flip them into GPU targets.
_GPU_LIBRARIES = ("cudnn", "cublas", "tensorrt", "cv-cuda", "nvjpeg", "nvdec", "nvrtc",
                  "cutlass")
_USERLAND_HINTS = ("命令行", "gui", "分析器", "解析器", "工具")


class TargetEnvironmentProfile(BaseModel):
    """Host-independent execution prerequisites for one CVE.

    ``automation_tier`` describes the strongest automation this *class* of
    target may receive. It is not an authorization; it is an upper bound that a
    later admission decision must still respect.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    profile_schema_version: Literal["1.0"] = "1.0"
    cve_id: str = Field(min_length=1)
    environment_class: EnvironmentClass
    requires_gpu: bool
    tools: List[str]
    input_kind: InputKind
    needs_network: bool
    isolation_tier: IsolationTier
    automation_tier: AutomationTier
    reasons: List[str] = Field(min_length=1)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(_text(item) for item in value.values())
    return ""


def _dimension(dimensions: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = dimensions.get(key)
    return value if isinstance(value, dict) else {}


def _collect_tools(dimensions: Dict[str, Any]) -> List[str]:
    """Read declared tool names, never splitting on an ASCII hyphen.

    Component labels separate a tool from its subsystem with an em dash or a
    colon. Splitting on "-" would turn "CV-CUDA" into "CV".
    """
    found: List[str] = []
    for key in ("cuda_environment", "affected_component"):
        dimension = _dimension(dimensions, key)
        declared = dimension.get("affected_tools")
        if isinstance(declared, list):
            for item in declared:
                if isinstance(item, str) and item.strip() and item.strip() not in found:
                    found.append(item.strip())
        name = dimension.get("name") or dimension.get("component_name")
        if isinstance(name, str) and name.strip():
            head = re.split(r"[—–:|]", name, maxsplit=1)[0].strip()
            if head and len(head) <= 40 and head not in found:
                found.append(head)
    return found


def _requires_gpu(dimensions: Dict[str, Any], tools: List[str]) -> bool:
    cuda = _dimension(dimensions, "cuda_environment")
    arch = _text(cuda.get("gpu_architecture")) + " " + _text(cuda.get("compute_capability"))
    declared = _text(cuda.get("cuda_driver_version"))
    if arch.strip() and _NO_GPU.search(arch):
        # The architecture field may say "N/A because the defect is in the
        # Python layer" while the library still needs a device to run at all.
        lowered = " ".join(tools).lower() + " " + _text(
            _dimension(dimensions, "affected_component").get("type")).lower()
        return any(token in lowered for token in _GPU_LIBRARIES)
    if not arch.strip():
        return False
    return not _NO_GPU.search(declared)


def _input_kind(dimensions: Dict[str, Any]) -> InputKind:
    surface = _dimension(dimensions, "attack_surface")
    component = _dimension(dimensions, "affected_component")
    entry = _text(surface.get("entry_type")) + " " + _text(surface.get("entry_point"))
    if _NETWORK.search(entry):
        return "NETWORK_REQUEST"
    fmt = _text(component.get("file_format_input"))
    if fmt.strip() and not _NO_GPU.search(fmt):
        return "FILE"
    if "文件" in entry or "file" in entry.lower():
        return "FILE"
    if "api" in entry.lower():
        return "API_CALL"
    return "UNKNOWN"


def classify_target(dimensions: Dict[str, Any], cve_id: Optional[str] = None) -> TargetEnvironmentProfile:
    """Classify one CVE from its normalized seven dimensions.

    Precedence is explicit and ordered: a driver defect stays a driver target
    even when a userland tool name also appears. Every decision records a reason
    so a later reader can disagree with a specific rule rather than the verdict.
    """
    if not isinstance(dimensions, dict):
        raise ValueError("dimensions must be a mapping")
    component = _dimension(dimensions, "affected_component")
    cve = cve_id or _text(component.get("cve_id"))
    if not cve:
        for value in dimensions.values():
            if isinstance(value, dict) and isinstance(value.get("cve_id"), str) and value["cve_id"]:
                cve = value["cve_id"]
                break
    if not cve:
        raise ValueError("a target profile requires a CVE identifier")

    tools = _collect_tools(dimensions)
    identity = (_text(component.get("name")) + " " + _text(component.get("type")) + " "
                + " ".join(tools))
    lowered = identity.lower()
    requires_gpu = _requires_gpu(dimensions, tools)
    input_kind = _input_kind(dimensions)
    needs_network = input_kind == "NETWORK_REQUEST"
    reasons: List[str] = []

    is_driver = any(token in lowered for token in _DRIVER_TOKENS)
    if is_driver:
        environment_class: EnvironmentClass = "DRIVER"
        isolation: IsolationTier = "DEDICATED_HOST"
        automation: AutomationTier = "MANUAL_ONLY"
        requires_gpu = True
        reasons.append("component lives in the GPU display/compiler driver stack")
        reasons.append("a container shares the host driver, so rollback needs a disposable host")
    elif needs_network:
        environment_class = "NETWORK_SERVICE"
        isolation = "CONTAINER_SERVICE"
        automation = "SUPERVISED"
        reasons.append("entry point is a network service, so the run needs a start/health/stop protocol")
    elif requires_gpu:
        environment_class = "GPU_LIBRARY"
        isolation = "CONTAINER_GPU"
        automation = "GPU_WATCHDOG"
        reasons.append("the trigger needs a GPU device; a wedged device is a host-level failure")
    elif tools or any(hint in lowered for hint in _USERLAND_HINTS):
        environment_class = "USERLAND_TOOL"
        isolation = "CONTAINER_CPU"
        automation = "FULL_AUTO"
        reasons.append("userland tool with no GPU requirement; blast radius is one container process")
    else:
        environment_class = "UNKNOWN"
        isolation = "UNCLASSIFIED"
        automation = "NOT_ALLOWED"
        reasons.append("inputs declare neither a GPU requirement nor an executable tool")

    if not requires_gpu:
        reasons.append("the CUDA dimensions state no GPU participation")
    if input_kind == "FILE":
        reasons.append("the trigger consumes a file, so inputs can be mounted read-only")
    return TargetEnvironmentProfile(
        cve_id=cve,
        environment_class=environment_class,
        requires_gpu=requires_gpu,
        tools=tools,
        input_kind=input_kind,
        needs_network=needs_network,
        isolation_tier=isolation,
        automation_tier=automation,
        reasons=reasons,
    )


def profile_from_input_dir(directory: str) -> TargetEnvironmentProfile:
    """Normalize a CVE input directory, then classify it without side effects."""
    bundle = normalize_input_files(directory)
    bundle.require_valid()
    return classify_target(bundle.dimensions, cve_id=bundle.cve_id)
