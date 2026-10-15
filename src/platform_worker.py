"""Fixed, standard-library-only, read-only platform probe worker.

The same source bundle is used by local and WSL subprocesses. The request only
sets bounds and run labels; it cannot provide commands or filesystem targets.
"""

import base64
import csv
import glob
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time
from datetime import datetime, timezone


def _load_function(filename, name):
    spec = importlib.util.spec_from_file_location(
        "_cuda_probe_" + Path(filename).stem, Path(__file__).with_name(filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, name)


if "run_bounded" not in globals():
    if __package__:
        from .probe_process import run_bounded
    else:
        run_bounded = _load_function("probe_process.py", "run_bounded")
if "compute_environment_id" not in globals():
    if __package__:
        from .platform_identity import compute_environment_id
    else:
        compute_environment_id = _load_function("platform_identity.py", "compute_environment_id")


def field(status="UNKNOWN", value=None, sources=(), method="not observed"):
    return {"status": status, "value": value, "source_ids": list(sources), "method": method}


def _decode(record, stream="stdout"):
    return base64.b64decode(record[stream + "_b64"]).decode("utf-8", errors="replace")


def _find_tool(name):
    """Find an existing executable in this environment, never a foreign path."""
    found = shutil.which(name)
    if found and os.path.isfile(found):
        return os.path.abspath(found)
    is_win = os.name == "nt"
    suffix = ".exe" if is_win else ""
    candidates = []
    for variable in ("CUDA_PATH", "CUDA_ROOT", "CUDA_HOME"):
        root = os.environ.get(variable, "")
        if root and (is_win or not re.match(r"^[A-Za-z]:", root)):
            candidates.append(os.path.join(root, "bin", name + suffix))
    if is_win:
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(variable)
            if root:
                candidates += sorted(glob.glob(os.path.join(
                    root, "NVIDIA GPU Computing Toolkit", "CUDA", "v*", "bin", name + suffix
                )), reverse=True)
        if name == "cl":
            for variable in ("ProgramFiles", "ProgramFiles(x86)"):
                root = os.environ.get(variable)
                if root:
                    candidates += sorted(glob.glob(os.path.join(
                        root, "Microsoft Visual Studio", "*", "*", "VC", "Tools", "MSVC",
                        "*", "bin", "Hostx64", "x64", "cl.exe"
                    )), reverse=True)
    else:
        if name == "nvidia-smi":
            candidates.append("/usr/lib/wsl/lib/nvidia-smi")
        candidates += sorted(glob.glob("/usr/local/cuda*/bin/" + name), reverse=True)
        if name == "compute-sanitizer":
            candidates += sorted(glob.glob("/usr/local/cuda*/compute-sanitizer/compute-sanitizer"), reverse=True)
    for candidate in candidates:
        if os.path.isfile(candidate) and (is_win or os.access(candidate, os.X_OK)):
            return os.path.abspath(candidate)
    return None


def _compiler_version(text, name):
    if name == "cl":
        match = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)*)", text)
        if match:
            return match.group(1)
        # Localized MSVC banners keep the ASCII build number. Accept only a
        # single unambiguous dotted build, from cl with no source input.
        builds = set(re.findall(r"\b[0-9]+\.[0-9]+\.[0-9]+\b", text))
        return next(iter(builds)) if len(builds) == 1 else None
    match = re.search(r"\b\d+\.\d+(?:\.\d+)*\b", text.splitlines()[0] if text.splitlines() else "")
    return match.group() if match else None


def probe_platform(request, runner=None):
    """Return a nonce-bound snapshot and exact bounded command evidence."""
    runner = runner or run_bounded
    backend = request.get("execution_backend", request.get("backend", "local"))
    if backend not in ("local", "wsl"):
        raise ValueError("execution_backend must be local or wsl")
    host_os = platform.system()
    kernel = platform.version() if host_os == "Windows" else platform.release()
    is_wsl = host_os == "Linux" and "microsoft" in kernel.lower()
    platform_type = "wsl" if is_wsl else ("windows" if host_os == "Windows" else "linux")
    environment = str(request.get("environment_label", backend))
    distro = None
    if is_wsl:
        distro = os.environ.get("WSL_DISTRO_NAME", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", distro) or distro != distro.strip():
            raise ValueError("WSL distribution identity is unavailable or malformed")
        actual_environment = "wsl:" + distro
        if environment not in {"local", "wsl", actual_environment}:
            raise ValueError("requested probe target differs from the observed WSL distribution")
        environment = actual_environment
    elif backend == "wsl" or environment.startswith("wsl:"):
        raise ValueError("WSL request reached a non-WSL environment")
    timeout = float(request.get("command_timeout_seconds", request.get("timeout_seconds", 3)))
    limit = int(request.get("max_output_bytes", 32768))
    budget = float(request.get("total_budget_seconds", 40))
    if not (0 < timeout <= 10 and 1024 <= limit <= 1048576 and 0 < budget <= 120):
        raise ValueError("probe bounds outside the permitted range")
    commands, provenance, diagnostics = [], {}, []
    deadline = time.monotonic() + budget

    def source(source_id, method, command_id=None):
        provenance[source_id] = {"method": method, "environment": environment, "command_id": command_id}

    def command(command_id, argv, expected_codes=(0,)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostics.append({"code": "PROBE_BUDGET_EXHAUSTED", "field": command_id,
                                "message": "No further tool query was started."})
            return None
        result = runner(argv, timeout_seconds=min(timeout, remaining), max_output_bytes=limit,
                        environment=environment, command_id=command_id)
        commands.append(result)
        source(command_id, "fixed argv read-only tool query", command_id)
        if result["status"] != "COMPLETED" or result["returncode"] not in expected_codes:
            diagnostics.append({"code": "TOOL_QUERY_FAILED", "field": command_id,
                                "message": "Tool query failed; see its exact command record."})
        return result

    def success(record):
        return bool(record and record["status"] == "COMPLETED" and record["returncode"] == 0)

    def observed(value, sources, method):
        return field("OBSERVED", value, sources, method)

    source("python_stdlib", "sys.version / platform module")
    source("filesystem", "existing executable discovery in this environment")
    snapshot = {
        "schema_version": "1.0",
        "platform_type": platform_type,
        "execution_backend": backend,
        "host_os": observed(host_os, ["python_stdlib"], "platform.system"),
        "kernel": observed(kernel, ["python_stdlib"], "platform.version (Windows) / platform.release (Linux)"),
        "architecture": observed(platform.machine(), ["python_stdlib"], "platform.machine"),
        "python_version": observed(platform.python_version(), ["python_stdlib"], "platform.python_version"),
        "gpu_devices": field(), "driver_release": field(),
        "cuda_driver_api_version": field("NOT_CHECKED", method="CUDA Driver API not loaded by read-only probe"),
        "driver_reported_cuda_version": field(), "cuda_toolkit_version": field(),
        "nvcc_path": field(), "nvcc_version": field(), "supported_architectures": field(),
        "compute_sanitizer_path": field(), "compute_sanitizer_version": field(),
        "host_compiler": field(), "probe_status": "COMPLETE",
        "provenance": provenance, "diagnostics": diagnostics,
        "metadata": {"probe_id": str(request.get("probe_id", "")),
                     "nonce": str(request.get("nonce", "")),
                     "started_at": datetime.now(timezone.utc).isoformat(),
                     "environment_label": environment,
                     "platform_classification": field("INFERRED" if is_wsl else "OBSERVED", platform_type,
                                                       ["python_stdlib"], "platform.system and kernel WSL marker"),
                     "backend_selection": field("CONFIGURED", backend, [], "explicit dispatcher selection"),
                     "smoke_test": "NOT_RUN", "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED"},
    }
    if distro is not None:
        source("wsl_environment", "read current-process WSL_DISTRO_NAME")
        snapshot["metadata"]["wsl_distribution"] = observed(
            distro, ["wsl_environment"], "WSL distribution process environment; not hardware attestation")
    if host_os == "Linux":
        try:
            release_bytes = Path("/etc/os-release").read_bytes()
            release = {}
            for line in release_bytes.decode("utf-8", errors="replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    release[key] = value.strip('"')
            source("os_release", "read /etc/os-release")
            if release.get("PRETTY_NAME"):
                snapshot["host_os"] = observed(release["PRETTY_NAME"], ["os_release"], "read /etc/os-release PRETTY_NAME")
            snapshot["metadata"]["os_release"] = release
            snapshot["metadata"]["os_release_raw_b64"] = base64.b64encode(release_bytes).decode("ascii")
        except OSError:
            diagnostics.append({"code": "OS_RELEASE_UNAVAILABLE", "field": "host_os",
                                "message": "/etc/os-release could not be read."})

    smi = _find_tool("nvidia-smi")
    if smi:
        gpu_record = command("gpu_query", [smi, "--query-gpu=index,name,compute_cap,driver_version", "--format=csv,noheader"])
        with_cap = success(gpu_record)
        if not with_cap:
            gpu_record = command("gpu_query_fallback", [smi, "--query-gpu=index,name,driver_version", "--format=csv,noheader"])
        if success(gpu_record):
            sid = gpu_record["command_id"]
            devices, drivers = [], []
            malformed = False
            for row in csv.reader(io.StringIO(_decode(gpu_record))):
                if not row or not any(cell.strip() for cell in row):
                    continue
                if len(row) != (4 if with_cap else 3):
                    malformed = True
                    continue
                row = [cell.strip() for cell in row]
                if not row[0].isdigit() or not row[1]:
                    malformed = True
                    continue
                device = {"index": observed(int(row[0]), [sid], "nvidia-smi GPU index"),
                          "name": observed(row[1], [sid], "nvidia-smi GPU name"),
                          "compute_capability": field(method="nvidia-smi compute_cap unavailable"),
                          "sm_arch": field(method="no measured compute capability")}
                if with_cap and re.fullmatch(r"\d+\.\d+", row[2]):
                    device["compute_capability"] = observed(row[2], [sid], "nvidia-smi compute_cap")
                    major, minor = row[2].split(".")
                    device["sm_arch"] = field("INFERRED", f"sm_{int(major)}{int(minor)}", [sid],
                                              "architecture notation derived from measured compute_cap")
                driver = row[3 if with_cap else 2]
                if re.fullmatch(r"\d+(?:\.\d+)+", driver):
                    drivers.append(driver)
                devices.append(device)
            if malformed:
                snapshot["gpu_devices"] = field("FAILED", sources=[sid], method="malformed GPU CSV")
                diagnostics.append({"code": "GPU_RESPONSE_INVALID", "field": "gpu_devices", "message": "GPU query returned malformed CSV."})
            else:
                snapshot["gpu_devices"] = observed(devices, [sid], "nvidia-smi per-device CSV query")
            if drivers and len(set(drivers)) == 1:
                snapshot["driver_release"] = observed(drivers[0], [sid], "nvidia-smi driver_version")
            elif len(set(drivers)) > 1:
                snapshot["driver_release"] = field("FAILED", sources=[sid], method="conflicting per-device driver releases")
        else:
            snapshot["gpu_devices"] = field("FAILED", sources=[r["command_id"] for r in commands], method="GPU query failed")
            snapshot["driver_release"] = field("FAILED", method="driver query failed")
        banner = command("smi_banner", [smi])
        if success(banner):
            match = re.search(r"CUDA Version\s*:\s*([0-9]+\.[0-9]+)", _decode(banner))
            if match:
                snapshot["driver_reported_cuda_version"] = observed(
                    match.group(1), ["smi_banner"], "nvidia-smi banner CUDA compatibility, not Driver API or Toolkit")
            else:
                umd = re.search(r"CUDA UMD Version\s*:\s*([0-9]+\.[0-9]+)", _decode(banner))
                if umd:
                    snapshot["metadata"]["reported_cuda_umd_version"] = observed(
                        umd.group(1), ["smi_banner"], "literal CUDA UMD Version banner label; not mapped to maximum compatibility")
                diagnostics.append({"code": "DRIVER_COMPATIBILITY_UNKNOWN", "field": "driver_reported_cuda_version",
                                    "message": "No CUDA Version compatibility label was returned; UMD labels are not substituted."})
        else:
            snapshot["driver_reported_cuda_version"] = field("FAILED", method="nvidia-smi banner query failed")
    else:
        diagnostics.append({"code": "NVIDIA_SMI_MISSING", "field": "gpu_devices", "message": "nvidia-smi was not found; GPU accessibility is unknown."})

    nvcc = _find_tool("nvcc")
    if nvcc:
        snapshot["nvcc_path"] = observed(nvcc, ["filesystem"], "existing nvcc executable discovery")
        version = command("nvcc_version", [nvcc, "--version"])
        if success(version):
            text = _decode(version)
            match = re.search(r"release\s+(\d+\.\d+)", text)
            full = re.search(r"\bV(\d+\.\d+(?:\.\d+)?)", text)
            if match:
                snapshot["cuda_toolkit_version"] = observed(match.group(1), ["nvcc_version"], "nvcc --version release")
                snapshot["nvcc_version"] = observed(full.group(1) if full else match.group(1), ["nvcc_version"], "nvcc --version compiler build")
            else:
                snapshot["cuda_toolkit_version"] = field("FAILED", sources=["nvcc_version"], method="nvcc version text not recognized")
                snapshot["nvcc_version"] = field("FAILED", sources=["nvcc_version"], method="nvcc version text not recognized")
        else:
            for key in ("nvcc_version", "cuda_toolkit_version"):
                snapshot[key] = field("FAILED", method="nvcc version query failed")
        code = command("nvcc_gpu_code", [nvcc, "--list-gpu-code"])
        arch = command("nvcc_gpu_arch", [nvcc, "--list-gpu-arch"])
        if success(code) and success(arch):
            entries = sorted(set(re.findall(r"\b(?:sm|compute)_\d+[a-z]?\b", _decode(code) + "\n" + _decode(arch))))
            snapshot["supported_architectures"] = observed(entries, ["nvcc_gpu_code", "nvcc_gpu_arch"], "nvcc --list-gpu-code and --list-gpu-arch") if entries else field("FAILED", method="nvcc architecture output not recognized")
        else:
            snapshot["supported_architectures"] = field("FAILED", method="nvcc architecture query failed")
    else:
        diagnostics.append({"code": "NVCC_MISSING", "field": "nvcc_path", "message": "nvcc was not found; Toolkit and supported architectures remain unknown."})

    sanitizer = _find_tool("compute-sanitizer")
    if sanitizer:
        snapshot["compute_sanitizer_path"] = observed(sanitizer, ["filesystem"], "existing Compute Sanitizer executable discovery")
        record = command("sanitizer_version", [sanitizer, "--version"])
        if success(record):
            match = re.search(r"(?:version\s*:?\s*)(\d+\.\d+(?:\.\d+)*)", _decode(record) + "\n" + _decode(record, "stderr"), re.IGNORECASE)
            snapshot["compute_sanitizer_version"] = observed(match.group(1), ["sanitizer_version"], "compute-sanitizer --version") if match else field("FAILED", method="Compute Sanitizer version output not recognized")
        else:
            snapshot["compute_sanitizer_version"] = field("FAILED", method="Compute Sanitizer version query failed")
    else:
        diagnostics.append({"code": "SANITIZER_MISSING", "field": "compute_sanitizer_path", "message": "Compute Sanitizer executable was not found."})

    compilers, compiler_sources = {}, []
    for name in (["cl"] if os.name == "nt" else ["gcc", "g++"]):
        path = _find_tool(name)
        key = "msvc" if name == "cl" else name
        if not path:
            compilers[key] = field(method="host compiler executable not found")
            continue
        cid = {"gcc": "gcc_version", "g++": "gxx_version", "cl": "msvc_version"}[name]
        record = command(cid, [path] if name == "cl" else [path, "--version"], expected_codes=(0, 2) if name == "cl" else (0,))
        text = _decode(record) + "\n" + _decode(record, "stderr") if record else ""
        # cl invoked without source prints its version then exits 2; no compilation.
        valid = bool(record and record["status"] == "COMPLETED" and
                     (record["returncode"] == 0 or (name == "cl" and record["returncode"] == 2)))
        version = _compiler_version(text, name)
        compilers[key] = observed(version, [cid], "host compiler version query") if valid and version else field("FAILED", sources=[cid] if record else [], method="host compiler query failed or version output unrecognized")
        compiler_sources += [cid] if record else []
    # The mapping is observed by executable discovery even if a compiler is missing.
    snapshot["host_compiler"] = observed(compilers, ["filesystem"] + compiler_sources, "per-compiler discovery and version queries")
    if diagnostics or any(value.get("status") in ("UNKNOWN", "FAILED") for value in snapshot.values() if isinstance(value, dict)):
        snapshot["probe_status"] = "PARTIAL"
    devices = snapshot["gpu_devices"]["value"] or []
    if any(d["compute_capability"]["status"] in ("UNKNOWN", "FAILED") for d in devices):
        snapshot["probe_status"] = "PARTIAL"
    if any(item["status"] in ("UNKNOWN", "FAILED") for item in compilers.values()):
        snapshot["probe_status"] = "PARTIAL"
    snapshot["environment_id"] = compute_environment_id(snapshot)
    return {"protocol_version": "1.0", "nonce": str(request.get("nonce", "")),
            "worker_exit_code": 0, "snapshot": snapshot, "commands": commands}


def build_worker_source(request):
    """Package only trusted local source plus JSON data, with no shell command."""
    root = Path(__file__).parent
    chunks = ["import json\nPROBE_REQUEST = json.loads(" + repr(json.dumps(request, ensure_ascii=True)) + ")\n"]
    for filename in ("probe_process.py", "platform_identity.py", "platform_worker.py"):
        source = (root / filename).read_text(encoding="utf-8")
        source = "\n".join(line for line in source.splitlines()
                           if line.strip() != "from __future__ import annotations")
        chunks.append(source)
    return "\n\n".join(chunks).encode("utf-8")


def main(request=None):
    request = request if request is not None else globals().get("PROBE_REQUEST", {})
    packet = probe_platform(request)
    raw = (json.dumps(packet, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
