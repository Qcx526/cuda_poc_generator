"""Private probe evidence and deterministic, redacted human summaries."""

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat


def protect_directory(path):
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise OSError("Private evidence permissions could not be enforced; use a native Linux filesystem")
        return {"status": "APPLIED", "method": "POSIX directory 0700 / files 0600"}
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = wintypes.HANDLE()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    sid_text, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise OSError("Probe evidence ACL token query failed")
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError("Probe evidence identity query failed")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError("Probe evidence SID conversion failed")
        sddl = f"D:P(A;OICI;FA;;;{sid_text.value})(A;OICI;FA;;;SY)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError("Probe evidence ACL construction failed")
        if not advapi.SetFileSecurityW(str(path.resolve()), 0x80000004, descriptor):
            raise OSError("Private probe directory ACL could not be applied")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)
    return {"status": "APPLIED", "method": "protected Windows DACL: current process user and SYSTEM"}


def _public_value(name, observation):
    if observation["value"] is None:
        return "unknown"
    if name.endswith("_path"):
        return "[private directory]/" + str(observation["value"]).replace("\\", "/").rsplit("/", 1)[-1]
    if name == "gpu_devices":
        return str([{"index": d["index"]["value"], "name": d["name"]["value"],
                     "compute_capability": d["compute_capability"]["value"],
                     "sm_arch": d["sm_arch"]["value"]} for d in observation["value"]])
    return str(observation["value"])


def render_report(result):
    lines = ["# Read-only platform probe report", "", "This is a platform observation record, not a vulnerability verification report.",
             "Candidate execution: NOT_EXECUTED. Vulnerability verification: NOT_VERIFIED.", "",
             "Probe status: " + result["status"], ""]
    for label, snapshot in (("Development host (local)", result.get("host_snapshot")),
                            ("Selected target", result.get("snapshot"))):
        lines.extend(["## " + label, ""])
        if snapshot is None:
            lines.append("No validated current snapshot. Windows/WSL information is never substituted.")
            lines.append("")
            continue
        lines.extend([f"Platform: {snapshot['platform_type']}; backend: {snapshot['execution_backend']}",
                      "Content identity: " + snapshot["environment_id"] + " (local integrity hash, not hardware attestation)",
                      "", "| Field | Status | Value (redacted) | Source / method |", "|---|---|---|---|"])
        for name, item in snapshot.items():
            if isinstance(item, dict) and "status" in item and "value" in item:
                value = _public_value(name, item).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
                lines.append(f"| {name} | {item['status']} | {value} | {', '.join(item['source_ids'])}: {item['method']} |")
        lines.extend(["", "Compiler/GPU queries are not compile, kernel, or PoC execution tests. Smoke: NOT_RUN.", ""])
        umd = snapshot["metadata"].get("reported_cuda_umd_version")
        if umd:
            lines.extend(["Additional literal banner field: CUDA UMD Version " + str(umd["value"])
                          + " (source smi_banner; not substituted for Driver API or maximum compatibility).", ""])
    lines.extend(["## Transport and diagnostics", "", "Launcher return code: " + str(result["transport"].get("launcher_returncode")),
                  "Worker reported exit code: " + str(result["transport"].get("worker_reported_exit_code")),
                  "A killed WSL launcher does not prove remote process termination; the worker also has its own time bounds.", ""])
    for diagnostic in result["diagnostics"]:
        lines.append("- " + diagnostic["code"] + ": " + diagnostic["message"])
    lines.extend(["", "Original logs and argv are private in this directory; commands.json contains exact byte encodings and digests.",
                  "This summary is generated deterministically without an LLM.", ""])
    return "\n".join(lines)


def write_probe_artifacts(root, result):
    folder = Path(root) / result["probe_id"]
    protection = protect_directory(folder)

    def write(name, data):
        destination = folder / name
        destination.write_bytes(data)
        if os.name != "nt":
            destination.chmod(0o600)
            if stat.S_IMODE(destination.stat().st_mode) != 0o600:
                raise OSError("Private evidence file permissions could not be enforced")

    def json_file(name, value):
        write(name, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))

    json_file("platform_snapshot.json", result["snapshot"])
    if result.get("host_snapshot") is not None:
        json_file("host_snapshot.json", result["host_snapshot"])
    json_file("commands.json", result["commands"])
    write("probe_stdout.log", base64.b64decode(result["stdout_b64"]))
    write("probe_stderr.log", base64.b64decode(result["stderr_b64"]))
    public = {key: value for key, value in result.items() if key not in {"commands", "stdout_b64", "stderr_b64", "snapshot", "host_snapshot"}}
    public["access_control"] = protection
    public["artifacts"] = {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in folder.iterdir() if item.is_file()
    }
    json_file("probe_result.json", public)
    write("probe_report.md", render_report(result).encode("utf-8"))
    return folder
