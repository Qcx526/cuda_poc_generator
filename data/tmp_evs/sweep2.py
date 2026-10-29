"""Find the exact acceptance edge of the SINCOS source register type/index."""
import struct, subprocess, pathlib

seed = pathlib.Path("data/harness/c.bin")
words0 = list(struct.unpack("<%dI" % (seed.stat().st_size // 4), seed.read_bytes()))
HARNESS = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
out = pathlib.Path("data/tmp_evs/sweep2"); out.mkdir(parents=True, exist_ok=True)

def attribute(p):
    try:
        done = subprocess.run([CDB, "-g", "-G", "-c", "sxe av; g; .lastevent; kb; q",
                               HARNESS, "bytecode", str(p)],
                              capture_output=True, text=True, timeout=90)
    except Exception:
        return "?"
    text = (done.stdout or "") + (done.stderr or "")
    for mod in ("nvgpucomp", "d3d9", "nvwgf2um", "shader_runner"):
        if mod + "!" in text:
            return mod
    return "?"

def run(regtype, index):
    words = list(words0)
    t = 0xA0000000
    t &= ~0x7FF; t |= index & 0x7FF
    t &= ~(0x7 << 28); t |= (regtype & 0x7) << 28
    words[9] = t
    p = out / ("rt%d_i%d.bin" % (regtype, index))
    p.write_bytes(b"".join(w.to_bytes(4, "little") for w in words))
    done = subprocess.run([HARNESS, "bytecode", str(p)], capture_output=True, text=True, timeout=30)
    rc = done.returncode
    if rc == 0:
        return "ok", p
    if rc == 1:
        return "rejected", p
    return "FAULT@" + attribute(p), p

edges = []
for index in range(129, 256):
    tag, _ = run(2, index)
    if tag != "ok":
        edges.append(("const", index, tag)); break
for regtype in (3, 4, 5, 6, 7):
    for index in (0, 1, 15, 31, 63, 127, 128, 255):
        tag, _ = run(regtype, index)
        if tag not in ("rejected",):
            edges.append((regtype, index, tag))
print("边界/异常:", edges or "全部被拒")
