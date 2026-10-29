"""Sweep the SINCOS source token: constant index and register type."""
import struct, subprocess, pathlib, sys

seed = pathlib.Path("data/harness/c.bin")
words0 = list(struct.unpack("<%dI" % (seed.stat().st_size // 4), seed.read_bytes()))
HARNESS = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
out = pathlib.Path("data/tmp_evs/sweep"); out.mkdir(parents=True, exist_ok=True)

def attribute(binpath):
    try:
        done = subprocess.run([CDB, "-g", "-G", "-c", "sxe av; g; .lastevent; kb; q",
                               HARNESS, "bytecode", str(binpath)],
                              capture_output=True, text=True, timeout=90)
    except Exception:
        return "?"
    text = (done.stdout or "") + (done.stderr or "")
    for line in text.splitlines():
        if "!" in line and ("0x" in line or ":" in line):
            for mod in ("nvgpucomp", "d3d9", "nvwgf2um", "shader_runner"):
                if mod in line:
                    return mod
    return "?"

for regtype in (0, 1, 2):
    for index in (0, 1, 15, 31, 63, 127, 128, 255, 256, 511, 1023, 2047):
        words = list(words0)
        t = 0xA0000000
        t &= ~0x7FF
        t |= index & 0x7FF
        t &= ~(0x7 << 28)
        t |= (regtype & 0x7) << 28
        words[9] = t
        path = out / ("rt%d_i%d.bin" % (regtype, index))
        path.write_bytes(b"".join(w.to_bytes(4, "little") for w in words))
        done = subprocess.run([HARNESS, "bytecode", str(path)],
                              capture_output=True, text=True, timeout=30)
        rc = done.returncode
        if rc in (0, 1):
            tag = "ok" if rc == 0 else "rejected"
        else:
            tag = "FAULT@" + attribute(path)
        print("regtype=%d index=%-4d -> %s" % (regtype, index, tag), flush=True)
