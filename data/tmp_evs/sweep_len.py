"""Sweep the SINCOS token: length field and instruction-token control bits."""
import struct, subprocess, pathlib

seed = pathlib.Path("data/harness/c.bin")
words0 = list(struct.unpack("<%dI" % (seed.stat().st_size // 4), seed.read_bytes()))
HARNESS = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
out = pathlib.Path("data/tmp_evs/len"); out.mkdir(parents=True, exist_ok=True)

def frame(p):
    try:
        done = subprocess.run([CDB, "-g", "-G", "-c", "sxe av; g; .lastevent; kb; q",
                               HARNESS, "bytecode", str(p)],
                              capture_output=True, text=True, errors="replace", timeout=90)
    except Exception:
        return "?"
    for line in ((done.stdout or "") + (done.stderr or "")).splitlines():
        if "!" in line:
            tok = line.strip().split()[-1].rstrip(":")
            if "!" in tok:
                return tok.split("!")[0].lower()
    return "?"

def run(words, tag):
    p = out / ("%s.bin" % tag)
    p.write_bytes(b"".join(w.to_bytes(4, "little") for w in words))
    done = subprocess.run([HARNESS, "bytecode", str(p)], capture_output=True,
                          text=True, errors="replace", timeout=30)
    rc = done.returncode
    if rc == 0:
        return "ok"
    if rc == 1:
        return "rejected"
    return "FAULT@" + frame(p)

print("--- SINCOS 长度字段 (bits 24-27 of word 7) ---")
for length in range(1, 16):
    w = list(words0)
    w[7] = (w[7] & 0x00FFFFFF) | (length << 24)
    print("  len=%2d -> %s" % (length, run(w, "len%d" % length)))

print("--- SINCOS 指令字高位 (bits 16-23) ---")
for bit in range(16, 24):
    w = list(words0)
    w[7] |= (1 << bit)
    print("  bit=%2d -> %s" % (bit, run(w, "bit%d" % bit)))
