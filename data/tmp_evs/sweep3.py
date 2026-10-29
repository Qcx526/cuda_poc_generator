"""Set each bit of the SINCOS dest and source tokens, one at a time."""
import struct, subprocess, pathlib

seed = pathlib.Path("data/harness/c.bin")
words0 = list(struct.unpack("<%dI" % (seed.stat().st_size // 4), seed.read_bytes()))
HARNESS = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
out = pathlib.Path("data/tmp_evs/sweep3"); out.mkdir(parents=True, exist_ok=True)

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

hits = []
for word in (8, 9):
    for bit in range(32):
        words = list(words0)
        words[word] |= (1 << bit)
        p = out / ("w%d_b%d.bin" % (word, bit))
        p.write_bytes(b"".join(w.to_bytes(4, "little") for w in words))
        done = subprocess.run([HARNESS, "bytecode", str(p)], capture_output=True, text=True, timeout=30)
        rc = done.returncode
        if rc == 0:
            hits.append((word, bit, "ok"))
        elif rc != 1:
            hits.append((word, bit, "FAULT@" + attribute(p)))
print("非拒绝结果:", hits if hits else "全部被拒")
print("被接受但无崩溃的位:", [h for h in hits if h[2] == "ok"])
