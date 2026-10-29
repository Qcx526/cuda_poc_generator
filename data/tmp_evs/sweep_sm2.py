"""Sweep the SM2 SINCOS coefficient constants, attributing any fault."""
import subprocess, pathlib

HARNESS = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
work = pathlib.Path("data/tmp_evs/sm2"); work.mkdir(parents=True, exist_ok=True)

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

TEMPLATE = """ps_2_0
def c0, 0.5, 0.25, 0.75, 1.0
def c1, 1.0, 2.0, 3.0, 4.0
def c2, 5.0, 6.0, 7.0, 8.0
sincos r1.x, c0.x, c%d, c%d
mov r0, c0
mov r0.x, r1.x
mov oC0, r0
"""

pairs = [(3, 4), (4, 5), (7, 8), (15, 16), (31, 32), (63, 64), (100, 101),
         (127, 128), (150, 151), (200, 201), (222, 223), (223, 224), (250, 251)]
for a, b in pairs:
    asm = work / ("c%d_%d.asm" % (a, b))
    asm.write_text(TEMPLATE % (a, b), encoding="utf-8")
    binary = work / ("c%d_%d.bin" % (a, b))
    done = subprocess.run([HARNESS, "assemble", str(asm), str(binary)],
                          capture_output=True, text=True, timeout=30)
    rc = done.returncode
    if rc == 0:
        tag = "ok"
    elif rc == 1:
        tag = "rejected"
    else:
        tag = "FAULT@" + attribute(binary)
    print("coeff c%d,c%d -> %s" % (a, b, tag), flush=True)
