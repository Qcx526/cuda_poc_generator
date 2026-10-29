"""Which instruction reaches the vulnerable dispatch block (0x15030FA)?"""
import subprocess, pathlib

H = "data/harness/shader_runner.exe"
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
W = pathlib.Path("data/tmp_evs/ops"); W.mkdir(parents=True, exist_ok=True)
SCRIPT = W.parent / "p.cdb"
SCRIPT.write_text("\n".join([
    "sxe ld:nvgpucomp64", "g",
    'bp nvgpucomp64+0x15030FA "gc"',
    "g", "q"]) + "\n", encoding="utf-8")

CASES = {
    "add":   "add r0, c0, c1",
    "mad":   "mad r0, c0, c1, c2",
    "mul":   "mul r0, c0, c1",
    "dp3":   "dp3 r0, c0, c1",
    "exp":   "expp r0, c0",
    "log":   "logp r0, c0",
    "frc":   "frc r0, c0",
    "rcp":   "rcp r0, c0",
    "sincos":"sincos r0.xy, c0.x",
    "texld": "texld r0, v0, s0",
    "if":    "if_gt c0.x, c0.y",
}

for name, inst in CASES.items():
    body = ["ps_3_0"]
    if name == "texld":
        body += ["dcl_texcoord0 v0.xy", "dcl_2d s0"]
    body += ["def c0, 0.5, 0.25, 0.75, 1.0", "def c1, 1.0, 2.0, 3.0, 4.0",
             "def c2, 5.0, 6.0, 7.0, 8.0", "mov r0, c0", inst]
    if name == "if":
        body += ["endif"]
    body.append("mov oC0, r0")
    asm, binary = W / (name + ".asm"), W / (name + ".bin")
    asm.write_text("\n".join(body) + "\n", encoding="utf-8")
    built = subprocess.run([H, "assemble", str(asm), str(binary)],
                           capture_output=True, text=True, timeout=30)
    if built.returncode != 0:
        print("%-8s assemble failed" % name); continue
    run = subprocess.run([CDB, "-cf", str(SCRIPT), H, "bytecode", str(binary)],
                         capture_output=True, text=True, errors="replace", timeout=90)
    import re
    out = (run.stdout or "") + (run.stderr or "")
    # The command echo contains the marker too, so only a real breakpoint hit counts.
    hit = re.search(r"Breakpoint \d+ hit", out) is not None
    print("%-8s -> %s" % (name, "REACHED 0x15030FA" if hit else "-"))
