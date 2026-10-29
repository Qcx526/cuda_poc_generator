"""Which SM3 instruction reaches 0x15030FA? Legal operands only (one constant per instruction)."""
import re, subprocess, pathlib

H = pathlib.Path("data/harness/shader_runner.exe").resolve()
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
W = pathlib.Path("data/tmp_evs/ops2"); W.mkdir(parents=True, exist_ok=True)
SCRIPT = W / "p.cdb"
SCRIPT.write_text("\n".join(["sxe ld:nvgpucomp64", "g",
                             'bp nvgpucomp64+0x15030FA "gc"', "g", "q"]) + "\n", encoding="utf-8")

OPS = {
    "mov": "mov r2, c0", "add": "add r2, r0, r1", "sub": "sub r2, r0, r1",
    "mul": "mul r2, r0, r1", "mad": "mad r2, r0, r1, c0", "dp3": "dp3 r2, r0, r1",
    "dp4": "dp4 r2, r0, r1", "min": "min r2, r0, r1", "max": "max r2, r0, r1",
    "slt": "slt r2, r0, r1", "sge": "sge r2, r0, r1", "rcp": "rcp r2, r0.x",
    "rsq": "rsq r2, r0.x", "expp": "expp r2, r0.x", "logp": "logp r2, r0.x",
    "lit": "lit r2, r0", "dst": "dst r2, r0, r1", "lrp": "lrp r2, r0, r1, c0",
    "frc": "frc r2, r0", "pow": "pow r2, r0.x, r1.x", "crs": "crs r2, r0, r1",
    "sgn": "sgn r2, r0, r1, c0", "abs": "abs r2, r0", "nrm": "nrm r2, r0",
    "sincos": "sincos r2.xy, c0.x", "texkill": "texkill r0",
    "dsx": "dsx r2, r0", "dsy": "dsy r2, r0", "cmp": "cmp r2, r0, r1, c0",
}

for name, inst in OPS.items():
    body = ["ps_3_0", "def c0, 0.5, 0.25, 0.75, 1.0",
            "mov r0, c0", "mov r1, c0", inst, "mov oC0, r0"]
    asm, binary = W / (name + ".asm"), W / (name + ".bin")
    asm.write_text("\n".join(body) + "\n", encoding="utf-8")
    built = subprocess.run([str(H), "assemble", str(asm), str(binary)],
                           capture_output=True, text=True, errors="replace", timeout=30)
    if built.returncode != 0:
        print("%-8s skip" % name); continue
    run = subprocess.run([CDB, "-cf", str(SCRIPT), str(H), "bytecode", str(binary)],
                         capture_output=True, text=True, errors="replace", timeout=90)
    text = (run.stdout or "") + (run.stderr or "")
    hit = re.search(r"Breakpoint \d+ hit", text) is not None
    fault = "Access violation" in text
    print("%-8s -> %s%s" % (name, "REACHED" if hit else "-", " +FAULT" if fault else ""))
