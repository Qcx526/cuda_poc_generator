"""Does SINCOS on a non-constant source reach 0x15030FA?"""
import re, subprocess, pathlib
H = pathlib.Path("data/harness/shader_runner.exe").resolve()
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"
W = pathlib.Path("data/tmp_evs/src"); W.mkdir(parents=True, exist_ok=True)
S = W / "p.cdb"
S.write_text("\n".join(["sxe ld:nvgpucomp64", "g",
                        'bp nvgpucomp64+0x15030FA "gc"', "g", "q"]) + "\n", encoding="utf-8")

CASES = {
    "const": ["def c0, 0.5, 0.25, 0.75, 1.0", "sincos r0.xy, c0.x", "mov oC0, r0"],
    "input": ["dcl_texcoord0 v0.xy", "sincos r0.xy, v0.x", "mov oC0, r0"],
    "tmp_of_input": ["dcl_texcoord0 v0.xy", "mov r1, v0", "sincos r0.xy, r1.x", "mov oC0, r0"],
    "two": ["dcl_texcoord0 v0.xy", "sincos r0.xy, v0.x", "sincos r1.xy, v0.y", "mov oC0, r0"],
}
for name, body in CASES.items():
    asm, binary = W / (name + ".asm"), W / (name + ".bin")
    asm.write_text("ps_3_0\n" + "\n".join(body) + "\n", encoding="utf-8")
    built = subprocess.run([str(H), "assemble", str(asm), str(binary)],
                           capture_output=True, text=True, errors="replace", timeout=30)
    if built.returncode != 0:
        print("%-12s skip: %s" % (name, (built.stdout or built.stderr).split("error")[-1][:60])); continue
    run = subprocess.run([CDB, "-cf", str(S), str(H), "bytecode", str(binary)],
                         capture_output=True, text=True, errors="replace", timeout=90)
    text = (run.stdout or "") + (run.stderr or "")
    print("%-12s -> %s" % (name, "REACHED" if re.search(r"Breakpoint \d+ hit", text) else "-"))
