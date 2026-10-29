"""Call pointer-taking NVAPI functions with a well-formed buffer, no handles."""
import json, re, subprocess, pathlib

protos = json.loads(pathlib.Path("data/nvapi_protos.json").read_text(encoding="utf-8"))
names = json.loads(pathlib.Path("data/nvapi_names.json").read_text(encoding="utf-8"))
ids = {v: int(k, 16) for k, v in names.items()}
H = pathlib.Path("data/harness/nvapi_call.exe").resolve()

SKIP = ("Handle", "ID3D", "IDXGI", "HANDLE", "HINSTANCE", "HMONITOR")

def argc_of(args: str) -> int:
    if args.strip() in ("", "void"):
        return 0
    depth = 0; n = 1
    for ch in args:
        if ch in "([": depth += 1
        elif ch in ")]": depth -= 1
        elif ch == "," and depth == 0: n += 1
    return n

candidates = []
for name, proto in protos.items():
    if "*" not in proto or any(s in proto for s in SKIP):
        continue
    if name not in ids:
        continue
    candidates.append((name, ids[name], argc_of(proto), proto))

print("candidates without handles:", len(candidates))
results = []
for name, ident, argc, proto in candidates[:60]:
    try:
        run = subprocess.run([str(H), hex(ident), str(argc)], capture_output=True,
                             text=True, errors="replace", timeout=20)
        rc, out = run.returncode, (run.stdout or "")[-120:]
    except subprocess.TimeoutExpired:
        rc, out = "timeout", ""
    m = re.search(r"status=(-?\d+)", out)
    results.append({"name": name, "id": hex(ident), "argc": argc,
                    "rc": rc, "status": int(m.group(1)) if m else None,
                    "raw": out.strip()[:80]})
    print("%-42s argc=%d rc=%-4s %s" % (name[:42], argc, rc,
          ("status=%d" % int(m.group(1))) if m else out.strip()[:50]))
pathlib.Path("data/nvapi_baseline.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
ok = [r for r in results if r["status"] == 0]
print("\nOK(0): %d | other status: %d | crash/timeout: %d"
      % (len(ok), len([r for r in results if isinstance(r['status'], int) and r['status'] != 0]),
         len([r for r in results if not isinstance(r['rc'], int) or r['rc'] not in (0, 1)])))
