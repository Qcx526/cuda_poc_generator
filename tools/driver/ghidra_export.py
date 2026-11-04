# -*- coding: utf-8 -*-
"""Drive Ghidra's headless analyzer from Python, without analysing everything.

A 120 MB driver with 79,615 functions does not fit a one-shot "analyse it all"
step: the analysis alone can run for an hour and the resulting project is far too
large to keep in Git. So the workflow is one project per image, imported without
analysis, and every question answered by a script that touches a single function.

The Ghidra installation itself is configuration, not content: it is located
through ``CPG_GHIDRA_HOME`` or the usual install roots, and never copied into the
repository.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = ROOT / "tools" / "driver" / "ghidra_scripts"
PROJECTS = ROOT / "data" / "driver" / "ghidra"

# Ghidra ships a launcher per platform; picking the wrong one fails with a Java
# error that looks like a missing JDK, so the choice is made explicitly.
_LAUNCHER = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def find_home() -> Optional[Path]:
    configured = os.environ.get("CPG_GHIDRA_HOME", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates += [Path("D:/tools/ghidra_12.2_PUBLIC"),
                   Path("C:/tools/ghidra_12.2_PUBLIC"),
                   Path("/opt/ghidra")]
    for path in candidates:
        if path and (path / "support" / _LAUNCHER).is_file():
            return path
    return None


# Ghidra 12.2 refuses anything below 25; the launcher says so only after printing
# a prompt that a headless run cannot answer, so the requirement is encoded here.
MIN_JAVA_MAJOR = 25


def _java_major(java: Path) -> Optional[int]:
    try:
        done = subprocess.run([str(java), "-version"], capture_output=True,
                              text=True, timeout=20, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    text = (done.stderr or "") + (done.stdout or "")
    match = re.search(r'version "(\d+)', text)
    return int(match.group(1)) if match else None


def find_java(home: Path) -> Optional[Path]:
    """Locate a JDK new enough for this Ghidra, not merely any java on disk."""
    configured = os.environ.get("JAVA_HOME", "").strip()
    candidates = [Path(configured)] if configured else []
    for pattern in ("jdk-25*", "jdk-2[1-9]*"):
        root = Path("D:/tools")
        if root.is_dir():
            candidates += sorted(root.glob(pattern), reverse=True)
    for path in candidates:
        exe = path / "bin" / ("java.exe" if os.name == "nt" else "java")
        if not exe.is_file():
            continue
        major = _java_major(exe)
        if major is None or major >= MIN_JAVA_MAJOR:
            return path
    return None


def _run(command: List[str], env: Dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    # stdin must be closed: the launcher asks an interactive question when it
    # cannot find a suitable JDK, and an unanswered prompt looks exactly like a
    # hang. Closing stdin turns that into an immediate, readable failure.
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", env=env,
                          stdin=subprocess.DEVNULL)


def import_image(image: Path, name: str, *, timeout: int = 900,
                 analysis_timeout: int = 0,
                 home: Optional[Path] = None, java: Optional[Path] = None) -> Dict[str, object]:
    """Create the project if needed, without running auto-analysis.

    ``-noanalysis`` is the point: the loader still records sections and the
    exception directory, which is what the function index needs, but the
    decompiler is only ever asked about one function at a time.
    """
    home = home or find_home()
    if home is None:
        raise RuntimeError("找不到 Ghidra：设置 CPG_GHIDRA_HOME 指向安装目录")
    java = java or find_java(home)
    env = dict(os.environ)
    if java is not None:
        env["JAVA_HOME"] = str(java)
    PROJECTS.mkdir(parents=True, exist_ok=True)
    project_dir = PROJECTS / name
    project_dir.mkdir(exist_ok=True)
    command = [str(home / "support" / _LAUNCHER), str(project_dir), name,
               "-import", str(image), "-overwrite"]
    # The PE loader only builds its function index (from .pdata) when analysis
    # runs. `-noanalysis` is fastest but leaves an empty function table, which is
    # why one build produced facts and the other produced none.
    if analysis_timeout > 0:
        command += ["-analysisTimeoutPerFile", str(analysis_timeout)]
    else:
        command += ["-noanalysis"]
    if SCRIPTS.is_dir():
        command += ["-scriptPath", str(SCRIPTS)]
    result = _run(command, env, timeout)
    stem = Path(image).name
    (project_dir / "program_name.txt").write_text(stem, encoding="utf-8")
    return {"returncode": result.returncode,
            "program": stem,
            "stdout_tail": (result.stdout or "")[-2000:],
            "stderr_tail": (result.stderr or "")[-2000:],
            "project": str(project_dir)}


def program_name(name: str) -> str:
    """The name Ghidra uses inside the project is the imported file name.

    Passing the *project* name to ``-process`` is accepted silently and then
    matches nothing, which is what made the first attempt look like a hang.
    """
    project = PROJECTS / name
    marker = project / "program_name.txt"
    if marker.is_file():
        return marker.read_text(encoding="utf-8").strip()
    return name


def export_function(name: str, rva: int, *, program: str = "",
                    home: Optional[Path] = None,
                    java: Optional[Path] = None, timeout: int = 600,
                    script: str = "ExportFunctionFacts.java") -> Dict[str, object]:
    """Run the export script against one function and return its JSON."""
    home = home or find_home()
    if home is None:
        raise RuntimeError("找不到 Ghidra：设置 CPG_GHIDRA_HOME 指向安装目录")
    java = java or find_java(home)
    env = dict(os.environ)
    if java is not None:
        env["JAVA_HOME"] = str(java)
    project_dir = PROJECTS / name
    if not project_dir.is_dir():
        raise RuntimeError("项目不存在，请先 import_image：%s" % project_dir)
    output = project_dir / ("function_%x.json" % rva)
    command = [str(home / "support" / _LAUNCHER), str(project_dir), name,
               "-process", program or program_name(name), "-noanalysis",
               "-scriptPath", str(SCRIPTS),
               "-postScript", script, hex(rva), str(output),
               "-readOnly"]
    result = _run(command, env, timeout)
    payload: Dict[str, object] = {}
    if output.is_file():
        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
        except ValueError:
            payload = {}
    return {"returncode": result.returncode, "facts": payload,
            "stdout_tail": (result.stdout or "")[-1500:],
            "stderr_tail": (result.stderr or "")[-1500:]}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="headless Ghidra export")
    sub = parser.add_subparsers(dest="action", required=True)

    imp = sub.add_parser("import")
    imp.add_argument("--image", required=True)
    imp.add_argument("--name", required=True)

    fn = sub.add_parser("function")
    fn.add_argument("--name", required=True)
    fn.add_argument("--rva", required=True)

    args = parser.parse_args(argv)
    if args.action == "import":
        result = import_image(Path(args.image), args.name)
    else:
        result = export_function(args.name, int(args.rva, 0))
    print(json.dumps(result, ensure_ascii=False, indent=2)[:4000])
    return 0 if result.get("returncode") == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
