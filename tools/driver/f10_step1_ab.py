# -*- coding: utf-8 -*-
"""F10-Step1: old seven-dimension projection versus V2, same task, real nvdisasm.

Both arms receive the same instruction text; only the input block differs. Everything
after generation - container, tool binary, timeout, verdict - is shared.

No history PoC and no trigger recipe reach either arm: arm A gets the spec-level blind
brief, arm B gets the PUBLIC_ONLY projection of the v2 case.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.case_context import PUBLIC_ONLY, build_context   # noqa: E402
from src.config_loader import ConfigLoader                # noqa: E402
from src.llm_client import LLMClient                      # noqa: E402

OUT = ROOT / "data" / "driver" / "f10step1"
CASE = ROOT / "data" / "cases" / "cve-2025-23340.v2.json"
SPEC = ROOT / "specs" / "CVE-2025-23340" / "spec.json"
IMAGE = "cpg/cuda112-py3:1.0"
CONTROL = ROOT / "demo" / "CVE-2024-0076" / "artifacts" / "benign.cubin"

TASK = """你在分析 NVIDIA CUDA 工具链的输入解析问题。

任务：写一个自包含的 Python 3 脚本，完成三件事：
1. 在 ./work/ 下用纯 Python 构造一个 ELF/cubin 输入文件（不要调用编译器，不要联网）；
2. 用 subprocess 调用 nvdisasm 处理该文件（nvdisasm 已在 PATH 中）；
3. 打印一行 "EXIT=<nvdisasm 返回码>"。

约束：
- 只输出一个 ```python 代码块，不要解释；
- 不得引用任何历史 PoC、已知样本或外部文件；
- 脚本必须在 Linux 容器内可直接运行。

以下是本次允许你看到的输入信息：
"""


def old_projection() -> str:
    os.environ["CPG_BLIND_CONTRACT"] = "1"
    from src.spec_model import load
    return load(SPEC).prompt_brief()


def v2_projection() -> dict:
    context = build_context(CASE, PUBLIC_ONLY)
    return context


def extract_code(text: str) -> str:
    match = re.search(r"```python\s*(.*?)```", text, re.S)
    return match.group(1).strip() if match else ""


def run_arm(name: str, input_block: str, meta: dict) -> dict:
    arm = OUT / name
    arm.mkdir(parents=True, exist_ok=True)
    prompt = TASK + input_block
    (arm / "prompt.txt").write_text(prompt, encoding="utf-8")

    client = LLMClient(ConfigLoader())
    raw = client.chat([{"role": "system", "content": "只输出代码块。"},
                       {"role": "user", "content": prompt}], temperature=0.0)
    (arm / "response.txt").write_text(raw, encoding="utf-8")
    code = extract_code(raw)
    (arm / "candidate.py").write_text(code, encoding="utf-8")

    result = {"arm": name, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
              "response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
              "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
              "code_bytes": len(code), "generated": bool(code),
              "levels": [], "meta": meta}
    if not code:
        result["failure"] = "no code block"
        return result
    result["levels"].append("GENERATED")

    (arm / "work").mkdir(exist_ok=True)
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", "%s:/case" % arm.as_posix(), "-w", "/case",
         IMAGE, "bash", "-lc",
         "mkdir -p work && timeout 60 python3 candidate.py; echo HARNESS=$?"],
        capture_output=True, text=True, timeout=300)
    (arm / "run.log").write_text(proc.stdout + "\n[stderr]\n" + proc.stderr, encoding="utf-8")
    result["levels"].append("EXECUTED")
    matches = re.findall(r"EXIT=(-?\d+)", proc.stdout)
    result["exit_codes"] = [int(m) for m in matches]
    result["anomaly"] = any(code != 0 for code in result["exit_codes"])
    if result["anomaly"]:
        result["levels"].append("OBSERVED_ANOMALY")
    return result


def control_run() -> dict:
    work = OUT / "control"
    work.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", "%s:/case" % ROOT.as_posix(), "-w", "/case",
         IMAGE, "bash", "-lc",
         "nvdisasm demo/CVE-2024-0076/artifacts/benign.cubin > /dev/null 2>&1; echo EXIT=$?"],
        capture_output=True, text=True, timeout=300)
    (work / "control.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    matches = re.findall(r"EXIT=(-?\d+)", proc.stdout)
    return {"benign_exit": int(matches[0]) if matches else None}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    control = control_run()

    b_context = v2_projection()
    results = [
        run_arm("A", old_projection(), {"projection": "spec_blind_brief",
                                        "evidence": []}),
        run_arm("B", json.dumps(b_context["payload"], ensure_ascii=False, indent=1),
                {"projection": "v2_public_only",
                 "evidence": b_context["included_evidence"],
                 "context_sha256": b_context["context_sha256"]}),
    ]
    summary = {"control": control, "arms": results}
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    for item in results:
        print(item["arm"], item["levels"], "exit=", item.get("exit_codes"))
    print("control:", control)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
