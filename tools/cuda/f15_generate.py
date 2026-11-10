# -*- coding: utf-8 -*-
"""CVE-2026-65160: generate JPEG inputs, then judge them with a fixed probe.

The candidate only builds inputs. Decoding is done by nvjpeg_probe.exe, which loads one
named DLL and reports every stage, so a result is attributed to the library that ran and
a rejection is distinguishable from a crash.

The three earlier rounds all guessed "some field is zero". All three were rejected before
the arithmetic, so the prompt now states what has been refuted and asks for a hypothesis
of a different kind rather than another zero.
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

from src.config_loader import ConfigLoader     # noqa: E402
from src.llm_client import LLMClient           # noqa: E402
from tools.cuda.f15_probe import VERSIONS, is_crash   # noqa: E402

F15 = ROOT / "data" / "driver" / "f15"
CASE = F15 / "case_cve_2026_65160.v2.json"
PROBE = F15 / "nvjpeg_probe.exe"

TASK = """任务：为 NVIDIA nvJPEG 的 CWE-369（除零）构造受控输入样本。

官方公开信息（仅此而已）：
- CVE-2026-65160，2026-11-03，组件 nvJPEG，CWE-369，影响拒绝服务，CVSS 5.5。
- 受影响 nvJPEG 0–26.06，修复 26.07。
- 本机可用：11.4.0 / 12.3.1 / 13.2.2，均含 Windows DLL，真实解码可用。

已被实验否证的假设（不要再重复）：
1. SOF 的采样因子 H=0      → nvjpegGetImageInfo=BAD_JPEG，未进算术
2. 帧高度 height=0          → nvjpegGetImageInfo=BAD_JPEG，未进算术
3. 采样因子整体置 0         → nvjpegGetImageInfo=BAD_JPEG，未进算术
共同点：零值字段在头解析阶段就被合法性校验拦下。

Harness 会回报每个阶段的真实状态：
STAGE2 文件读取 / STAGE4 GetImageInfo / STAGE5 显存分配 / STAGE6 解码 / STAGE7 回传。

你的产出：**一个只依赖标准库的 Python 脚本**，运行后在当前目录写出三个 JPEG：
  benign_<描述>.jpg  合法、可正常解码（基线）
  poc_<描述>.jpg     按你的新假设构造
  ctrl_<描述>.jpg    与 poc 同构造，但把假设涉及的那一处恢复为合法值

要求：
1. 脚本开头注释写明：假设除零发生在哪个**派生量**（不是原始零字段），
   该派生量由哪些合法字段算出，为什么合法字段组合会让它变成零或极小。
2. 三个文件必须是完整 JPEG（FFD8 开头、FFD9 结尾），必须能通过基本格式校验。
3. 只用标准库，不联网，不读其他 CVE 样本。
4. 打印 `[F15_PLAN] <一行假设摘要>` 与 `[F15_FILE] <角色> <文件名> <字节> <sha256>`。

只输出一个 ```python 代码块。
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def probe(version: str, jpg: Path) -> dict:
    dll = VERSIONS[version]
    env = dict(os.environ)
    env["PATH"] = str(dll.parent) + os.pathsep + env["PATH"]
    proc = subprocess.run([str(PROBE), "--dll", str(dll), "--file", str(jpg)],
                          capture_output=True, text=True, errors="replace",
                          timeout=180, env=env)
    out = proc.stdout or ""
    stage = re.search(r"^VERDICT last_success_stage=(\S+)", out, re.M)
    reject = re.search(r"^(STAGE\d [^=]+)=(\w+)", out, re.M)
    return {"version": version, "exit": proc.returncode,
            "kind": ("crash" if is_crash(proc.returncode)
                     else "rejected" if proc.returncode == 1
                     else "ok" if proc.returncode == 0 else "other"),
            "last_stage": stage.group(1) if stage else None,
            "stdout": out[-2500:], "stderr": (proc.stderr or "")[-800:],
            "input_sha256": sha256(jpg),
            "dll": str(dll), "dll_sha256": sha256(dll),
            "rejection_marker": "%s=%s" % (reject.group(1), reject.group(2)) if reject else None}


def classify(runs: list) -> dict:
    by_role = {}
    for r in runs:
        name = r["file"]
        role = ("BENIGN" if name.startswith("benign")
                else "CONTROL" if name.startswith(("ctrl", "control"))
                else "MALICIOUS" if name.startswith("poc") else "UNLABELED")
        by_role.setdefault(role, []).append(r)
    crashed = lambda items: [i for i in items if i["kind"] == "crash"]  # noqa: E731
    mal, ctrl, ben = (crashed(by_role.get(k, [])) for k in ("MALICIOUS", "CONTROL", "BENIGN"))
    rejected = [i["file"] for v in by_role.values() for i in v if i["kind"] == "rejected"]
    return {
        "roles": {k: [i["file"] for i in v] for k, v in by_role.items()},
        "benign_ok": all(i["kind"] == "ok" for i in by_role.get("BENIGN", []))
                     and bool(by_role.get("BENIGN")),
        "control_ok": all(i["kind"] == "ok" for i in by_role.get("CONTROL", []))
                      and bool(by_role.get("CONTROL")),
        "crafted_crashed": bool(mal),
        "differential": bool(mal) and bool(by_role.get("CONTROL")) and not ctrl,
        "rejected": rejected,
        "crashes": [(i["file"], i["exit"]) for i in mal],
    }


def main() -> int:
    round_no = int(os.environ.get("F15_ROUND", "1"))
    feedback = os.environ.get("F15_FEEDBACK", "").strip()
    versions = [v.strip() for v in os.environ.get("F15_VERSIONS", "13.2.2,11.4.0").split(",")]

    work = F15 / ("run%d" % round_no)
    work.mkdir(parents=True, exist_ok=True)

    task = TASK
    if feedback:
        task += ("\n\n上一轮的真实阶段反馈（固定探针产生）：\n" + feedback +
                 "\n\n请据此提出**不同类型**的假设；如果上一轮仍停在 STAGE4，"
                 "说明还没进入解码，需要换约束而不是换零值。")

    prompt = task + "\n\n实验上下文（允许你看到的全部信息）：\n" + json.dumps(
        json.loads(CASE.read_text(encoding="utf-8")), ensure_ascii=False, indent=1)
    (work / "prompt.txt").write_text(prompt, encoding="utf-8")

    raw = LLMClient(ConfigLoader()).chat(
        [{"role": "system", "content": "只输出一个代码块，不要解释。"},
         {"role": "user", "content": prompt}], temperature=0.0)
    (work / "response.txt").write_text(raw, encoding="utf-8")
    match = re.search(r"```(?:python)?\s*(.*?)```", raw, re.S)
    source = match.group(1).strip() if match else ""
    (work / "candidate.py").write_text(source, encoding="utf-8")
    if not source:
        print("no code block")
        return 1

    proc = subprocess.run([sys.executable, "-B", str(work / "candidate.py")],
                          cwd=str(work), capture_output=True, text=True,
                          errors="replace", timeout=300)
    (work / "candidate_run.log").write_text(
        (proc.stdout or "") + "\n[stderr]\n" + (proc.stderr or ""), encoding="utf-8")
    print("candidate rc:", proc.returncode)

    runs = []
    for jpg in sorted(work.glob("*.jpg")):
        for version in versions:
            r = probe(version, jpg)
            r["file"] = jpg.name
            runs.append(r)

    verdicts = {v: classify([r for r in runs if r["version"] == v]) for v in versions}
    report = {"cve": "CVE-2026-65160", "round": round_no,
              "candidate_sha256": sha256(work / "candidate.py"),
              "candidate_returncode": proc.returncode,
              "inputs": [{"file": p.name, "sha256": sha256(p), "bytes": p.stat().st_size}
                         for p in sorted(work.glob("*.jpg"))],
              "runs": runs, "verdicts": verdicts,
              "policy": "解码由固定探针执行并逐阶段记录；候选不参与判定"}
    (work / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=1),
                                      encoding="utf-8")

    for version, v in verdicts.items():
        print("%-8s crafted_crashed=%-5s differential=%-5s rejected=%s"
              % (version, v["crafted_crashed"], v["differential"], ",".join(v["rejected"])))
    for r in runs:
        if r["file"].startswith("poc"):
            print("  %-8s %-34s %-9s 停在 %s" % (r["version"], r["file"], r["kind"],
                                                r["last_stage"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
