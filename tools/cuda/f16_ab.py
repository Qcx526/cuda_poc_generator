# -*- coding: utf-8 -*-
"""F16 A/B: hand-written JPEG bytes versus a plan the adapter materialises.

Arm A is the F15 archive: the model wrote the JPEG builder itself and produced nine
files across seven rounds. Arm B is new: the model writes a mutation plan, the adapter
builds baseline/crafted/control with a real encoder, and only the named fields change.

Both arms are judged by the same probe, the same library versions and the same rule -
reference decoder first, then nvJPEG stages, then crash vs rejection.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.config_loader import ConfigLoader          # noqa: E402
from src.jpeg_adapter import build_baseline, write_bundle   # noqa: E402
from src.llm_client import LLMClient                # noqa: E402
from tools.cuda.f15_probe import VERSIONS, is_crash  # noqa: E402

OUT = ROOT / "data" / "driver" / "f16"
PROBE = ROOT / "data" / "driver" / "f15" / "nvjpeg_probe.exe"

PLAN_TASK = """你是 nvJPEG 输入构造规划器。不要写 JPEG 编码器，也不要输出二进制。

你输出一个 **JSON 变异计划**，由适配器基于一张真实编码器产出的合法 JPEG 应用：
{
  "hypothesis": "<一句话：你希望触发什么派生量为零，依据是什么>",
  "operations": [
    {"op": "set_sof_size", "width": <int>, "height": <int>},
    {"op": "set_component_sampling", "component": <0..2>, "h": <1..4>, "v": <1..4>},
    {"op": "set_dri", "interval": <int>},
    {"op": "insert_segment", "marker": <int 十进制>, "hex": "<payload 十六进制>"},
    {"op": "strip_segment", "marker": <int>}
  ]
}

已知事实（实测，非推测）：
- nvJPEG 11.4.0 / 12.3.1 / 13.2.2 均可用，合法 64x64 JPEG 解码成功。
- 平面尺寸 = ceil(w*Hi/Hmax)，宽高 ≥1 时恒 ≥1，所以"色度平面为 0"不可达。
- 直接把采样因子或高度置 0 会在 nvjpegGetImageInfo 被拒（BAD_JPEG）。
- 自适应编码器会重新计算熵数据；你的计划改结构字段，适配器不重算熵流，
  因此改几何可能让参考解码器也拒绝——这本身是允许的结果，会被记录。

若上一轮计划失败，请针对失败层级调整（结构不可解析 / 参考解码器拒绝 / nvJPEG 拒绝 / 无异常）。

只输出 ```json 代码块。
"""


def probe(version: str, jpg: Path) -> dict:
    dll = VERSIONS[version]
    env = dict(os.environ)
    env["PATH"] = str(dll.parent) + os.pathsep + env["PATH"]
    proc = subprocess.run([str(PROBE), "--dll", str(dll), "--file", str(jpg)],
                          capture_output=True, text=True, errors="replace",
                          timeout=180, env=env)
    out = proc.stdout or ""
    stage4 = "SUCCESS" if "STAGE4 nvjpegGetImageInfo=SUCCESS" in out else "REJECTED"
    verdict = re.search(r"^VERDICT last_success_stage=(\S+)", out, re.M)
    return {"version": version, "exit": proc.returncode,
            "crash": is_crash(proc.returncode),
            "stage4": stage4,
            "last_stage": verdict.group(1) if verdict else None,
            "stdout": out[-2000:]}


def run_round(round_no: int, feedback: str, client) -> dict:
    work = OUT / ("b_run%d" % round_no)
    work.mkdir(parents=True, exist_ok=True)

    prompt = PLAN_TASK + "\n\n实验上下文：\n" + json.dumps(
        json.loads((ROOT / "data/driver/f15/case_cve_2026_65160.v2.json")
                   .read_text(encoding="utf-8")), ensure_ascii=False, indent=1)
    if feedback:
        prompt += "\n\n上一轮真实结果（探针与参考解码器）：\n" + feedback
    (work / "prompt.txt").write_text(prompt, encoding="utf-8")

    raw = client.chat([{"role": "system", "content": "只输出一个 JSON 代码块。"},
                       {"role": "user", "content": prompt}], temperature=0.0)
    (work / "response.txt").write_text(raw, encoding="utf-8")
    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    try:
        plan = json.loads(match.group(1) if match else raw)
    except ValueError as exc:
        return {"round": round_no, "plan_error": str(exc), "work": str(work)}

    baseline = build_baseline()
    bundle = write_bundle(work, baseline, plan)

    runs = []
    for artifact in bundle["artifacts"]:
        jpg = work / artifact["name"]
        for version in ("13.2.2", "11.4.0"):
            record = probe(version, jpg)
            record["file"] = artifact["name"]
            record["role"] = artifact["role"]
            record["reference_ok"] = artifact["reference_ok"]
            runs.append(record)

    roles = {a["role"]: a for a in bundle["artifacts"]}
    crashes = [r for r in runs if r["crash"]]
    result = {"round": round_no, "work": str(work), "plan": plan, "bundle": bundle,
              "runs": runs,
              "metrics": {
                  "files_built": len(bundle["artifacts"]),
                  "reference_ok": sum(1 for a in bundle["artifacts"] if a["reference_ok"]),
                  "stage4_pass": sum(1 for r in runs if r["stage4"] == "SUCCESS"),
                  "stage7_pass": sum(1 for r in runs if r["last_stage"] == "7_output"),
                  "crashes": len(crashes),
                  "poc_rejected_with_clean_control": all(
                      r["last_stage"] in ("6_decode", "7_failed") for r in runs
                      if r["role"] == "MALICIOUS") and all(
                      r["last_stage"] == "7_output" for r in runs
                      if r["role"] == "CONTROL"),
                  "benign_ok": roles.get("BENIGN", {}).get("reference_ok", False),
              }}
    (work / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    return result


def feedback_for(result: dict) -> str:
    if "plan_error" in result:
        return "计划 JSON 无法解析：%s" % result["plan_error"]
    lines = []
    for a in result["bundle"]["artifacts"]:
        lines.append("%s %s: 参考解码=%s%s，段=%s" % (
            a["role"], a["name"], "接受" if a["reference_ok"] else "拒绝",
            "" if a["reference_ok"] else "(%s)" % a["reference_error"][:60],
            ",".join(a["segments"][:8])))
    for r in result["runs"]:
        if r["role"] == "MALICIOUS" and r["version"] == "13.2.2":
            lines.append("poc 在 %s: STAGE4=%s, 最后阶段=%s, exit=%s"
                         % (r["version"], r["stage4"], r["last_stage"], r["exit"]))
    return "\n".join(lines)


def main() -> int:
    rounds = int(os.environ.get("F16_ROUNDS", "3"))
    client = LLMClient(ConfigLoader())
    feedback, results = "", []
    for n in range(1, rounds + 1):
        result = run_round(n, feedback, client)
        results.append(result)
        m = result.get("metrics")
        if m:
            print("B round %d: files=%d ref_ok=%d stage4=%d stage7=%d crash=%d benign_ok=%s"
                  % (n, m["files_built"], m["reference_ok"], m["stage4_pass"],
                     m["stage7_pass"], m["crashes"], m["benign_ok"]))
            feedback = feedback_for(result)
        else:
            print("B round %d: plan error %s" % (n, result.get("plan_error")))
            feedback = feedback_for(result)
    (OUT / "b_summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1),
                                        encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
