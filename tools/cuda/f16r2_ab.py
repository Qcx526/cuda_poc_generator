# -*- coding: utf-8 -*-
"""F16-R2 strict A/B: direct JPEG bytes versus a mutation plan.

Both arms get the same baseline, the same hypothesis text, the same model and the same
budget: one call per cell, no retries, no filtering of failures. A produces base64 that
the harness decodes itself - model code is never executed. B produces a plan that the
adapter materialises and journals.

A pair is strict only when the control is byte-identical to the baseline and the
candidate differs from it; everything else is recorded as an invalid sample rather than
quietly dropped.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.config_loader import ConfigLoader                       # noqa: E402
from src.jpeg_adapter import build_baseline, reference_decode, sha256, walk, write_bundle  # noqa: E402
from src.jpeg_bundle import verify_bundle                        # noqa: E402
from src.jpeg_parser import summary                              # noqa: E402
from src.llm_client import LLMClient                             # noqa: E402
from tools.cuda.f15_probe import VERSIONS, is_crash              # noqa: E402

OUT = ROOT / "data" / "driver" / "f16r2"
PROBE = ROOT / "data" / "driver" / "f15" / "nvjpeg_probe.exe"
VERSIONS_USED = ("13.2.2", "11.4.0")

HYPOTHESES = [
    ("H1", "restart-interval", "让重启间隔参与的分组计数为 0 或越界，例如 DRI 设为 0。"),
    ("H2", "scan-structure", "改变扫描结构：在 SOS 前后插入额外的段，观察解码器对非预期段序的处理。"),
    ("H3", "app-metadata", "在 APP 段中加入异常长度或重复段，观察元数据处理路径。"),
    ("H4", "sampling-geometry", "修改某分量的采样因子，使色度与亮度平面尺寸关系退化。"),
    ("H5", "sof-geometry", "修改帧宽高为极小或极不均匀值，观察 MCU 网格计算。"),
]

A_TASK = """你在做 JPEG 输入构造实验。基线是一张 64x64 的合法 JPEG（SHA256 见下）。
目标假设：{hypothesis}

请输出一个**完整 JPEG 文件**的 Base64（`data:image/jpeg;base64,` 前缀可省略）。
要求：
- 必须是完整可解码的 JPEG（SOI 开头、EOI 结尾）；
- 与基线不同，体现上述假设；
- 只输出 ```base64 代码块，不要解释，不要输出脚本。
"""

B_TASK = """你在做 JPEG 输入构造实验。基线由真实编码器生成（SHA256 见下），适配器会在基线上
按你的计划改字段，不改动熵数据。目标假设：{hypothesis}

只输出一个 JSON 变异计划：
{{"hypothesis": "<一句话>", "operations": [
  {{"op":"set_sof_size","width":<int>,"height":<int>}},
  {{"op":"set_component_sampling","component":<0..2>,"h":<1..4>,"v":<1..4>}},
  {{"op":"set_dri","interval":<int>}},
  {{"op":"insert_segment","marker":<224..239 或 254>,"hex":"<payload>"}},
  {{"op":"strip_segment","marker":<int>}}
]}}
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
    return {"version": version, "exit": proc.returncode, "crash": is_crash(proc.returncode),
            "stage4": "STAGE4 nvjpegGetImageInfo=SUCCESS" in out,
            "stage7": "VERDICT last_success_stage=7_output" in out,
            "stdout": out[-1500:],
            "dll_sha256": sha256(Path(dll).read_bytes()),
            "probe_sha256": sha256(PROBE.read_bytes())}


def run_arm_a(cell: Path, baseline: bytes, hypothesis: str, client) -> dict:
    cell.mkdir(parents=True, exist_ok=True)
    prompt = A_TASK.format(hypothesis=hypothesis) + "\n基线 SHA256: %s\n" % sha256(baseline)
    (cell / "prompt.txt").write_text(prompt, encoding="utf-8")
    raw = client.chat([{"role": "system", "content": "只输出一个 base64 代码块。"},
                       {"role": "user", "content": prompt}], temperature=0.0)
    (cell / "response.txt").write_text(raw, encoding="utf-8")

    match = re.search(r"```(?:base64)?\s*([A-Za-z0-9+/=\s]{100,})```", raw, re.S)
    payload = match.group(1) if match else ""
    try:
        data = base64.b64decode(re.sub(r"\s+", "", payload), validate=True) if payload else b""
    except Exception:  # noqa: BLE001 - a malformed answer is a recorded outcome
        data = b""

    record = {"arm": "A", "output_ok": bool(data), "bytes": len(data)}
    if data:
        (cell / "candidate.jpg").write_bytes(data)
        ok, error, size, mode = reference_decode(data)
        record.update({"sha256": sha256(data), "structure": summary(data),
                       "reference": {"ok": ok, "error": error, "size": list(size)},
                       "runs": [probe(v, cell / "candidate.jpg") for v in VERSIONS_USED]})
        # Control for arm A is the baseline itself, copied and compared.
        control = cell / "control.jpg"
        control.write_bytes(baseline)
        record["control_equals_baseline"] = control.read_bytes() == baseline
        record["candidate_differs"] = data != baseline
    else:
        record["runs"] = []
        record["control_equals_baseline"] = False
        record["candidate_differs"] = False
        record["error"] = "no decodable base64 payload"
    return record


def run_arm_b(cell: Path, baseline: bytes, hypothesis: str, client) -> dict:
    cell.mkdir(parents=True, exist_ok=True)
    prompt = B_TASK.format(hypothesis=hypothesis) + "\n基线 SHA256: %s\n" % sha256(baseline)
    (cell / "prompt.txt").write_text(prompt, encoding="utf-8")
    raw = client.chat([{"role": "system", "content": "只输出一个 JSON 代码块。"},
                       {"role": "user", "content": prompt}], temperature=0.0)
    (cell / "response.txt").write_text(raw, encoding="utf-8")

    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    record = {"arm": "B", "output_ok": False, "runs": [],
              "control_equals_baseline": False, "candidate_differs": False}
    try:
        plan = json.loads(match.group(1) if match else raw)
    except ValueError as exc:
        record["error"] = "plan json: %s" % exc
        return record

    try:
        bundle = write_bundle(cell, baseline, plan)
    except Exception as exc:  # noqa: BLE001 - adapter refusal is a recorded outcome
        record["error"] = "adapter: %s: %s" % (type(exc).__name__, exc)
        return record

    candidate = (cell / "poc_plan.jpg").read_bytes()
    record.update({
        "output_ok": True,
        "sha256": sha256(candidate),
        "plan_sha256": bundle["manifest_sha256"],
        "structure": summary(candidate),
        "control_equals_baseline": bundle["control_equals_baseline"],
        "candidate_differs": candidate != baseline,
        "journal": bundle["journal"],
        "runs": [probe(v, cell / "poc_plan.jpg") for v in VERSIONS_USED],
    })
    try:
        record["bundle_verified"] = verify_bundle(cell)["ok"]
    except Exception as exc:  # noqa: BLE001 - verification failure is evidence too
        record["bundle_verified"] = False
        record["bundle_error"] = str(exc)
    return record


def strict_pair(record: dict) -> bool:
    return bool(record.get("output_ok") and record.get("control_equals_baseline")
                and record.get("candidate_differs"))


def rebuild_from_cells() -> dict:
    """Recompute the summary from what is on disk, without calling the model again."""
    root = OUT / "ab"
    baseline = (root / "baseline.jpg").read_bytes()
    rows, families = [], set()
    for tag, family, hypothesis in HYPOTHESES:
        row = {"pair": tag, "family": family, "hypothesis": hypothesis,
               "baseline_sha256": sha256(baseline), "arms": {}}
        for arm in ("A", "B"):
            cell = root / ("%s_%s" % (tag, arm))
            candidate_path = cell / ("candidate.jpg" if arm == "A" else "poc_plan.jpg")
            control_path = cell / ("control.jpg" if arm == "A" else "ctrl_restored.jpg")
            record = {"arm": arm, "output_ok": candidate_path.is_file(),
                      "runs": [], "control_equals_baseline": False,
                      "candidate_differs": False}
            if candidate_path.is_file():
                data = candidate_path.read_bytes()
                ok, error, size, mode = reference_decode(data)
                record.update({"sha256": sha256(data), "structure": summary(data),
                               "reference": {"ok": ok, "error": error, "size": list(size)},
                               "runs": [probe(v, candidate_path) for v in VERSIONS_USED]})
                record["candidate_differs"] = data != baseline
                if control_path.is_file():
                    record["control_equals_baseline"] = control_path.read_bytes() == baseline
                if arm == "B" and (cell / "manifest.json").is_file():
                    try:
                        record["bundle_verified"] = verify_bundle(cell)["ok"]
                    except Exception as exc:  # noqa: BLE001
                        record["bundle_verified"] = False
                        record["bundle_error"] = str(exc)
            record["strict_pair"] = strict_pair(record)
            record["crashes"] = sum(1 for r in record["runs"] if r["crash"])
            record["stage4"] = sum(1 for r in record["runs"] if r["stage4"])
            record["stage7"] = sum(1 for r in record["runs"] if r["stage7"])
            row["arms"][arm] = record
            if arm == "B" and record["output_ok"]:
                families.add(family)
        rows.append(row)
    return {"baseline_sha256": sha256(baseline),
            "versions": {v: {"dll": str(VERSIONS[v]),
                             "sha256": sha256(Path(VERSIONS[v]).read_bytes())}
                         for v in VERSIONS_USED},
            "pairs": len(HYPOTHESES), "unique_mutation_families_B": sorted(families),
            "rows": rows}


def main() -> int:
    root = OUT / "ab"
    root.mkdir(parents=True, exist_ok=True)
    baseline = build_baseline(64, 64)
    (root / "baseline.jpg").write_bytes(baseline)
    client = LLMClient(ConfigLoader())

    rows, families = [], set()
    for tag, family, hypothesis in HYPOTHESES:
        row = {"pair": tag, "family": family, "hypothesis": hypothesis,
               "baseline_sha256": sha256(baseline), "arms": {}}
        for arm, runner in (("A", run_arm_a), ("B", run_arm_b)):
            cell = root / ("%s_%s" % (tag, arm))
            record = runner(cell, baseline, hypothesis, client)
            record["strict_pair"] = strict_pair(record)
            record["crashes"] = sum(1 for r in record.get("runs", []) if r["crash"])
            record["stage4"] = sum(1 for r in record.get("runs", []) if r["stage4"])
            record["stage7"] = sum(1 for r in record.get("runs", []) if r["stage7"])
            row["arms"][arm] = record
            if arm == "B" and record.get("output_ok") and record.get("journal"):
                families.add(family)
            print("%s %s: ok=%s strict=%s stage4=%d stage7=%d crash=%d"
                  % (tag, arm, record.get("output_ok"), record["strict_pair"],
                     record["stage4"], record["stage7"], record["crashes"]))
        rows.append(row)

    summary_doc = {
        "baseline_sha256": sha256(baseline),
        "versions": {v: {"dll": str(VERSIONS[v]),
                         "sha256": sha256(Path(VERSIONS[v]).read_bytes())}
                     for v in VERSIONS_USED},
        "pairs": len(HYPOTHESES),
        "unique_mutation_families_B": sorted(families),
        "rows": rows,
    }
    (root / "summary.json").write_text(json.dumps(summary_doc, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    print("saved", root / "summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
