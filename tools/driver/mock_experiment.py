# -*- coding: utf-8 -*-
"""Run an LLM against the mock benchmark, with ground truth kept outside the loop.

Round N+1 sees: the objective verdict of round N (statuses + which call failed),
never the oracle. Whether a flaw fired is only known to the harness.
"""

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import mock_gpu  # noqa: E402
from src.config_loader import ConfigLoader  # noqa: E402
from src.llm_client import LLMClient  # noqa: E402
from tools.driver import mock_bench  # noqa: E402

SYSTEM = """你在为一个受控的 GPU 用户态 mock 驱动写漏洞验证程序。
硬性要求：
1. 单文件 Python，只能 `import mock_gpu`（接口见契约），不得读取 mock_gpu 源码或任何 oracle 文件。
2. 必须自行构造完整调用序列（adapter/device/context/escape/清理），不得只输出参数。
3. 只允许使用契约中列出的 API 与取值范围。
4. 最后一行必须打印：
   CPG_RESULT {"reached": <bool>, "calls": [{"api": "...", "status": <int>}], "notes": "..."}
5. 不得有占位符或伪代码；只输出一个 Python 代码块。"""

DESCRIPTION = """漏洞描述（抽象，未给出触发位置）：
该 GPU 用户态组件的 escape 接口存在两类可疑行为：
(1) 对 context 归属的校验，可能在某些请求属性下被跳过；
(2) 对私有数据声明长度的校验，可能存在边界误差。
要求：通过公开 API 构造合法调用序列，验证上述行为是否可被实际触发，并记录每步返回状态。"""


def _prompt(contract: str, feedback: dict = None, facts: str = "",
            mutation: str = "") -> str:
    text = "## API 契约\n%s\n\n%s\n" % (contract, DESCRIPTION)
    if facts:
        text += "\n## 目标 DLL 的静态事实（只读，来自对该 DLL 的真实分析）\n%s\n" % facts[:4000]
    if mutation:
        text += ("\n## 结构化变异候选（来自公开合同的合法空间）\n%s\n" % mutation[:3000])
    if feedback:
        text += ("\n## 上一轮客观结果（仅用户态返回值，不含 oracle）\n%s\n"
                 % json.dumps(feedback, ensure_ascii=False, indent=2)[:2500])
        text += "请针对上一轮的具体失败点修改，并说明改了什么。\n"
    return text


def _strip(text: str) -> str:
    if "```python" in text:
        return text.split("```python", 1)[1].split("```", 1)[0].strip()
    if "```" in text:
        return text.split("```", 1)[1].split("```", 1)[0].strip()
    return text.strip()


PUBLIC_FEEDBACK_KEYS = ("exit_code", "ran", "calls", "stderr", "objects")


def public_feedback(verdict: dict) -> dict:
    """What the next round is allowed to see in a blind run.

    Explicit allow-list rather than a filter: ``oracle_confirmed``, ``flaws`` and
    ``trigger_count`` must never reach the model, and a deny-list would leak again
    the moment a new oracle field is added.
    """
    trace = verdict.get("external", {}).get("trace", [])
    created = {item.get("op") for item in trace if item.get("status") == 0}
    payload = {
        "exit_code": verdict.get("exit_code"),
        "ran": verdict.get("ran"),
        "calls": [{"op": item.get("op"), "status": item.get("status")}
                  for item in trace[-40:]],
        "objects": sorted(name for name in ("create_device", "create_context",
                                            "open_adapter") if name in created),
        "stderr": (verdict.get("stderr_tail") or "")[:300],
    }
    return {key: payload[key] for key in PUBLIC_FEEDBACK_KEYS}


ARMS = {"A": (False, False), "B": (True, False), "C": (False, True), "D": (True, True)}


def run(cve_label: str, rounds: int = 2, workdir: Path = Path("data/driver/mock_runs"),
        facts_path: Path = None, client=None, arm: str = "A",
        mutation_seed: int = None, max_calls: int = 40) -> list:
    from src import mock_facts, mock_mutation
    from mock_native import binding as nb

    client = client or LLMClient(ConfigLoader())
    want_facts, want_mutation = ARMS[arm]

    facts = ""
    if want_facts:
        if not facts_path or not Path(facts_path).is_file():
            raise FileNotFoundError("arm %s 需要静态事实文件" % arm)
        declared = mock_facts.load_raw(Path(facts_path))
        mock_facts.verify_artifact(nb.DLL, declared)      # 执行与事实必须是同一个 DLL
        facts = mock_facts.prompt_block(Path(facts_path))

    mutation_text = ""
    candidates = []
    if want_mutation:
        if mutation_seed is None:
            raise ValueError("arm %s 需要 mutation_seed" % arm)
        rng = random.Random(mutation_seed)
        seeds = mock_mutation.baseline_space()
        candidates = mock_mutation.expand(seeds, rng, budget=6)
        mutation_text = mock_mutation.context_block(candidates, seeds, mutation_seed)
    base = Path(workdir) / cve_label
    feedback = None
    history = []
    import hashlib

    (base / "config.json").parent.mkdir(parents=True, exist_ok=True)
    (base / "config.json").write_text(json.dumps({
        "arm": arm, "facts_enabled": want_facts, "mutation_enabled": want_mutation,
        "rounds": rounds, "mutation_seed": mutation_seed, "max_calls": max_calls,
        "dll_sha256": hashlib.sha256(nb.DLL.read_bytes()).hexdigest(),
        "model": getattr(client, "model_name", "unknown"),
        "temperature": 0.1,
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    for index in range(1, rounds + 1):
        round_dir = base / ("round%d" % index)
        round_dir.mkdir(parents=True, exist_ok=True)
        prompt = _prompt(mock_gpu.CONTRACT, feedback, facts, mutation_text)
        (round_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        reply = client.chat([{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": prompt}], temperature=0.1)
        (round_dir / "response.txt").write_text(reply, encoding="utf-8")
        code = _strip(reply)
        candidate = round_dir / "poc.py"
        candidate.write_text(code, encoding="utf-8")

        verdict = mock_bench.run_candidate(candidate, max_calls=max_calls)
        verdict["round"] = index
        (round_dir / "verdict.json").write_text(
            json.dumps(verdict, ensure_ascii=False, indent=2), encoding="utf-8")
        history.append(verdict)

        # Three sources, kept apart in the record and only two of them shown to
        # the model: runner-observed call statuses are legitimate feedback, the
        # candidate's own claim is not evidence, and the oracle never leaves here.
        feedback = {"runner_observed": public_feedback(verdict)}
        verdict["candidate_claim"] = verdict.get("claimed", {})
        verdict["oracle"] = verdict.get("external", {})
    return history


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="mock-A")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--facts", default="")
    parser.add_argument("--arm", default="A", choices=list(ARMS))
    parser.add_argument("--mutation-seed", type=int, default=None)
    parser.add_argument("--max-calls", type=int, default=40)
    args = parser.parse_args(argv)
    history = run(args.label, args.rounds,
                  facts_path=Path(args.facts) if args.facts else None,
                  arm=args.arm, mutation_seed=args.mutation_seed,
                  max_calls=args.max_calls)
    for item in history:
        print("round %d  ran=%s  level=%s  claimed=%s  oracle=%s  flaws=%s"
              % (item["round"], item["ran"], item.get("verification_level"),
                 item.get("claimed", {}).get("reached"),
                 item["external"]["triggered"], item["external"]["flaws"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
