# -*- coding: utf-8 -*-
"""Run an LLM against the mock benchmark, with ground truth kept outside the loop.

Round N+1 sees: the objective verdict of round N (statuses + which call failed),
never the oracle. Whether a flaw fired is only known to the harness.
"""

import argparse
import json
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


def _prompt(contract: str, feedback: dict = None, facts: str = "") -> str:
    text = "## API 契约\n%s\n\n%s\n" % (contract, DESCRIPTION)
    if facts:
        text += ("\n## 目标 DLL 的静态事实（只读，来自对该 DLL 的真实分析）\n%s\n"
                 % facts[:4000])
        text += ("说明：这些是函数边界、指令统计与比较常量，不含漏洞位置或标签；"
                 "未给出的语义一律视为 UNKNOWN。\n")
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


def run(cve_label: str, rounds: int = 2, workdir: Path = Path("data/driver/mock_runs"),
        facts_path: Path = None) -> list:
    client = LLMClient(ConfigLoader())
    facts = ""
    if facts_path and Path(facts_path).is_file():
        facts = Path(facts_path).read_text(encoding="utf-8")
    base = Path(workdir) / cve_label
    feedback = None
    history = []
    for index in range(1, rounds + 1):
        round_dir = base / ("round%d" % index)
        round_dir.mkdir(parents=True, exist_ok=True)
        prompt = _prompt(mock_gpu.CONTRACT, feedback, facts)
        (round_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        reply = client.chat([{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": prompt}], temperature=0.1)
        (round_dir / "response.txt").write_text(reply, encoding="utf-8")
        code = _strip(reply)
        candidate = round_dir / "poc.py"
        candidate.write_text(code, encoding="utf-8")

        verdict = mock_bench.run_candidate(candidate)
        verdict["round"] = index
        (round_dir / "verdict.json").write_text(
            json.dumps(verdict, ensure_ascii=False, indent=2), encoding="utf-8")
        history.append(verdict)

        # Only user-visible facts go back to the model; the oracle stays here.
        feedback = {"exit_code": verdict["exit_code"], "ran": verdict["ran"],
                    "claimed": verdict.get("claimed", {}),
                    "stderr": verdict.get("stderr_tail", "")[:300]}
    return history


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="mock-A")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--facts", default="")
    args = parser.parse_args(argv)
    history = run(args.label, args.rounds, facts_path=Path(args.facts) if args.facts else None)
    for item in history:
        print("round %d  ran=%s  claimed_reached=%s  external_triggered=%s  flaws=%s"
              % (item["round"], item["ran"],
                 item.get("claimed", {}).get("reached"),
                 item["external"]["triggered"], item["external"]["flaws"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
