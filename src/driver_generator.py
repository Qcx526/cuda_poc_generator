# -*- coding: utf-8 -*-
"""Generate a runnable driver probe, run it once, and hand the result back.

Two rules shape this module.

First, the model writes a *program*, not a snippet: one file, standard library
plus ctypes, no placeholders. A candidate that cannot run produces no evidence,
and an unrunnable snippet is indistinguishable from a wrong hypothesis.

Second, a candidate runs once. Kernel paths do not get retried in a loop, so the
generator never wraps execution in a retry; the caller decides whether another
round is safe.
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from . import driver_outcome

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKDIR = ROOT / "data" / "driver" / "llm_poc"

SYSTEM = """你在为 NVIDIA GPU 驱动漏洞的触发验证写一个可运行的程序。

硬性要求：
1. 单文件 Python，只用标准库 + ctypes；不得有占位符、TODO、伪代码。
2. 程序必须自己打印一行结果，格式严格为：
   CPG_RESULT {"stage": "...", "status": <int>, "reached": <bool>, "calls": [{"api": "...", "status": <int>}], "notes": "..."}
   这一行必须是最后一行输出。
3. ABI 必须复用公共模块，不得自行定义任何 D3DKMT 结构体或句柄类型：
   在文件开头写
       import sys; sys.path.insert(0, r"F://qcx//code//test//cuda_poc_generator")
       from src.driver_abi import (D3DKMT_ESCAPE, D3DKMT_OPENADAPTERFROMHDC,
           D3DKMT_CREATEDEVICE, D3DKMT_CREATECONTEXT, D3DKMT_DESTROYCONTEXT,
           D3DKMT_DESTROYDEVICE, D3DKMT_CLOSEADAPTER, DISPLAY_DEVICEW,
           bind_gdi32, bind_user32)
   已知官方事实（不要改）：D3DKMT_HANDLE 是 4 字节 UINT；用户态 D3DKMT_* 与内核
   DXGKARG_* 是不同结构，字段偏移不可混用；D3DKMTCreateDevice 首字段是
   含 void* 的 union（8 字节）。用 CreateDCW("DISPLAY", 设备名) 得到的 HDC 才能
   通过 D3DKMTOpenAdapterFromHdc；GetDC(NULL) 会被拒（0xC000000D）。
4. 只执行一次，不写重试循环，不扫描 IOCTL 范围，不遍历命令号。
5. 任何会写内核或触发蓝屏的操作只允许一次调用。
6. 失败要有信息量：把每一步的返回值写进 calls，即使失败也要打印 CPG_RESULT。
7. 不要输出解释，只输出一个 Python 代码块。"""


def _strip_code(text: str) -> str:
    fenced = re.search(r"```(?:python)?\s*(.*?)```", text, re.S)
    return (fenced.group(1) if fenced else text).strip()


def _feedback_block(feedback: Optional[dict], previous_code: str) -> str:
    if not feedback:
        return "## 上一轮失败事实\n（首轮，无）"
    facts = json.dumps(feedback, ensure_ascii=False, indent=2)[:2200]
    code = (previous_code or "")[:4000]
    return ("## 上一轮失败事实（来自真实执行记录，UNKNOWN 表示未知，禁止补造）\n"
            "%s\n\n## 上一轮生成的代码\n```python\n%s\n```" % (facts, code or "（无）"))


def build_prompt(*, cve: str, analysis: dict, spec: Optional[dict],
                 last_run: Optional[dict], feedback: Optional[dict] = None,
                 previous_code: str = "", history_text: str = "",
                 mutation_context: str = "") -> list:
    spec_text = json.dumps(spec, ensure_ascii=False, indent=2)[:2500] if spec else "（无）"
    run_text = json.dumps(last_run, ensure_ascii=False, indent=2)[:2000] if last_run else "（首轮）"
    feedback_block = _feedback_block(feedback, previous_code)
    user = f"""## 目标
{cve}

## 分析结果（本轮要验证的假设）
{json.dumps(analysis, ensure_ascii=False, indent=2)[:4000]}

## 规格
{spec_text}

## 本轮可用的合法变异（由变异引擎给出，不得越界）
{mutation_context.strip() or "（本组不启用结构化变异）"}

## 上一轮执行结果
{run_text}

{feedback_block}

## 历史实验（只读，来自真实运行日志；代码片段仅供参考，禁止整体照抄）
{history_text or "（无）"}

## 本轮必须遵守
1. 先分析上一轮失败的直接原因（具体到哪个 API、哪组参数、什么返回值）。
2. 明确本轮要改哪个调用或参数，以及依据。
3. 若坚持使用同一个 API，必须说明：上一轮为什么失败、这次改了什么、为什么这次有意义。
   仅仅改注释、变量名或无关代码**不算修改**，会被判为 NO_PROGRESS 并终止本轮迭代。
4. 输出的前两行必须是注释，格式严格为：
   # REUSE: experiment=<历史实验 id 或 none> unchanged=<保持不变的历史调用> changed=<本轮改动> why=<依据>
   # CHANGE: api=<API名> from=<上一轮调用形态> to=<本轮调用形态> why=<依据>
   若复用了历史路径，必须说明复用了哪一条、哪些调用照旧、哪些改了、为什么；
   并指出哪些历史信息不能直接迁移（例如环境不同、驱动版本不同）。
5. 代码必须是完整可运行的，只输出一个 Python 代码块。

参考约束：若上一轮某个 Win32 调用返回 NULL/-1，换一个已经验证可行的入口
（例如用 EnumDisplayDevicesW 拿到设备名再 OpenAdapterFromGdiDisplayName），
而不是重复同一个失败调用。"""
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": user}]


def parse_change_plan(code: str) -> dict:
    """Read the model's own statement of what it changed.

    Parsed with plain string positions rather than a regular expression: the
    values are argument lists, so they contain commas, '=' and backslashes that a
    pattern would have to escape twice over. The header is the model's own
    contract ("# CHANGE: key=value ..."), and only the last line of the header
    matters.
    """
    marker = "# CHANGE"
    index = code.find(marker)
    if index < 0:
        return {}
    body = code[index + len(marker):].lstrip(": ").splitlines()[0] if code[index:] else ""
    if not body:
        return {}
    keys = ("api", "from", "to", "why")
    marks = []
    for key in keys:
        token = key + "="
        position = body.find(token)
        if position >= 0:
            marks.append((position, key))
    marks.sort()
    plan = {}
    for order, (position, key) in enumerate(marks):
        start = position + len(key) + 1
        stop = marks[order + 1][0] if order + 1 < len(marks) else len(body)
        value = body[start:stop].strip()
        if value:
            plan[key] = value
    return plan


def parse_reuse(code: str) -> dict:
    """Read which historical experiment the model says it reused.

    Keys are located by position, and a key only counts when it starts a word:
    ``unchanged=`` contains ``changed=``, so a naive search reads the wrong field.
    """
    marker = "# REUSE"
    index = code.find(marker)
    if index < 0:
        return {}
    body = code[index + len(marker):].lstrip(": ").splitlines()[0]
    keys = ("experiment", "unchanged", "changed", "why")
    marks = []
    for key in keys:
        token = key + "="
        position = body.find(token)
        while position > 0 and body[position - 1] not in " \t":
            position = body.find(token, position + 1)
        if position >= 0:
            marks.append((position, key))
    marks.sort()
    plan = {}
    for order, (position, key) in enumerate(marks):
        begin = position + len(key) + 1
        stop = marks[order + 1][0] if order + 1 < len(marks) else len(body)
        value = body[begin:stop].strip()
        if value:
            plan[key] = value
    return plan


def generate(client, *, cve: str, analysis: dict, spec: Optional[dict] = None,
             last_run: Optional[dict] = None, workdir: Path = DEFAULT_WORKDIR,
             round_index: int = 1, feedback: Optional[dict] = None,
             previous_code: str = "", history_text: str = "",
             mutation_context: str = "") -> Path:
    """Ask for one program and write it where the runner can execute it.

    The failure block is not decoration: it is the only place the model learns
    which call it must stop repeating, so it is written to disk with the prompt
    for later inspection.
    """
    target_dir = Path(workdir) / cve / ("round%d" % round_index)
    target_dir.mkdir(parents=True, exist_ok=True)
    messages = build_prompt(cve=cve, analysis=analysis, spec=spec,
                            last_run=last_run, feedback=feedback,
                            previous_code=previous_code, history_text=history_text,
                            mutation_context=mutation_context)
    (target_dir / "generator_prompt.txt").write_text(
        "\n\n".join("%s://n%s" % (m["role"], m["content"]) for m in messages),
        encoding="utf-8")
    text = client.chat(messages, temperature=0.1)
    (target_dir / "llm_response.txt").write_text(text, encoding="utf-8")
    code = _strip_code(text)
    if "CPG_RESULT" not in code:
        # A program that cannot report is worse than one that reports failure.
        code += ('\n\nprint("CPG_RESULT " + __import__("json").dumps('
                 '{"stage": "generated", "status": None, "reached": False, '
                 '"calls": [], "notes": "模型未生成结果行"}))\n')
    candidate = target_dir / "poc.py"
    candidate.write_text(code, encoding="utf-8")
    plan = parse_change_plan(code)
    plan["reuse"] = parse_reuse(code)
    (target_dir / "change_plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (target_dir / "prompt.json").write_text(
        json.dumps({"analysis": analysis, "spec": spec, "last_run": last_run},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    return candidate


def run(candidate: Path, *, timeout: int = 120) -> driver_outcome.Outcome:
    """Execute once. No retry: a kernel path that faulted must not be re-entered."""
    try:
        done = subprocess.run([sys.executable, "-B", str(candidate)],
                              capture_output=True, text=True, errors="replace",
                              timeout=timeout, cwd=str(candidate.parent))
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return driver_outcome.classify(returncode=None, output=str(output),
                                       timed_out=True)
    output = (done.stdout or "") + (done.stderr or "")
    (candidate.parent / "run.log").write_text(output, encoding="utf-8")
    return driver_outcome.classify(returncode=done.returncode, output=output)


def one_round(client, *, cve: str, analysis: dict, spec: Optional[dict] = None,
              last_run: Optional[dict] = None, workdir: Path = DEFAULT_WORKDIR,
              round_index: int = 1, timeout: int = 120) -> Dict[str, Any]:
    """generate -> run -> classify, with everything written next to the code."""
    candidate = generate(client, cve=cve, analysis=analysis, spec=spec,
                         last_run=last_run, workdir=workdir,
                         round_index=round_index)
    outcome = run(candidate, timeout=timeout)
    record = {"cve": cve, "round": round_index, "candidate": str(candidate),
              "outcome": outcome.as_dict()}
    (candidate.parent / "outcome.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record
