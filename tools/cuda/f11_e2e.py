# -*- coding: utf-8 -*-
"""F11 end-to-end: case -> LLM -> nvcc -> real GPU -> diagnose -> fix -> rerun.

Two experiments through the same loop: a normal functional program and one that
deliberately calls APIs against their contracts. If the compiler or the program fails,
the failure goes back to the model with the original source, and the whole loop -
compile, run, observe - runs again.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src import cuda_api_backend as backend              # noqa: E402
from src.case_context import PUBLIC_ONLY, build_context  # noqa: E402
from src.config_loader import ConfigLoader               # noqa: E402
from src.llm_client import LLMClient                     # noqa: E402

OUT = ROOT / "data" / "driver" / "f11"
CASE = ROOT / "data" / "cases" / "cuda-driver-api-baseline.v2.json"
MAX_FIX_ROUNDS = 2

TASKS = {
    "normal": """任务：写一个 C 程序（Windows x64，用 CUDA Driver API）：

1. 依次调用 cuInit(0)、cuDeviceGet、cuCtxCreate（用 cuDevicePrimaryCtxRetain 也可以）；
2. cuMemAlloc 分配 256 字节设备内存；
3. 用 cuMemcpyHtoD 写入一段已知模式，再用 cuMemcpyDtoH 读回；
4. 校验读回数据与写入一致，打印 "DATA=OK" 或 "DATA=MISMATCH"；
5. 每次调用后打印一行 "API <函数名> = <返回码>"；
6. 按相反顺序释放资源（cuMemFree、cuCtxDestroy），程序正常 return 0。

要求：#include <cuda.h> 和 <stdio.h>；不使用 Runtime API；只输出一个 ```c 代码块。""",

    "boundary": """任务：写一个 C 程序（Windows x64，CUDA Driver API），专门观察**参数合同错误**：

1. 先 cuInit(0) 正常初始化；
2. 调用 cuMemAlloc(&dPtr, 0)（0 字节），打印返回码；
3. 用错误的 major 版本号构造 CUcontext 参数调用 cuCtxCreate（或对未初始化句柄调用 cuCtxDestroy），打印返回码；
4. 每次调用后打印一行 "API <函数名> = <返回码>"；
5. 程序必须在收到 CUDA_ERROR_INVALID_VALUE / CUDA_ERROR_INVALID_CONTEXT 等参数错误后
   **正常清理并 return 0**——预期错误不是崩溃；
6. 最后打印一行 "BOUNDARY=DONE"。

要求：同上；只输出一个 ```c 代码块。""",
}


def extract_code(text: str) -> str:
    match = re.search(r"```(?:c|cpp|c\+\+)?\s*(.*?)```", text, re.S)
    return match.group(1).strip() if match else ""


def run_experiment(name: str, task: str, client, context) -> dict:
    work = OUT / name
    work.mkdir(parents=True, exist_ok=True)
    rounds = []
    prompt = task + "\n\n实验上下文（允许你看到的全部信息）：\n" + \
        json.dumps(context["payload"], ensure_ascii=False, indent=1)

    source_text, feedback = None, None
    for index in range(1 + MAX_FIX_ROUNDS):
        user = prompt if feedback is None else \
            prompt + "\n\n[上一轮候选失败，以下是客观诊断，请修复]\n" + feedback + \
            "\n\n[上一轮源码]\n```c\n" + source_text + "\n```"
        (work / ("round%d_prompt.txt" % (index + 1))).write_text(user, encoding="utf-8")
        raw = client.chat([{"role": "system", "content": "只输出代码块。"},
                           {"role": "user", "content": user}], temperature=0.0)
        (work / ("round%d_response.txt" % (index + 1))).write_text(raw, encoding="utf-8")
        source_text = extract_code(raw)
        source = work / ("candidate%d.c" % (index + 1))
        source.write_text(source_text, encoding="utf-8")
        if not source_text:
            feedback = "未输出代码块"
            rounds.append({"round": index + 1, "compile_rc": None, "failure": "no code"})
            continue

        compile_result = backend.compile_source(source, work / ("candidate%d" % (index + 1)), work)
        (work / ("round%d_compile.log" % (index + 1))).write_text(
            json.dumps(compile_result, ensure_ascii=False, indent=1), encoding="utf-8")
        if compile_result["returncode"] != 0:
            feedback = ("编译失败（nvcc rc=%d）：\nstdout://n%s//nstderr://n%s"
                        % (compile_result["returncode"],
                           compile_result["stdout"][-1500:],
                           compile_result["stderr"][-1500:]))
            rounds.append({"round": index + 1, "compile_rc": compile_result["returncode"],
                           "failure": "compile"})
            continue

        binary = Path(compile_result["binary"])
        invocation = backend.run_program(binary, "%s-r%d" % (name, index + 1))
        record = backend.build_record(compile_result, invocation, source)
        api_rows = backend.parse_api_lines(invocation.stdout)
        (work / ("round%d_run.json" % (index + 1))).write_text(
            json.dumps({"api": api_rows, "states": record.states(),
                        "exit": invocation.exit_code, "stdout": invocation.stdout,
                        "stderr": invocation.stderr, "timed_out": invocation.timed_out},
                       ensure_ascii=False, indent=1), encoding="utf-8")
        rounds.append({"round": index + 1, "compile_rc": 0,
                       "states": record.states(), "exit": invocation.exit_code,
                       "api_calls": len(api_rows),
                       "api_errors": sum(1 for r in api_rows if r["is_error"])})
        if not invocation.timed_out and invocation.exit_code == 0:
            return {"rounds": rounds, "done": True, "api": api_rows}
        feedback = ("程序 exit=%s timed_out=%s stderr=%s"
                    % (invocation.exit_code, invocation.timed_out,
                       invocation.stderr[-1000:]))
    return {"rounds": rounds, "done": False, "api": []}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    env = backend.probe()
    context = build_context(CASE, PUBLIC_ONLY)
    client = LLMClient(ConfigLoader())
    (OUT / "environment.json").write_text(
        json.dumps(env.__dict__, ensure_ascii=False, indent=1), encoding="utf-8")

    results = {}
    for name, task in TASKS.items():
        results[name] = run_experiment(name, task, client, context)
        print(name, "done:", results[name]["done"],
              "| rounds:", len(results[name]["rounds"]),
              "| last:", results[name]["rounds"][-1] if results[name]["rounds"] else None)

    (OUT / "summary.json").write_text(
        json.dumps({"environment": env.__dict__, "context_sha256": context["context_sha256"],
                    "results": results}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
