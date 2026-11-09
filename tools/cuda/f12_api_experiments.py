# -*- coding: utf-8 -*-
"""F12: four real CUDA Driver API experiments, two platforms, one pipeline.

The case, the projection, the prompt contract and the verdict ladder are shared.
Only the transport differs. The boundary experiment creates a real context first, so
a zero-byte allocation is judged under a valid context, and the invalid-context call
is a separate item rather than the only test.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.case_context import PUBLIC_ONLY, build_context      # noqa: E402
from src.config_loader import ConfigLoader                   # noqa: E402
from src.cuda_api_backend import parse_api_lines             # noqa: E402
from src.cuda_transport import save_record, transport_for     # noqa: E402
from src.llm_client import LLMClient                         # noqa: E402

OUT = ROOT / "data" / "driver" / "f12-api"
CASES = {"windows": ROOT / "data" / "cases" / "cuda-driver-api-baseline.v2.json",
         "linux": ROOT / "data" / "cases" / "cuda-driver-api-linux.v2.json"}

PLATFORM_TEXT = {
    "windows": ("Windows x64，用 nvcc 编译（CUDA 11.2），链接 cuda.lib；"
                "只能包含 <cuda.h> 与标准 C 头文件，不要使用 <windows.h> 之外的平台头。"),
    "linux": ("Linux x86-64，用 gcc 编译（-I/usr/local/cuda/include -lcuda）；"
              "只能包含 <cuda.h> 与标准 C 头文件，**禁止 <windows.h>**。"),
}

TASKS = {
    "normal": """写一个 C 程序完成 CUDA Driver API 生命周期：
cuInit → cuDeviceGet → cuCtxCreate → cuMemAlloc(256) → cuMemcpyHtoD → cuMemcpyDtoH
→ 校验数据一致 → 打印 "DATA=OK" 或 "DATA=MISMATCH" → cuMemFree → cuCtxDestroy。
每次调用后打印一行 "API <函数名> = <返回码>"，正常 return 0。""",

    "boundary": """写一个 C 程序，**先建立有效 Context**，再观察参数合同：

1. cuInit(0) → cuDeviceGet → cuCtxCreate（必须成功，得到有效 context）；
2. 在有效 context 下调用 cuMemAlloc(&ptr, 0)（零字节），记录真实返回码；
3. 在有效 context 下调用 cuMemAlloc(&ptr, 256) 作为对照，记录返回码；
4. 销毁 context 后，再调用 cuMemAlloc(&p, 256)，记录返回码（无效 context 用例）；
5. 每次调用后打印 "API <函数名> = <返回码>"；
6. 无论返回码如何，程序都要正常清理并 return 0，最后打印 "BOUNDARY=DONE"。

注意：不要假设零字节分配一定有某个错误码，如实报告实际结果。""",
}


def build_prompt(task_name: str, platform: str, context: dict) -> str:
    return ("任务：%s\n\n目标平台：%s\n\n实验上下文（允许你看到的全部信息）：\n%s"
            % (TASKS[task_name], PLATFORM_TEXT[platform],
               json.dumps(context["payload"], ensure_ascii=False, indent=1)))


def extract_code(text: str) -> str:
    match = re.search(r"```(?:c|cpp)?\s*(.*?)```", text, re.S)
    return match.group(1).strip() if match else ""


def run_one(platform: str, task_name: str, client) -> dict:
    work = OUT / platform / task_name
    work.mkdir(parents=True, exist_ok=True)
    context = build_context(CASES[platform], PUBLIC_ONLY)
    prompt = build_prompt(task_name, platform, context)
    (work / "prompt.txt").write_text(prompt, encoding="utf-8")

    raw = client.chat([{"role": "system", "content": "只输出代码块。"},
                       {"role": "user", "content": prompt}], temperature=0.0)
    (work / "response.txt").write_text(raw, encoding="utf-8")
    source_text = extract_code(raw)
    source = work / "candidate.c"
    source.write_text(source_text, encoding="utf-8")

    result = {"platform": platform, "task": task_name,
              "context_sha256": context["context_sha256"],
              "evidence_ids": context["included_evidence"],
              "generated": bool(source_text)}
    if not source_text:
        result["failure"] = "no code block"
        return result

    transport = transport_for(platform)
    build = transport.build(source, work)
    result["build"] = {"ok": build.ok, "rc": build.returncode,
                       "artifact": build.artifact,
                       "source_sha256": build.source_sha256,
                       "artifact_sha256": build.artifact_sha256,
                       "log_tail": build.log[-1200:]}
    if not build.ok:
        result["failure"] = "build"
        (work / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
        return result

    invocation = transport.run(build.artifact, "%s-%s" % (platform, task_name))
    save_record(work, build, invocation)
    api_rows = parse_api_lines(invocation.stdout)
    result.update({"exit": invocation.exit_code, "timed_out": invocation.timed_out,
                   "api": api_rows,
                   "data_ok": "DATA=OK" in invocation.stdout,
                   "boundary_done": "BOUNDARY=DONE" in invocation.stdout,
                   "stderr_tail": invocation.stderr[-600:]})
    (work / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    client = LLMClient(ConfigLoader())
    summary = {}
    for platform in ("windows", "linux"):
        for task_name in ("normal", "boundary"):
            key = "%s/%s" % (platform, task_name)
            summary[key] = run_one(platform, task_name, client)
            item = summary[key]
            print("%-18s build=%s exit=%s api=%d data_ok=%s boundary=%s"
                  % (key, item.get("build", {}).get("ok"), item.get("exit"),
                     len(item.get("api", [])), item.get("data_ok"),
                     item.get("boundary_done")))
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
