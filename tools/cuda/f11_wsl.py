# -*- coding: utf-8 -*-
"""F11 on the Linux side: same case, same context, different target platform.

The Windows run produced a candidate that includes <windows.h>, which cannot build
under gcc. That is a defect in the task text, not in the model: the prompt never said
which platform the program was for. Here the platform is stated explicitly and the
build/run happens inside WSL, so the two sides are comparable.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.case_context import PUBLIC_ONLY, build_context   # noqa: E402
from src.config_loader import ConfigLoader                # noqa: E402
from src.llm_client import LLMClient                      # noqa: E402

OUT = ROOT / "data" / "driver" / "f11-linux"
CASE = ROOT / "data" / "cases" / "cuda-driver-api-baseline.v2.json"
DISTRO = "Ubuntu-22.04"

TASK = """任务：写一个 C 程序，在 **Linux x86-64** 上使用 CUDA Driver API：

1. cuInit(0) → cuDeviceGet → cuCtxCreate；
2. cuMemAlloc 分配 256 字节，cuMemcpyHtoD 写入已知模式，cuMemcpyDtoH 读回；
3. 校验一致性，打印 "DATA=OK" 或 "DATA=MISMATCH"；
4. 每次调用后打印一行 "API <函数名> = <返回码>"；
5. 按相反顺序释放（cuMemFree、cuCtxDestroy），正常 return 0。

硬性约束：
- 只能包含 <cuda.h> 与标准 C 头文件，**禁止 <windows.h>** 或其他平台专有头；
- 不使用 CUDA Runtime API；
- 用 gcc 可编译（-I/usr/local/cuda/include -lcuda）；
- 只输出一个 ```c 代码块。

实验上下文：
"""


def wsl(script: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["wsl.exe", "-d", DISTRO, "--", "bash", "-lc", script],
                          capture_output=True, text=True, errors="replace",
                          timeout=timeout)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    context = build_context(CASE, PUBLIC_ONLY)
    prompt = TASK + json.dumps(context["payload"], ensure_ascii=False, indent=1)
    (OUT / "prompt.txt").write_text(prompt, encoding="utf-8")

    raw = LLMClient(ConfigLoader()).chat(
        [{"role": "system", "content": "只输出代码块。"},
         {"role": "user", "content": prompt}], temperature=0.0)
    (OUT / "response.txt").write_text(raw, encoding="utf-8")
    match = re.search(r"```(?:c)?\s*(.*?)```", raw, re.S)
    source = match.group(1).strip() if match else ""
    (OUT / "candidate.c").write_text(source, encoding="utf-8")
    if not source:
        print("no code block")
        return 1

    subprocess.run(["wsl.exe", "-d", DISTRO, "--", "bash", "-lc",
                    "mkdir -p ~/f11linux && cat > ~/f11linux/candidate.c"],
                   input=source.encode("utf-8"), check=False, timeout=120)

    script = ("export LD_LIBRARY_PATH=$HOME/cuda-wsl-libs; cd $HOME/f11linux; "
              "gcc candidate.c -o candidate -I/usr/local/cuda/include "
              "-L$HOME/cuda-wsl-libs -lcuda 2>&1 | head -5; echo BUILD_RC=$?; "
              "./candidate 2>&1; echo RUN_RC=$?")
    proc = wsl(script)
    (OUT / "run.log").write_text(proc.stdout + "\n[stderr]\n" + proc.stderr,
                                 encoding="utf-8")
    print(proc.stdout[-600:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
