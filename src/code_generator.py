# =============================================================================
# CUDA PoC Generator — CUDA PoC 代码生成器模块
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
CUDA PoC 代码生成器。

基于 CudaSecurityExpert 输出的验证策略和 CUDA 漏洞上下文，
调用 LLM 生成完整的 CUDA 漏洞验证 PoC 脚本。

生成的代码遵循以下规范：
- Python 3.10+ 语言
- 包含 [CUDA_STEP:Sxx] 步骤日志标记
- 自动检测 CUDA 环境（GPU、驱动、Toolkit 版本）
- 使用 ctypes/pycuda 调用 CUDA API
- 完整的错误处理和 CUDA 错误码解释
"""

import json
import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional

from .llm_client import LLMClient
from .cuda_library import CudaLibrary
from .models.analysis import resolve_target_cve, validate_analysis
from .quality_lints import run_lints
from .models.generation import CandidateResult
from .utils import ensure_dir, write_json, write_text

logger = logging.getLogger("cuda_poc_generator.code_generator")

# ---------------------------------------------------------------------------
# CUDA PoC 代码生成系统提示
# ---------------------------------------------------------------------------
_CUDA_CODEGEN_SYSTEM_PROMPT = """\
You are an expert CUDA vulnerability researcher. Your task is to translate a structured \
CUDA verification strategy into a fully functional, self-contained PoC script.

## CUDA PoC Hard Requirements

1. **Language**: Python 3.10+ ONLY. Use `ctypes` to call CUDA Driver/Runtime API.
   If pycuda is required, provide a fallback to ctypes.

2. **CUDA Environment Detection**: The script MUST auto-detect at startup:
   - GPU availability (device count, compute capability)
   - CUDA Driver version (cuDriverGetVersion)
   - CUDA Toolkit version (nvcc --version or cudaRuntimeGetVersion)
   - OS and kernel version

3. **Step Logging**: Every logical step MUST print a status line in the format:
   ```
   [CUDA_STEP:Sxx] <description> — START
   [CUDA_STEP:Sxx] <description> — OK | FAIL: <error_details>
   ```
   Where Sxx matches the step_id from the strategy. This is critical for
   automated feedback parsing.

4. **CUDA Error Handling**: Every CUDA API call MUST check the return code.
   Wrap each step in try/except. On CUDA error, print:
   - The CUDA error code (int)
   - The human-readable error name
   - The step context
   Decide whether to abort or continue based on error severity.

5. **Imports**: Use standard library + ctypes for CUDA API.
   Optionally use pycuda if more convenient, but always include a ctypes fallback.

6. **Subprocess Error Reporting (CRITICAL)**: Any time you use subprocess.run()
   to call nvcc, cuobjdump, nvdisasm, or any CUDA toolchain binary, you MUST
   capture both stdout and stderr. On non-zero return code, print BOTH:
   - The full command line that failed
   - The first 4000 bytes of stdout and stderr

7. **Version Classification (CRITICAL)**: When the PoC classifies installed
   driver/toolkit versions against affected ranges, a version whose branch is
   NOT in the known table MUST be classified UNKNOWN, never NOT-AFFECTED.
   Branch tables are always incomplete; "major 551 not in {470,535,550,555}"
   does NOT mean patched. An unmapped version must produce an explicit
   "UNKNOWN — consult the advisory" verdict.

8. **Driver API Precondition (CRITICAL)**: If the PoC probes nvcuda/nvml/nvapi
   entry points, the process (or child) MUST initialize first — cuInit(0) and
   a real cuCtxCreate for CUDA APIs — before the first probe call. Without a
   context every call returns CUDA_ERROR_NOT_INITIALIZED and the matrix
   measures nothing. Verify this holds for EACH probe function, not just one.

9. **Shader Instruction Tokens (CRITICAL)**: Before searching a compiled
   shader byte stream for an instruction opcode token, confirm the target
   profile actually contains that instruction. D3DSIO_* opcodes (e.g. SINCOS)
   exist only in SM2/SM3; SM4/SM5 (ps_5_0 and friends) do not contain them,
   and D3D11 rejects SM2/SM3 shaders. Match the token constant to the profile
   and verify the token occurs in the compiled output before patching.

10. **CUDA Version Parsing**: When parsing version strings from `nvcc --version`,
   `nvdisasm --version`, `cuobjdump --version`, or any CUDA tool, NEVER assume
   a specific output format (e.g. "Version 12.5.0" vs "V12.5.39" vs
   "release 12.5"). ALWAYS use the generic fallback pattern:
   `re.search(r'(\\d+)\\.(\\d+)\\.?(\\d+)?', output)`
   This single pattern works on ALL CUDA tool version outputs. If you need
   to extract tool-specific info, also print the full --version output at
   startup for the user to inspect.

11. **nvcc Arch Auto-Detection**: NEVER hardcode `-arch=sm_75` or any fixed
   compute capability. Instead, detect the installed GPU's arch at runtime:
   - Use `nvidia-smi --query-gpu=compute_cap --format=csv,noheader` if available
   - Fallback: try compiling with `nvcc -arch=native` first (CUDA 11.8+)
   - Last resort: try a list of common arches (sm_52, sm_61, sm_75, sm_86, sm_89)
     and use the first one that succeeds.
   If no GPU is present, use `-arch=sm_52` as the safest baseline.

12. **CUDA Helper Functions**: When a CUDA helper library signature list is provided,
   you MUST use those helper signatures as a reference. Implement them in the PoC.

13. **Code Quality & Professionalism**:
   - Every function MUST have a one-line docstring describing what it does.
   - NO placeholder or AI-generated commentary like "stub", "TODO: implement",
     "not necessary", "simplified version", "basic implementation", "helper using".
     Write production-quality code, not notes-to-self.
   - NO section divider comments like `# ---- Step 1 ----`, `# === helpers ===`,
     or `# ELF helpers using only struct`. Use proper module/function docstrings instead.
   - NO commented-out code. NO "Optional:" or "maybe" in comments.
   - The `main()` function should be at most 80 lines — extract logic into named
     helper functions with clear responsibilities.
   - Keep line length under 100 characters.
   - All imports at the top, grouped: stdlib → third-party → local.

14. **Vulnerability Trigger Construction (通用原则)**: The way you construct the
   malicious input depends on the vulnerability category. Follow the correct
   strategy for each — never hand-craft complex binary structures from scratch:

   **File-format parsers (nvdisasm, cuobjdump, ptxas, fatbinary, nvlink):**
   - Step A: compile a minimal VALID file with nvcc (e.g. `-arch=sm_52 -cubin`)
   - Step B: struct-patch SPECIFIC fields in that valid file to trigger the
     vulnerability. CRITICAL RULES for ELF cubin manipulation:
     * Standard ELF64 section header: `<IIQQQQIIQQ` (64 bytes, 10 fields)
     * sh_offset is tuple index 4, sh_size is tuple index 5
     * To replace section content: append new data at EOF, then update that
       section's sh_offset and sh_size in the section header table
     * Do NOT add new section headers — tools only recognize the first
       occurrence of a section by name (e.g. .debug_abbrev)
     * Do NOT modify e_shnum
     * After every ELF modification, write out the file and IMMEDIATELY
       re-read it with struct.unpack to validate the layout before proceeding
   - Step C: generate multiple variants with different corruption parameters
     in a single run, printing which variant was attempted and its outcome
   - NEVER build an ELF/cubin/DWARF from raw bytes with struct.pack()

   **CUDA Driver/Runtime API misuse (ctypes-based PoCs):**
   - Step A: initialize CUDA normally, allocate a valid buffer/context/stream
   - Step B: pass intentionally malformed values to the vulnerable API
     (near-U32_MAX offset, freed handle, double-free, oversized grid/block dims)
   - Step C: check return codes AND dmesg for kernel OOPS/KASAN reports

   **Kernel-level race conditions:**
   - Spawn multiple threads calling the vulnerable ioctl/API concurrently
   - Vary timing with small sleeps between critical calls
   - Check dmesg for use-after-free or race-condition KASAN reports

   **GPU memory safety (device-side OOB/UAF):**
   - Write a minimal kernel that performs the dangerous memory access pattern
   - Use cuda-memcheck or compute-sanitizer to confirm the access violation
   - Fallback: check kernel launch errors and dmesg if sanitizer unavailable

   ALWAYS generate multiple test cases in a single PoC run — a single fixed
   input is unlikely to trigger the vulnerability on the first attempt.

15. **Minimal & Reproducible**: The script should be the shortest code that
   reliably triggers the vulnerability in the described CUDA environment.
   BUT do NOT sacrifice the code quality rules above for brevity.

16. **Safety Banner**: Print a disclaimer banner at startup:
   ```
   ===========================================================
   DISCLAIMER: This script is a Proof-of-Concept for CUDA
   vulnerability <CVE-ID>. It is intended ONLY for authorized
   security research on systems you own or have permission to test.
   ===========================================================
   ```

17. **Exit Code**: Exit 0 on successful vulnerability trigger, non-zero on failure.

18. **GPU Cleanup**: Always attempt to free GPU resources before exiting,
    even on error paths.

19. **File Output Location**: NEVER write output files (crafted cubin, ELF,
   exploit payloads) to `/tmp/` or `tempfile.mkdtemp()`. Write them to the
   script's own directory (`os.path.dirname(__file__)` or `"."`) so the user
   can inspect them. Print the output directory at startup. Do NOT auto-delete
   generated files on exit.

20. **Observation Rendezvous (CRITICAL)**: after the target library or device is
   loaded, and BEFORE the first trigger call, check `CPG_DEBUG_PAUSE`: when it
   is set, print `[CPG_READY] <pid>` (flush immediately) and sleep that many
   seconds. The closed-loop harness attaches a debugger inside this window to
   record whether the vulnerable function was actually executed. Without the
   rendezvous the loop can only observe crashes, never reachability.

21. **Per-artifact Observation Line (CRITICAL)**: after each artifact is run,
   print exactly `[CPG_RUN] <artifact-name> exit=<code>` on its own line
   (flush it), and for each artifact print `[CPG_LABEL] <artifact-name>
   MALICIOUS|BENIGN|CONTROL` exactly once, before running it. Names are not
   enough: the harness needs the declared role to build the differential
   verdict, and a run without a label cannot count as evidence.

22. **Trigger Oracle (do this BEFORE writing the mutation code)**: state, as a
   comment block at the top of the script, the precondition that must hold for
   the defect to fire:
   `FIELD: <name>  OFFSET: <n>  SIZE: <n>  REQUIRED: <value or range>
    CHECK PRESENT: <yes|no>  WHY IT FAILS: <one sentence>`.
   Then assert it at runtime: read the field back from the crafted file and
   print `[CPG_ORACLE] <field> actual=<value> expected=<value>`. A PoC whose
   oracle was never evaluated is not evidence, even if something crashed.

23. **Method Not Blind Mutation**: mutate the field the parser actually
   consumes, at the offset its code reads. If the input data does not name that
   field, say so in the oracle block and keep the mutation conservative. Do not
   spray random bytes: an unrelated crash is a false positive, and the
   differential control will expose it.

24. **Differential Is The Definition of Success**: the trigger must crash while
   the control — same file, exactly one variable changed — does not. Print both
   results. If both crash, the PoC has proven nothing; report that instead of
   claiming success.

25. **Minimize**: prefer the smallest input that still triggers. Report the
   final artifact size in bytes and the number of mutated bytes. Large PoCs are
   harder to attribute and harder to defend.

26. **Attribute The Fault**: when a crash occurs, print the signal/exit code
   and, where available, the faulting frame or module. A crash that cannot be
   attributed to the target parser is not a reproduced vulnerability.

Respond with the COMPLETE Python script only. Follow these rules STRICTLY:

1. Your ENTIRE response MUST be executable Python code — the first character
   of your response must be `#` or `\"\"\"`. NOTHING else.
2. DO NOT simulate execution. DO NOT write a play-by-play of what would happen.
   DO NOT write "[CUDA_STEP:S01] ... — OK" as narrative text. Those markers
   belong ONLY inside Python print() calls in the code itself.
3. DO NOT write a preamble like "Now I will generate..." or "Here is the script:".
   The response IS the script.
4. If your output cannot be saved to a .py file and executed with python3,
   you have failed.
"""


class CudaCodeGenerator:
    """CUDA PoC 代码生成器。

    Attributes:
        llm: LLM 客户端。
        cuda_lib: CUDA 辅助函数库。
        outputs_dir: 输出目录路径。
    """

    def __init__(
        self,
        llm: LLMClient,
        cuda_lib: CudaLibrary,
        outputs_dir: str,
    ) -> None:
        """初始化 CUDA 代码生成器。

        Args:
            llm: 已配置好的 LLM 客户端。
            cuda_lib: CUDA 领域辅助函数库实例。
            outputs_dir: PoC 文件输出目录。
        """
        self.llm = llm
        self.cuda_lib = cuda_lib
        self.outputs_dir = outputs_dir
        self.last_result = CandidateResult()
        ensure_dir(outputs_dir)

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------
    def generate(
        self,
        vuln_context: Dict[str, Any],
        expert_analysis: Dict[str, Any],
        iteration: int = 1,
        extra_context: str = "",
    ) -> str:
        """根据 CUDA 验证策略生成完整的 PoC 脚本。

        Args:
            vuln_context: 七类 CUDA 漏洞输入数据。
            expert_analysis: CudaSecurityExpert 输出的分析结果。
            iteration: 当前迭代轮次，用于文件命名。
            extra_context: 额外上下文（如用户补充信息、RAG 知识片段）。

        Returns:
            生成的 PoC 代码字符串。同时将其写入输出文件。
        """
        # Reset before every attempt so a previous successful candidate cannot leak status.
        self.last_result = CandidateResult()
        retries = 0
        last_code = ""
        try:
            # Direct callers must also obey the analysis contract; no invalid dict reaches chat.
            expected_cve = resolve_target_cve(vuln_context)
            expert_analysis = validate_analysis(
                expert_analysis, expected_cve_id=expected_cve,
            ).model_dump(exclude_unset=True)
            user_prompt = self._build_prompt(vuln_context, expert_analysis, extra_context)
            logger.info("正在生成 CUDA PoC 代码（迭代 #%d）…", iteration)
            raw_code = self.llm.chat(
                messages=[
                    {"role": "system", "content": _CUDA_CODEGEN_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,  # reproducibility: same input must give the same candidate
            )
            self._require_source(raw_code)
            code = self._clean_code(raw_code)
            self._require_source(code)
            last_code = code
            ok, err_msg = self._validate_code(code)
            while not ok and retries < 2:
                retries += 1
                logger.warning("PoC 静态检查错误 (尝试 %d/2): %s", retries, err_msg[:120])
                correction_prompt = (
                    f"The previous code had a Python static check failure:\n"
                    f"```\n{err_msg}\n```\n"
                    f"Please fix the error and regenerate the COMPLETE script."
                )
                raw_code = self.llm.chat(
                    messages=[
                        {"role": "system", "content": _CUDA_CODEGEN_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                        {"role": "assistant", "content": code[:4000]},
                        {"role": "user", "content": correction_prompt},
                    ],
                    temperature=0.0,
                )
                self._require_source(raw_code)
                code = self._clean_code(raw_code)
                self._require_source(code)
                last_code = code
                ok, err_msg = self._validate_code(code)

            if not ok:
                logger.warning("PoC 静态修正失败，保存候选供人工检查: %s", err_msg[:120])
                print(f"  [!] STATIC_INVALID: {err_msg[:120]}")
                # Keep the rejected source: without it the loop can only report
                # "syntax error" and nobody can see what the model actually wrote.
                rejected = os.path.join(self.outputs_dir,
                                        f"cuda_poc_v{iteration}.invalid.py")
                with open(rejected, "w", encoding="utf-8") as handle:
                    handle.write("// static check failed: %s\n" % err_msg)
                    handle.write(code)
            else:
                print("  [✓] STATIC_VALID（仅静态检查，未执行或验证）")

            filename = f"cuda_poc_v{iteration}.py"
            filepath = os.path.join(self.outputs_dir, filename)
            write_text(filepath, code)
            with open(filepath, "rb") as source:
                source_hash = hashlib.sha256(source.read()).hexdigest()
            self.last_result = CandidateResult(
                generation="GENERATED", static="STATIC_VALID" if ok else "STATIC_INVALID",
                source_file=filename, sha256=source_hash, correction_attempts=retries,
                errors=[] if ok else [err_msg],
            )
            self._write_result(iteration)
            logger.info("CUDA 候选已保存: %s", filepath)
        except Exception as exc:
            # Even a failed run must leave the last source behind: otherwise
            # the loop can only say "generation failed" without evidence.
            if last_code.strip():
                rejected = os.path.join(self.outputs_dir,
                                        f"cuda_poc_v{iteration}.invalid.py")
                with open(rejected, "w", encoding="utf-8") as handle:
                    handle.write("// generation failed: %s\n" % type(exc).__name__)
                    handle.write(last_code)
            self.last_result = CandidateResult(
                generation="GENERATION_FAILED", correction_attempts=retries,
                errors=[f"GENERATION_ERROR: {type(exc).__name__}"],
            )
            self._write_result(iteration)
            raise
        return code

    @staticmethod
    def _require_source(source: str) -> None:
        """An empty response is a generation failure, independent of AST semantics."""
        if not isinstance(source, str) or not source.strip():
            raise ValueError("生成模型没有返回非空候选源码。")

    def _write_result(self, iteration: int) -> None:
        write_json(
            os.path.join(self.outputs_dir, f"cuda_poc_v{iteration}.status.json"),
            self.last_result.model_dump(mode="json"),
        )

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------
    def _build_prompt(
        self,
        vuln_ctx: Dict[str, Any],
        analysis: Dict[str, Any],
        extra: str,
    ) -> str:
        """拼装 CUDA 代码生成的用户提示。"""
        parts: List[str] = []

        # --- CUDA 验证策略 ---
        parts.append("## CUDA Exploit Strategy\n")
        parts.append(
            f"```json\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n```\n"
        )

        # --- CUDA 环境信息 ---
        env = vuln_ctx.get("os_environment", {})
        if env:
            parts.append("## Source OS assertions (not selected execution target)\n")
            parts.append(
                f"```json\n{json.dumps(env, indent=2, ensure_ascii=False)}\n```\n"
            )

        cuda_env = vuln_ctx.get("cuda_environment", {})
        if cuda_env:
            parts.append("## Source CUDA assertions (not selected execution target)\n")
            parts.append(
                f"```json\n{json.dumps(cuda_env, indent=2, ensure_ascii=False)}\n```\n"
            )

        # --- CUDA 辅助函数签名 ---
        helper_sigs = self.cuda_lib.get_signatures_text()
        if helper_sigs:
            parts.append("## Available CUDA Helper Functions\n")
            parts.append(
                "You MUST use these CUDA helper signatures as a reference. "
                "Implement them in the PoC as needed.\n"
            )
            parts.append(f"```python\n{helper_sigs}\n```\n")

        # --- CUDA 攻击面知识 (Attack Surface Reference) ---
        attack_surface_text = self.cuda_lib.get_cuda_attack_surface_text()
        parts.append(f"{attack_surface_text}\n")

        # --- IMPORTABLE TOOL LIBRARY (verified, battle-tested) ---
        from .tools import get_tools_reference_text
        parts.append(get_tools_reference_text()[:800] + "\n")  # trimmed for speed

        # --- 额外上下文 ---
        if extra:
            parts.append(f"## Additional Context\n{extra}\n")

        # --- 受影响组件 ---
        affected = vuln_ctx.get("affected_component", {})
        if affected:
            parts.append("## Affected Component Details\n")
            parts.append(
                f"```json\n{json.dumps(affected, indent=2, ensure_ascii=False)}\n```\n"
            )

        parts.append(
            "Generate the complete CUDA PoC Python script now.\n"
            "CRITICAL REMINDERS:\n"
            "- [CUDA_STEP:Sxx] logging is MANDATORY for every step.\n"
            "- All CUDA API and subprocess calls must have error checking.\n"
            "- NO AI commentary, stub markers, section dividers, or commented-out code.\n"
            "- Use only the selected TARGET PLATFORM SNAPSHOT paths; unknown architecture stays unknown.\n"
            "- Print subprocess stderr on any failure.\n"
            "- Your response must START with executable Python code (shebang or docstring).\n"
            "- DO NOT simulate execution — write the script, not a play-by-play."
        )
        return "\n".join(parts)

    @staticmethod
    def _clean_code(raw: str) -> str:
        """Clean LLM output: strip fences, detect simulation-style garbage."""
        # Detect simulation-style output (LLM narrated execution instead of writing code)
        lines = raw.strip().splitlines()
        narrative_lines = 0
        for line in lines[:20]:  # check first 20 lines
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "\"\"\"", "'''", "import ", "from ", "def ", "class ", "try:", "if ", "@")):
                continue
            if re.search(r'\[CUDA_STEP:S\d{2}\]', stripped) and 'print(' not in stripped:
                narrative_lines += 1
        if narrative_lines > 3:
            logger.warning(
                "LLM output appears to be a simulation narrative (%d non-code [CUDA_STEP] lines), "
                "not executable code. Consider regenerating.", narrative_lines
            )
        # Strip markdown fences
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _validate_code(code: str) -> tuple:
        """Python syntax + import completeness check. Returns (ok, error_msg)."""
        import ast as _ast
        import builtins as _builtins

        try:
            tree = _ast.parse(code)
        except SyntaxError as e:
            return False, f"SyntaxError at line {e.lineno}: {e.msg}"

        # ---- 1. struct format checks (existing) ----
        # Match the three real call spellings: pack / pack_into / unpack. The
        # earlier "pack\(?_?into" form could only match pack_into, so plain
        # struct.pack("") and struct.pack("<") were never rejected.
        struct_call = r"(?:pack_into|unpack|pack)\s*\("
        for i, line in enumerate(code.split("\n"), 1):
            if not re.search(r"struct\.(?:pack_into|unpack|pack)\s*\(", line):
                continue
            if re.search(struct_call + r"\s*['\"]\s*['\"]\s*,", line):
                return False, f"Line {i}: struct format empty — {line.strip()[:80]}"
            if re.search(struct_call + r"\s*['\"][@=<>!]?['\"]\s*,", line):
                return False, f"Line {i}: struct format missing type code — {line.strip()[:80]}"

        # ---- 2. missing-import detection (new) ----
        builtin_names = set(dir(_builtins)) | {
            "self", "True", "False", "None", "cls",
            "__name__", "__file__", "__doc__", "__init__",
            "Exception", "BaseException", "object", "type",
            "enumerate", "zip", "range", "super", "property",
        }
        # Collect names defined by imports and assignments
        defined = set(builtin_names)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    defined.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, _ast.ImportFrom):
                for alias in node.names:
                    defined.add(alias.asname or alias.name)
            elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                defined.add(node.name)
                for arg in node.args.args:
                    defined.add(arg.arg)
            elif isinstance(node, _ast.ClassDef):
                defined.add(node.name)
            elif isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Store):
                defined.add(node.id)
            elif isinstance(node, _ast.arg):
                defined.add(node.arg)
            elif isinstance(node, _ast.ExceptHandler) and node.name:
                defined.add(node.name)  # except ... as name

        # Find all Name references that aren't defined
        undefined = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Load):
                if node.id not in defined and not node.id.startswith("_"):
                    undefined.add(node.id)

        if undefined:
            hints = ", ".join(sorted(undefined)[:5])
            return False, f"Likely missing imports: {hints}"

        # ---- 3. domain lints (failure modes observed in real PoCs) ----
        findings = run_lints(code)
        if findings:
            ids = ", ".join(lint_id for lint_id, _ in findings)
            detail = " | ".join(msg for _, msg in findings[:3])
            return False, f"{ids} — {detail}"

        return True, ""
