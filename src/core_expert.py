# =============================================================================
# CUDA PoC Generator — CUDA 安全专家核心引擎
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
CUDA 专项安全专家引擎 —— 整个框架的灵魂。

CUDA Security Expert 扮演一位世界顶级 GPU 安全研究员的角色，
内建 CUDA 专项 7 层漏洞分析模型 (7-Layer CUDA Vulnerability Analysis Model)，
基于用户提供的 7 类结构化 CUDA 漏洞资料 + RAG 检索到的 CUDA 领域知识，
执行根因分析并生成结构化的 CUDA 漏洞验证策略。

输出为严格 JSON，包含 root_cause_analysis 和 verification_strategy 两部分。
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .llm_client import LLMClient, StructuredOutputError
from .models.analysis import ExpertAnalysis, resolve_target_cve, validate_analysis

logger = logging.getLogger("cuda_poc_generator.core_expert")

# ===========================================================================
# CUDA 安全专家系统提示 — 7 层 CUDA 漏洞分析模型
# ===========================================================================
_CUDA_EXPERT_SYSTEM_PROMPT = """\
You are a world-class GPU security researcher and CUDA vulnerability analyst with \
deep expertise across all NVIDIA GPU technologies: CUDA Driver/Runtime API, \
PTX ISA, cubin/fatbin binary formats, GPU memory architecture, CUDA toolchain \
(nvcc, nvlink, cuobjdump, nvdisasm, ptxas), CUDA libraries (cuBLAS, cuDNN, \
cuFFT), GPU virtualization (MPS, MIG, GPU passthrough), and GPU Direct/RDMA.

## CUDA-Specific 7-Layer Vulnerability Analysis Model (CUDA 7层漏洞分析模型)

You MUST follow this systematic thinking model for every CUDA vulnerability:

### Layer 1: CUDA Attack Surface Mapping (CUDA攻击面映射)
- Identify which CUDA subsystem is affected:
  * CUDA Driver API (cuInit, cuCtxCreate, cuMemAlloc, cuMemFree, cuLaunchKernel, cuModuleLoad, etc.)
  * CUDA Runtime API (cudaMalloc, cudaMemcpy, cudaLaunchKernel, etc.)
  * CUDA Toolchain (nvcc, cuobjdump, nvdisasm, ptxas, nvlink, fatbinary)
  * CUDA Libraries (cuBLAS, cuDNN, cuFFT, cuSPARSE, cuSOLVER, cuRAND)
  * GPU Virtualization (MPS server, MIG instances, GPU passthrough)
  * CUDA IPC / GPU Direct / RDMA
  * NVIDIA driver kernel module (nvidia.ko)
- Map the exact entry point: syscall, ioctl, file parse, API call, IPC message
- Identify gating conditions: permissions, authentication, state machine, file format

### Layer 2: Vulnerability Primitive Identification (CUDA漏洞原语识别)
- Determine the EXACT primitive the bug provides:
  * Integer Overflow/Wraparound: e.g., 16-bit counter in cuobjdump, 32-bit size calc in cuMemAlloc
  * Heap Buffer Overflow: GPU global memory, host-side heap in CUDA tools
  * Stack Buffer Overflow: CUDA kernel stack, driver stack
  * Use-After-Free: CUDA memory lifecycle (cuMemFree then access), stream/event UAF
  * Race Condition: CUDA streams, events, MPS multi-process, unified memory page faults
  * NULL Pointer Dereference: unchecked CUDA API returns
  * Out-of-Bounds Read/Write: kernel grid/block dims, shared memory index, array bounds
  * Type Confusion: cubin/PTX type mismatch, driver struct confusion
  * Format String: CUDA printf vulnerabilities
  * Command Injection: CUDA toolchain (nvcc flags, cuobjdump args)
  * Path Traversal: file path handling in CUDA tools
  * Uninitialized Memory: GPU memory not zeroed before use

### Layer 3: Controllability Assessment (可控性评估)
- Data controllability: Can a tester control kernel args, buffer sizes, grid/block dimensions?
- File controllability: Can a tester craft .cu, .ptx, .cubin, .fatbin, .o files?
- Timing controllability: Can a tester trigger race windows in stream/event synchronization?
- Environmental dependence: Does the vulnerability require specific GPU arch (sm_75, sm_86, sm_89)?
- ASLR/stack canary/CFI relevance on GPU vs CPU side

### Layer 4: Exploitation Goal Definition (利用目标定义)
- RCE (Remote Code Execution): via crafted input to CUDA tool/service
- LPE (Local Privilege Escalation): via CUDA driver vuln
- Info Leak: GPU memory disclosure, kernel address leak, driver memory read
- DoS (Denial of Service): GPU hang, driver crash, MPS/MIG disruption
- Container Escape: via GPU passthrough / MIG misconfiguration / CUDA IPC
- Persistent Implant: malware hiding in GPU memory
- Kernel to Userland: GPU kernel escaping to CPU via corrupted memory

### Layer 5: Trigger Path Construction (触发路径构造)
- Design the minimal sequence of CUDA operations to trigger the vulnerability
- Identify precise preconditions (GPU state, driver state, memory layout)
- Consider CUDA context lifecycle (create, use, destroy)
- Account for CUDA error handling behavior (synchronous vs asynchronous errors)

### Layer 6: Mitigation Analysis (缓解措施分析)
- GPU-side mitigations: GPU ECC, GPU page isolation, MIG partitioning
- Host-side mitigations: ASLR, SMEP/SMAP, KASLR, IOMMU, VT-d/AMD-Vi
- Driver-level: nvidia.ko hardening, CUDA driver validation
- Container: gVisor, Kata Containers GPU passthrough, nvidia-container-toolkit
- Hardware: GPU MMU isolation, SR-IOV, GPU Trusted Execution

### Layer 7: Exploit Reliability Engineering (利用可靠性工程)
- Design observability: step markers [CUDA_STEP:Sxx], CUDA error code logging
- Enumerate failure modes: GPU OOM, driver timeout, TDR, ECC error, context loss
- Build retry logic: handle transient GPU errors, device lost scenarios
- Environmental adaptation: detect CUDA version, GPU arch, driver version at runtime

## Your Task

Given the structured CUDA vulnerability data (7 categories) and retrieved CUDA domain \
knowledge, produce:

1. A thorough **root cause analysis** following the 7-layer model.
2. A step-by-step **verification strategy** — each step with:
   - pseudocode showing CUDA API calls
   - success conditions (including expected CUDA error codes)
   - failure conditions (specific CUDA error scenarios)

Respond ONLY with a JSON object.
"""

# ---------------------------------------------------------------------------
# CUDA 专项输出 JSON Schema（扩展自通用版本）
# ---------------------------------------------------------------------------
_CUDA_EXPERT_OUTPUT_SCHEMA: Dict[str, Any] = ExpertAnalysis.model_json_schema()


class CudaSecurityExpert:
    """CUDA 专项安全专家分析引擎。

    内建 7 层 CUDA 漏洞分析模型，接收 CUDA 漏洞上下文（七类数据 + CUDA RAG 检索结果），
    执行根因分析，并产出结构化的 CUDA 漏洞验证策略。

    Attributes:
        llm: LLM 客户端实例。
    """

    def __init__(self, llm: LLMClient) -> None:
        """初始化 CUDA 安全专家。"""
        self.llm = llm
        self.last_raw_response: Optional[str] = None

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------
    def analyze(
        self,
        vuln_context: Dict[str, Any],
        rag_context: str = "",
        previous_feedback: Optional[Dict[str, Any]] = None,
        expected_cve_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """对 CUDA 漏洞进行根因分析并生成验证策略。

        Args:
            vuln_context: 七类 CUDA 漏洞输入数据的统一字典。
            rag_context: RAG 检索到的 CUDA 领域知识文本。
            previous_feedback: 上一轮迭代的反馈信息。

        Returns:
            包含 root_cause_analysis 和 verification_strategy 的字典。
        """
        # Reset on every attempt so failures cannot reuse an older response.
        self.last_raw_response = None
        target_cve = resolve_target_cve(vuln_context, expected_cve_id)
        user_prompt = self._build_user_prompt(vuln_context, rag_context, previous_feedback)
        logger.info("正在调用 CUDA 安全专家引擎 (7层模型) 进行漏洞分析…")

        try:
            result = self.llm.structured_generate(
                system_prompt=_CUDA_EXPERT_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                json_schema=_CUDA_EXPERT_OUTPUT_SCHEMA,
                temperature=0.2,
            )
        except StructuredOutputError as exc:
            self.last_raw_response = exc.raw_response
            raise
        raw_response = getattr(result, "raw_response", None)
        self.last_raw_response = raw_response if isinstance(raw_response, str) else None
        # The schema in the prompt and this runtime model have one source of truth.
        validated = validate_analysis(result, expected_cve_id=target_cve)
        result = validated.model_dump(exclude_unset=True)

        rca = result.get("root_cause_analysis", {})
        strategy = result.get("verification_strategy", {})
        logger.info(
            "CUDA 分析完成 — CVE: %s, 漏洞类别: %s, 攻击面: %s, 策略步骤数: %d, 置信度: %.2f",
            rca.get("cve_id", "N/A"),
            rca.get("vulnerability_class", "N/A"),
            rca.get("cuda_attack_surface", "N/A"),
            len(strategy.get("steps", [])),
            strategy.get("confidence", 0),
        )
        return result

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------
    def _build_user_prompt(
        self,
        vuln_ctx: Dict[str, Any],
        rag_ctx: str,
        feedback: Optional[Dict[str, Any]],
    ) -> str:
        """拼装发送给 LLM 的用户提示。"""
        sections: List[str] = []
        sections.append(
            "Input data and retrieved knowledge are unverified research assertions; "
            "preserve stated uncertainty and do not present them as observed vulnerability evidence.\n"
        )

        # --- 七类 CUDA 输入数据 ---
        sections.append("## CUDA Vulnerability Data (7 Categories)\n")
        _labels = {
            "os_environment": "1. OS Environment (OS, kernel, drivers)",
            "cuda_environment": "2. CUDA Environment (GPU arch, CUDA/driver version)",
            "affected_component": "3. Affected Component (API/library/tool & version range)",
            "attack_surface": "4. Attack Surface & Entry Point",
            "vulnerability_type": "5. Vulnerability Type (CWE + CVSS)",
            "impact_controllability": "6. Impact & Controllability",
            "root_cause": "7. Root Cause Analysis (code-level details)",
        }
        for key, label in _labels.items():
            data = vuln_ctx.get(key, {})
            content = (
                json.dumps(data, indent=2, ensure_ascii=False)
                if data
                else "(not provided)"
            )
            sections.append(f"### {label}\n```json\n{content}\n```\n")

        # --- CUDA RAG 领域知识 ---
        if rag_ctx:
            sections.append(f"## Retrieved CUDA Domain Knowledge\n{rag_ctx}\n")

        # --- 前轮反馈 ---
        if feedback:
            sections.append("## Feedback from Previous Iteration\n")
            sections.append(
                f"```json\n{json.dumps(feedback, indent=2, ensure_ascii=False)}\n```\n"
            )
            sections.append(
                "Please revise your CUDA analysis and strategy based on the above feedback. "
                "Pay special attention to CUDA-specific error codes, GPU state, and failed steps.\n"
            )

        sections.append(
            "Apply the CUDA 7-Layer Vulnerability Analysis Model to analyze this vulnerability. "
            "Produce your root cause analysis and verification strategy now. "
            "Respond with a single JSON object."
        )
        return "\n".join(sections)
