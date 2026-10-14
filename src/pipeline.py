# =============================================================================
# CUDA PoC Generator — 主流水线模块（单次生成版）
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""CUDA PoC 主流水线 — 单次生成，不做反馈循环。

Phase 1: 情报收集 — 加载 7 类输入 + RAG + 环境探测
Phase 2: 漏洞分析 — CUDA 安全专家 7 层分析
Phase 3: PoC 构造 — LLM 生成 PoC 代码，写入文件

生成的 PoC 代码交由用户手动执行和调试，不再自动迭代。
"""

import logging
import os
from typing import Any, Dict, Optional

from .code_generator import CudaCodeGenerator
from .config_loader import ConfigLoader
from .core_expert import CudaSecurityExpert
from .cuda_library import CudaLibrary
from .data_loader import CudaDataLoader
from .env_probe import probe_environment, format_for_prompt
from .llm_client import LLMClient
from .utils import ensure_dir, write_json

logger = logging.getLogger("cuda_poc_generator.pipeline")


class CudaPipeline:
    """端到端 CUDA PoC 生成流水线 — 单次生成，无迭代。"""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.cfg = ConfigLoader(config_path)
        logger.info("CUDA PoC 配置加载完成。")
        self.llm = LLMClient(self.cfg)
        self.data_loader = CudaDataLoader(self.cfg)
        self.cuda_lib = CudaLibrary()
        self.expert = CudaSecurityExpert(self.llm)

        outputs_dir = str(
            self.cfg.resolve_path(self.cfg.paths.get("outputs_dir", "data/outputs"))
        )
        self.code_gen = CudaCodeGenerator(self.llm, self.cuda_lib, outputs_dir)
        self._outputs_dir = outputs_dir

    # ------------------------------------------------------------------
    def run(
        self,
        input_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        """加载输入 → 专家分析 → 生成 PoC，一次性完成。

        Args:
            input_dir: 7 类 JSON 输入目录。
            output_dir: PoC 和报告输出目录（覆盖配置）。
        """
        if output_dir:
            ensure_dir(output_dir)
            self._outputs_dir = output_dir
            self.code_gen.outputs_dir = output_dir
            logger.info("输出目录已覆盖: %s", output_dir)

        self._print_banner()

        # ================================================================
        # Phase 1: 情报收集
        # ================================================================
        logger.info("Phase 1: CUDA 情报收集")
        print("\n[Phase 1/3] CUDA 情报收集…")

        # 1a. 加载 7 维度输入
        vuln_context = self.data_loader.load_inputs(input_dir)
        non_empty = sum(1 for v in vuln_context.values() if v and not str(v).startswith("_"))
        if non_empty == 0:
            print("\n[ERROR] 输入目录中未找到 CUDA 漏洞数据。请准备 7 类 JSON 文件。")
            return
        print(f"  已加载 {non_empty}/7 个 CUDA 漏洞输入维度。")

        # 提取 CVE，设置输出子目录
        cve_id = self._extract_cve_id(vuln_context)
        if cve_id:
            cve_out = os.path.join(self._outputs_dir, cve_id)
            ensure_dir(cve_out)
            self._outputs_dir = cve_out
            self.code_gen.outputs_dir = cve_out
            print(f"  CVE 编号: {cve_id} — 输出目录: {cve_out}")

        # 1b. RAG
        self.data_loader.build_or_load_knowledge_base()
        rag_context = self._query_rag(vuln_context)

        # 1b2. Web Search (Tavily — supplements RAG with live results)
        web_context = self._query_web_search(vuln_context)

        # 1c. 环境探测
        print("  正在探测 GPU/CUDA 环境…", end=" ")
        env_info = probe_environment()
        env_prompt_block = format_for_prompt(env_info)
        gpu_count = env_info.get("gpu", {}).get("gpu_count", 0)
        cap = env_info.get("gpu", {}).get("primary_compute_cap", "N/A")
        nvcc = env_info.get("toolchain", {}).get("nvcc_path", "N/A")
        print(f"GPU={gpu_count}, arch={cap}, nvcc={nvcc}")

        # ================================================================
        # Phase 2: 漏洞分析
        # ================================================================
        logger.info("Phase 2: CUDA 安全专家分析")
        print("\n[Phase 2/3] CUDA 安全专家分析 (7-Layer Model)…")
        analysis = self.expert.analyze(
            vuln_context=vuln_context,
            rag_context=rag_context,
            previous_feedback=None,
        )
        write_json(os.path.join(self._outputs_dir, "cuda_analysis_v1.json"), analysis)
        self._print_analysis_summary(analysis)

        # ================================================================
        # Phase 3: PoC 构造
        # ================================================================
        logger.info("Phase 3: 生成 CUDA PoC 代码")
        print("\n[Phase 3/3] 生成 CUDA PoC 代码…")

        extra_ctx = env_prompt_block + "\n\n" + rag_context[:1500] + "\n\n" + web_context[:1000]
        poc_code = self.code_gen.generate(
            vuln_context=vuln_context,
            expert_analysis=analysis,
            iteration=1,
            extra_context=extra_ctx,
        )

        poc_path = os.path.join(self._outputs_dir, "cuda_poc_v1.py")
        print(f"\n[+] CUDA PoC 已生成: {poc_path}")
        print(f"    代码长度: {len(poc_code)} 字符, {poc_code.count(chr(10)) + 1} 行")
        print(f"\n    执行方式: python {poc_path}")
        print(f"    执行后可将输出粘贴给 AI 助手进行调试和修改。")

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    def _query_rag(self, vuln_context: Dict[str, Any]) -> str:
        """构造 RAG 查询，返回检索到的知识文本。"""
        if not self.data_loader.rag_enabled:
            return ""
        rc = vuln_context.get("root_cause", {})
        vt = vuln_context.get("vulnerability_type", {})
        ce = vuln_context.get("cuda_environment", {})
        af = vuln_context.get("affected_component", {})
        parts = []
        cid = rc.get("cve_id", "") or vt.get("cve_id", "")
        if cid:
            parts.append(f"CVE: {cid}")
        cwe = vt.get("cwe_id", "") or vt.get("vulnerability_type", "")
        if cwe:
            parts.append(f"CWE: {cwe}")
        comp = af.get("name", "") or af.get("component_name", "")
        if comp:
            parts.append(f"CUDA Component: {comp}")
        arch = ce.get("gpu_architecture", "") or ce.get("compute_capability", "")
        if arch:
            parts.append(f"GPU Architecture: {arch}")
        summary = rc.get("summary", "")
        if summary:
            parts.append(f"Summary: {summary[:200]}")
        query = " ".join(parts)[:500]
        if query:
            out = self.data_loader.query_knowledge(query)
            logger.info("RAG 检索到 %d 字符。", len(out))
            print(f"  RAG 检索完成: {len(out)} 字符相关知识。")
            return out
        return ""

    @staticmethod
    def _query_web_search(vuln_context: Dict[str, Any]) -> str:
        """Use Tavily to search for live CVE info."""
        try:
            from .tools.search import search_cve, search_to_context, is_available
            if not is_available():
                return ""
            rc = vuln_context.get("root_cause", {})
            vt = vuln_context.get("vulnerability_type", {})
            cve_id = rc.get("cve_id", "") or vt.get("cve_id", "")
            if not cve_id:
                return ""
            results = search_cve(cve_id, max_results=3)
            if results:
                print(f"  Web搜索: {len(results)} 条结果 ({cve_id})")
            return search_to_context(results)
        except Exception:
            return ""

    @staticmethod
    def _extract_cve_id(vuln_context: Dict[str, Any]) -> str:
        for key in vuln_context:
            ctx = vuln_context.get(key, {})
            if isinstance(ctx, dict):
                cve = ctx.get("cve_id", "")
                if cve and cve.startswith("CVE-"):
                    return cve
        return ""

    @staticmethod
    def _print_banner() -> None:
        print(r"""
╔══════════════════════════════════════════════════════════════╗
║         CUDA PoC Generator v0.2.0                           ║
║         NVIDIA CUDA 漏洞专项 PoC 生成工具                    ║
║                                                              ║
║  7 层分析 → 代码生成 → 人工调试                              ║
║  DeepSeek 默认 API | LangChain + 可选 RAG 知识增强           ║
║                                                              ║
║  [!] 仅供授权安全研究使用 — Authorized Research Only          ║
╚══════════════════════════════════════════════════════════════╝
""")

    @staticmethod
    def _print_analysis_summary(analysis: Dict[str, Any]) -> None:
        rca = analysis.get("root_cause_analysis", {})
        st = analysis.get("verification_strategy", {})
        print("\n--- CUDA 7-Layer 分析摘要 ---")
        print(f"  CVE: {rca.get('cve_id','N/A')}  CWE: {rca.get('cwe_id','N/A')}")
        print(f"  攻击面: {rca.get('cuda_attack_surface','N/A')}")
        print(f"  原语: {rca.get('vulnerability_class','N/A')} / {rca.get('primitive','N/A')}")
        print(f"  置信度: {st.get('confidence',0):.2f}  步骤数: {len(st.get('steps',[]))}")
        for s in st.get("steps", []):
            print(f"    [{s.get('step_id','?')}] {s.get('description','')[:70]}")
