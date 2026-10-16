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
import hashlib
import os
from pathlib import Path
import uuid
import copy
import re
from typing import Any, Dict, Optional

from .code_generator import CudaCodeGenerator
from .config_loader import ConfigLoader
from .core_expert import CudaSecurityExpert
from .cuda_library import CudaLibrary
from .data_loader import CudaDataLoader
from .env_probe import probe_environment, format_for_prompt
from .llm_client import LLMClient
from .models.analysis import validate_analysis
from .models.generation import CandidateResult
from .utils import ensure_dir, write_json

logger = logging.getLogger("cuda_poc_generator.pipeline")


class CudaPipeline:
    """端到端 CUDA PoC 生成流水线 — 单次生成，无迭代。"""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.cfg = ConfigLoader(config_path)
        logger.info("CUDA PoC 配置加载完成。")
        # Input validation precedes provider setup, including missing-key checks.
        self.llm = None
        self.data_loader = CudaDataLoader(self.cfg)
        self.cuda_lib = CudaLibrary()
        self.expert = None

        outputs_dir = str(
            self.cfg.resolve_path(self.cfg.paths.get("outputs_dir", "data/outputs"))
        )
        self.code_gen = None
        self._outputs_dir = outputs_dir
        self.last_run = None
        self.archive_artifacts = False  # frozen v1 API; main.py enables formal archives
        self.package_artifacts = False
        self.last_delivery = None

    def _initialize_components(self, outputs_dir: str) -> None:
        if self.llm is None:
            self.llm = LLMClient(self.cfg)
        if self.expert is None:
            self.expert = CudaSecurityExpert(self.llm)
        if self.code_gen is None:
            self.code_gen = CudaCodeGenerator(self.llm, self.cuda_lib, outputs_dir)
        self.code_gen.outputs_dir = outputs_dir

    # ------------------------------------------------------------------
    def run(
        self,
        input_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
        target_backend: Optional[str] = None,
        wsl_distro: Optional[str] = None,
        archive_artifacts: Optional[bool] = None,
        package_artifacts: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Normalize inputs, validate analysis, then save an unexecuted candidate.

        The returned report describes this invocation. Failures also persist a
        report before raising, so the CLI exits unsuccessfully. Existing v1
        sources are retained and never cited as current successful artifacts.
        """
        self.last_delivery = None  # Also clear stale delivery on invalid arguments.
        archive_artifacts = self.archive_artifacts if archive_artifacts is None else archive_artifacts
        if type(archive_artifacts) is not bool:
            raise ValueError("archive_artifacts must be a bool")
        package_artifacts = self.package_artifacts if package_artifacts is None else package_artifacts
        if type(package_artifacts) is not bool:
            raise ValueError("package_artifacts must be a bool")
        if package_artifacts:
            archive_artifacts = True
        base_dir = Path(output_dir or self._outputs_dir)
        ensure_dir(str(base_dir))
        self._print_banner()
        print("\n[Phase 1/3] Input normalization and consistency checks")
        bundle = self.data_loader.load_normalized_inputs(input_dir)
        target_dir = base_dir / bundle.cve_id if bundle.is_valid else base_dir
        ensure_dir(str(target_dir))
        run_id = uuid.uuid4().hex
        candidate = CandidateResult(run_id=run_id)
        artifact_names = (
            "cuda_analysis_v1.json", "cuda_analysis_v1.raw.txt", "cuda_poc_v1.py",
            "cuda_poc_v1.status.json", "input_manifest_v1.json", "cuda_run_v1.json",
        )
        preexisting = {
            name: hashlib.sha256((target_dir / name).read_bytes()).hexdigest()
            for name in artifact_names if (target_dir / name).is_file()
        }
        report: Dict[str, Any] = {
            "schema_version": "1.0", "run_id": run_id, "status": "INPUT_INVALID",
            "cve_id": bundle.cve_id or None,
            "input_status": "VALID" if bundle.is_valid else "INVALID",
            "analysis_status": "NOT_ANALYZED",
            "candidate": candidate.model_dump(mode="json"),
            "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED",
            "artifacts": {}, "preexisting_artifacts": preexisting,
            "diagnostics": [],
        }
        self.last_run = report

        def artifact(name: str) -> Dict[str, str]:
            return {"file": name, "sha256": hashlib.sha256((target_dir / name).read_bytes()).hexdigest()}

        def finish(status: str, exc: Optional[Exception] = None) -> Dict[str, Any]:
            report["status"] = status
            report["candidate"] = candidate.model_dump(mode="json")
            if exc is not None:
                # Never print provider bodies, raw model text or input field values.
                report["error_type"] = type(exc).__name__
                report["diagnostics"] = getattr(exc, "diagnostics", [])
                report["diagnostics"] = [
                    item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                    for item in report["diagnostics"]
                ]
            write_json(str(target_dir / "cuda_poc_v1.status.json"), report["candidate"])
            report["artifacts"]["candidate_status"] = artifact("cuda_poc_v1.status.json")
            write_json(str(target_dir / "cuda_run_v1.json"), report)
            # Immutable per-run research archive; v1 generation files and their
            # scientific status/hash semantics remain unchanged.
            if package_artifacts:
                from .generation_delivery import deliver_generation, save_delivery_receipt, GenerationDelivery
                inputs_path = input_dir or str(self.cfg.resolve_path(self.cfg.paths.get("inputs_dir", "data/inputs")))
                delivery = deliver_generation(run_record=report, source_directory=target_dir,
                    output_root=base_dir, input_directory=inputs_path,
                    cve_id=bundle.cve_id if bundle.is_valid else None)
                self.last_delivery = delivery.model_dump(mode="json")
                try:
                    save_delivery_receipt(delivery, output_root=base_dir)
                except (OSError, ValueError, RuntimeError) as delivery_exc:
                    failed = {**self.last_delivery, "package_status": "FAILED",
                              "package_path": None, "package_sha256": None, "manifest_sha256": None,
                              "error_type": type(delivery_exc).__name__,
                              "explanation_zh": "交付回执未完整保存，不能确认本轮交付成功；原始材料及已写文件保留。"}
                    self.last_delivery = GenerationDelivery.model_validate(failed).model_dump(mode="json")
                if status == "COMPLETE" and self.last_delivery["package_status"] != "INTEGRITY_VERIFIED":
                    raise RuntimeError("本轮归档或 ZIP 交付不完整，请核对 delivery_attempts 中文报告；未回退到历史 run。")
            elif archive_artifacts and bundle.is_valid and bundle.cve_id:
                from .artifact_packaging import create_generation_run
                inputs_path = input_dir or str(self.cfg.resolve_path(self.cfg.paths.get("inputs_dir", "data/inputs")))
                create_generation_run(bundle.cve_id, run_id, target_dir, report,
                                      output_root=base_dir, input_directory=inputs_path)
            elif archive_artifacts:
                from .report_locale import write_report_view, _json
                write_report_view(base_dir / "generation_runs" / run_id / "reports", "GENERATION", {"generation.json": _json(report)})
            return report

        manifest = bundle.model_dump(mode="json")
        manifest["run_id"] = run_id
        manifest["input_status"] = report["input_status"]
        write_json(str(target_dir / "input_manifest_v1.json"), manifest)
        report["artifacts"]["input_manifest"] = artifact("input_manifest_v1.json")
        try:
            bundle.require_valid()
        except ValueError as exc:
            finish("INPUT_INVALID", exc)
            raise
        vuln_context = bundle.dimensions
        print(f"  CVE: {bundle.cve_id}; all seven inputs passed structural checks")

        try:
            # Platform preflight precedes providers, embeddings and Web requests.
            selected_backend = target_backend or "local"  # WSL is never selected implicitly.
            if selected_backend == "wsl":
                from .platform_probe import run_platform_probe
                platform_run = run_platform_probe(
                    backend="wsl", distro=wsl_distro or self.cfg.get("platform.wsl_distro", "Ubuntu-22.04"),
                    linux_python=self.cfg.get("platform.wsl_python", "/home/pocdev/.venvs/cuda-poc-generator/bin/python"),
                    user=self.cfg.get("platform.wsl_user", "pocdev"),
                    timeout_seconds=self.cfg.get("platform.timeout_seconds", 45),
                    max_output_bytes=self.cfg.get("platform.max_output_bytes", 1048576),
                )
                report["platform_probe_record"] = platform_run.get("run_directory")
                report["platform_transport"] = platform_run.get("transport")
                if platform_run["snapshot"] is None:
                    report["platform_status"] = "FAILED"
                    report["platform_diagnostics"] = platform_run["diagnostics"]
                    raise RuntimeError("Selected WSL platform probe failed; no historical/local snapshot was substituted.")
                env_info = platform_run["snapshot"]
            elif selected_backend == "local":
                env_info = probe_environment()
            else:
                raise ValueError("Unknown target backend; choose local or wsl.")
            report["platform_status"] = env_info.get("probe_status", "NOT_CHECKED")
            report["platform_environment_id"] = env_info.get("environment_id")
            report["platform_probe_record"] = env_info.get("metadata", {}).get("record_directory")
            env_prompt_block = format_for_prompt(env_info)
        except Exception as exc:
            finish("CONTEXT_ERROR", exc)
            raise

        try:
            self._initialize_components(str(target_dir))
        except Exception as exc:
            finish("PROVIDER_ERROR", exc)
            raise
        try:
            self.data_loader.build_or_load_knowledge_base()
            rag_context = self._query_rag(vuln_context)
            web_context = self._query_web_search(vuln_context)
        except Exception as exc:
            finish("CONTEXT_ERROR", exc)
            raise

        print("\n[Phase 2/3] CUDA expert analysis and strict contract validation")
        self.expert.last_raw_response = None

        def save_raw() -> None:
            raw = self.expert.last_raw_response
            if isinstance(raw, str):
                # write_bytes preserves Unicode and CRLF exactly, including outer whitespace.
                (target_dir / "cuda_analysis_v1.raw.txt").write_bytes(raw.encode("utf-8"))
                report["artifacts"]["analysis_raw"] = artifact("cuda_analysis_v1.raw.txt")

        try:
            analysis = self.expert.analyze(
                vuln_context=vuln_context, rag_context=rag_context,
                previous_feedback=None, expected_cve_id=bundle.cve_id,
            )
            # Defense in depth, including externally injected/mock experts.
            analysis = validate_analysis(analysis, expected_cve_id=bundle.cve_id).model_dump(exclude_unset=True)
            save_raw()
        except Exception as exc:
            save_raw()
            category = getattr(exc, "category", None)
            if category in ("PARSE_ERROR", "SCHEMA_ERROR", "CVE_MISMATCH"):
                report["analysis_status"] = "INVALID"
                finish("ANALYSIS_" + category, exc)
            else:
                finish("PROVIDER_ERROR", exc)
            raise
        report["analysis_status"] = "VALID"
        write_json(str(target_dir / "cuda_analysis_v1.json"), analysis)
        report["artifacts"]["analysis"] = artifact("cuda_analysis_v1.json")
        self._print_analysis_summary(analysis)

        print("\n[Phase 3/3] Candidate generation and static checks only")
        extra_ctx = env_prompt_block + "\n\n" + self._target_view(rag_context[:1500], env_info) + "\n\n" + self._target_view(web_context[:1000], env_info)
        try:
            generation_context = self._target_view(vuln_context, env_info)
            generation_analysis = self._target_view(analysis, env_info)
            self.code_gen.generate(
                vuln_context=generation_context, expert_analysis=generation_analysis,
                iteration=1, extra_context=extra_ctx,
            )
            candidate = self.code_gen.last_result.model_copy(update={"run_id": run_id})
            self.code_gen.last_result = candidate
            if candidate.generation != "GENERATED":
                raise RuntimeError("Candidate was not saved by the generator.")
            report["artifacts"]["candidate"] = artifact(candidate.source_file)
        except Exception as exc:
            candidate = self.code_gen.last_result.model_copy(update={"run_id": run_id})
            if candidate.generation != "GENERATION_FAILED":
                candidate = CandidateResult(
                    run_id=run_id, generation="GENERATION_FAILED",
                    errors=[f"GENERATION_ERROR: {type(exc).__name__}"],
                )
            self.code_gen.last_result = candidate
            finish("GENERATION_FAILED", exc)
            raise
        finish("COMPLETE")
        print(f"\n[+] Candidate saved: {target_dir / candidate.source_file}")
        print(f"    {candidate.generation} / {candidate.static} / NOT_EXECUTED / NOT_VERIFIED")
        return report

    @staticmethod
    def _target_view(value, snapshot):
        """Preserve source artifacts; omit foreign paths only in WSL generation view."""
        is_linux = snapshot.get("platform_type") in ("linux", "wsl")
        def transform(item):
            if isinstance(item, dict):
                return {key: transform(child) for key, child in item.items()}
            if isinstance(item, list):
                return [transform(child) for child in item]
            if is_linux and isinstance(item, str):
                return re.sub(r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\)[^\s\"'<>|,;]*",
                              "[Windows source path omitted for Linux target; use the selected platform snapshot]", item)
            return copy.deepcopy(item)
        return transform(value)

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
        # Existing inputs use a short name and a separate formal component label.
        # Preserve both rather than assuming they are interchangeable aliases.
        for key in ("name", "component_name"):
            component = af.get(key)
            if isinstance(component, str) and component:
                parts.append(f"CUDA Component {key}: {component}")
        arch = ce.get("gpu_architecture", "") or ce.get("compute_capability", "")
        if arch:
            parts.append(f"GPU Architecture: {arch}")
        for key in ("summary", "vulnerable_code_summary"):
            summary = rc.get(key)
            if isinstance(summary, str) and summary:
                parts.append(f"{key}: {summary[:200]}")
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
