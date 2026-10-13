# =============================================================================
# CUDA PoC Generator — CUDA 数据加载与 RAG 知识库管理模块
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
CUDA 数据加载器。

负责：
1. 加载用户提供的 7 类 CUDA 专项结构化漏洞输入 JSON（七维度信息）。
2. 基于 LangChain + ChromaDB 构建 / 加载 CUDA 领域知识库（RAG）。
3. 提供统一的 CUDA 知识检索接口。
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config_loader import ConfigLoader
from .utils import read_json

logger = logging.getLogger("cuda_poc_generator.data_loader")

# ---------------------------------------------------------------------------
# CUDA 专项七维度漏洞输入数据 (D1~D7)
# ---------------------------------------------------------------------------
_DEFAULT_INPUT_KEYS = [
    "os_environment",          # D1 操作系统与环境依赖 (OS、kernel、驱动版本)
    "cuda_environment",        # D2 CUDA 运行环境 (GPU 架构、CUDA 版本、驱动版本)
    "affected_component",      # D3 受影响组件 (具体库/工具/API 及版本范围)
    "attack_surface",          # D4 攻击面与入口点 (API 调用、文件输入、网络端点)
    "vulnerability_type",      # D5 漏洞类型 (CWE 分类 + CVSS)
    "impact_controllability",  # D6 影响后果与可控性
    "root_cause",              # D7 漏洞根源描述 (代码级分析)
]

# CUDA 漏洞分类关键词 → 用于 RAG 检索增强
CUDA_VULN_KEYWORDS = [
    "integer overflow", "integer wraparound", "buffer overflow",
    "heap overflow", "stack overflow", "use after free", "UAF",
    "race condition", "NULL pointer", "out-of-bounds", "OOB",
    "format string", "command injection", "path traversal",
    "uninitialized memory", "memory corruption", "double free",
    "GPU kernel", "CUDA driver", "cuobjdump", "nvcc", "cubin",
    "PTX", "fatbin", "ELF parsing", "CUDA IPC", "GPU Direct",
    "cuBLAS", "cuDNN", "cuFFT", "MPS", "MIG", "unified memory",
]


def _simple_split_documents(documents: list, chunk_size: int = 1024, chunk_overlap: int = 128) -> list:
    """简单的文档分割器，避免引入 langchain_text_splitters → torch 依赖链。
    
    按段落（双换行）优先分割，再按单换行分割，最后按字符分割。
    """
    from langchain_core.documents import Document
    
    splits = []
    for doc in documents:
        text = doc.page_content
        if len(text) <= chunk_size:
            splits.append(doc)
            continue
        
        # 按双换行分块
        paragraphs = text.split("\n\n")
        current = ""
        for para in paragraphs:
            if len(current) + len(para) + 2 <= chunk_size:
                current = (current + "\n\n" + para) if current else para
            else:
                if current:
                    splits.append(Document(page_content=current, metadata=doc.metadata))
                # 如果单个段落仍然太长，强制截断
                while len(para) > chunk_size:
                    splits.append(Document(page_content=para[:chunk_size], metadata=doc.metadata))
                    para = para[chunk_size - chunk_overlap:]
                current = para
        if current:
            splits.append(Document(page_content=current, metadata=doc.metadata))
    
    return splits


class CudaDataLoader:
    """CUDA 漏洞输入数据加载 & RAG 知识库管理。

    Attributes:
        cfg: 全局配置加载器实例。
        rag_enabled: 是否启用 RAG 检索增强。
        _vectorstore: LangChain Chroma 向量存储实例。
        _retriever: LangChain 检索器实例。
    """

    def __init__(self, cfg: ConfigLoader) -> None:
        self.cfg = cfg
        self.rag_enabled: bool = cfg.rag.get("enabled", False)
        self._vectorstore: Any = None
        self._retriever: Any = None

    # ------------------------------------------------------------------
    # 1. 加载 7 类 CUDA 漏洞输入
    # ------------------------------------------------------------------
    def load_inputs(self, directory: Optional[str] = None) -> Dict[str, Any]:
        """从指定目录加载 7 个 CUDA 专项结构化漏洞 JSON 文件。

        Args:
            directory: 输入目录路径。为 None 时使用配置中的 ``paths.inputs_dir``。

        Returns:
            统一字典，key 为逻辑名称（如 ``os_environment``），
            value 为对应 JSON 文件的解析结果。缺失文件对应空字典。
        """
        if directory is None:
            directory = str(
                self.cfg.resolve_path(self.cfg.paths.get("inputs_dir", "data/inputs"))
            )

        input_files: Dict[str, str] = self.cfg.vulnerability.get("input_files", {})
        result: Dict[str, Any] = {}

        for key in _DEFAULT_INPUT_KEYS:
            filename = input_files.get(key, "")
            if not filename:
                idx = _DEFAULT_INPUT_KEYS.index(key) + 1
                filename = f"{idx}_{key}.json"
            filepath = os.path.join(directory, filename)
            data = read_json(filepath)
            result[key] = data
            if data:
                logger.info("已加载 CUDA 输入 [%s]: %s", key, filepath)
            else:
                logger.warning("输入为空或缺失 [%s]: %s", key, filepath)

        return result

    # ------------------------------------------------------------------
    # 2. RAG 知识库构建 / 加载 (基于 LangChain + ChromaDB)
    # ------------------------------------------------------------------
    def build_or_load_knowledge_base(
        self,
        kb_dir: Optional[str] = None,
        force_rebuild: bool = False,
    ) -> None:
        """构建或从持久化目录加载 CUDA RAG 向量索引。

        使用 LangChain 的 Chroma 集成 + OpenAI 兼容的嵌入模型。

        Args:
            kb_dir: CUDA 知识库文档目录。为 None 时自动推断。
            force_rebuild: 强制重新构建索引。
        """
        if not self.rag_enabled:
            logger.info("RAG 未启用，跳过 CUDA 知识库构建。")
            return

        print("[RAG] 正在初始化 CUDA 知识库…")

        # 延迟导入：仅在 RAG 启用时才需要 LangChain 包
        try:
            from langchain_chroma import Chroma
        except ImportError as exc:
            logger.error(
                "RAG 依赖未安装，请执行: pip install langchain langchain-chroma langchain-community (%s)",
                exc,
            )
            self.rag_enabled = False
            return

        # ---------- 配置嵌入模型 (本地 sentence-transformers；中转站 OpenAI 兼容端点仅用于对话生成，嵌入走本地模型) ----------
        print("[RAG] 加载本地嵌入模型 (首次运行需下载 ~80MB)…")
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
            embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2",
                model_kwargs={"device": "cpu"},
                encode_kwargs={"normalize_embeddings": True},
            )
            logger.info("CUDA RAG 使用本地嵌入模型: all-MiniLM-L6-v2")
        except ImportError:
            logger.error("langchain-huggingface 未安装，请执行: pip install langchain-huggingface sentence-transformers")
            self.rag_enabled = False
            return
        except OSError as exc:
            logger.error("加载嵌入模型失败 (torch/sentence-transformers 环境问题): %s", exc)
            print("[RAG] 嵌入模型加载失败，RAG 已禁用。可尝试: pip install torch --force-reinstall")
            self.rag_enabled = False
            return

        # ---------- 确定知识库目录 ----------
        if kb_dir is None:
            base_kb_dir = self.cfg.rag.get("knowledge_base_dir", "data/knowledge_bases")
            vuln_type = self.cfg.vulnerability.get("vuln_type", "cuda")
            kb_dir = str(self.cfg.resolve_path(base_kb_dir) / vuln_type)

        persist_dir = str(
            self.cfg.resolve_path(
                self.cfg.rag.get("persist_directory", "data/knowledge_bases/.chromadb")
            )
        )

        kb_path = Path(kb_dir)
        if not kb_path.exists() or not any(kb_path.iterdir()):
            logger.warning("CUDA 知识库目录为空或不存在: %s — RAG 将不可用。", kb_dir)
            self.rag_enabled = False
            return

        # ---------- 尝试加载已有持久化索引 ----------
        if not force_rebuild and Path(persist_dir).exists():
            try:
                print("[RAG] 加载已有向量索引…")
                logger.info("从持久化目录加载 CUDA RAG 索引: %s", persist_dir)
                from chromadb import PersistentClient
                self._vectorstore = Chroma(
                    collection_name="cuda_knowledge",
                    embedding_function=embeddings,
                    persist_directory=persist_dir,
                )
                self._retriever = self._vectorstore.as_retriever(
                    search_kwargs={"k": self.cfg.rag.get("top_k", 5)}
                )
                logger.info("CUDA RAG 索引加载完成。")
                print("[RAG] CUDA 知识库就绪。")
                return
            except Exception as exc:
                logger.warning("加载持久化 CUDA 索引失败，将重新构建: %s", exc)

        # ---------- 全新构建 ----------
        print("[RAG] 首次构建向量索引 (仅运行一次)…")
        logger.info("从文档目录构建 CUDA RAG 索引: %s", kb_dir)

        # 内联文档加载 (避免 langchain_community → torch DLL 依赖链)
        from langchain_core.documents import Document
        documents = []
        kb_path_obj = Path(kb_dir)
        for filepath in kb_path_obj.rglob("*"):
            if filepath.is_file() and filepath.suffix in (".txt", ".md"):
                try:
                    content = filepath.read_text(encoding="utf-8")
                    documents.append(Document(
                        page_content=content,
                        metadata={"source": str(filepath), "filename": filepath.name}
                    ))
                    logger.info("已加载文档: %s (%d 字符)", filepath.name, len(content))
                except Exception as exc:
                    logger.warning("加载文档 %s 失败: %s", filepath, exc)

        if not documents:
            logger.warning("CUDA 知识库目录中未找到任何可处理的文档。")
            self.rag_enabled = False
            return

        logger.info("共读取 %d 个 CUDA 文档片段。", len(documents))

        # 文本分割 (内联简单分割器，避免 langchain_text_splitters → torch DLL 依赖)
        chunk_size = self.cfg.rag.get("chunk_size", 1024)
        chunk_overlap = self.cfg.rag.get("chunk_overlap", 128)
        splits = _simple_split_documents(documents, chunk_size, chunk_overlap)
        logger.info("分割为 %d 个文本块。", len(splits))

        # 构建向量存储
        self._vectorstore = Chroma.from_documents(
            documents=splits,
            embedding=embeddings,
            collection_name="cuda_knowledge",
            persist_directory=persist_dir,
        )
        self._retriever = self._vectorstore.as_retriever(
            search_kwargs={"k": self.cfg.rag.get("top_k", 5)}
        )
        logger.info("CUDA RAG 索引构建并持久化完成: %s", persist_dir)
        print("[RAG] 索引构建完成，后续运行将直接加载。")

    # ------------------------------------------------------------------
    # 3. CUDA 知识检索
    # ------------------------------------------------------------------
    def query_knowledge(self, query_text: str, top_k: Optional[int] = None) -> str:
        """检索与查询文本相关的 CUDA 领域知识。

        Args:
            query_text: 自然语言查询（可以是 CVE 描述、CWE 编号、API 名称等）。
            top_k: 覆盖配置中的 top_k（可选）。

        Returns:
            检索到的相关文本拼接结果。RAG 未启用时返回空字符串。
        """
        if not self.rag_enabled or self._retriever is None:
            return ""

        try:
            k = top_k or self.cfg.rag.get("top_k", 5)
            # 临时调整检索参数
            if top_k and top_k != self.cfg.rag.get("top_k", 5):
                self._retriever.search_kwargs["k"] = top_k

            docs = self._retriever.invoke(query_text)
            if not docs:
                return ""

            # 拼接检索结果
            parts = []
            for i, doc in enumerate(docs, 1):
                parts.append(f"[CUDA-KB-{i}] {doc.page_content}")
            return "\n\n".join(parts)

        except Exception as exc:
            logger.error("CUDA RAG 检索失败: %s", exc)
            return ""

    def query_with_metadata(self, query_text: str) -> List[Dict[str, Any]]:
        """检索并返回带元数据的结果列表。

        Args:
            query_text: 查询文本。

        Returns:
            检索结果列表，每个元素包含 content 和 metadata。
        """
        if not self.rag_enabled or self._retriever is None:
            return []

        try:
            docs = self._retriever.invoke(query_text)
            return [
                {"content": doc.page_content, "metadata": doc.metadata}
                for doc in docs
            ]
        except Exception as exc:
            logger.error("CUDA RAG 元数据检索失败: %s", exc)
            return []
