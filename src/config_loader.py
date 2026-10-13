# =============================================================================
# CUDA PoC Generator — 配置加载模块
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
配置加载器。

从 YAML 文件读取配置，并支持通过环境变量覆盖关键参数，
为框架提供统一的运行参数入口。
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .utils import resolve_project_root

logger = logging.getLogger("cuda_poc_generator.config_loader")

try:
    from dotenv import load_dotenv
    _DOTENV_LOADED = load_dotenv()
    if _DOTENV_LOADED:
        logger.info(".env 文件已加载，环境变量已注入。")
except ImportError:
    _DOTENV_LOADED = False
    logger.debug("python-dotenv 未安装，跳过 .env 加载。")

# 检测 LangSmith
_LANGSMITH_ENABLED = os.environ.get("LANGCHAIN_TRACING_V2", "").lower() == "true" \
                     and bool(os.environ.get("LANGCHAIN_API_KEY", ""))
if _LANGSMITH_ENABLED:
    project = os.environ.get("LANGCHAIN_PROJECT", "(default)")
    logger.info("LangSmith 追踪已启用 — 项目: %s", project)


class ConfigLoader:
    """统一配置加载与访问。

    Attributes:
        config: 解析后的完整配置字典。
        project_root: 项目根目录路径。
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """初始化配置加载器。

        Args:
            config_path: YAML 配置文件路径。为 None 时使用默认路径。
        """
        self.project_root: Path = resolve_project_root()

        if config_path is None:
            config_path = str(self.project_root / "config" / "default.yaml")

        logger.info("加载配置文件: %s", config_path)
        with open(config_path, "r", encoding="utf-8") as f:
            self.config: Dict[str, Any] = yaml.safe_load(f) or {}

        # 用环境变量覆盖部分配置
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        """读取环境变量并覆盖对应配置项。"""
        _env_map = {
            "CPG_LLM_MODEL_NAME":  ("llm", "model_name", str),
            "CPG_LLM_API_BASE":    ("llm", "api_base", str),
            "CPG_LLM_TEMPERATURE": ("llm", "temperature", float),
            "CPG_LLM_MAX_TOKENS":  ("llm", "max_tokens", int),
            "CPG_LLM_TIMEOUT":     ("llm", "timeout", int),
            "CPG_RAG_ENABLED":     ("rag", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
            "CPG_MAX_ITERATIONS":  ("iteration", "max_iterations", int),
            "CPG_VULN_TYPE":       ("vulnerability", "vuln_type", str),
        }
        for env_key, (section, key, cast) in _env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                self.config.setdefault(section, {})[key] = cast(val)
                logger.info("环境变量覆盖: %s -> %s.%s = %s", env_key, section, key, cast(val))

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """用点号分隔的路径访问嵌套配置。"""
        keys = dotted_key.split(".")
        node: Any = self.config
        for k in keys:
            if isinstance(node, dict):
                node = node.get(k)
            else:
                return default
            if node is None:
                return default
        return node

    @property
    def llm(self) -> Dict[str, Any]:
        return self.config.get("llm", {})

    @property
    def rag(self) -> Dict[str, Any]:
        return self.config.get("rag", {})

    @property
    def paths(self) -> Dict[str, Any]:
        return self.config.get("paths", {})

    @property
    def vulnerability(self) -> Dict[str, Any]:
        return self.config.get("vulnerability", {})

    @property
    def iteration(self) -> Dict[str, Any]:
        return self.config.get("iteration", {})

    def resolve_path(self, relative: str) -> Path:
        """将相对路径转换为基于项目根目录的绝对路径。"""
        return self.project_root / relative
