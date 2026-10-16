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
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from .utils import resolve_project_root

logger = logging.getLogger("cuda_poc_generator.config_loader")

# Only these exact, field-specific legacy placeholders have compatibility
# semantics. Arbitrary uppercase strings remain ordinary YAML values.
_LEGACY_LLM_PLACEHOLDERS = {
    "model_name": ("CPG_LLM_MODEL_NAME", "deepseek-flash"),
    "api_base": ("CPG_LLM_API_BASE", "https://api.deepseek.com"),
    "api_key_env": ("CPG_LLM_API_KEY_ENV", "DEEPSEEK_API_KEY"),
}
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


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
        self._load_project_dotenv()

        if config_path is None:
            config_path = str(self.project_root / "config" / "default.yaml")

        logger.info("加载配置文件: %s", config_path)
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
        except yaml.YAMLError:
            # YAML exceptions can include local configuration contents; do not echo them.
            raise ValueError("配置 YAML 语法错误，请检查配置文件的缩进和字段格式。") from None
        self.config: Dict[str, Any] = {} if loaded is None else loaded
        self.configuration_diagnostics: list[dict[str, str]] = []
        self._validate_sections()

        # 用环境变量覆盖部分配置
        self._apply_env_overrides()
        self._resolve_llm_references()
        self._validate_config()

    def _resolve_llm_references(self) -> None:
        """Resolve bounded LLM references without expanding ordinary strings.

        Standard CPG overrides were applied first. Explicit reference mappings
        have the form {env: NAME, default: VALUE}; {literal: VALUE} escapes the
        three documented legacy placeholder strings. Values are never evaluated
        as shell text and reference expansion is deliberately non-recursive.
        """
        for field, (legacy_name, published_default) in _LEGACY_LLM_PLACEHOLDERS.items():
            if field not in self.llm:
                continue
            value = self.llm[field]
            # An override is already a final value, not reference syntax. In
            # particular api_key_env names the variable containing the key.
            if legacy_name in os.environ:
                continue
            if isinstance(value, dict):
                if set(value) == {"literal"}:
                    resolved = value["literal"]
                    code = "EXPLICIT_LITERAL"
                else:
                    if not {"env"} <= set(value) <= {"env", "default"}:
                        raise ValueError(f"配置字段 llm.{field} 的环境变量引用格式无效。")
                    name = value["env"]
                    if not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None:
                        raise ValueError(f"配置字段 llm.{field} 的环境变量名称无效。")
                    if "default" in value and (
                            not isinstance(value["default"], str) or not value["default"].strip()):
                        raise ValueError(f"配置字段 llm.{field} 的引用默认值必须为非空字符串。")
                    resolved = os.environ.get(name, value.get("default"))
                    if resolved is None:
                        raise ValueError(f"配置字段 llm.{field} 的显式环境变量引用未设置且没有默认值。")
                    code = "EXPLICIT_ENVIRONMENT_REFERENCE"
                if not isinstance(resolved, str) or not resolved.strip():
                    raise ValueError(f"配置字段 llm.{field} 的引用结果必须为非空字符串。")
                self.llm[field] = resolved
                self.configuration_diagnostics.append({"field": f"llm.{field}", "code": code})
            elif value == legacy_name:
                self.llm[field] = published_default
                self.configuration_diagnostics.append({
                    "field": f"llm.{field}", "code": "LEGACY_PLACEHOLDER_DEFAULT",
                })
                logger.warning(
                    "配置字段 llm.%s 使用历史 CPG 占位符且未设置对应覆盖；"
                    "采用已发布默认值。建议使用明确值或 {env: NAME, default: VALUE}。", field,
                )

    def _load_project_dotenv(self) -> None:
        """仅在实例化时加载项目根 .env，保留已设置的进程环境变量。"""
        if load_dotenv is None:
            logger.debug("python-dotenv 未安装，跳过 .env 加载；可使用进程环境变量。")
            return
        if load_dotenv(self.project_root / ".env", override=False):
            logger.info("项目根 .env 文件已加载（已有环境变量保持优先）。")
        if (os.environ.get("LANGCHAIN_TRACING_V2", "").lower() == "true"
                and os.environ.get("LANGCHAIN_API_KEY")):
            logger.info("LangSmith 追踪已启用。")

    def _validate_sections(self) -> None:
        if not isinstance(self.config, dict):
            raise ValueError("配置根节点必须为 YAML mapping。")
        for section in ("llm", "rag", "paths", "vulnerability", "iteration", "platform"):
            if section in self.config and not isinstance(self.config[section], dict):
                raise ValueError(f"配置字段 {section} 必须为 mapping。")

    @staticmethod
    def _parse_bool(value: str) -> bool:
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
        raise ValueError("必须是明确的布尔值。")

    def _apply_env_overrides(self) -> None:
        """读取环境变量并覆盖对应配置项。"""
        _env_map = {
            "CPG_LLM_MODEL_NAME":  ("llm", "model_name", str),
            "CPG_LLM_API_BASE":    ("llm", "api_base", str),
            "CPG_LLM_API_KEY_ENV": ("llm", "api_key_env", str),
            "CPG_LLM_TEMPERATURE": ("llm", "temperature", float),
            "CPG_LLM_MAX_TOKENS":  ("llm", "max_tokens", int),
            "CPG_LLM_TIMEOUT":     ("llm", "timeout", int),
            "CPG_LLM_MAX_RETRIES": ("llm", "max_retries", int),
            "CPG_RAG_ENABLED":     ("rag", "enabled", self._parse_bool),
            "CPG_MAX_ITERATIONS":  ("iteration", "max_iterations", int),
            "CPG_VULN_TYPE":       ("vulnerability", "vuln_type", str),
        }
        for env_key, (section, key, cast) in _env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    converted = cast(val)
                except (TypeError, ValueError, OverflowError):
                    raise ValueError(f"环境变量 {env_key} 的格式无效（配置字段 {section}.{key}）。") from None
                self.config.setdefault(section, {})[key] = converted
                logger.info("环境变量覆盖: %s -> %s.%s", env_key, section, key)

    def _validate_config(self) -> None:
        """校验已使用的字段；保留未知字段以兼容现有本地配置。"""
        string_fields = {
            "llm": ("model_name", "api_base", "api_key_env"),
            "rag": ("persist_directory", "knowledge_base_dir"),
            "paths": ("inputs_dir", "outputs_dir", "templates_dir"),
            "vulnerability": ("vuln_type",),
        }
        for section, fields in string_fields.items():
            for field in fields:
                if field in self.config.get(section, {}):
                    value = self.config[section][field]
                    if not isinstance(value, str) or not value.strip():
                        raise ValueError(f"配置字段 {section}.{field} 必须为非空字符串。")
        for section, field in (("rag", "enabled"), ("llm", "streaming"), ("llm", "use_responses_api")):
            if field in self.config.get(section, {}) and not isinstance(self.config[section][field], bool):
                raise ValueError(f"配置字段 {section}.{field} 必须为 boolean。")
        positive_int_fields = {
            "llm": ("max_tokens", "max_retries"),
            "rag": ("chunk_size", "top_k"),
            "iteration": ("max_iterations", "max_auto_retries"),
        }
        for section, fields in positive_int_fields.items():
            for field in fields:
                if field in self.config.get(section, {}):
                    value = self.config[section][field]
                    if type(value) is not int or value <= 0:
                        raise ValueError(f"配置字段 {section}.{field} 必须为正整数。")
        numeric_fields = (("llm", "timeout", 0, None),
                          ("llm", "temperature", 0, 2),
                          ("iteration", "low_confidence_threshold", 0, 1))
        for section, field, minimum, maximum in numeric_fields:
            if field not in self.config.get(section, {}):
                continue
            value = self.config[section][field]
            try:
                finite_number = type(value) in (int, float) and math.isfinite(value)
            except OverflowError:
                finite_number = False
            if (not finite_number
                    or value < minimum or (field == "timeout" and value == 0)
                    or (maximum is not None and value > maximum)):
                raise ValueError(f"配置字段 {section}.{field} 必须为范围内的有限数值。")
        overlap = self.rag.get("chunk_overlap", 128)
        chunk_size = self.rag.get("chunk_size", 1024)
        if type(overlap) is not int or overlap < 0 or overlap >= chunk_size:
            raise ValueError("配置字段 rag.chunk_overlap 必须为非负整数且小于 rag.chunk_size。")
        headers = self.llm.get("headers")
        if headers is not None and (not isinstance(headers, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())):
            raise ValueError("配置字段 llm.headers 必须为字符串到字符串的 mapping。")
        input_files = self.vulnerability.get("input_files")
        if input_files is not None and (not isinstance(input_files, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in input_files.items())):
            raise ValueError("配置字段 vulnerability.input_files 必须为字符串到字符串的 mapping。")
        platform_cfg = self.config.get("platform", {})
        for name in ("wsl_distro", "wsl_user", "wsl_python"):
            if name in platform_cfg and (not isinstance(platform_cfg[name], str) or not platform_cfg[name].strip()):
                raise ValueError(f"配置字段 platform.{name} 必须为非空字符串。")
        timeout = platform_cfg.get("timeout_seconds", 45)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 120:
            raise ValueError("配置字段 platform.timeout_seconds 必须在 [1,120]。")
        limit = platform_cfg.get("max_output_bytes", 1048576)
        if type(limit) is not int or not 4096 <= limit <= 4194304:
            raise ValueError("配置字段 platform.max_output_bytes 必须在 [4096,4194304]。")

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
