# =============================================================================
# CUDA PoC Generator — 工具函数模块
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
通用工具函数集合。

提供日志配置、目录管理、JSON 读写、文本截断等基础功能，
供框架内所有模块复用。
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """配置全局日志系统。

    Args:
        level: 日志级别字符串，如 "DEBUG", "INFO", "WARNING"。
        log_file: 可选的日志文件路径；为 None 时仅输出到控制台。

    Returns:
        配置好的根 Logger 实例。
    """
    fmt = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        ensure_dir(str(Path(log_file).parent))
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
        force=True,
    )
    logger = logging.getLogger("cuda_poc_generator")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger


def ensure_dir(path: str) -> Path:
    """确保目录存在，不存在则递归创建。"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_json(filepath: str) -> Dict[str, Any]:
    """安全读取 JSON 文件并返回字典。"""
    logger = logging.getLogger("cuda_poc_generator.utils")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("文件不存在: %s", filepath)
        return {}
    except json.JSONDecodeError as exc:
        logger.error("JSON 解析失败 (%s): %s", filepath, exc)
        return {}


def write_json(filepath: str, data: Any, indent: int = 2) -> None:
    """将数据写入 JSON 文件。"""
    ensure_dir(str(Path(filepath).parent))
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def write_text(filepath: str, text: str) -> None:
    """将纯文本写入文件。"""
    ensure_dir(str(Path(filepath).parent))
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(text)


def truncate(text: str, max_len: int = 4000) -> str:
    """截断过长文本，保留头尾信息。"""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + "\n...[TRUNCATED]...\n" + text[-half:]


def timestamp_str() -> str:
    """返回当前时间戳字符串。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def resolve_project_root() -> Path:
    """推算项目根目录。"""
    return Path(__file__).resolve().parent.parent
