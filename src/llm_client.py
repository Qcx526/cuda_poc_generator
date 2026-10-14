# =============================================================================
# CUDA PoC Generator — LLM 客户端模块 (基于 LangChain)
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
LLM 调用客户端。

基于 LangChain 封装 LLM 调用接口，默认通过官方 DeepSeek 的 OpenAI 兼容端点
(https://api.deepseek.com) 访问模型，兼容显式配置的其他端点和自定义请求头。
提供普通对话、严格 JSON 文本解析与有界请求重试；CUDA 分析模型由专家层校验。
"""

import json
import logging
import math
import os
import re
import time
from typing import Any, Dict, List, Optional

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
except ImportError as exc:
    raise ImportError('LLM 核心依赖未安装，请在当前虚拟环境执行: python -m pip install -e "."') from exc

from .config_loader import ConfigLoader

logger = logging.getLogger("cuda_poc_generator.llm_client")

# ---------------------------------------------------------------------------
# 安全研究免责声明
# ---------------------------------------------------------------------------
SECURITY_DISCLAIMER = (
    "\n\n[DISCLAIMER] This interaction is conducted strictly within the scope of "
    "authorized security research, vulnerability verification, and defensive "
    "security improvement. All generated content must be used solely for lawful "
    "purposes with explicit permission from the system owner."
)


class StructuredOutputError(ValueError):
    """Invalid structured response with its unchanged text kept for diagnostics."""

    category = "PARSE_ERROR"

    def __init__(
        self, raw_response: Optional[str], diagnostics: List[Dict[str, Any]]
    ) -> None:
        self.raw_response = raw_response
        self.diagnostics = diagnostics
        super().__init__("LLM structured response rejected (PARSE_ERROR); see diagnostics.")


class StructuredResponse(dict):
    """A backwards-compatible dictionary carrying the unchanged provider text."""

    def __init__(self, parsed: Dict[str, Any], raw_response: str) -> None:
        super().__init__(parsed)
        self.raw_response = raw_response


class LLMClient:
    """基于 LangChain 的 LLM 调用客户端。

    封装 ChatOpenAI，通过 OpenAI 兼容接口访问配置的模型，
    支持透传自定义请求头，提供普通对话、JSON 解析和重试机制。

    Attributes:
        model: 模型名称。
        temperature: 默认采样温度。
        max_tokens: 最大生成 token 数。
        max_retries: 历史字段名，当前表示最大尝试次数（含首次）。
        chat_model: LangChain ChatOpenAI 实例。
    """

    def __init__(self, cfg: ConfigLoader) -> None:
        """初始化 LLM 客户端。

        Args:
            cfg: 全局配置加载器。

        Raises:
            ImportError: 缺少 langchain 依赖时抛出。
            ValueError: 所配置的 API Key 环境变量未设置时抛出。
        """
        self.last_chat_raw_response: Optional[str] = None
        llm_cfg = cfg.llm
        self._api_key_env: str = llm_cfg.get("api_key_env", "DEEPSEEK_API_KEY")
        api_key = os.environ.get(self._api_key_env, "").strip()
        if not api_key and self._api_key_env == "DEEPSEEK_API_KEY":
            # Only the known DeepSeek legacy alias is eligible; never use another provider's key.
            api_key = os.environ.get("DEEPSEEK_KEY", "").strip()
            if api_key:
                self._api_key_env = "DEEPSEEK_KEY"
                logger.info("使用兼容 API Key 环境变量 DEEPSEEK_KEY。")
        if not api_key:
            alias_note = "（兼容旧名称 DEEPSEEK_KEY）" if self._api_key_env == "DEEPSEEK_API_KEY" else ""
            raise ValueError(
                f"缺少 API Key：请在项目根 .env 或进程环境变量中设置 {self._api_key_env}{alias_note}。"
                "其他服务商请显式配置 llm.api_key_env 或 CPG_LLM_API_KEY_ENV。"
            )

        self.model: str = llm_cfg.get("model_name", "deepseek-flash")
        self.temperature: float = llm_cfg.get("temperature", 0.3)
        self.max_tokens: int = llm_cfg.get("max_tokens", 4096)
        self.max_retries: int = llm_cfg.get("max_retries", 3)
        self._timeout: float = llm_cfg.get("timeout", 600)
        self._headers: Optional[Dict[str, str]] = llm_cfg.get("headers") or None
        # 保留其他端点的可选 Responses 协议兼容；官方 DeepSeek 默认使用 Chat Completions。
        self._use_responses: bool = bool(llm_cfg.get("use_responses_api", False)) and (
            "use_responses_api" in getattr(ChatOpenAI, "model_fields", {})
        )
        self._extra_init: Dict[str, Any] = {"use_responses_api": True} if self._use_responses else {}
        if bool(llm_cfg.get("use_responses_api", False)) and not self._use_responses:
            logger.warning(
                "已请求 use_responses_api，但当前 langchain-openai 版本不支持该参数，已忽略。"
            )

        # 显式设置 httpx 超时，防止默认值（connect=5s）覆盖配置
        import httpx
        _httpx_timeout = httpx.Timeout(
            connect=30.0,          # 建连超时
            read=float(self._timeout),    # 读取超时 = 配置值
            write=30.0,            # 写入超时
            pool=30.0,             # 连接池超时
        )

        self.chat_model = ChatOpenAI(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            api_key=api_key,
            base_url=llm_cfg.get("api_base", "https://api.deepseek.com"),
            default_headers=self._headers,
            timeout=_httpx_timeout,          # httpx.Timeout 对象，不是 float
            max_retries=0,  # 关闭 SDK 内置重试，统一由本类控制并打印每次尝试日志
            **self._extra_init,
        )
        logger.info(
            "LLM 客户端就绪 (LangChain) — 模型: %s, API base: %s",
            self.model,
            llm_cfg.get("api_base", "https://api.deepseek.com"),
        )

    # ------------------------------------------------------------------
    # 基础聊天
    # ------------------------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """发送聊天请求并返回助手回复文本。

        仅对瞬时错误（限流 / 网络超时 / 服务端 5xx）自动重试；
        内容审核、参数错误、鉴权等确定性错误（4xx）会立即失败，避免无谓等待。

        Args:
            messages: 消息列表 [{"role": "system"|"user"|"assistant", "content": "..."}]
            temperature: 覆盖默认温度（可选）。
            max_tokens: 覆盖默认最大 token 数（可选）。

        Returns:
            模型回复的纯文本内容。

        Raises:
            RuntimeError: 重试耗尽，或遇到不可重试的确定性错误。
        """
        self.last_chat_raw_response = None
        # 构建 LangChain 消息
        lc_messages = []
        for m in messages:
            if m["role"] == "system":
                lc_messages.append(SystemMessage(content=m["content"]))
            elif m["role"] == "user":
                lc_messages.append(HumanMessage(content=m["content"]))
            else:
                lc_messages.append(HumanMessage(content=m["content"]))

        # 如果指定了覆盖参数，创建新的模型实例
        if temperature is not None or max_tokens is not None:
            import httpx as _httpx
            kwargs = {
                "model": self.model,
                "temperature": self.temperature if temperature is None else temperature,
                "max_tokens": self.max_tokens if max_tokens is None else max_tokens,
                "api_key": self.chat_model.openai_api_key,
                "base_url": self.chat_model.openai_api_base,
                "default_headers": self._headers,
                "timeout": _httpx.Timeout(connect=30.0, read=float(self._timeout), write=30.0, pool=30.0),
                "max_retries": 0,  # 同上：关闭 SDK 内置重试
                **self._extra_init,
            }
            model = ChatOpenAI(**kwargs)
        else:
            model = self.chat_model

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            logger.info(
                "LLM 调用 尝试 %d/%d — 模型: %s, 单次读取超时: %gs",
                attempt, self.max_retries, self.model, self._timeout,
            )
            try:
                resp = model.invoke(lc_messages)
                content = resp.content
                if not isinstance(content, str):
                    raise StructuredOutputError(
                        None, [{"path": [], "code": "non_text_provider_response"}]
                    )
                self.last_chat_raw_response = content
                return content.strip()
            except StructuredOutputError:
                # An unsupported response representation is not a transport failure.
                raise
            except Exception as exc:
                last_exc = exc
                if not self._is_retryable(exc):
                    raise RuntimeError(self._format_fatal(exc, self._api_key_env)) from None
                if attempt == self.max_retries:
                    break
                # 在剩余尝试之间使用有界退避。
                code = getattr(exc, "status_code", None)
                wait = min(10 * attempt, 60) if code is None else min(2 ** attempt, 30)
                logger.warning(
                    "LLM 请求失败 (尝试 %d/%d): %s — %ds 后重试",
                    attempt, self.max_retries, type(exc).__name__, wait,
                )
                time.sleep(wait)

        raise RuntimeError(
            f"LLM 请求在 {self.max_retries} 次尝试后仍失败（{type(last_exc).__name__}）。"
            "请检查服务状态、网络连接和配置的请求超时。"
        ) from None

    # ------------------------------------------------------------------
    # 重试判定 / 错误信息
    # ------------------------------------------------------------------
    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """判断异常是否值得重试。

        仅对瞬时错误重试：网络/超时（无 status_code）、限流 (429)、服务端 (5xx)。
        客户端错误 (400/401/403/404) 多为确定性（内容审核、参数错误、鉴权），
        重试只会白白等待，故直接失败。
        """
        code = getattr(exc, "status_code", None)
        if code is None:
            return True
        if code == 429 or code >= 500:
            return True
        return False

    @staticmethod
    def _format_fatal(exc: Exception, api_key_env: str = "llm.api_key_env") -> str:
        """为不可重试的错误组装带处置建议的提示。"""
        msg = str(exc)
        low = msg.lower()
        code = getattr(exc, "status_code", None)
        hints: List[str] = []
        is_html = ("<!doctype html" in low) or ("cloudflare" in low) or ("<html" in low)
        if code == 404 or "model_not_found" in low or "unknown model" in low:
            hints.append("模型或 API 路径不可用：检查 llm.model_name / CPG_LLM_MODEL_NAME 和 llm.api_base，确认服务商当前支持该模型。")
        elif is_html:
            hints.append(
                "响应包含 HTML 网关页面，不能据此确定具体原因。请检查 llm.api_base、"
                "服务商状态和网络连接，必要时联系服务商。"
            )
        elif ("cybersecurity" in low) or ("trusted access" in low) or ("flagged" in low):
            hints.append(
                "请求被服务商内容策略拒绝。请确认研究授权和服务商使用政策，必要时联系服务商。"
            )
        elif code in (401, 403) or "unauthorized" in low or "forbidden" in low:
            hints.append(f"鉴权或访问权限失败：检查 {api_key_env} 是否正确、过期，以及账户是否有访问权限。")
        elif "invalid_request" in low or code == 400:
            hints.append("请求被上游以 400 拒绝（参数或内容），重试不会改变结果。请检查模型名/参数或上游内容策略。")
        # Do not echo server bodies: they may contain private prompts or credentials.
        head = f"LLM 请求被上游拒绝 (HTTP {code})，已停止重试（{type(exc).__name__}）。"
        return head + ("  提示: " + " ".join(hints) if hints else "")

    # ------------------------------------------------------------------
    # 结构化 JSON 生成
    # ------------------------------------------------------------------
    def structured_generate(
        self,
        system_prompt: str,
        user_prompt: str,
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """请求 LLM 生成结构化 JSON 输出。

        在系统提示末尾自动追加安全免责声明。
        若提供了 ``json_schema``，会将其包含在提示中。

        Args:
            system_prompt: 系统级角色提示。
            user_prompt: 用户级具体指令与上下文。
            json_schema: 期望的 JSON 结构描述（可选）。
            temperature: 覆盖默认温度（可选）。

        Returns:
            StructuredResponse 字典（包含未经修改的 raw_response 属性）。
            解析失败抛出 StructuredOutputError；不作结构纠正重试。
            json_schema 用于提示；CUDA 专家层执行同源 Pydantic 模型校验。
        """
        # 拼装系统提示
        full_system = system_prompt + SECURITY_DISCLAIMER
        if json_schema:
            schema_str = json.dumps(json_schema, indent=2, ensure_ascii=False)
            full_system += (
                "\n\n[OUTPUT FORMAT] You MUST respond with a single valid JSON object "
                "conforming to the following schema. Do NOT include any text outside "
                f"the JSON block.\n```json\n{schema_str}\n```"
            )

        messages = [
            {"role": "system", "content": full_system},
            {"role": "user", "content": user_prompt},
        ]
        self.last_chat_raw_response = None
        raw = self.chat(messages, temperature=temperature)
        original = self.last_chat_raw_response
        if original is None:
            # Offline mocks and compatible custom chat implementations return raw text.
            original = raw
        return self._strict_parse_json(original)

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _strict_parse_json(text: str) -> StructuredResponse:
        """Accept one full JSON object or one complete Markdown JSON fence only.

        No extraction from surrounding prose, permissive constants, duplicate
        keys, or partial objects. Diagnostics never include response contents.
        """
        if not isinstance(text, str):
            raise StructuredOutputError(None, [{"path": [], "code": "response_not_text"}])
        payload = text.strip()
        if not payload:
            raise StructuredOutputError(text, [{"path": [], "code": "empty_response"}])
        if payload.startswith("```"):
            fence = re.fullmatch(r"```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```", payload)
            if fence is None:
                raise StructuredOutputError(text, [{"path": [], "code": "invalid_json_fence"}])
            payload = fence.group(1).strip()

        def reject_constant(_constant: str) -> None:
            raise StructuredOutputError(text, [{"path": [], "code": "non_finite_json_constant"}])

        def finite_float(number: str) -> float:
            value = float(number)
            if not math.isfinite(value):
                raise StructuredOutputError(text, [{"path": [], "code": "non_finite_json_number"}])
            return value

        def unique_object(pairs: List[Any]) -> Dict[str, Any]:
            value: Dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise StructuredOutputError(text, [{"path": [], "code": "duplicate_json_key"}])
                value[key] = item
            return value

        try:
            parsed = json.loads(
                payload, parse_constant=reject_constant,
                parse_float=finite_float, object_pairs_hook=unique_object,
            )
        except StructuredOutputError:
            raise
        except json.JSONDecodeError as exc:
            raise StructuredOutputError(
                text, [{"path": [], "code": "invalid_json", "line": exc.lineno, "column": exc.colno}]
            ) from None
        except (RecursionError, ValueError):
            # Avoid dumping JSON or parser values into public error messages.
            raise StructuredOutputError(text, [{"path": [], "code": "invalid_json"}]) from None
        if not isinstance(parsed, dict):
            raise StructuredOutputError(text, [{"path": [], "code": "json_root_not_object"}])
        return StructuredResponse(parsed, text)

    @staticmethod
    def _safe_parse_json(text: str) -> Dict[str, Any]:
        """Legacy best-effort helper; never used by the strict expert path."""
        original = text.strip()

        # 1. 先在原文上提取 ```json ... ``` / ``` ... ``` 代码块
        m = re.search(r"```(?:json)?\s*\n?(.*?)```", original, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(1).strip())
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        # 2. 去掉 LLM 叙述前缀后尝试直接解析
        cleaned = original
        for prefix in ["Here is", "Certainly", "Sure", "Below is", "The following"]:
            if cleaned.startswith(prefix) and "\n" in cleaned:
                cleaned = cleaned.split("\n", 1)[1].strip()
                break
        if cleaned.startswith("{"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        # 3. 兜底：正则取第一个 { ... } 块
        b = re.search(r"\{.*\}", text, re.DOTALL)
        if b:
            try:
                parsed = json.loads(b.group(0))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        logger.warning("Legacy JSON helper could not parse response text.")
        return {"raw": text}
