# =============================================================================
# CUDA PoC Generator — LLM 客户端模块 (基于 LangChain)
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
LLM 调用客户端。

基于 LangChain 封装 LLM 调用接口，默认通过 NIUBIAPI 中转站的 OpenAI 兼容端点
(https://www.niubiapi.com/v1) 访问模型，并按中转站要求透传自定义请求头，
提供普通对话、结构化 JSON 生成、重试与流式输出能力。
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import JsonOutputParser

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


class LLMClient:
    """基于 LangChain 的 LLM 调用客户端。

    封装 ChatOpenAI，通过 OpenAI 兼容接口访问 NIUBIAPI 中转站模型，
    支持透传自定义请求头（如中转站要求的 User-Agent），
    提供普通对话、结构化 JSON 生成、重试机制。

    Attributes:
        model: 模型名称。
        temperature: 默认采样温度。
        max_tokens: 最大生成 token 数。
        max_retries: 请求最大重试次数。
        chat_model: LangChain ChatOpenAI 实例。
    """

    def __init__(self, cfg: ConfigLoader) -> None:
        """初始化 LLM 客户端。

        Args:
            cfg: 全局配置加载器。

        Raises:
            ImportError: 缺少 langchain 依赖时抛出。
        """
        try:
            import langchain_openai  # noqa: F401
        except ImportError:
            raise ImportError(
                "请安装 LangChain 依赖: pip install langchain langchain-openai langchain-core"
            )

        llm_cfg = cfg.llm
        api_key = os.environ.get(llm_cfg.get("api_key_env", "NIUBIAPI_KEY"), "")
        if not api_key:
            logger.warning(
                "环境变量 %s 未设置，LLM 调用可能失败。",
                llm_cfg.get("api_key_env", "NIUBIAPI_KEY"),
            )

        self.model: str = llm_cfg.get("model_name", "gpt-5.6-sol")
        self.temperature: float = llm_cfg.get("temperature", 0.3)
        self.max_tokens: int = llm_cfg.get("max_tokens", 8192)
        self.max_retries: int = llm_cfg.get("max_retries", 3)
        self._timeout: int = llm_cfg.get("timeout", 300)
        self._headers: Optional[Dict[str, str]] = llm_cfg.get("headers") or None
        # 可选: 走 OpenAI Responses 协议 (/v1/responses)。某些中转站/上游对该路径的内容策略不同，
        # 对照参考配置中的 "api": "openai-responses"。默认关闭，不影响现有 chat-completions 行为。
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
            base_url=llm_cfg.get("api_base", "https://www.niubiapi.com/v1"),
            default_headers=self._headers,
            timeout=_httpx_timeout,          # httpx.Timeout 对象，不是 float
            max_retries=0,  # 关闭 SDK 内置重试，统一由本类控制并打印每次尝试日志
            **self._extra_init,
        )
        logger.info(
            "LLM 客户端就绪 (LangChain) — 模型: %s, API base: %s",
            self.model,
            llm_cfg.get("api_base"),
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
                "api_key": self.chat_model.openai_api_key,
                "base_url": self.chat_model.openai_api_base,
                "default_headers": self._headers,
                "timeout": _httpx.Timeout(connect=30.0, read=float(self._timeout), write=30.0, pool=30.0),
                "max_retries": 0,  # 同上：关闭 SDK 内置重试
                **self._extra_init,
            }
            if temperature is not None:
                kwargs["temperature"] = temperature
            if max_tokens is not None:
                kwargs["max_tokens"] = max_tokens
            model = ChatOpenAI(**kwargs)
        else:
            model = self.chat_model

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            logger.info(
                "LLM 调用 尝试 %d/%d — 模型: %s, 单次超时: %ds（推理+结构化输出可能较慢，属正常，请耐心等待）",
                attempt, self.max_retries, self.model, self._timeout,
            )
            try:
                resp = model.invoke(lc_messages)
                content = resp.content or ""
                return content.strip()
            except Exception as exc:
                last_exc = exc
                if not self._is_retryable(exc):
                    raise RuntimeError(self._format_fatal(exc)) from exc
                # 连接/超时类错误用更长等待（API 慢不是网络瞬断，短等无用）
                code = getattr(exc, "status_code", None)
                wait = min(10 * attempt, 60) if code is None else min(2 ** attempt, 30)
                logger.warning(
                    "LLM 请求失败 (尝试 %d/%d): %s — %ds 后重试",
                    attempt, self.max_retries, exc, wait,
                )
                time.sleep(wait)

        raise RuntimeError(f"LLM 请求在 {self.max_retries} 次重试后仍失败: {last_exc}")

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
    def _format_fatal(exc: Exception) -> str:
        """为不可重试的错误组装带处置建议的提示。"""
        msg = str(exc)
        low = msg.lower()
        hints: List[str] = []
        is_html = ("<!doctype html" in low) or ("cloudflare" in low) or ("<html" in low)
        if is_html:
            hints.append(
                "响应是 Cloudflare/网关 的 HTML 拦截页（并非模型返回），多为边缘 WAF/反爬或短时频控，"
                "与提示内容、模型名、客户端类型均无关，也不是 Key 错误。建议: "
                "(1) 稍等几分钟再重试，避开频控窗口; "
                "(2) 核对另一台能跑通机器的 NIUBI_BASE_URL 是否就是 www.niubiapi.com（不同域名/IP 可能不走同一 Cloudflare 规则）; "
                "(3) 更换出口网络/代理后再试。"
            )
        elif ("cybersecurity" in low) or ("trusted access" in low) or ("flagged" in low):
            hints.append(
                "上游判定内容存在网络安全风险（OpenAI 内容审核）。可选对策: "
                "(1) 在 config/default.yaml 设 llm.use_responses_api: true 改走 Responses 协议再试; "
                "(2) 改用中转站上非 OpenAI 的模型路由（如 Claude/DeepSeek/Qwen），通过 llm.model_name 或环境变量 CPG_LLM_MODEL_NAME; "
                "(3) 由中转站/上游账号加入 OpenAI Trusted Access for Cyber; "
                "(4) 弱化提示中的攻击/利用类措辞。"
            )
        elif ("401" in msg) or ("403" in msg) or ("unauthorized" in low) or ("forbidden" in low):
            hints.append("鉴权失败：检查 .env 中 NIUBIAPI_KEY 是否正确、是否过期。")
        elif ("invalid_request" in low) or ("400" in msg):
            hints.append("请求被上游以 400 拒绝（参数或内容），重试不会改变结果。请检查模型名/参数或上游内容策略。")
        code = getattr(exc, "status_code", None)
        head = f"LLM 请求被上游拒绝 (HTTP {code})，已停止重试。原始错误: {msg}"
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
            解析后的字典。若解析失败则返回 ``{"raw": "<原始文本>"}``。
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
        raw = self.chat(messages, temperature=temperature)
        return self._safe_parse_json(raw)

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_parse_json(text: str) -> Dict[str, Any]:
        """从模型输出中尽力提取 JSON 字典。"""
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

        logger.warning("无法解析 JSON。前100字符: %s", text[:100])
        return {"raw": text}
