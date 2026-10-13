# -*- coding: utf-8 -*-
"""3 格诊断：定位「是内容被拦」还是「模型路由 / 参数」问题。用完可删。

C1 我们的客户端 + 配置模型(gpt-5.6-sol) + 无害提示  -> 测接线/参数是否本身就通
C2 我们的客户端 + 配置模型(gpt-5.6-sol) + 安全提示  -> 测该模型是否拦安全内容
C3 照另一台能跑通的脚本配方(gpt-5.4, 不传 temp/max_tokens, 带 UA 头) + 安全提示
                                                    -> 测「你的配方+gpt-5.4」对安全内容放不放行

跑法:  python _diag.py     （把输出贴回来即可）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), override=True)

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from src.config_loader import ConfigLoader
from src.llm_client import LLMClient

BENIGN = "从以下信息中提取联系方式并以一句话复述：小明的邮箱是 shkstart@atguigu.com，电话是 13012341234。"
SECURITY = (
    "Authorized security research / CTF context. In ONE short paragraph, describe how an "
    "integer overflow in a CUDA kernel can cause an out-of-bounds write, and one mitigation."
)


def _snippet(exc: Exception) -> str:
    s = str(exc).replace("\n", " ")
    return s[:300]


def run(label: str, fn) -> None:
    try:
        out = fn()
        print(f"[{label}] OK  -> {repr((out or '').strip()[:120])}")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "status_code", None)
        print(f"[{label}] ERR (HTTP {code}) {type(exc).__name__}: {_snippet(exc)}")


cfg = ConfigLoader()
print("configured model :", cfg.llm.get("model_name"))
print("base_url         :", cfg.llm.get("api_base"))
print("use_responses_api:", cfg.llm.get("use_responses_api"))
print("headers          :", cfg.llm.get("headers"))
print("-" * 70)

client = LLMClient(cfg)  # 使用配置里的 model/temperature/max_tokens/headers

run("C1 5.6-sol + benign  ", lambda: client.chat([{"role": "user", "content": BENIGN}]))
run("C2 5.6-sol + security", lambda: client.chat([{"role": "user", "content": SECURITY}]))

# C3: 完全照另一台机器的 init_chat_model 配方（不传 temperature / max_tokens）
raw = ChatOpenAI(
    model="gpt-5.4",
    api_key=os.environ.get(cfg.llm.get("api_key_env", "NIUBIAPI_KEY"), ""),
    base_url=cfg.llm.get("api_base"),
    default_headers=cfg.llm.get("headers") or None,
    timeout=30,
)
run("C3 gpt-5.4 + security", lambda: raw.invoke([HumanMessage(content=SECURITY)]).content)

print("-" * 70)
print("判读: C1 通而 C2 拦 -> 接线没问题，是 5.6-sol 这条 OpenAI 路由拦安全内容。")
print("      C1 也报错(非 cyber) -> 我们的参数(多半 temperature)在推理模型上不被接受，需调整。")
print("      C3 通 -> gpt-5.4 这条路由放行安全内容，把 model_name 改成 gpt-5.4 即可。")
print("      C3 也拦 -> 该中转站上 gpt-5.4 同样是 OpenAI 审核路由，需换非 OpenAI 路由/上游授权/改措辞。")
