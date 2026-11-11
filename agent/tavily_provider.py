# -*- coding: utf-8 -*-
"""Tavily provider: web search and page extraction as tools, not as runtime code.

The runtime knows nothing about Tavily. This module reports whether the provider is
usable and, if it is, hands the registry two tool specs. Credentials come from the
existing project ``.env`` through ``ConfigLoader`` - there is no second config file and
no key ever reaches a log: results are redacted like any other tool output, and the key
itself is only ever passed to the SDK constructor.

Unconfigured is a normal state, not an error: the agent starts, the tools are absent,
and ``status()`` says exactly why.
"""

import json
import os
from typing import List

from .evidence import redact

PROVIDER = "tavily"
SEARCH_SNIPPET_CHARS = 600
ENV_KEY = "TAVILY_API_KEY"


def status() -> dict:
    """Report availability without importing the SDK unless it is installed."""
    key = os.environ.get(ENV_KEY, "").strip()
    try:
        import tavily  # noqa: F401
        sdk = True
        sdk_reason = ""
    except Exception as exc:  # noqa: BLE001 - a missing optional dependency
        sdk = False
        sdk_reason = "%s: %s" % (type(exc).__name__, exc)
    available = bool(key) and sdk
    if available:
        reason = "ready"
    elif not key and not sdk:
        reason = "%s is not set and tavily-python is not installed" % ENV_KEY
    elif not key:
        reason = "%s is not set" % ENV_KEY
    else:
        reason = "tavily-python is not installed (%s)" % sdk_reason
    return {"provider": PROVIDER, "sdk_installed": sdk, "key_present": bool(key),
            "available": available, "reason": reason}


def _client():
    from tavily import TavilyClient
    return TavilyClient(api_key=os.environ.get(ENV_KEY, "").strip())


def build_tools(log) -> List[dict]:
    """Two tool specs, or an empty list when the provider is not usable."""
    state = status()
    if not state["available"]:
        return []
    artifacts = log.artifacts

    def web_search(query: str, max_results: int = 5, search_depth: str = "basic") -> dict:
        try:
            wanted = int(max_results)
            depth = str(search_depth)
        except (TypeError, ValueError):
            return {"ok": False, "status": "failed",
                    "summary": {"error": "max_results must be an integer"},
                    "artifacts": []}
        if not 1 <= wanted <= 20:
            log.append("search", {"query": query, "error": "max_results out of range"},
                       status="rejected")
            return {"ok": False, "status": "failed",
                    "summary": {"error": "max_results out of range (1..20): %r" % max_results},
                    "artifacts": []}
        if depth not in ("basic", "advanced"):
            log.append("search", {"query": query, "error": "bad search_depth"},
                       status="rejected")
            return {"ok": False, "status": "failed",
                    "summary": {"error": "search_depth must be basic or advanced: %r" % depth},
                    "artifacts": []}

        try:
            payload = _client().search(query=query, max_results=wanted, search_depth=depth)
        except Exception as exc:  # noqa: BLE001 - a failed call is an observation
            message, _ = redact("%s: %s" % (type(exc).__name__, exc))
            entry = {"query": query, "error": message}
            log.append("search", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": []}

        results = payload.get("results", []) if isinstance(payload, dict) else []
        ref = artifacts.save("http", "tavily-search.json",
                             json.dumps(payload, ensure_ascii=False)) if artifacts else None
        digest = (ref or {}).get("sha256")
        items = []
        for item in results[:10]:
            body = item.get("content") or ""
            items.append({"title": item.get("title", "")[:120],
                          "url": item.get("url", ""),
                          "score": item.get("score"),
                          "content": body[:SEARCH_SNIPPET_CHARS],
                          "content_truncated": len(body) > SEARCH_SNIPPET_CHARS})
        # Zero hits is a successful request with no data, not a failure and not a hit.
        status = "empty" if not items else "success"
        summary = {"query": query, "results": len(results), "payload_sha256": digest,
                   "search_depth": depth, "items": items,
                   "note": "content is the search engine's snippet, not the page body"}
        log.append("search", {"query": query, "results": len(results),
                              "payload_sha256": digest, "search_depth": depth,
                              "artifacts": [ref] if ref else []}, status=status)
        return {"ok": True, "status": status, "summary": summary,
                "artifacts": [ref] if ref else []}

    def web_extract(url: str) -> dict:
        try:
            payload = _client().extract(urls=[url])
        except Exception as exc:  # noqa: BLE001
            message, _ = redact("%s: %s" % (type(exc).__name__, exc))
            entry = {"url": url, "error": message}
            log.append("extract", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": []}

        items = payload.get("results", []) if isinstance(payload, dict) else []
        failed = payload.get("failed_results", []) if isinstance(payload, dict) else []
        content = (items[0].get("raw_content") or "") if items else ""
        ref = artifacts.save("http", "tavily-extract.json",
                             json.dumps(payload, ensure_ascii=False)) if artifacts else None
        digest = (ref or {}).get("sha256")
        refs = [ref] if ref else []

        # API success is not extraction success: an empty result set or an empty body
        # means the page was not read, and must not be reported as a hit.
        if not items:
            entry = {"url": url, "error": "extraction returned no results",
                     "failed_results": len(failed), "payload_sha256": digest,
                     "artifacts": refs}
            log.append("extract", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": refs}
        if not content.strip():
            entry = {"url": url, "error": "extracted body is empty",
                     "failed_results": len(failed), "payload_sha256": digest,
                     "artifacts": refs}
            log.append("extract", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": refs}

        status = "partial" if failed else "success"
        summary = {"url": url, "chars": len(content), "payload_sha256": digest,
                   "failed_results": failed[:5], "truncated": len(content) > 4000,
                   "content_preview": content[:4000]}
        log.append("extract", {"url": url, "chars": len(content),
                               "payload_sha256": digest, "failed_results": len(failed),
                               "artifacts": refs}, status=status)
        return {"ok": True, "status": status, "summary": summary, "artifacts": refs}

    return [
        {"name": "web_search", "fn": web_search, "category": "research", "source": PROVIDER,
         "description": "Search the web. Returns titles, URLs and scores; the full payload "
                        "is stored as an artifact.",
         "parameters": {"query": "str", "max_results": "int", "search_depth": "basic|advanced"}},
        {"name": "web_extract", "fn": web_extract, "category": "research", "source": PROVIDER,
         "description": "Fetch and extract the readable text of one URL. Long pages are "
                        "truncated in the reply; the full payload is an artifact.",
         "parameters": {"url": "str"}},
    ]
