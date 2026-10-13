"""Web search tool — Tavily Search API wrapper.

Supplements RAG with live web search for CVE details, patches, and
technical writeups that aren't in the static knowledge base.
"""

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cuda_poc_generator.tools.search")


def is_available() -> bool:
    """Check if Tavily API key is configured."""
    return bool(os.environ.get("TAVILY_API_KEY", ""))


def search_cve(cve_id: str, max_results: int = 5) -> List[Dict[str, str]]:
    """Search for CVE details, advisories, and technical writeups.

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2024-0124'.
        max_results: Maximum number of results (default 5).

    Returns:
        List of dicts with 'title', 'url', 'content' keys.
        Returns empty list if Tavily is not configured.
    """
    if not is_available():
        logger.info("Tavily API key not set — skipping web search for %s", cve_id)
        return []
    try:
        from tavily import TavilyClient
        client = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
        query = f"{cve_id} NVIDIA CUDA vulnerability technical details exploit"
        response = client.search(query=query, max_results=max_results,
                                 search_depth="advanced")
        results = []
        for r in response.get("results", []):
            results.append({
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "content": r.get("content", "")[:500],
            })
        logger.info("Tavily search for %s: %d results", cve_id, len(results))
        return results
    except Exception as e:
        logger.warning("Tavily search failed for %s: %s", cve_id, e)
        return []


def search_cuda_vuln(component: str, vuln_type: str, max_results: int = 5) -> List[Dict[str, str]]:
    """Search for CUDA vulnerability information by component and type.

    Args:
        component: CUDA component name, e.g. 'cuobjdump', 'nvdisasm'.
        vuln_type: Vulnerability type, e.g. 'buffer overflow', 'integer overflow'.
        max_results: Maximum number of results.

    Returns:
        List of dicts with 'title', 'url', 'content' keys.
    """
    if not is_available():
        return []
    try:
        from tavily import TavilyClient
        client = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
        query = f"{component} {vuln_type} NVIDIA CUDA CVE exploit PoC"
        response = client.search(query=query, max_results=max_results,
                                 search_depth="advanced")
        results = []
        for r in response.get("results", []):
            results.append({
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "content": r.get("content", "")[:500],
            })
        return results
    except Exception as e:
        logger.warning("Tavily search failed: %s", e)
        return []


def search_to_context(results: List[Dict[str, str]]) -> str:
    """Convert search results to LLM-prompt-ready context text."""
    if not results:
        return ""
    lines = ["## Web Search Results (Tavily)\n"]
    for i, r in enumerate(results, 1):
        lines.append(f"### [{i}] {r['title']}")
        lines.append(f"URL: {r['url']}")
        lines.append(f"```\n{r['content']}\n```\n")
    return "\n".join(lines)
