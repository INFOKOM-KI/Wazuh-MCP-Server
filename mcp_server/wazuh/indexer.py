#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh Indexer (OpenSearch) query helpers - _search, _msearch.
"""
from __future__ import annotations
import json, logging
from typing import Dict, Optional, List
import httpx

logger = logging.getLogger("blue_team_mcp.indexer")

from mcp_server import (WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD,
                         WAZUH_INDEXER_VERIFY_SSL, _WAZUH_INDEXER_MAX_SIZE)
from mcp_server.core.http_client import _api_call

_WAZUH_INDEX_PATTERNS = {"alerts": "wazuh-alerts-*", "events": "wazuh-events-*",
                           "vulnerabilities": "wazuh-states-vulnerabilities-*"}
_KEYWORD_SEARCH_FIELDS: list[tuple[str, int]] = [
    ("full_log", 3), ("rule.description", 2), ("rule.info", 2),
    ("data.srcip", 2), ("data.srcip2", 2), ("srcip", 2),
    ("data.url", 0), ("data.domain", 0), ("data.user_agent", 0), ("data.referrer", 0),
]
_SRCIP_FIELD_PATHS: list[str] = [
    "data.srcip.keyword", "data.src_ip.keyword", "data.client_ip.keyword",
    "data.remote_ip.keyword", "data.source_ip.keyword", "data.ip.keyword", "srcip.keyword",
]
_MSEARCH_FALLBACK_ERROR: dict = {"error": "_msearch_failed"}


async def _wazuh_indexer_post(body: dict, index_pattern: Optional[str] = None) -> Dict:
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"
    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                json=body, headers={"Content-Type": "application/json"})
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


async def _wazuh_indexer_msearch(bodies: list[dict], index_pattern: Optional[str] = None) -> list[dict]:
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return [{"error": "Not configured"}] * len(bodies)
    if not bodies:
        return []
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_msearch"
    header = json.dumps({"index": index_pattern, "allow_partial_search_results": True})
    parts = []
    for b in bodies:
        parts.append(header)
        parts.append(json.dumps(b, separators=(",", ":"), default=str))
    ndjson = "\n".join(parts) + "\n"
    if not ndjson.endswith("\n"):
        ndjson += "\n"
    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                content=ndjson.encode("utf-8"),
                                headers={"Content-Type": "application/x-ndjson"})
        raw = resp.json()
        if isinstance(raw, dict) and "responses" in raw:
            return raw["responses"]
        return [raw] if not isinstance(raw, list) else raw
    except Exception as e:
        logger.warning("_msearch failed (%s) — fallback to individual calls", e)
        return [_MSEARCH_FALLBACK_ERROR] * len(bodies)
