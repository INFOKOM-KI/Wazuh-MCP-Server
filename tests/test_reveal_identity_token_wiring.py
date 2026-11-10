#!/usr/bin/env python3
"""reveal_identities must forward forensic_token to _redact_alert_data.

Without it, a correct token is refused as if it were missing.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import mcp_server.core.redact as redact_mod
from mcp_server.tools import dsl_query


def test_dsl_query_forwards_forensic_token():
    async def fake_post(body, **kwargs):
        return {"aggregations": {"top_agents": {"buckets": [
            {"key": "web01", "doc_count": 1}]}}}

    params = dsl_query.DslQueryInput(
        aggs={"top_agents": {"terms": {"field": "agent.name"}}},
        reveal_identities=True, forensic_token="tok-12345678")

    with patch.object(dsl_query, "_wazuh_indexer_post", fake_post), \
            patch.object(redact_mod, "BLUETEAM_ALLOW_IDENTITY_REVEAL", True), \
            patch.object(redact_mod, "BLUETEAM_FORENSIC_TOKEN", "tok-12345678"):
        out = asyncio.run(dsl_query.wazuh_alert_dsl_query(params))

    assert "web01" in out
