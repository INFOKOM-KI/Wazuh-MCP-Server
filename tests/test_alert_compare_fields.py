#!/usr/bin/env python3
"""Behavioral tests for mapping-resolved curated filters (W2)."""
from __future__ import annotations

import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools.alert_compare import (CuratedReportFilters, _build_curated_query,
                                            _filter_field_bases)

WINDOW = ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")

STOCK_DOC = {"data": {"domain": "evil.cn", "url": "http://evil.cn/x",
                      "user_agent": "curl/8.0", "referrer": "http://evil.cn"},
             "rule": {"id": "5710", "description": "sshd: attempted login"},
             "location": "/var/log/auth.log"}

STOCK_RESOLVED = {"data.domain": "data.domain", "rule.id": "rule.id", "data.url": "data.url",
                  "data.user_agent": "data.user_agent", "data.referrer": "data.referrer",
                  "rule.description": "rule.description", "location": "location"}


def _filters():
    return CuratedReportFilters(domain_pattern="*.evil.cn", rule_ids=["5710"],
                                url_pattern="*evil*", user_agent_contains="curl",
                                referrer_pattern="*evil*", rule_desc_contains="login",
                                log_source_pattern="/var/log/*")


def _dig(doc, path):
    node = doc
    for part in path.split("."):
        node = node[part]
    return node


def test_stock_mapping_filters_name_plain_fields_only():
    clauses = _build_curated_query(*WINDOW, _filters(), STOCK_RESOLVED)
    text = json.dumps(clauses)
    assert ".keyword" not in text
    for field in STOCK_RESOLVED:
        assert field in text
        assert _dig(STOCK_DOC, field) is not None


def test_keyword_mapped_field_uses_subfield_clause():
    clauses = _build_curated_query(*WINDOW, CuratedReportFilters(domain_pattern="*.evil.cn"),
                                   {"data.domain": "data.domain.keyword"})
    assert {"wildcard": {"data.domain.keyword": "*.evil.cn"}} in clauses


def test_mixed_mapping_builds_should_over_both():
    clauses = _build_curated_query(*WINDOW, CuratedReportFilters(domain_pattern="*.evil.cn"),
                                   {"data.domain": None})
    assert {"bool": {"should": [{"wildcard": {"data.domain": "*.evil.cn"}},
                                {"wildcard": {"data.domain.keyword": "*.evil.cn"}}],
                     "minimum_should_match": 1}} in clauses


def test_rule_groups_is_a_single_plain_clause():
    clauses = _build_curated_query(*WINDOW,
                                   CuratedReportFilters(rule_groups=["authentication_failures"]),
                                   {})
    assert {"terms": {"rule.groups": ["authentication_failures"]}} in clauses
    assert ".keyword" not in json.dumps(clauses)


def test_filter_field_bases_lists_only_configured_filters():
    assert _filter_field_bases(CuratedReportFilters()) == []
    assert _filter_field_bases(_filters()) == [
        "data.domain", "rule.id", "data.url", "data.user_agent",
        "data.referrer", "rule.description", "location"]
