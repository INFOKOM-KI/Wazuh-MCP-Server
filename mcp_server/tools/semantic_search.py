#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Semantic search - BM25 lexical ranking over Wazuh rule descriptions.
Zero external dependencies. Pure Python BM25 implementation.
"""
from __future__ import annotations
import json, math, re
from typing import Optional, Literal
from collections import defaultdict
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
from mcp_server.wazuh.time_utils import _parse_time_window

# BM25
# BM25(D, Q) = Σ IDF(q_i) · TF(q_i, D)
# IDF(q_i) = ln((N - n_i + 0.5) / (n_i + 0.5) + 1)
# TF(q_i, D) = f(q_i, D) · (k1 + 1) / (f(q_i, D) + k1 · (1 - b + b · |D| / avgdl))
_K1 = 1.5
_B = 0.75

class _BM25:
    """Minimal BM25 Okapi scorer over a text corpus."""
    def __init__(self, corpus: list[str]):
        self.corpus = corpus
        self.n = len(corpus)
        self.tokenized = [_tokenize(d) for d in corpus]
        self.doc_len = [len(t) for t in self.tokenized]
        self.avgdl = sum(self.doc_len) / max(self.n, 1)
        # Pre-compute IDF per term
        df: dict[str, int] = defaultdict(int)
        for tokens in self.tokenized:
            for t in set(tokens):
                df[t] += 1
        self.idf = {t: math.log((self.n - c + 0.5) / (c + 0.5) + 1)
                     for t, c in df.items()}

    def score(self, query: str) -> list[tuple[int, float]]:
        q_tokens = _tokenize(query)
        scores: list[tuple[int, float]] = []
        for idx, doc_tokens in enumerate(self.tokenized):
            dl = self.doc_len[idx]
            score = 0.0
            for qt in q_tokens:
                if qt not in self.idf:
                    continue
                f = doc_tokens.count(qt)
                if f == 0:
                    continue
                tf = f * (_K1 + 1) / (f + _K1 * (1 - _B + _B * dl / self.avgdl))
                score += self.idf[qt] * tf
            if score > 0:
                scores.append((idx, score))
        scores.sort(key=lambda x: -x[1])
        return scores


def _tokenize(text: str) -> list[str]:
    """Lowercase, split, remove short tokens and punctuation."""
    text = re.sub(r"[^a-z0-9\s._-]", " ", text.lower())
    tokens = [t.strip("._-") for t in text.split() if len(t.strip("._-")) >= 2]
    return tokens


# Wazuh Rule Corpus
# Static fallback corpus — used when Wazuh API is unavailable.
# Replaced by live rules on first successful API call.
_STATIC_RULE_CORPUS: list[dict] = [
    # Auth / Brute Force
    {"id": "5710", "desc": "SSHD brute force authentication failure", "groups": "authentication_failed,bruteforce"},
    {"id": "5712", "desc": "SSHD brute force detected", "groups": "authentication_failed,bruteforce"},
    {"id": "5716", "desc": "SSHD authentication failed", "groups": "authentication_failed"},
    {"id": "5551", "desc": "Multiple authentication failures from same source", "groups": "authentication_failed,bruteforce"},
    {"id": "60106", "desc": "Multiple Windows logon failures", "groups": "windows,authentication_failed,bruteforce"},
    # Web Attacks
    {"id": "31100", "desc": "Web server SQL injection attempt", "groups": "web,attack,sql_injection"},
    {"id": "31103", "desc": "Web server path traversal attempt", "groups": "web,attack,path_traversal"},
    {"id": "31108", "desc": "Web server command injection attempt", "groups": "web,attack,command_injection"},
    {"id": "31151", "desc": "Web server PHP file upload attempt", "groups": "web,attack,php"},
    {"id": "31500", "desc": "Web server remote code execution attempt", "groups": "web,attack,rce"},
    {"id": "604042", "desc": "Generic webshell or malicious PHP script detected", "groups": "web,attack,webshell"},
    # Recon / Scanning
    {"id": "600029", "desc": "Nmap scan detection multiple ports from single source", "groups": "recon,scan,nmap"},
    {"id": "33100", "desc": "Network port scan detected", "groups": "recon,scan"},
    {"id": "5760", "desc": "SSHD port scanning detected", "groups": "recon,scan,ssh"},
    # Malware / C2
    {"id": "606029", "desc": "C2 indicator detected active response triggered", "groups": "c2,active_response"},
    {"id": "640", "desc": "Possible malware or rootkit detected by rkhunter", "groups": "malware,rootkit"},
    {"id": "641", "desc": "File integrity change detected syscheck", "groups": "syscheck,fim"},
    # Windows Events
    {"id": "60100", "desc": "Windows event log cleared", "groups": "windows,defense_evasion"},
    {"id": "60204", "desc": "Windows privilege escalation attempt", "groups": "windows,privilege_escalation"},
    # Exploitation
    {"id": "33500", "desc": "Denial of service attack detected", "groups": "dos,attack"},
    # Data Exfiltration
    {"id": "700", "desc": "Large data transfer possible exfiltration", "groups": "exfiltration"},
    {"id": "701", "desc": "DNS tunneling exfiltration detected", "groups": "dns,exfiltration,tunneling"},
    # Suspicious Activity
    {"id": "510", "desc": "Suspicious cron job created", "groups": "cron,persistence"},
    {"id": "530", "desc": "Suspicious SUID binary detected", "groups": "suid,privilege_escalation"},
    {"id": "550", "desc": "Suspicious network connection to known bad IP", "groups": "network,c2"},
    {"id": "560", "desc": "Suspicious PowerShell execution", "groups": "powershell,windows,execution"},
    # Linux
    {"id": "5500", "desc": "PAM authentication failure", "groups": "pam,authentication_failed"},
    {"id": "5502", "desc": "Sudo command executed", "groups": "sudo,privilege_escalation"},
    # Compliance
    {"id": "800", "desc": "CIS benchmark compliance check failed", "groups": "cis,compliance"},
    {"id": "801", "desc": "PCI DSS compliance violation detected", "groups": "pci_dss,compliance"},
]

# Live corpus builder (calls Wazuh API for full rule set)
_bm25_index: _BM25 | None = None
_bm25_corpus: list[dict] = []
_bm25_live_loaded = False


def _build_bm25_from_corpus(corpus: list[dict]) -> _BM25:
    """Build BM25 index from a rule corpus."""
    texts = [f"{r['id']} {r['desc']} {r['groups']}" for r in corpus]
    return _BM25(texts)


async def _try_load_live_corpus():
    """Fetch rules from Wazuh API and rebuild BM25 index. Falls back to static."""
    global _bm25_index, _bm25_corpus, _bm25_live_loaded
    if _bm25_live_loaded:
        return
    _bm25_live_loaded = True
    try:
        from mcp_server import WAZUH_API_URL, WAZUH_API_PASSWORD
        if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
            raise RuntimeError("Wazuh API not configured")
        from mcp_server.wazuh.auth import _wazuh_api_get
        data = await _wazuh_api_get("/rules", {"limit": "500", "sort": "-level"})
        if isinstance(data.get("error"), str):
            raise RuntimeError(data["error"])
        items = data.get("data", {}).get("affected_items", [])
        if len(items) < 10:
            raise RuntimeError(f"Only {len(items)} rules returned")
        live_corpus = []
        for r in items:
            live_corpus.append({
                "id": str(r.get("id", "?")),
                "desc": str(r.get("description", ""))[:100],
                "groups": ",".join(r.get("groups", [])) if r.get("groups") else "",
            })
        _bm25_corpus = live_corpus
        _bm25_index = _build_bm25_from_corpus(live_corpus)
    except Exception:
        # Fall back to static corpus
        _bm25_corpus = _STATIC_RULE_CORPUS
        _bm25_index = _build_bm25_from_corpus(_STATIC_RULE_CORPUS)

# Semantic Search Tool
class SemanticSearchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    query: str = Field(..., min_length=2, max_length=512,
                       description="Natural language query (English or Indonesian).")
    since: str | None = Field(default="24h", max_length=30)
    until: str | None = Field(default=None, max_length=30)
    top_k: int = Field(default=10, ge=3, le=30)
    search_alerts: bool = Field(default=False,
                                 description="If true, also search actual alerts matching top rules.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(name="blueteam_semantic_search",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": False})
async def blueteam_semantic_search(params: SemanticSearchInput) -> str:
    """Semantic search over Wazuh rules using BM25 lexical ranking.

    Matches natural language queries against Wazuh rule descriptions and returns
    the most relevant rule IDs. Use this BEFORE querying alerts — find which
    rules match "credential theft" or "serangan webshell" then use
    ``blueteamWazuhIndexerSearch`` to retrieve the actual alerts.

    **Worked Examples**

    1. *Find rules about brute force*:
       ``blueteam_semantic_search(query="brute force SSH login attempt")``

    2. *Indonesian: serangan web*:
       ``blueteam_semantic_search(query="serangan webshell pada server")``

    3. *Search and fetch matching alerts*:
       ``blueteam_semantic_search(query="ransomware encryption", search_alerts=true, since="7d")``
    """
    _audit_log("blueteam_semantic_search", {"query": params.query, "top_k": params.top_k})
    await _try_load_live_corpus()
    results = _bm25_index.score(params.query)[:params.top_k]

    if params.response_format == "json":
        matches = [{"rule_id": _bm25_corpus[idx]["id"],
                     "description": _bm25_corpus[idx]["desc"],
                     "groups": _bm25_corpus[idx]["groups"],
                     "bm25_score": round(score, 4)}
                   for idx, score in results]
        if not params.search_alerts:
            return json.dumps({"query": params.query, "matches": matches}, indent=2, ensure_ascii=False)
        # Also fetch alerts
        rule_ids = [m["rule_id"] for m in matches[:5]]
        return await _search_alerts_for_rules(rule_ids, params.since, params.until, matches)

    lines = [f"# 🔍 Semantic Search — `{params.query}`", "",
             f"**Top {len(results)} matching rules**:", "",
             "| Rule ID | BM25 Score | Description | Groups |",
             "|---------|-----------|-------------|--------|"]
    for idx, score in results[:params.top_k]:
        r = _bm25_corpus[idx]
        lines.append(f"| `{r['id']}` | {score:.3f} | {r['desc'][:60]} | {r['groups'][:40]} |")
    lines.append("")

    if not params.search_alerts:
        lines.append("*Gunakan `blueteamWazuhIndexerSearch` dengan rule ID dari hasil di atas untuk melihat alert terkait.*")
        return _truncate_if_needed("\n".join(lines))

    # Search actual alerts for top matching rule ID
    rule_ids = [_bm25_corpus[idx]["id"] for idx, _ in results[:5]]
    return await _search_alerts_for_rules(rule_ids, params.since, params.until,
                                           [{"rule_id": _bm25_corpus[idx]["id"],
                                             "description": _bm25_corpus[idx]["desc"],
                                             "score": round(score, 4)}
                                            for idx, score in results[:5]])


async def _search_alerts_for_rules(rule_ids: list[str], since: str | None,
                                    until: str | None, matches: list[dict]) -> str:
    """Fetch alert counts for specific rule IDs."""
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        s = json.dumps({"error": "Indexer not configured", "matches": matches}, indent=2, ensure_ascii=False)
        return _truncate_if_needed(s)
    since_iso, until_iso = _parse_time_window(since, until)
    body = {"size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                           "format": "strict_date_optional_time"}}},
                {"terms": {"rule.id.keyword": rule_ids}},
            ]}},
            "aggs": {"by_rule": {"terms": {"field": "rule.id.keyword", "size": len(rule_ids)}},
                     "top_srcips": {"terms": {"field": "data.srcip.keyword", "size": 10}}}}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps({"error": raw["error"], "matches": matches}, indent=2, ensure_ascii=False)
    aggs = raw.get("aggregations", {})
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    lines = [f"# 🔍 Semantic Search — Alert Results", "",
             f"**Total matching alerts**: {total:,}", "",
             "## By Rule", "| Rule ID | Alerts | Description |",
             "|---------|--------|-------------|"]
    by_rule = {b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])}
    for m in matches:
        cnt = by_rule.get(m["rule_id"], 0)
        lines.append(f"| `{m['rule_id']}` | {cnt:,} | {m['description'][:50]} |")
    lines.append("")
    top_ips = aggs.get("top_srcips", {}).get("buckets", [])
    if top_ips:
        lines.append("## Top Source IPs")
        for b in top_ips[:10]:
            lines.append(f"- `{b['key']}`: {b['doc_count']:,} alerts")
    return _truncate_if_needed("\n".join(lines))
