#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
cve.now client - vulnerability catalog looked up by technology, ecosystem, or id.

cve.now is a free, unauthenticated MCP endpoint. It is consumed as stateless
JSON-RPC 2.0 over one HTTP POST, not through an MCP client session: a single POST
already returns the full result, and the endpoint issues no session id. Reusing
``_api_call`` gets retry, the per-upstream circuit breaker, and the shared TTL
cache for free.

Two properties shape this module:

* Enrichment is optional. Every failure path raises a typed exception so the
  calling tool can degrade to ``cve_context.status = "unavailable"`` instead of
  failing a Wazuh analysis that was working before cve.now existed.
* Upstream text is untrusted. No tool returns a raw payload: each has a
  projection, and the vendor promotion block the server appends to every result
  is dropped before anything leaves this module.

Correlation honesty (see ``correlate_alert``): a technology match yields
*candidates*. It is not evidence that the detected activity exploited them.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import httpx

from mcp_server.core.http_client import CircuitOpenError, _api_call
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.cve_now")

CVE_NOW_MCP_URL = "https://mcp.cve.now/mcp"
CVE_NOW_HOME = "https://cve.now"

# Fixed endpoint, no user-controlled host: no SSRF surface. The only values that
# cross the wire are allowlisted slugs, validated ids, and integer limits.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 2_000_000
MAX_COMBINATIONS = 16

TTL_LOOKUP = 86400
TTL_SEARCH = 900
TTL_FEED = 900

TECH_SLUGS = frozenset({
    "nextjs", "react", "node", "express", "django", "flask", "rails", "spring",
    "log4j", "kubernetes", "docker", "nginx", "apache-httpd", "openssl",
    "postgresql", "mysql", "redis", "microsoft-sql-server", "oracle-database",
    "mariadb", "ibm-db2", "mongodb", "sap-ase", "php", "wordpress", "jenkins",
    "gitlab", "fortinet", "citrix", "ivanti", "cisco-ios", "palo-alto-panos",
    "vmware", "microsoft-exchange", "chrome", "linux-kernel",
})

ECOSYSTEMS = frozenset({
    "npm", "pypi", "go", "maven", "crates.io", "packagist", "rubygems", "hex",
    "nuget",
})

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_RE = re.compile(r"^GHSA(-[23456789CFGHJMPQRVWX]{4}){3}$")
_OSV_RE = re.compile(r"^OSV-\d{4}-\d+$")

# Strip by host, not by block position: upstream may fold the promo into a text field.
_PROMO_RE = re.compile(r"https?://[^\s\"'<>]*sazabi\.com[^\s\"'<>]*", re.IGNORECASE)

# Structured fields only: a CVE in full_log is attacker-controlled text, not an attribution.
_ALERT_CVE_PATHS = (
    ("vulnerability", "cve"),
    ("vulnerability", "cve_id"),
    ("data", "cve"),
    ("rule", "cve"),
    ("data", "vulnerability", "cve"),
)

_MAP_PATH = Path(__file__).with_name("cve_now_tech_map.json")

_limiter = get_limiter("cve_now", max_concurrent=2, min_interval=0.5)


class CveNowError(RuntimeError):
    """Upstream answered, but not with a usable result."""


class CveNowNotFound(CveNowError):
    """Upstream confirmed the identifier is not in its catalog."""


def _load_tech_map() -> dict:
    with _MAP_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


_TECH_MAP = _load_tech_map()
_GROUP_MAP: dict[str, str] = _TECH_MAP.get("groups") or {}
_LOCATION_MAP: dict[str, str] = (_TECH_MAP.get("field_markers") or {}).get("location_prefix") or {}
_URL_MAP: dict[str, str] = (_TECH_MAP.get("field_markers") or {}).get("url_contains") or {}


def normalize_id(value: str) -> str | None:
    """Return the upper-cased id when it is a CVE, GHSA, or OSV identifier."""
    text = (value or "").strip().upper()
    if _CVE_RE.match(text) or _GHSA_RE.match(text) or _OSV_RE.match(text):
        return text
    return None


def valid_tech(values: list[str]) -> list[str]:
    """Return the slugs that are in the documented allowlist, de-duplicated."""
    seen: list[str] = []
    for raw in values:
        slug = (raw or "").strip().lower()
        if slug in TECH_SLUGS and slug not in seen:
            seen.append(slug)
    return seen


def valid_ecosystems(values: list[str]) -> list[str]:
    seen: list[str] = []
    for raw in values:
        eco = (raw or "").strip().lower()
        if eco in ECOSYSTEMS and eco not in seen:
            seen.append(eco)
    return seen


def strip_promo(value):
    """Remove third-party promotional URLs from every string in a projection."""
    if isinstance(value, str):
        return _PROMO_RE.sub("", value).strip()
    if isinstance(value, list):
        return [strip_promo(item) for item in value]
    if isinstance(value, dict):
        return {key: strip_promo(item) for key, item in value.items()}
    return value


def _parse_blocks(result: dict):
    """Return the first JSON-parsable text block, or the first text block."""
    blocks = [block.get("text", "") for block in (result.get("content") or [])
              if block.get("type") == "text"]
    for block in blocks:
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            continue
    return blocks[0] if blocks else ""


async def _rpc(tool: str, arguments: dict, *, ttl: float) -> dict:
    """Call one cve.now tool and return its parsed JSON payload.

    Raises:
        CveNowNotFound: the server reported the identifier is unknown.
        CveNowError: the server reported any other error, or returned no JSON.
        httpx.HTTPStatusError, httpx.TimeoutException, CircuitOpenError: transport.
    """
    key = f"{tool}:{json.dumps(arguments, sort_keys=True, default=str)}"
    cached = cache_get("cve_now", key)
    if cached is not None:
        return cached

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    async with _limiter:
        resp = await _api_call(
            "post", CVE_NOW_MCP_URL, client_name="cve_now",
            json=body, headers={"Accept": "application/json"},
        )

    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise CveNowError(f"upstream response exceeded {MAX_RESPONSE_BYTES} bytes")
    payload = resp.json()
    if not isinstance(payload, dict):
        raise CveNowError("upstream returned a non-object JSON-RPC payload")
    if payload.get("error"):
        detail = (payload["error"] or {}).get("message", "")
        raise CveNowError(f"upstream JSON-RPC error: {str(detail)[:200]}")

    result = payload.get("result") or {}
    parsed = _parse_blocks(result)

    if result.get("isError"):
        message = parsed if isinstance(parsed, str) else json.dumps(parsed)[:200]
        if message.startswith("No entry found"):
            raise CveNowNotFound(message[:200])
        # Anything else is an upstream fault. Reporting it as "not found" would
        # turn a broken service into a confirmed negative.
        raise CveNowError(f"upstream tool error: {message[:200]}")

    if not isinstance(parsed, dict):
        raise CveNowError("upstream returned no JSON object")

    projected = strip_promo(parsed)
    cache_set("cve_now", key, projected, ttl)
    return projected


def _cap(items, limit: int) -> list:
    return list(items or [])[:limit]


def project_vulnerability(raw: dict) -> dict:
    """Reduce one upstream record to the fields a SOC analyst acts on."""
    severity = raw.get("severity") or {}
    exploit = raw.get("exploitation") or {}
    context = raw.get("context") or {}
    kev = exploit.get("kev") or {}
    fix = context.get("fix") or {}
    ssvc = raw.get("ssvc") or {}
    summary = raw.get("summary") or {}
    poc = exploit.get("githubPoc") or {}

    affected = []
    for entry in _cap(raw.get("affected"), 6):
        if entry.get("package"):
            affected.append({
                "ecosystem": entry.get("ecosystem"),
                "package": entry.get("package"),
                "ranges": _cap(entry.get("ranges"), 3),
            })
        else:
            affected.append({
                "vendor": entry.get("vendor"),
                "product": entry.get("product"),
                "ranges": _cap(entry.get("ranges"), 3),
            })

    return {
        "id": raw.get("id"),
        "aliases": _cap(raw.get("aliases"), 5),
        "title": raw.get("title"),
        "summary": summary.get("text"),
        "severity": {
            "cvss": severity.get("cvss"),
            "vector": severity.get("vector"),
            "source": severity.get("source"),
        },
        "kev": {
            "listed": bool(kev),
            "date_added": kev.get("dateAdded"),
            "due_date": kev.get("dueDate"),
        },
        "exploitation": {
            "epss_reached": (exploit.get("epssReached") or {}).get("date"),
            "exploitdb_ids": _cap((exploit.get("exploitDb") or {}).get("ids"), 5),
            "metasploit_modules": _cap((exploit.get("metasploit") or {}).get("modules"), 5),
            "nuclei_templates": _cap((exploit.get("nuclei") or {}).get("templates"), 5),
            "public_poc_count": len(poc.get("repos") or []) + len(poc.get("exploits") or []),
        },
        "affected": affected,
        "fix": {
            "versions": _cap(fix.get("versions"), 5),
            "workaround": fix.get("workaround"),
            "partial": fix.get("partial"),
            "source_url": fix.get("sourceUrl"),
        },
        "exposure": raw.get("exposure"),
        "ssvc": {
            "exploitation": ssvc.get("exploitation"),
            "automatable": ssvc.get("automatable"),
            "technical_impact": ssvc.get("technicalImpact"),
            "source": ssvc.get("source"),
        },
        "context": {
            "sentence": context.get("sentence"),
            "conditions": [c.get("text") for c in _cap(context.get("conditions"), 3)],
            "attacker": context.get("attacker") or {},
            "vendor_severity": context.get("vendorSeverity"),
        },
        "references": _cap([r.get("url") for r in (raw.get("references") or []) if r.get("url")], 8),
        "timestamps": {
            "published": raw.get("publishedAt"),
            "modified": raw.get("modifiedAt"),
            "first_seen": raw.get("firstSeenAt"),
        },
        "url": raw.get("url") or f"{CVE_NOW_HOME}/{raw.get('id')}",
    }


def project_feed(raw: dict) -> dict:
    items = []
    for item in raw.get("items") or []:
        items.append({
            "id": item.get("id") or item.get("feedId"),
            "title": item.get("title"),
            "summary": item.get("summary"),
            "updated_at": item.get("updatedAt"),
            "kind": item.get("kind"),
            "url": item.get("url") or f"{CVE_NOW_HOME}/{(item.get('id') or '').split('#')[0]}",
        })
    return {
        "name": raw.get("name"),
        "title": raw.get("title"),
        "updated_at": raw.get("updatedAt"),
        "items": items,
    }


def project_search_entry(entry: dict) -> dict:
    entry_id = entry.get("id") or ""
    return {
        "id": entry_id,
        "title": entry.get("title"),
        "summary": entry.get("summary"),
        "cvss": entry.get("cvss"),
        "kev": bool(entry.get("kev")),
        "published": entry.get("published"),
        "modified": entry.get("modified"),
        "url": entry.get("url") or f"{CVE_NOW_HOME}/{entry_id}",
    }


async def lookup(vulnerability_id: str) -> dict | None:
    """Fetch one vulnerability record. Returns None when the id is unknown."""
    try:
        raw = await _rpc("get_vulnerability", {"id": vulnerability_id}, ttl=TTL_LOOKUP)
    except CveNowNotFound:
        return None
    return project_vulnerability(raw)


async def feed(*, tech: list[str] | None = None,
               ecosystem: list[str] | None = None,
               filter_name: str | None = None,
               limit: int = 20) -> dict:
    """Return the newest entries for a technology/ecosystem selection.

    The upstream feed is a "newest N" list, not a time-ranged query: there is no
    parameter that restricts it to the window an alert was raised in.
    """
    arguments: dict = {"limit": limit}
    if tech:
        arguments["tech"] = tech
    if ecosystem:
        arguments["ecosystem"] = ecosystem
    if filter_name:
        arguments["filter"] = [filter_name]
    raw = await _rpc("list_feed", arguments, ttl=TTL_FEED)
    return project_feed(raw)


_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,39}$")


async def search_tech(tech: list[str], limit: int, component: str | None = None,
                      cursor: str | None = None, terms: list[str] | None = None) -> dict:
    """Return catalog entries for one or more technology slugs, highest CVSS first.

    ``component`` is a plugin or theme directory name taken from the alert path and
    matched against the catalog by free text. It is restricted to a slug alphabet,
    so no query operator or alert prose can reach the upstream query language.
    """
    parts = [f'"{term}"' for term in (terms or []) if term]
    if tech:
        parts.append(f"tech:{','.join(tech)}")
    if component and _COMPONENT_RE.match(component.lower()):
        parts.append(component.lower())
    parts.append("sort:cvss")
    query = " ".join(parts)
    arguments = {"q": query, "limit": limit}
    if cursor:
        arguments["cursor"] = cursor
    raw = await _rpc("search", arguments, ttl=TTL_SEARCH)
    entries = [project_search_entry(entry) for entry in raw.get("entries") or []]
    return {
        "entries": entries,
        "total": raw.get("total"),
        "next_cursor": raw.get("next_cursor"),
    }


def _as_list(value) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def alert_cve_ids(alert: dict) -> list[str]:
    """Extract CVE ids from structured alert fields, de-duplicated and validated."""
    found: list[str] = []
    for path in _ALERT_CVE_PATHS:
        node = alert
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        for candidate in _as_list(node):
            normalized = normalize_id(candidate)
            if normalized and normalized.startswith("CVE-") and normalized not in found:
                found.append(normalized)
    return found


def map_alert_tech(alert: dict) -> tuple[list[dict], list[str]]:
    """Map alert fields to cve.now slugs.

    Only whole-value matches count. ``mysql_login_fail`` is a database event, not
    proof the alert concerns a MySQL package version, so it stays unmapped rather
    than being prefix-matched into a technology claim.

    Returns:
        (technologies, unmapped_groups) where each technology carries the exact
        field values that produced it.
    """
    rule = alert.get("rule") or {}
    groups = _as_list(rule.get("groups") or alert.get("rule.groups"))
    evidence_by_tech: dict[str, list[dict]] = {}
    unmapped: list[str] = []

    for group in groups:
        token = group.strip().lower()
        slug = _GROUP_MAP.get(token)
        if slug:
            evidence_by_tech.setdefault(slug, []).append(
                {"source": "rule.groups", "value": group})
        else:
            unmapped.append(group)

    location = str(alert.get("location") or "")
    for prefix, slug in _LOCATION_MAP.items():
        if location.startswith(prefix):
            evidence_by_tech.setdefault(slug, []).append(
                {"source": "location", "value": location})
            break

    data = alert.get("data") or {}
    url = str(data.get("url") or "")
    if url:
        lowered = url.lower()
        for marker, slug in _URL_MAP.items():
            if marker in lowered:
                evidence_by_tech.setdefault(slug, []).append(
                    {"source": "data.url", "value": marker})

    technologies = [{"tech": slug, "evidence": evidence}
                    for slug, evidence in evidence_by_tech.items()]
    return technologies, _cap(unmapped, 20)


def _merge_entry(merged: dict[str, dict], entry: dict, source: str) -> None:
    """Add an entry once, keeping every discovery source that surfaced it."""
    existing = merged.get(entry.get("id"))
    if existing is None:
        merged[entry["id"]] = {**entry, "discovery_sources": [source]}
        return
    if source not in existing["discovery_sources"]:
        existing["discovery_sources"].append(source)


def _rank_key(entry: dict):
    return (
        1 if entry.get("kev") else 0,
        float(entry.get("cvss") or 0),
        entry.get("modified") or "",
    )


def _relevance(entry: dict) -> str:
    if entry.get("kev"):
        return "kev"
    if (entry.get("cvss") or 0) >= 9:
        return "critical"
    return "severity_only"


CANDIDATE_DISCLAIMER = (
    "A technology match lists vulnerabilities that affect that technology. It is "
    "not evidence that the observed activity exploited any of them."
)


async def correlate_alert(alert: dict, technologies: list[dict], *,
                          limit: int = 5, include_details: bool = False,
                          component: str | None = None, max_pages: int = 1,
                          terms: list[str] | None = None,
                          context: dict | None = None, attack: dict | None = None,
                          packages: list[dict] | None = None,
                          target_families: list[str] | None = None,
                          identity_slugs: list[str] | None = None) -> dict:
    """Rank cve.now entries for the technologies mapped from an alert.

    The result is a candidate list. Nothing here checks whether the host runs the
    affected version, and nothing checks the alert's time window - cve.now ranks
    its whole catalog, so an old CVE can outrank a fresh one.
    """
    slugs = [entry["tech"] for entry in technologies]
    page_size = min(limit * 4, 40)
    # Attack pattern first, with no technology restriction: a .php hint or a missing
    # slug must not narrow the catalog. Technology only leads when no pattern exists.
    primary_terms = list(terms or [])
    primary_slugs = [] if primary_terms else slugs
    primary_source = "attack_pattern" if primary_terms else "catalog_search"

    merged: dict[str, dict] = {}
    sources: dict[str, dict] = {}
    total_matches = 0
    pages_fetched = 0
    cursor = None

    if primary_terms or primary_slugs:
        result = await search_tech(primary_slugs, page_size, terms=primary_terms)
        total_matches = result.get("total") or len(result["entries"])
        cursor = result.get("next_cursor")
        pages_fetched = 1
        for entry in result["entries"]:
            _merge_entry(merged, entry, primary_source)
        while cursor and pages_fetched < max(1, min(max_pages, 5)):
            more = await search_tech(primary_slugs, page_size, cursor=cursor,
                                     terms=primary_terms)
            pages_fetched += 1
            total_matches = more.get("total") or total_matches
            cursor = more.get("next_cursor")
            for entry in more["entries"]:
                _merge_entry(merged, entry, primary_source)
        sources[primary_source] = {
            "status": "ok", "query_terms": primary_terms,
            "technologies": primary_slugs, "total_matches": total_matches,
            "retrieved": len(merged), "pages_fetched": pages_fetched,
            "pagination_complete": not cursor}

    if component:
        # A niche plugin CVE will not outrank a platform CVE in the pattern query, so
        # identity matching gets its own lookup, still without a technology filter.
        targeted = await search_tech([], 10, component=component, terms=terms)
        for entry in targeted["entries"]:
            _merge_entry(merged, entry, "component_search")
        sources["component_search"] = {"status": "ok", "component": component,
                                       "retrieved": len(targeted["entries"])}

    # Sufficiency is judged on assessed relevance, not raw hit count: ten
    # incompatible CVEs are not a reason to skip the feed.
    relevant = len(merged)
    specific = len(merged)
    if context is not None and attack is not None:
        from mcp_server.threat_intel.cve_now_assess import assess_candidate
        relevant = 0
        specific = 0
        for entry in merged.values():
            provisional = assess_candidate(entry, context, attack,
                                           list(identity_slugs or []),
                                           list(packages or []),
                                           target_families=target_families)
            if provisional["relationship"] == "no_supported_match":
                continue
            relevant += 1
            # Class-only matches are leads. The feed is skipped only when specific
            # evidence fills the display.
            if provisional["relationship"] in ("confirmed_cve_reference",
                                               "attack_specific_match",
                                               "vulnerability_exposure"):
                specific += 1
            elif (provisional["product_compatibility"] == "compatible"
                  and provisional["product_identity"] in ("exact_product", "exact_component")):
                specific += 1

    if slugs and specific < limit:
        try:
            feed_result = await feed(tech=slugs, limit=min(limit * 4, 20))
            added = 0
            for item in feed_result.get("items") or []:
                before = len(merged)
                _merge_entry(merged, {**item, "cvss": None, "kev": None,
                                      "modified": item.get("updated_at")},
                             "technology_feed")
                added += len(merged) - before
            sources["technology_feed"] = {"status": "ok", "technologies": slugs,
                                          "retrieved": added}
        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError,
                CircuitOpenError, CveNowError) as error:
            sources["technology_feed"] = {"status": "unavailable",
                                          "reason": str(error)[:160]}
    elif slugs:
        sources["technology_feed"] = {"status": "skipped_sufficient_relevant_candidates",
                                      "technologies": slugs, "retrieved": 0,
                                      "assessed_relevant": relevant,
                                      "assessed_specific": specific}

    # When the caller will assess and re-rank, hand back a wider raw set so a
    # low-CVSS candidate with better evidence is not cut before it is looked at.
    keep = len(merged) if context is not None else limit
    ranked = sorted(merged.values(), key=_rank_key, reverse=True)[:keep]

    candidates = []
    for entry in ranked:
        candidates.append({
            "id": entry["id"],
            "title": entry.get("title"),
            "cvss": entry.get("cvss"),
            "kev": entry.get("kev"),
            "relevance": _relevance(entry),
            "modified": entry.get("modified"),
            "url": entry.get("url"),
            "discovery_sources": entry.get("discovery_sources") or [primary_source],
            "why": (
                f"affects {', '.join(slugs)}; technology match only, "
                "no alert evidence ties this CVE to the activity"
                if slugs else
                "matched by attack pattern only; no product identity ties this CVE "
                "to the activity"
            ),
        })

    detail = None
    if include_details and candidates:
        detail = await lookup(candidates[0]["id"])

    return {
        "match_basis": "tech_feed",
        "confidence": "candidate",
        "cve_ids": [],
        "technologies": technologies,
        "unmapped_groups": map_alert_tech(alert)[1] if alert else [],
        "candidates": candidates,
        "candidate_detail": detail,
        "coverage": {
            "source": "cve.now",
            "technologies_queried": slugs,
            "catalog_matches": result.get("total"),
            "returned": len(candidates),
            "page_truncated": result.get("truncated"),
            "time_window": "none - the catalog is ranked in full, not filtered to the alert window",
            "catalog_scope": "search endpoint (catalog-wide, CVSS-sorted), not the newest-entries feed",
            "component_term": bool(component),
            "query_terms": list(terms or []),
            "discovery_sources": [name for name, block in sources.items()
                                  if block.get("status") == "ok"],
            "sources": sources,
            "technology_slugs_queried": slugs,
            "technology_feed_status": (sources.get("technology_feed") or {}).get("status"),
            "total_matches": total_matches,
            "retrieved_count": len(merged),
            "displayed_count": len(ranked),
            "has_more": bool(cursor) or total_matches > len(merged),
            "truncated": total_matches > len(ranked),
            "pagination_complete": not cursor,
            "pages_fetched": pages_fetched,
            "technology_feed_is_not_exhaustive": True,
        },
        "limitations": [
            CANDIDATE_DISCLAIMER,
            "No host inventory was checked: a listed CVE may affect a version this "
            "host does not run.",
            "The catalog is not filtered to the alert time window, so old CVEs "
            "remain in the candidate list.",
            "A CVE missing from this list is not a negative result; coverage depends "
            "on cve.now's catalog, not on Wazuh.",
        ],
        "source": CVE_NOW_HOME,
    }
