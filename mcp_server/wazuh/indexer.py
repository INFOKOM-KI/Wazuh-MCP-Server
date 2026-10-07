#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh Indexer (OpenSearch) query helpers (_search, _msearch, cursor pagination)
"""
from __future__ import annotations
import asyncio, base64, json, logging, os, time
from typing import Dict, Optional, List
import httpx

logger = logging.getLogger("blue_team_mcp.indexer")

from mcp_server import (WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD,
                         WAZUH_INDEXER_VERIFY_SSL, _WAZUH_INDEXER_MAX_SIZE)
from mcp_server.core.exceptions import BlueTeamMCPError, ConfigurationError
from mcp_server.core.http_client import _api_call

_WAZUH_INDEX_PATTERNS = {"alerts": "wazuh-alerts-*", "events": "wazuh-events-*",
                           "vulnerabilities": "wazuh-states-vulnerabilities-*"}
_KEYWORD_SEARCH_FIELDS: list[tuple[str, int]] = [
    ("full_log", 3), ("rule.description", 2), ("rule.info", 2),
    ("data.srcip", 2), ("data.srcip2", 2), ("srcip", 2),
    ("rule.cve", 2), ("data.command", 1), ("data.protocol", 1),
    ("data.url", 0), ("data.domain", 0), ("data.user_agent", 0), ("data.referrer", 0),
]
# Base source-IP paths, matched with `match`. The pinned template has no
# `.keyword` sub-field for these. Template-valid families first, then aliases.
_SRCIP_FIELD_PATHS: list[str] = [
    "data.srcip", "data.src_ip", "data.audit.srcip",
    "data.aws.sourceIPAddress", "data.aws.source_ip_address",
    "data.office365.ClientIP", "data.ms-graph.actor.ipAddress",
    "data.ms-graph.ipAddress", "data.win.eventdata.ipAddress",
    "data.osquery.columns.src_ip", "GeoLocation.ip",
    "data.client_ip", "data.remote_ip", "data.source_ip", "data.ip", "srcip",
]

# Template-derived syscheck (FIM) leaves; tests pin this list to the fixture so
# tools validate requested fields without duplicating hard-coded lists.
_SYSCHECK_FIELD_PATHS: frozenset[str] = frozenset({
    "syscheck.arch",
    "syscheck.audit.effective_user.id",
    "syscheck.audit.effective_user.name",
    "syscheck.audit.group.id",
    "syscheck.audit.group.name",
    "syscheck.audit.login_group.id",
    "syscheck.audit.login_group.name",
    "syscheck.audit.login_user.id",
    "syscheck.audit.login_user.name",
    "syscheck.audit.process.id",
    "syscheck.audit.process.name",
    "syscheck.audit.process.ppid",
    "syscheck.audit.user.id",
    "syscheck.audit.user.name",
    "syscheck.changed_attributes",
    "syscheck.diff",
    "syscheck.event",
    "syscheck.gid_after",
    "syscheck.gid_before",
    "syscheck.gname_after",
    "syscheck.gname_before",
    "syscheck.hard_links",
    "syscheck.inode_after",
    "syscheck.inode_before",
    "syscheck.md5_after",
    "syscheck.md5_before",
    "syscheck.mode",
    "syscheck.mtime_after",
    "syscheck.mtime_before",
    "syscheck.path",
    "syscheck.perm_after",
    "syscheck.perm_before",
    "syscheck.sha1_after",
    "syscheck.sha1_before",
    "syscheck.sha256_after",
    "syscheck.sha256_before",
    "syscheck.size_after",
    "syscheck.size_before",
    "syscheck.tags",
    "syscheck.uid_after",
    "syscheck.uid_before",
    "syscheck.uname_after",
    "syscheck.uname_before",
    "syscheck.value_name",
    "syscheck.value_type",
})

_MSEARCH_FALLBACK_ERROR: dict = {"error": "_msearch_failed"}

# Attacker side fields only, never full_log (victim usernames/paths). ``data.file``
# is flat because the template maps it as keyword; dotted children cannot index.
_ATTACKER_FIELDS: list[str] = [
    "data.url", "data.domain", "data.command", "data.file",
]
_ATTACKER_CONTEXT_FIELDS: list[str] = [
    "rule.id", "rule.description", "rule.groups", "rule.level", "rule.mitre.id",
    "decoder.name", "agent.name",
]

# (3-Sum, pivot, threat-card) re-fire identical aggregations within seconds;
# dedupe those round-trips. TTL is deliberately short so relative time windows
# (now-24h) don't serve stale results. Errors are never cached.
_INDEXER_CACHE_TTL = float(os.environ.get("BLUETEAM_INDEXER_CACHE_TTL", "30"))
_INDEXER_CACHE: dict = {}  # {cache_key: (expiry_monotonic, response)}


async def _wazuh_indexer_mapping(index_pattern: Optional[str] = None) -> Dict:
    """Fetch index field mappings from the OpenSearch _mapping endpoint.
    Returns the raw mapping dict keyed by index name. Used by the schema
    explorer tool to discover field names/types before building aggregations
    (prevents the `.keyword` vs `keyword` field-mapping false-negative class).
    """
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_mapping"
    try:
        resp = await _api_call("get", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                headers={"Content-Type": "application/json"})
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


def _mark_partial(data: Dict) -> None:
    """Flag a shard-partial response in place. A failed shard excludes its
    documents from every aggregation without raising, so the counts still read
    like a complete answer."""
    failed = (data.get("_shards") or {}).get("failed") or 0
    if failed:
        data["_partial"] = True
        data["_failed_shards"] = int(failed)


async def _wazuh_indexer_post(body: dict, index_pattern: Optional[str] = None) -> Dict:
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}
    cache_key = (index_pattern, json.dumps(body, sort_keys=True, default=str))
    now = time.monotonic()
    cached = _INDEXER_CACHE.get(cache_key)
    if cached and now < cached[0]:
        return cached[1]
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"
    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                json=body, headers={"Content-Type": "application/json"})
        data = resp.json()
        _mark_partial(data)
        if _INDEXER_CACHE_TTL > 0:
            _INDEXER_CACHE[cache_key] = (now + _INDEXER_CACHE_TTL, data)
            if len(_INDEXER_CACHE) > 1000:  # bound the cache
                _INDEXER_CACHE.pop(next(iter(_INDEXER_CACHE)))
        return data
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


async def _wazuh_indexer_field_caps(fields: list[str],
                                    index_pattern: Optional[str] = None) -> Dict[str, str]:
    """Probe which of ``fields`` the index actually knows, via ``_field_caps``.
    Cheaper than pulling the whole ``_mapping`` when only a handful of names need
    checking. Rule synthesis must not emit a field the deployment never populates;
    that is the silent-false-negative class this guards against.
    Returns ``{field: type}`` for fields the index knows. A field absent from the
    result is genuinely unmapped. Returns ``{}`` on any transport/probe error, and
    callers must read that as "could not verify", not as "field missing".
    """
    if not fields:
        return {}
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_field_caps"
    try:
        resp = await _api_call("get", url, client_name="indexer",
                               verify=WAZUH_INDEXER_VERIFY_SSL,
                               auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                               params={"fields": ",".join(fields)},
                               headers={"Content-Type": "application/json"})
        raw = resp.json()
    except Exception as e:
        logger.warning("field_caps probe failed: %s", e)
        return {}
    if not isinstance(raw, dict) or "error" in raw:
        return {}
    out: Dict[str, str] = {}
    for name, types in (raw.get("fields") or {}).items():
        if not isinstance(types, dict) or not types:
            out[name] = "unknown"
            continue
        # {field: {type_name: {"type": "keyword", ...}}} one entry per type.
        first = next(iter(types.values()))
        out[name] = first.get("type", "unknown") if isinstance(first, dict) else str(first)
    return out


_AGG_SAFE_TYPES = ("keyword", "long", "integer", "double", "date", "boolean", "ip")


def _flatten_props(prefix: str, props: dict, out: dict) -> None:
    """Flatten nested mapping ``properties`` into dotted field paths."""
    for name, spec in props.items():
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(spec, dict) and "properties" in spec:
            _flatten_props(path, spec["properties"], out)
            continue
        out[path] = spec


def _shape(spec: dict) -> str:
    """Mapping shape for one index, e.g. ``text+fielddata+analyzer=keyword``."""
    parts = [spec.get("type", "object")]
    if "keyword" in spec.get("fields", {}):
        parts.append("keyword")
    if spec.get("fielddata"):
        parts.append("fielddata")
    if spec.get("analyzer"):
        parts.append(f"analyzer={spec['analyzer']}")
    return "+".join(parts)


def _shape_is_agg_safe(shape: str) -> bool:
    """True when the field name aggregates to values, not analysed tokens.

    A text field with fielddata does aggregate, but the analyser decides whether
    the buckets are values or tokens (the standard analyser keeps
    ``101.255.167.98`` whole while splitting ``a.b.go.id``), so this refuses
    rather than permits.
    """
    return shape.split("+")[0] in _AGG_SAFE_TYPES


def _agg_safe_field(field: str, by_shape: dict) -> Optional[str]:
    """Field name that aggregates in every matched index, or None when mixed."""
    if not by_shape:
        return None
    if all(_shape_is_agg_safe(shape) for shape in by_shape):
        return field
    if all("keyword" in shape.split("+")[1:] for shape in by_shape):
        return f"{field}.keyword"
    return None


def _agg_safe_paths(path: str, caps: dict) -> list[str]:
    """Terms-aggregatable names for one base path from a ``_field_caps`` probe.
    Both names are returned when both are mapped (dual-mapping phases); the plain
    name only when its type aggregates; ``.keyword`` only when the mapping has one.
    """
    names = []
    if caps.get(path) in _AGG_SAFE_TYPES:
        names.append(path)
    keyword_path = f"{path}.keyword"
    if caps.get(keyword_path) in _AGG_SAFE_TYPES:
        names.append(keyword_path)
    return names


async def _resolve_agg_fields(fields: list[str],
                              index_pattern: Optional[str] = None) -> Dict[str, Optional[str]]:
    """Resolve each field to a name that aggregates across every matched index.
    None means the mapping is mixed with no single name spanning it; the caller
    decides the fallback. Uses the full mapping because ``_field_caps`` cannot
    say which index carries which type.
    """
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    raw = await _wazuh_indexer_mapping(index_pattern)
    if not isinstance(raw, dict) or "error" in raw:
        return {field: None for field in fields}
    shapes: Dict[str, Dict[str, List[str]]] = {field: {} for field in fields}
    for index_name, body in raw.items():
        props = ((body or {}).get("mappings") or {}).get("properties") or {}
        flat: dict = {}
        _flatten_props("", props, flat)
        for field in fields:
            spec = flat.get(field)
            if spec is not None:
                shapes[field].setdefault(_shape(spec), []).append(index_name)
    return {field: _agg_safe_field(field, shapes[field]) for field in fields}


def _srcip_should_clauses(srcip: str, *, full_log: bool = True,
                          extra_paths: tuple = ()) -> dict:
    """``bool.should`` matching one source IP across every candidate path.
    Unmapped paths simply do not match, so the clause is safe on any mapping.
    """
    should = [{"match": {path: srcip.strip()}} for path in _SRCIP_FIELD_PATHS]
    should += [{"match": {path: srcip.strip()}} for path in extra_paths]
    if full_log:
        should.append({"match_phrase": {"full_log": srcip.strip()}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


async def _exact_srcip_counts(query: dict, candidates: list[str],
                              index_pattern: Optional[str] = None) -> Dict[str, int]:
    """Exact distinct-alert count per candidate IP, batched into one _msearch.

    Each body counts documents matching the OR of every source-IP path for that
    address, so a document is counted once however many paths carry it (exact for
    overlapping and independent documents alike). ``full_log`` is excluded so the
    count stays comparable with the terms buckets.
    """
    if not candidates:
        return {}
    bodies = []
    for ip in candidates:
        should = _srcip_should_clauses(ip, full_log=False)["bool"]["should"]
        bodies.append({
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": [
                query,
                {"bool": {"should": should, "minimum_should_match": 1}},
            ]}},
        })
    responses = await _wazuh_indexer_msearch(bodies, index_pattern)
    counts: Dict[str, int] = {}
    for ip, raw in zip(candidates, responses):
        total = ((raw or {}).get("hits") or {}).get("total")
        counts[ip] = int(total.get("value", 0)) if isinstance(total, dict) else int(total or 0)
    return counts


async def _correct_srcip_counts(buckets: list, query: dict,
                                index_pattern: Optional[str] = None) -> list:
    """Replace merged bucket ``doc_count`` values with exact distinct-alert counts.
    Only the buckets returned to the caller are corrected, which bounds the batch
    to the displayed top list.
    """
    keys = [str(b.get("key")) for b in buckets if b.get("key") is not None]
    counts = await _exact_srcip_counts(query, keys[:200], index_pattern)
    for bucket in buckets:
        key = str(bucket.get("key"))
        if key in counts:
            bucket["doc_count"] = counts[key]
    return buckets


def _srcip_from_doc(doc: dict):
    """First source-IP value in an alert doc, in ``_SRCIP_FIELD_PATHS`` order.
    Reads nested objects and flat literal dotted keys.
    """
    for path in _SRCIP_FIELD_PATHS:
        node = doc
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node:
            return node
        if isinstance(doc, dict) and doc.get(path):
            return doc[path]
    return None


def _merge_bucket_lists(target: list, incoming: list) -> list:
    """Merge bucket lists by key; the larger ``doc_count`` wins per key and
    matching buckets merge their sub-aggregations recursively.

    The merged ``doc_count`` is a **lower bound** on distinct alerts: per-path
    counts cannot tell an alert carrying the address in two fields from two
    alerts using different fields. Callers that display a count must correct it
    with :func:`_correct_srcip_counts`, which counts documents server-side.
    """
    by_key = {str(b.get("key")): b for b in target}
    for bucket in incoming:
        key = str(bucket.get("key"))
        current = by_key.get(key)
        if current is None:
            by_key[key] = bucket
            continue
        current["doc_count"] = max(int(current.get("doc_count", 0)),
                                   int(bucket.get("doc_count", 0)))
        for name, node in bucket.items():
            if name in ("key", "doc_count"):
                continue
            if name not in current:
                current[name] = node
            elif isinstance(current[name], dict) and isinstance(node, dict):
                _merge_agg_nodes(current[name], node)
    return list(by_key.values())


def _merge_agg_nodes(target: dict, incoming: dict) -> None:
    for name, node in incoming.items():
        if name not in target:
            target[name] = node
            continue
        current = target[name]
        if isinstance(current, list) and isinstance(node, list):
            target[name] = _merge_bucket_lists(current, node)
        elif isinstance(current, dict) and isinstance(node, dict):
            if isinstance(current.get("buckets"), list) and isinstance(node.get("buckets"), list):
                current["buckets"] = _merge_bucket_lists(current["buckets"], node["buckets"])
                for extra in ("doc_count_error_upper_bound", "sum_other_doc_count"):
                    current[extra] = max(int(current.get(extra, 0)), int(node.get(extra, 0)))
            else:
                _merge_agg_nodes(current, node)
        else:
            target[name] = node


def _merge_agg_trees(target: dict, incoming: dict) -> dict:
    """Merge aggregation trees by bucket key, richer bucket wins per key.
    Merged ``doc_count`` values are lower bounds, not exact distinct-alert
    counts; see :func:`_merge_bucket_lists`.
    """
    _merge_agg_nodes(target, incoming)
    return target


def _with_srcip_field(node, field_name: str):
    """Deep-copy an agg spec with every source-IP leaf swapped for ``field_name``.
    Non-srcip leaves (``rule.id``, ``data.url``) are untouched.
    """
    if isinstance(node, dict):
        if node.get("field") in _SRCIP_FIELD_PATHS:
            node = {**node, "field": field_name}
        return {key: _with_srcip_field(value, field_name) for key, value in node.items()}
    if isinstance(node, list):
        return [_with_srcip_field(value, field_name) for value in node]
    return node


async def _srcip_aggs_merged(query: dict, aggs: dict,
                             index_pattern: Optional[str] = None) -> tuple:
    """Run one aggregation tree per mapped source-IP path and merge the results.

    The spec's ``data.srcip`` leaf is swapped for each live path, so callers keep
    one agg spec. Returns ``(aggregations, live_paths, errors)``. Absent paths are
    never queried; when the probe finds none, the ``data.srcip`` fallback is used.
    Bucket ``doc_count`` values from the merge are lower bounds; callers that
    display a count must correct it with :func:`_correct_srcip_counts`.
    """
    candidates = [f"{path}.keyword" for path in _SRCIP_FIELD_PATHS]
    caps = await _wazuh_indexer_field_caps(_SRCIP_FIELD_PATHS + candidates, index_pattern)
    live = [name for path in _SRCIP_FIELD_PATHS for name in _agg_safe_paths(path, caps)]
    if not live:
        live = ["data.srcip"]
    raw_results = await asyncio.gather(*[
        _wazuh_indexer_post({"size": 0, "query": query,
                             "aggs": _with_srcip_field(aggs, name)}, index_pattern)
        for name in live])
    merged: dict = {}
    errors: list[str] = []
    for raw in raw_results:
        if isinstance(raw, dict) and "error" not in raw:
            _merge_agg_trees(merged, raw.get("aggregations") or {})
        else:
            errors.append(str((raw or {}).get("error", "unreadable response")))
    return merged, live, errors


def field_coverage(docs: list[dict], fields: list[str]) -> dict:
    """Count how many of ``docs`` populate each dotted ``fields`` path.
    A run with 0 coverage on every field means the deployment's decoders do not
    populate the fields the caller reads, so any rule built from them would be
    built from nothing.
    """
    coverage = {f: 0 for f in fields}
    for doc in docs:
        for f in fields:
            node: object = doc
            for part in f.split("."):
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, str) and node:
                coverage[f] += 1
    return coverage


async def _fetch_attacker_alert_docs(srcip: Optional[str], rule_id: Optional[str],
                                     since: str, limit: int,
                                     source_fields: Optional[list[str]] = None) -> list[dict]:
    """Harvest alert documents from the Wazuh Indexer for rule synthesis.
    ``_source`` is restricted to ``source_fields`` (attacker side by default) so
    victim PII in ``full_log`` never reaches a synthesizer's working set.
    """
    from mcp_server.wazuh.time_utils import _parse_time_window

    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        raise ConfigurationError(
            "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set for mode='alert'"
        )
    since_iso, until_iso = _parse_time_window(since, None)
    must: list[dict] = [{"range": {"@timestamp": {
        "gte": since_iso, "lt": until_iso, "format": "strict_date_optional_time"}}}]
    if srcip:
        # Same multi-field srcip coverage Engine A uses: Wazuh decoder field
        # paths differ per integration (nginx, Zimbra, Suricata, Sysmon).
        should = [{"match": {path: srcip}} for path in _SRCIP_FIELD_PATHS]
        should.append({"match_phrase": {"full_log": srcip}})
        must.append({"bool": {"should": should, "minimum_should_match": 1}})
    if rule_id:
        must.append({"match_phrase": {"rule.id": rule_id}})

    body = {
        "size": min(limit, 1000),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": source_fields or list(_ATTACKER_FIELDS) + list(_ATTACKER_CONTEXT_FIELDS),
        "query": {"bool": {"must": must}},
    }
    raw = await _wazuh_indexer_post(body)
    if isinstance(raw, dict) and "error" in raw:
        raise BlueTeamMCPError(f"Indexer query failed: {raw['error']}")
    return [h.get("_source", h) for h in raw.get("hits", {}).get("hits", [])]


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
            responses = raw["responses"]
            # Per-response granularity: each response may independently
            # succeed or fail. Return individual error dicts for failed
            # queries so callers can distinguish partial failures.
            out: list[dict] = []
            for i, r in enumerate(responses):
                if isinstance(r, dict) and "error" in r:
                    out.append({"error": f"_msearch query {i} failed: {r['error'].get('reason', str(r['error']))}"})
                elif isinstance(r, dict) and "status" in r and r.get("status", 200) >= 400:
                    out.append({"error": f"_msearch query {i} HTTP {r['status']}",
                               "detail": str(r.get("error", {}))[:300]})
                else:
                    out.append(r)
            while len(out) < len(bodies):
                out.append({"error": f"_msearch query {len(out)}: no response"})
            return out
        return [raw] if not isinstance(raw, list) else raw
    except Exception as e:
        logger.warning("_msearch failed (%s) - returning per-query error dicts", e)
        # Perquery fallback: each body gets its own error dict rather than
        # a single blanket error. This lets callers that can handle partial
        # failures (e.g. 3-Sum with one category down) continue working.
        return [{"error": f"_msearch failed: {e}"}] * len(bodies)


# Cursor pagination (base64-encoded JSON)
def _encode_cursor(data: dict) -> str:
    """Encode a dict as a base64 cursor string for pagination tokens."""
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> dict | None:
    """Decode a base64 cursor string back to a dict. Returns None on invalid input."""
    try:
        padded = cursor + "=" * (4 - len(cursor) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
