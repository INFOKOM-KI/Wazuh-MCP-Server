#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Geo distribution tool country/city attack ranking and source concentration
"""
import json
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD, _BYPASS_REDACTION_DESC
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
from mcp_server.wazuh.time_utils import _parse_time_window
from mcp_server.tools.wazuh_scanning import _centroid_coord

from mcp_server.core.tool_decorator import blueteam_tool

class GeoDistributionInput(BaseModel):
    """Input model for blueteam_wazuh_geo_distribution."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    since: Optional[str] = Field(default="24h", max_length=30,
        description="Start of time window.")
    until: Optional[str] = Field(default=None, max_length=30,
        description="End of time window. Defaults to now.")
    top_n: int = Field(default=15, ge=3, le=50,
        description="Number of top countries/cities to return.")
    granularity: Literal["country", "city"] = Field(
        default="country", description="Aggregate by country_name or city_name.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")
    bypass_redaction: bool = Field(
        default=False, description=_BYPASS_REDACTION_DESC)


@blueteam_tool(
    name="blueteam_wazuh_geo_distribution",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_geo_distribution(params: GeoDistributionInput) -> str:
    """Show top attacking countries by alert volume using Wazuh GeoIP data.

    Pure aggregation - zero documents fetched (size: 0). Returns a country
    ranking with alert counts and unique IP counts. Uses Wazuh Indexer's
    built-in GeoLocation.country_name field.

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Last 24h*:
       ``blueteam_wazuh_geo_distribution()``

    2. *Last 7 days, top 25*:
       ``blueteam_wazuh_geo_distribution(since="7d", top_n=25)``

    3. *Specific date range*:
       ``blueteam_wazuh_geo_distribution(since="2026-07-17T00:00:00Z", until="2026-07-18T00:00:00Z")``
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."})

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    is_city = params.granularity == "city"
    geo_field = "GeoLocation.city_name" if is_city else "GeoLocation.country_name"
    geo_label = "City" if is_city else "Country"

    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                       "format": "strict_date_optional_time"}}},
            {"exists": {"field": geo_field}},
        ]}},
        "aggs": {
            "by_geo": {
                "terms": {"field": geo_field, "size": params.top_n,
                          "order": {"_count": "desc"}},
                "aggs": {
                    # Single-path cardinality: an exact cross-path count needs terms scans,
                    # which would change this per-geo metric's cost.
                    "unique_ips": {
                        "cardinality": {"field": "data.srcip",
                                        "precision_threshold": 40000},
                    },
                    "top_rules": {
                        "terms": {"field": "rule.id", "size": 3},
                    },
                },
            },
            "total_with_geo": {"value_count": {"field": geo_field}},
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return raw

    aggs = raw.get("aggregations", {})
    total_with_geo = aggs.get("total_with_geo", {}).get("value", 0)
    buckets = aggs.get("by_geo", {}).get("buckets", [])

    if params.response_format == "json":
        return json.dumps({
            "window": {"since": since_iso, "until": until_iso},
            "granularity": params.granularity,
            "total_alerts_with_geo": total_with_geo,
            geo_label.lower() + "s": [
                {"name": b["key"], "alerts": b["doc_count"],
                 "unique_ips": b.get("unique_ips", {}).get("value", 0),
                 "top_rules": [r["key"] for r in b.get("top_rules", {}).get("buckets", [])]}
                for b in buckets
            ],
        }, indent=2, ensure_ascii=False)

    lines = [
        f"# {'🏙️' if is_city else '🌍'} Attack Geography — `{since_iso}` → `{until_iso}`",
        "",
        f"**Granularity**: {geo_label}",
        f"**Alerts with GeoIP data**: {total_with_geo:,}",
        "",
        f"| {geo_label} | Alerts | Unique IPs | Top Rules |",
        "|---------|--------|------------|-----------|",
    ]
    for b in buckets:
        ips = b.get("unique_ips", {}).get("value", 0)
        rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:2]) or "-"
        lines.append(f"| {b['key']} | {b['doc_count']:,} | {ips:,} | {rules} |")

    if not buckets:
        lines.append("| *(no data)* | - | - | - |")
        lines.append("")
        lines.append("> ⚠️ GeoIP enrichment may not be enabled on this Wazuh Indexer. "
                     "Check that the GeoIP processor is configured.")

    return "\n".join(lines)


_UNRESOLVED = "(not resolved)"


class GeoConcentrationInput(BaseModel):
    """Input model for blueteam_wazuh_geo_concentration."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    since: Optional[str] = Field(default="24h", max_length=30,
        description="Start of time window.")
    until: Optional[str] = Field(default=None, max_length=30,
        description="End of time window. Defaults to now.")
    granularity: Literal["country", "city"] = Field(
        default="city", description="Rank countries or cities.")
    top_n: int = Field(default=15, ge=3, le=50,
        description="Rows returned after ranking by alerts per source IP.")
    min_alerts: int = Field(default=10, ge=1, le=100000,
        description="Buckets below this alert count are excluded before ranking.")
    max_buckets: int = Field(default=300, ge=50, le=1000,
        description="Candidate buckets fetched before ranking. Raise it when the "
                    "response reports truncated=true.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")
    bypass_redaction: bool = Field(
        default=False, description=_BYPASS_REDACTION_DESC)


def _concentration_rows(buckets: list[dict], min_alerts: int) -> list[dict]:
    """Fold aggregation buckets into rows carrying alerts per source IP.
    ``alerts_per_ip`` is ``None`` when the bucket resolved no source IP, which is
    an unmeasured ratio rather than a zero one.
    """
    rows: list[dict] = []
    for b in buckets:
        alerts = int(b.get("doc_count", 0))
        if alerts < min_alerts:
            continue
        ips = int((b.get("unique_ips") or {}).get("value", 0) or 0)
        rows.append({
            "geo": b.get("key"),
            "alerts": alerts,
            "unique_ips": ips,
            "alerts_per_ip": round(alerts / ips, 2) if ips else None,
            "max_rule_level": (b.get("max_level") or {}).get("value"),
            "top_rule": next((r.get("key") for r in
                              (b.get("top_rule") or {}).get("buckets", [])), None),
            "lat": _centroid_coord(b, "lat"),
            "lon": _centroid_coord(b, "lon"),
        })
    return rows


@blueteam_tool(
    name="blueteam_wazuh_geo_concentration",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_geo_concentration(params: GeoConcentrationInput) -> str:
    """Rank countries or cities by alerts per source IP (source concentration).
    A high alerts-per-IP ratio is one host or a small hosting cluster behind the
    geolocation; a low ratio is diffuse scanning. Built on GeoLocation.country_name,
    city_name and location. This index carries no ASN field, so concentration
    stands in for naming an infrastructure family.
    Concentration is a priority signal, not a verdict: one noisy sensor or one
    misconfigured internal host concentrates identically, and country/city are
    GeoIP estimates that proxy and VPN egress distorts. Ranked over the
    ``max_buckets`` highest-volume buckets, not every bucket, so a low-volume
    high-ratio location can fall outside the candidate set ``truncated=true``
    reports that the fetch hit its ceiling.

    **Required Permissions**: Wazuh Indexer read access.

    **Rate limits**: one aggregation request per call; zero documents fetched.

    **Worked Examples**

    1. *Last 24h, cities*:
       ``blueteam_wazuh_geo_concentration()``

    2. *Last 7 days, countries, 25 rows*:
       ``blueteam_wazuh_geo_concentration(since="7d", granularity="country", top_n=25)``

    3. *Keep thin buckets so nothing is hidden by the floor*:
       ``blueteam_wazuh_geo_concentration(min_alerts=1, response_format="json")``

    4. *Widen the candidate set after a truncated result*:
       ``blueteam_wazuh_geo_concentration(max_buckets=1000, top_n=50)``
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."})

    since_iso, until_iso = _parse_time_window(params.since, params.until)
    is_city = params.granularity == "city"
    geo_field = "GeoLocation.city_name" if is_city else "GeoLocation.country_name"
    geo_label = "City" if is_city else "Country"

    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                       "format": "strict_date_optional_time"}}},
        ]}},
        "aggs": {
            "by_geo": {
                "terms": {"field": geo_field, "size": params.max_buckets,
                          "missing": _UNRESOLVED, "order": {"_count": "desc"}},
                "aggs": {
                    # Single-path cardinality: an exact cross-path count needs terms scans,
                    # which would change this per-geo metric's cost.
                    "unique_ips": {"cardinality": {"field": "data.srcip",
                                                    "precision_threshold": 40000}},
                    "centroid": {"geo_centroid": {"field": "GeoLocation.location"}},
                    "max_level": {"max": {"field": "rule.level"}},
                    "top_rule": {"terms": {"field": "rule.id", "size": 1}},
                },
            },
            "total_with_geo": {"value_count": {"field": geo_field}},
            "total_with_country": {"value_count": {"field": "GeoLocation.country_name"}},
            "total_alerts": {"value_count": {"field": "@timestamp"}},
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return raw

    aggs = raw.get("aggregations", {})
    buckets = (aggs.get("by_geo") or {}).get("buckets", [])
    truncated = len(buckets) >= params.max_buckets
    rows = _concentration_rows(buckets, params.min_alerts)
    rows.sort(key=lambda r: (r["alerts_per_ip"] is None, -(r["alerts_per_ip"] or 0)))
    rows = rows[:params.top_n]
    resolved = (aggs.get("total_with_geo") or {}).get("value", 0)
    total = (aggs.get("total_alerts") or {}).get("value", 0)
    unresolved = next((b["doc_count"] for b in buckets
                       if b.get("key") == _UNRESOLVED), 0)

    if params.response_format == "json":
        return json.dumps({
            "window": {"since": since_iso, "until": until_iso},
            "granularity": params.granularity,
            "min_alerts": params.min_alerts,
            "candidates_fetched": len(buckets), "max_buckets": params.max_buckets,
            "truncated": truncated,
            "coverage": {"alerts": total, "fields_resolved": resolved,
                         "unresolved": unresolved},
            "ranking": rows,
        }, indent=2, ensure_ascii=False)

    lines = [
        f"# 🧭 Source Concentration - `{since_iso}` -> `{until_iso}`", "",
        f"**Granularity**: {geo_label} | **Min alerts**: {params.min_alerts:,} | "
        f"**Candidates fetched**: {len(buckets):,}" + (" (truncated)" if truncated else ""),
        f"**GeoIP coverage**: {resolved:,} of {total:,} alerts resolved "
        f"({unresolved:,} unresolved)",
        "",
        f"| {geo_label} | Alerts | Source IPs | Alerts/IP | Max Lvl | Top Rule |",
        "|---------|--------|-----------|-----------|---------|----------|",
    ]
    for r in rows:
        ratio = "unmeasured" if r["alerts_per_ip"] is None else f"{r['alerts_per_ip']:.2f}"
        level = "-" if r["max_rule_level"] is None else f"{r['max_rule_level']:.0f}"
        lines.append(f"| {r['geo']} | {r['alerts']:,} | {r['unique_ips']:,} | "
                     f"{ratio} | {level} | `{r['top_rule'] or '-'}` |")
    if not rows:
        lines.append(f"| *(no bucket reached {params.min_alerts} alerts)* | - | - | - | - | - |")
    lines.extend(["",
                  "> Concentration is a priority signal, not a verdict. A single "
                  "noisy sensor concentrates the same way a hostile host does, and "
                  "the country and city are GeoIP estimates."])
    if truncated:
        lines.append(
            f"> Ranking covered only the {params.max_buckets:,} highest-volume "
            "buckets. A low-volume, high-ratio location may be absent; raise "
            "`max_buckets` and re-run before treating this as complete.")
    if unresolved:
        lines.append(
            f"> {unresolved:,} alerts resolved no {geo_label.lower()}. They are "
            f"bucketed as `{_UNRESOLVED}` rather than dropped.")
    return "\n".join(lines)
