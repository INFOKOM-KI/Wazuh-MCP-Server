#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
RapidAPI capability lookups - three providers over a shared RapidAPI transport:
1. blueteam_ioc_search      - RapidAPI IOC Search (vendor verdicts, file + hostname telemetry)
2. blueteam_breach_check    - RapidAPI Breach Check (was this email in a known breach?)
3. blueteam_ip_intel_bulk   - IP Threat Intelligence (N IPs in one request)
4. blueteam_ioc_search_bulk - IOC Search over N IP, one metered request per IP, spaced
                              by BLUETEAM_RAPIDAPI_MIN_INTERVAL
All three accept the indicator (srcip / attacker IP / email / IP list) directly so the LLM
can feed values pulled from Wazuh alerts without any extra plumbing.

Apiverve IP Blacklist was removed on 2026-09-22: it was a fourth subscription on the same
account-wide pool, and ``blueteam_ioc_search`` already returns blacklist verdicts from ~89
engines. Quota model: the account carries ONE hard limit shared by every product above, so the
budget guard in ``rapidapi_quota`` is account-wide, not per product. It defaults to 0
(fail-closed) and is armed per incident window, because a daily report pass over 20 IPs
would otherwise spend a fifth of the month in one run. The bulk endpoint exists for the
same reason: N IPs cost one request instead of N.

Two response strategies, matched to the payload:
- breach_check / ip_intel_bulk use the generic `_dynamic_markdown` + `_envelope` pair, so an
  unknown or changing third-party schema degrades to a pretty-printed body instead of an
  empty report.
- ioc_search has a known, stable, ~70 KB schema, so it gets a provider-aware normalizer
  (`_normalize_ioc_search`) with three `detail_level`s. Its WHOIS block carries a natural
  person's name and postal address, which the shape-based redaction layers do not catch -
  `_strip_whois_pii` reduces it to technical registry fields at every detail level.

WHOIS posture differs between the two paths by design : ioc_search
allowlists technical registry fields, while ip_intel_bulk retains the provider's WHOIS
verbatim for abuse-escalation context. `_scrub_whois_deep` is the knob that closes it --
BLUETEAM_RAPIDAPI_RAW_WHOIS=false applies the same allowlist to the bulk body recursively.
"""
from __future__ import annotations
import hashlib, json, os, re
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import quote
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import (mcp, RAPIDAPI_KEY_ENV, RAPIDAPI_CACHE_TTL, RAPIDAPI_MONTHLY_CAP,
                        RAPIDAPI_BUDGET, RAPIDAPI_BUDGET_HOURS, RAPIDAPI_CACHE_PATH,
                        RAPIDAPI_RAW_WHOIS, RAPIDAPI_MIN_INTERVAL)
from mcp_server.core.http_client import (_api_call, _handle_api_error, ValidPublicIp,
                                         CircuitOpenError)
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.redact import _redact_alert_data
from mcp_server.threat_intel._cache import (cache_get, cache_set, get_limiter,
                                            PersistentJsonlCache)
from mcp_server.threat_intel.rapidapi_quota import RapidApiBudget

# RapidAPI host endpoints (The key is shared via RAPIDAPI_KEY).
_IOC_SEARCH_HOST = "ioc-search.p.rapidapi.com"
_BREACH_CHECK_HOST = "breachcheck-api.p.rapidapi.com"
_IP_INTEL_HOST = "ip-threat-intelligence.p.rapidapi.com"
_BULK_MAX_IPS = 50
# Lower than _BULK_MAX_IPS: that tool sends one request for the whole list, this one
# sends one request per IP at BLUETEAM_RAPIDAPI_MIN_INTERVAL spacing.
_IOC_BULK_MAX_IPS = 25

# Marks a response whose WHOIS block was returned unredacted. A reader of the rendered
# report cannot otherwise tell this tool's posture from blueteam_ioc_search's.
_WHOIS_RAW_NOTE = (
    "> WHOIS/registrant fields below are returned **unredacted** "
    "(BLUETEAM_RAPIDAPI_RAW_WHOIS). Third-party data: keep it inside the "
    "incident record and do not republish it.\n\n"
)

# Response cache and quota counter share one file, so a restart cannot hand back a
# budget the account was already billed for.
_STORE = PersistentJsonlCache(RAPIDAPI_CACHE_PATH) if RAPIDAPI_CACHE_PATH else None
_QUOTA = RapidApiBudget(RAPIDAPI_BUDGET, RAPIDAPI_BUDGET_HOURS, RAPIDAPI_MONTHLY_CAP, _STORE)

# One request in flight: max_concurrent=1 makes min_interval mean "time between
# request starts" (the shared AsyncRateLimiter reserves nothing under concurrency).
# BLUETEAM_RAPIDAPI_MIN_INTERVAL is the plan-level pacing knob (7.0 where required).
_limiter = get_limiter("rapidapi", max_concurrent=1, min_interval=RAPIDAPI_MIN_INTERVAL)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _rapidapi_headers(host: str) -> dict[str, str]:
    key = os.environ.get(RAPIDAPI_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"{RAPIDAPI_KEY_ENV} not set. Get a key at https://rapidapi.com (the account "
            f"limit is shared by IOC Search, Breach Check and IP Threat Intelligence)."
        )
    return {
        "x-rapidapi-key": key,
        "x-rapidapi-host": host,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0 (TangerangKota-CSIRT)",
    }


async def _rapidapi_request(method: str, host: str, path: str,
                            payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """One budgeted request. Callers must have checked the cache first: a cache hit
    costs no quota while a budget refusal costs the operator their incident window.
    ``max_retries=0``: a retry spends a second of 100 monthly requests on an upstream
    fault we did not cause, and buys nothing a single attempt would not.
    """
    # Credentials first: a missing key is a configuration fault that arming a budget
    # cannot fix, so reporting "budget closed" ahead of it points at the wrong problem.
    headers = _rapidapi_headers(host)
    _QUOTA.check()
    kwargs: dict[str, Any] = {"headers": headers, "max_retries": 0}
    if payload is not None:
        kwargs["json"] = payload
    try:
        resp = await _api_call(method, f"https://{host}{path}", client_name="rapidapi",
                               **kwargs)
    except CircuitOpenError:
        raise
    except Exception:
        _QUOTA.charge()
        raise
    _QUOTA.charge()
    return resp.json()


def _cache_key(host: str, path: str) -> str:
    return f"{host}{path}"


def _bulk_cache_key(host: str, path: str, ips: list[str]) -> str:
    """Sorted before hashing, so [a,b] and [b,a] share one entry instead of spending
    two of the month's requests on the same answer."""
    digest = hashlib.sha256(json.dumps(sorted(ips)).encode()).hexdigest()[:32]
    return f"{host}{path}#{digest}"


def _cache_lookup(key: str) -> Any | None:
    # `is not None`, never truthiness: PersistentJsonlCache defines __len__, so an
    # empty store is falsy and the persistent path would silently fall through to the
    # shared in-memory cache.
    return _STORE.get(key) if _STORE is not None else cache_get("rapidapi", key)


def _cache_store(key: str, value: Any, ttl: float) -> None:
    if _STORE is not None:
        _STORE.set(key, value, ttl)
    else:
        cache_set("rapidapi", key, value, ttl)


async def _rapidapi_get(host: str, path: str, ttl: int | None = None) -> dict[str, Any]:
    """GET a RapidAPI endpoint with TTL caching + rate limiting + budget guard.
    ``ttl`` defaults to ``RAPIDAPI_CACHE_TTL`` (default 7 days). All three products
    share one account-wide quota, so the TTL trades freshness for the month's
    allowance rather than for one product's headroom.
    Uses its own ``rapidapi`` HTTP client pool so the pool and circuit breaker are
    not shared with the other external threat-intel providers: a CrowdSec outage
    must not fail RapidAPI lookups fast with a circuit-open error.
    """
    if ttl is None:
        ttl = RAPIDAPI_CACHE_TTL
    cache_key = _cache_key(host, path)
    cached = _cache_lookup(cache_key)
    if cached is not None:
        return cached
    async with _limiter:
        data = await _rapidapi_request("get", host, path)
    _cache_store(cache_key, data, ttl)
    return data


async def _rapidapi_post(host: str, path: str, payload: dict[str, Any],
                         ttl: int | None = None) -> dict[str, Any]:
    """POST a RapidAPI endpoint, one budgeted request regardless of payload size.
    Same cache and budget path as GET so a bulk call cannot bypass either.
    """
    if ttl is None:
        ttl = RAPIDAPI_CACHE_TTL
    cache_key = _bulk_cache_key(host, path, payload.get("ips", []))
    cached = _cache_lookup(cache_key)
    if cached is not None:
        return cached
    async with _limiter:
        data = await _rapidapi_request("post", host, path, payload)
    _cache_store(cache_key, data, ttl)
    return data


def _dynamic_markdown(title: str, raw: dict[str, Any]) -> str:
    """Render a third-party JSON body without assuming a fixed schema.
    Surfaces common keys (status/message/data/result/matches/total/found) when present and
    falls back to a pretty-printed full body when the shape is unrecognized — so a schema
    change upstream never produces an empty or crashing report.
    """
    lines = [f"# {title}", ""]
    recognized = 0
    for key in ("status", "message", "total", "found", "result", "data", "matches"):
        if key in raw:
            recognized += 1
            value = raw[key]
            if isinstance(value, (dict, list)):
                lines.append(f"**{key}**")
                lines.append("```json")
                lines.append(json.dumps(value, indent=2, ensure_ascii=False))
                lines.append("```")
            else:
                lines.append(f"- **{key}**: {value}")
    if recognized == 0:
        lines.append("```json")
        lines.append(json.dumps(raw, indent=2, ensure_ascii=False))
        lines.append("```")
    return _truncate_if_needed("\n".join(lines))


def _envelope(query: str, source: str, raw: dict[str, Any], params=None) -> str:
    """Normalized JSON envelope: query + source + the dynamic raw body (redacted)."""
    return json.dumps(_redact_alert_data(
        {"query": query, "source": source, "result": raw}, params=params),
        indent=2, ensure_ascii=False)


def _sanitize_breach(raw: dict[str, Any]) -> dict[str, Any]:
    """Reduce a breach-check response to non-PII metadata only.
    Breach dumps can carry names, phone numbers, physical addresses, and leaked
    passwords none of which the shape-based redaction layers catch (they only
    match emails/domains/IPs). We surface only the verdict + breach metadata
    (name/date/data-classes already public) and drop raw PII.
    """
    out: dict[str, Any] = {}
    for k in ("found", "breached", "is_breached", "breach"):
        if k in raw and isinstance(raw[k], (bool, int)):
            out["breached"] = bool(raw[k])
            break
    breaches = raw.get("breaches") or raw.get("data") or raw.get("result")
    if isinstance(breaches, list):
        meta = []
        for b in breaches:
            if isinstance(b, dict):
                safe = {k: b[k] for k in ("name", "title", "breach_date", "date",
                                          "domain", "data_classes", "description")
                        if k in b}
                if safe:
                    meta.append(safe)
            elif isinstance(b, str):
                meta.append({"name": b})
        if meta:
            out["breaches"] = meta[:10]
    return out


# WHOIS allowlist
# Technical registry fields only. Allowlist, not denylist: a future registry field
# (e-mail, role, phone) is dropped by default instead of leaking until someone
# notices. Verified against a real RapidAPI IOC Search body, this drops
# person/address/phone/fax-no/nic-hdl/remarks and keeps netname TOR-EXIT, org-name ForPrivacyNET, route and origin.
# NOTE: `address` is dropped by field NAME, not by block. RIPE repeats the same
# street address in both the ORG block and the person block, so a block-level rule
# would have kept one copy.
_WHOIS_KEEP = frozenset({
    "inetnum", "netname", "descr", "country", "status", "source",
    "org", "organisation", "org-name", "org-type",
    "route", "origin", "created", "last-modified", "mnt-by",
    "admin-c", "tech-c", "abuse-c",  # registry role handles, needed for abuse escalation.
})
_WHOIS_MAX_KEYS = 40
_WHOIS_MAX_VALUE = 200
_WHOIS_MAX_VALUES_PER_KEY = 20


def _strip_whois_pii(whois: str) -> dict[str, list[str]]:
    """Reduce a WHOIS record to allowlisted technical fields.
    WHOIS is line-oriented ``key: value``; continuation lines repeat the key.
    Values are capped so a registrant cannot smuggle a payload through one field.
    """
    out: dict[str, list[str]] = {}
    for line in (whois or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        if key not in _WHOIS_KEEP:
            continue
        if key not in out and len(out) >= _WHOIS_MAX_KEYS:
            continue
        vals = out.setdefault(key, [])
        if len(vals) < _WHOIS_MAX_VALUES_PER_KEY:
            vals.append(value.strip()[:_WHOIS_MAX_VALUE])
    return out


def _scrub_whois_deep(value: Any) -> Any:
    """Apply the WHOIS allowlist to a body whose schema is unknown.

    ``_strip_whois_pii`` needs to know which field holds the record. The bulk endpoint's
    schema is unmapped, so the key is matched by name instead and the allowlist applied
    wherever it lands. This is the ``BLUETEAM_RAPIDAPI_RAW_WHOIS=false`` path.
    """
    if isinstance(value, dict):
        return {
            k: (_strip_whois_pii(v) if isinstance(v, str) else _scrub_whois_deep(v))
            if isinstance(k, str) and "whois" in k.lower() else _scrub_whois_deep(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub_whois_deep(v) for v in value]
    return value


# How much of each section each detail_level carries. raw also embeds the verbatim
# body, so its curated block matches forensic and there are two code paths, not three.
_IOC_LIMITS: dict[str, dict[str, int]] = {
    "summary":  {"files": 5,  "resolutions": 5,   "referrers": 0,  "vendors": 0},
    "forensic": {"files": 50, "resolutions": 100, "referrers": 10, "vendors": 30},
    "raw":      {"files": 50, "resolutions": 100, "referrers": 10, "vendors": 30},
}

# Refuse to re-indent a body past this. json.dumps(indent=2) roughly doubles the
# size, so a pathological response would otherwise build a multi-MB string first.
_RAW_BODY_MAX_CHARS = 2_000_000

_EPOCH_FIELDS = ("analysis_date", "modification_date")


def _epoch_iso(ts: Any) -> str | None:
    """Epoch seconds -> UTC ISO 8601, or None. An LLM cannot read 1789309660."""
    if not isinstance(ts, (int, float)) or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _ioc_band(ratio: float) -> str:
    """Presentation label for the vendor ratio.
    Never a scoring input, and never fed to blueteam_unified_threat_score - that
    tool has no RapidAPI provider, so the two can disagree and the prompt rule
    requires both to be reported rather than averaged.
    """
    if ratio >= 0.5:
        return "majority-malicious"
    if ratio >= 0.05:
        return "minority-malicious"
    if ratio > 0:
        return "single-vendor-flag"
    return "no-vendors-flag"


def _ioc_verdict(data: dict[str, Any], unknown: list[str]) -> dict[str, Any]:
    """Vendor counts from the provider's own rollup.
    A MISSING stats block yields {}, never zeros. Reporting
    ``malicious_engines: 0`` for a field we failed to map is a false negative in a
    SOC tool, and that failure mode is worse than an empty verdict.
    """
    stats = data.get("security_vendor_analysis_stats")
    if not isinstance(stats, dict):
        unknown.append("security_vendor_analysis_stats")
        return {}
    counts = {k: int(stats.get(k) or 0) for k in
              ("malicious", "suspicious", "harmless", "undetected")}
    total = sum(counts.values())
    out: dict[str, Any] = {f"{k}_engines": v for k, v in counts.items()}
    out["total_engines"] = total
    if isinstance(data.get("votes_result"), dict):
        out["votes"] = data["votes_result"]
    if "reputation" in data:
        out["provided_reputation"] = data["reputation"]
    if isinstance(data.get("tags"), list):
        out["tags"] = data["tags"]
    if total:
        out["malicious_ratio"] = round(counts["malicious"] / total, 3)
        out["band"] = _ioc_band(counts["malicious"] / total)
    return out


def _named_file_malicious(f: dict[str, Any]) -> int:
    stats = f.get("security_vendor_analysis_stats")
    return stats.get("malicious", 0) if isinstance(stats, dict) else 0


def _ioc_files(data: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """Communicating files, most-detected first. Zero-detection files are kept when
    fewer than ``limit`` qualify: a short list beats silently dropping evidence."""
    files = [f for f in (data.get("communicating_files") or []) if isinstance(f, dict)]
    if not limit or not files:
        return []
    out = []
    for f in sorted(files, key=_named_file_malicious, reverse=True)[:limit]:
        names = f.get("names") or []
        packers = f.get("packers")
        out.append({
            "sha256": f.get("sha256"),
            "name": names[0] if names else None,
            "type": f.get("type_description"),
            "size": f.get("size"),
            "malicious": _named_file_malicious(f),
            "packers": sorted(packers) if isinstance(packers, dict) else [],
        })
    return out


def _ioc_resolutions(data: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """Hostnames this IP resolved to, newest first. The DDNS cluster is usually the
    most actionable part of the payload."""
    rows = [r for r in (data.get("resolutions") or []) if isinstance(r, dict)]
    if not limit or not rows:
        return []
    rows.sort(key=lambda r: r.get("resolved_date") or 0, reverse=True)

    def _mal(r: dict[str, Any]) -> int:
        s = r.get("security_vendor_ip_address_analysis_stats")
        return s.get("malicious", 0) if isinstance(s, dict) else 0

    return [{"host_name": r.get("host_name"),
             "resolved_date": _epoch_iso(r.get("resolved_date")),
             "malicious_vendors": _mal(r)} for r in rows[:limit]]


def _ioc_flagged_vendors(data: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """Per-vendor tuples, flagged engines only. 89 clean 'harmless' rows carry no
    signal; the ones that fired are the evidence."""
    vendor_map = data.get("security_vendor_analysis")
    if not limit or not isinstance(vendor_map, dict):
        return []
    flagged = [v for v in vendor_map.values()
               if isinstance(v, dict) and v.get("category") in ("malicious", "suspicious")]
    flagged.sort(key=lambda v: (v.get("category") != "malicious", v.get("enginename") or ""))
    return [{"engine": v.get("enginename"), "result": v.get("result"),
             "category": v.get("category")} for v in flagged[:limit]]


def _ioc_raw_body(raw: dict[str, Any], whois_filtered: dict[str, list[str]]) -> dict[str, Any]:
    """Verbatim provider body with the whois field replaced by the allowlisted form.
    raw is a schema-debugging view, not a PII bypass the filter has no bypass.
    Copy-on-write at the two levels we touch instead of deepcopy: the body is
    ~70 KB and _rapidapi_get hands back a cached object, so mutating in place
    would poison the cache for every later caller. (That shared-mutable cache is
    pre-existing; this function avoids making it worse.)
    """
    body = dict(raw)
    data = raw.get("data")
    if isinstance(data, dict):
        data_copy = dict(data)
        if "whois" in data_copy:
            data_copy["whois"] = whois_filtered
        body["data"] = data_copy
    return body


def _normalize_ioc_search(ip: str, raw: dict[str, Any], level: str) -> dict[str, Any]:
    """Flatten a RapidAPI IOC Search body into one dict both renderers share."""
    limits = _IOC_LIMITS[level]
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict) or raw.get("is_success") is False:
        return {"ip": ip, "detail_level": level, "unknown_fields": ["data"],
                "error": (raw or {}).get("message") or "unrecognized provider response"}

    unknown: list[str] = []
    whois_raw = data.get("whois")
    whois = _strip_whois_pii(whois_raw if isinstance(whois_raw, str) else "")

    out: dict[str, Any] = {"ip": ip, "detail_level": level}
    verdict = _ioc_verdict(data, unknown)
    if verdict:
        out["verdict"] = verdict
    out["network"] = {k: data[k] for k in
                      ("asn", "as_owner", "network", "country", "continent",
                       "internet_registry") if k in data}
    out["timestamps"] = {k: _epoch_iso(data.get(k)) for k in _EPOCH_FIELDS}
    out["communicating_files"] = _ioc_files(data, limits["files"])
    out["resolutions"] = _ioc_resolutions(data, limits["resolutions"])

    referrals = data.get("referrerFiles")
    out["referrer_files_count"] = len(referrals) if isinstance(referrals, list) else 0
    if limits["referrers"] and isinstance(referrals, list):
        out["referrer_files"] = [
            r.get("meaningful_name") or (r.get("names") or [None])[0]
            for r in referrals[:limits["referrers"]] if isinstance(r, dict)
        ]
    if limits["vendors"]:
        out["flagged_vendors"] = _ioc_flagged_vendors(data, limits["vendors"])

    out["whois"] = whois or {"note": "no allowlisted WHOIS fields present"}
    if level == "raw":
        out["raw"] = _ioc_raw_body(raw, whois)
    if unknown:
        out["unknown_fields"] = unknown
    return out


def _render_ioc_search(summary: dict[str, Any]) -> str:
    """Markdown view of the normalizer output. Line 3 answers 'is this IP bad'
    without reading further; before this the answer sat ~70 KB down the page."""
    ip = summary["ip"]
    if "error" in summary:
        return f"# IOC Search - {ip}\n\n**Could not read provider response**: {summary['error']}"

    v = summary.get("verdict") or {}
    lines = [f"# IOC Search - {ip}", ""]
    if v:
        head = (f"**Verdict**: {v.get('malicious_engines', '?')}/"
                f"{v.get('total_engines', '?')} engines malicious")
        if "malicious_ratio" in v:
            head += f" ({v['malicious_ratio'] * 100:.1f}%) | band: {v.get('band')}"
        if v.get("tags"):
            head += f" | tags: {', '.join(v['tags'])}"
        if "provided_reputation" in v:
            head += f" | provider reputation: {v['provided_reputation']}"
        lines.append(head)
    else:
        lines.append("**Verdict**: unknown - provider returned no vendor statistics")

    n = summary.get("network") or {}
    if n:
        lines.append(f"**Network**: AS{n.get('asn', '?')} {n.get('as_owner', '')} "
                     f"({n.get('country', '?')}, {n.get('continent', '?')}) | "
                     f"{n.get('network', '?')} | {n.get('internet_registry', '?')}")

    w = summary.get("whois") or {}
    if w and "note" not in w:
        lines.append("**WHOIS**: " + " | ".join(
            f"{k} {' / '.join(vals)}" for k, vals in w.items() if isinstance(vals, list)))

    files = summary.get("communicating_files") or []
    if files:
        lines += ["", f"## Communicating files ({len(files)})", "",
                  "| sha256 | name | type | malicious | packers |",
                  "|---|---|---|---|---|"]
        for f in files:
            lines.append(f"| `{(f['sha256'] or '')[:16]}` | {f['name'] or '-'} | "
                         f"{f['type'] or '-'} | {f['malicious']} | "
                         f"{', '.join(f['packers']) or '-'} |")

    res = summary.get("resolutions") or []
    if res:
        lines += ["", f"## Resolutions ({len(res)})", "",
                  "| host | resolved | malicious vendors |", "|---|---|---|"]
        lines += [f"| `{r['host_name'] or '-'}` | {r['resolved_date'] or '-'} | "
                  f"{r['malicious_vendors']} |" for r in res]

    vendors = summary.get("flagged_vendors") or []
    if vendors:
        lines += ["", f"## Flagged vendors ({len(vendors)})", ""]
        lines += [f"- **{x['engine']}**: {x['result']} ({x['category']})" for x in vendors]

    unknown = summary.get("unknown_fields") or []
    if unknown:
        lines += ["", f"> Missing provider fields: {', '.join(unknown)}"]
    return "\n".join(lines)


class _IpInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45,
                              description="Source IP (attacker srcip) from a Wazuh alert.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


class IocSearchInput(_IpInput):
    """Input for blueteam_ioc_search: shared IP input plus response framing."""

    detail_level: Literal["summary", "forensic", "raw"] = Field(
        default="summary",
        description=(
            "summary: verdict-first triage view (vendor ratio, tags, ASN, top 5 files). "
            "forensic: all resolutions and files, plus per-vendor verdicts. "
            "raw: verbatim provider body WHOIS is still filtered, always JSON."
        ),
    )


class IocSearchBulkInput(BaseModel):
    """Input for blueteam_ioc_search_bulk: N public IPs, one request each."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ips: list[ValidPublicIp] = Field(
        ..., min_length=1, max_length=_IOC_BULK_MAX_IPS,
        description=(f"Public source IPs to look up one at a time (1-{_IOC_BULK_MAX_IPS}). "
                     "Each IP costs one metered RapidAPI request."),
    )
    detail_level: Literal["summary", "forensic"] = Field(
        default="summary",
        description=("summary: verdict-first triage per IP. "
                     "forensic: all resolutions and files per IP. "
                     "No raw level: N verbatim bodies would overflow the context."),
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")


class BreachCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    email: str = Field(..., min_length=6, max_length=254,
                       description="Email address to check (e.g. an official 'user_x@mail.go.id' account from Wazuh).")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError(f"Invalid email address: '{v}'")
        return v


@mcp.tool(name="blueteam_ioc_search",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": True})
async def blueteam_ioc_search(params: IocSearchInput) -> str:
    """Search IOC databases for a source IP (RapidAPI IOC Search).
    One RapidAPI product that aggregates per-vendor verdicts, file telemetry,
    hostname resolutions and WHOIS for a single IP. Feed the `srcip` from a
    Wazuh alert directly.

    Args:
        params.ip: public source IP.
        params.detail_level: `summary` (verdict-first triage), `forensic` (all
            resolutions and files, per-vendor verdicts), `raw` (verbatim
            provider body; WHOIS still filtered; always JSON).
        params.response_format: `markdown` (default) or `json`. Ignored when
            `detail_level="raw"`.

    **Required Permissions**: `RAPIDAPI_KEY` subscribed to "IOC Search" on
    RapidAPI. A 403 means the key is valid but that product is not subscribed,
    it is a separate subscription from the other RapidAPI tools.

    **Rate limits**: its own RapidAPI product quota. Requests are serialized at
    `BLUETEAM_RAPIDAPI_MIN_INTERVAL` (default 0.25s; 7.0 where the plan requires
    it) and successful results are cached for `RAPIDAPI_CACHE_TTL` (default 7
    days), so re-querying the same IP inside the window is free.

    **Worked Examples**
    1. ``blueteam_ioc_search(ip="185.220.101.49")`` triage a Tor exit.
    2. ``blueteam_ioc_search(ip="185.220.101.49", detail_level="forensic")`` every resolution and file
    3. ``blueteam_ioc_search(ip="185.220.101.49", detail_level="raw")`` verbatim body, WHOIS filtered
    4. ``blueteam_ioc_search(ip="103.94.133.20", detail_level="summary", response_format="json")``
    """
    _audit_log("blueteam_ioc_search", {"ip": params.ip, "detail_level": params.detail_level})
    try:
        raw = await _rapidapi_get(_IOC_SEARCH_HOST, f"/rapid/v1/ioc/search/ip?query={quote(params.ip)}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError, ValueError) as e:
        _handle_api_error(e, context="blueteam_ioc_search")

    summary = _normalize_ioc_search(params.ip, raw, params.detail_level)

    if params.detail_level == "raw":
        compact = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        if len(compact) > _RAW_BODY_MAX_CHARS:
            # Raise, do not return the text: an error string reaches the MCP client
            # as isError=false, which reads as a successful call.
            raise ThreatIntelError(
                f"[blueteam_ioc_search] provider body is {len(compact)} chars, over the "
                f"{_RAW_BODY_MAX_CHARS} raw cap. Use detail_level='forensic'."
            )
        return _truncate_if_needed(
            json.dumps(_redact_alert_data(summary), indent=2, ensure_ascii=False))

    if params.response_format == "json":
        return _truncate_if_needed(
            json.dumps(_redact_alert_data(summary), indent=2, ensure_ascii=False))
    return _truncate_if_needed(_redact_alert_data(_render_ioc_search(summary)))


def _render_ioc_bulk(results: list[dict[str, Any]]) -> str:
    """One report per IP, separated so a single failing IP never hides the rest."""
    state = _QUOTA.state()
    blocks = [f"# IOC Search (bulk) - {len(results)} IP(s)", "",
              f"> One metered request per IP, {RAPIDAPI_MIN_INTERVAL:g}s apart.",
              f"> RapidAPI budget: {state['remaining']}/{state['allowance']} remaining "
              f"this month."]
    for r in results:
        if "error" in r:
            blocks.append(f"# IOC Search - {r['ip']}\n\n**Lookup failed**: {r['error']}")
        elif "skipped" in r:
            blocks.append(f"# IOC Search - {r['ip']}\n\n**Skipped**: {r['skipped']}")
        else:
            blocks.append(_render_ioc_search(r))
    return "\n\n---\n\n".join(blocks)


@mcp.tool(name="blueteam_ioc_search_bulk",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": True})
async def blueteam_ioc_search_bulk(params: IocSearchBulkInput) -> str:
    """Search IOC databases for many source IPs, one metered request per IP.
    Use this instead of calling ``blueteam_ioc_search`` in a loop when you hold a
    list of srcips: the requests run sequentially inside one tool call and obey
    the configured spacing. Every uncached IP costs one request from the shared
    account pool, so prefer ``blueteam_ip_intel_bulk`` when that product is
    subscribed (N IPs in one request).

    Args:
        params.ips: public source IPs. Private, loopback, link-local and CGNAT
            addresses are rejected before any request is sent.
        params.detail_level: `summary` (default) or `forensic` per IP.
        params.response_format: `markdown` (default) or `json`.

    **Required Permissions**: `RAPIDAPI_KEY` subscribed to "IOC Search" on
    RapidAPI. A 403 means the key is valid but that product is not subscribed.

    **Rate limits**: one request per uncached IP, at least
    `BLUETEAM_RAPIDAPI_MIN_INTERVAL` apart (default 0.25s; set 7.0 where the
    plan requires it), drawn from the shared `BLUETEAM_RAPIDAPI_MONTHLY_CAP`
    (default 100/month). A cached IP is answered without a request or a delay.

    **Worked Examples**
    1. ``blueteam_ioc_search_bulk(ips=["185.220.101.49", "103.46.186.148"])``
    2. ``blueteam_ioc_search_bulk(ips=["185.220.101.49"], detail_level="forensic")``
    3. ``blueteam_ioc_search_bulk(ips=[...], response_format="json")``
    """
    unique_ips = sorted(dict.fromkeys(params.ips))
    _audit_log("blueteam_ioc_search_bulk", {"count": len(unique_ips),
                                            "detail_level": params.detail_level})
    results: list[dict[str, Any]] = []
    for ip in unique_ips:
        try:
            raw = await _rapidapi_get(
                _IOC_SEARCH_HOST, f"/rapid/v1/ioc/search/ip?query={quote(ip)}")
        except (RuntimeError, ThreatIntelError, CircuitOpenError) as e:
            # Key, budget and circuit state are process-wide: every later IP would
            # fail identically, so stop instead of repeating the same error N times.
            results.append({"ip": ip, "error": str(e)[:300]})
            results += [{"ip": left, "skipped": "not attempted after a process-wide failure"}
                        for left in unique_ips[len(results):]]
            break
        except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as e:
            results.append({"ip": ip, "error": str(e)[:300]})
            continue
        results.append(_normalize_ioc_search(ip, raw, params.detail_level))

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(_redact_alert_data(
            {"query": unique_ips, "source": "rapidapi_ioc_search_bulk",
             "detail_level": params.detail_level, "results": results,
             "budget": _QUOTA.state()}), indent=2, ensure_ascii=False))
    return _truncate_if_needed(_redact_alert_data(_render_ioc_bulk(results)))


@mcp.tool(name="blueteam_breach_check",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": True})
async def blueteam_breach_check(params: BreachCheckInput) -> str:
    """Check whether an email address appeared in a known data breach (RapidAPI Breach Check).
    Feed an official email (`email dinas`, e.g. ``user_x@tangerangkota.go.id``) from a Wazuh
    compromised-email alert. Returns the breach status for the address.
    Requires `RAPIDAPI_KEY` (subscribe to "Breach Check" on RapidAPI).

    **Worked Examples**
    1. ``blueteam_breach_check(email="csirt@tangerangkota.go.id")``
    2. ``blueteam_breach_check(email="csirt@tangerangkota.go.id", response_format="json")``
    """
    _audit_log("blueteam_breach_check", {"email": params.email})
    try:
        raw = await _rapidapi_get(_BREACH_CHECK_HOST, f"/email-check?email={quote(params.email)}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError, ValueError) as e:
        _handle_api_error(e, context="blueteam_breach_check")
    if params.response_format == "json":
        return _envelope(params.email, "rapidapi_breach_check", _sanitize_breach(raw), params=params)
    return _redact_alert_data(_dynamic_markdown(f"Breach Check - {params.email}", _sanitize_breach(raw)), params=params)


class BulkIpIntelInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ips: list[ValidPublicIp] = Field(
        ..., min_length=1, max_length=_BULK_MAX_IPS,
        description=(f"Public source IPs to look up in one request (1-{_BULK_MAX_IPS}). "
                     "Feed the attacker srcips from a Wazuh alert or a 3-Sum result."),
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(name="blueteam_ip_intel_bulk",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": True})
async def blueteam_ip_intel_bulk(params: BulkIpIntelInput) -> str:
    """Look up threat intelligence for many IPs in a single metered request.

    The account carries one shared RapidAPI budget, so this is the preferred path
    whenever more than one IP needs a verdict: 20 IPs cost one request instead of 20.
    Duplicates are collapsed before the call, and the result is cached under a
    sorted-IP hash so re-running the same set inside the TTL window is free.

    Args:
        params.ips: public source IPs. Private, loopback, link-local and CGNAT
            addresses are rejected before any request is sent.
        params.response_format: `markdown` (default) or `json`.

    **Required Permissions**: `RAPIDAPI_KEY` subscribed to "IP Threat Intelligence"
    on RapidAPI. A 403 means the key is valid but that product is not subscribed;
    it is a separate subscription from the other three RapidAPI tools.

    **Rate limits**: one request per call, drawn from the shared account-wide pool
    (`BLUETEAM_RAPIDAPI_MONTHLY_CAP`, default 100/month). The budget is closed
    unless the operator armed it (`BLUETEAM_RAPIDAPI_BUDGET`), so a scheduled
    report run gets a refusal, not a verdict. Results cached for
    `RAPIDAPI_CACHE_TTL` (default 7 days).

    **Worked Examples**
    1. ``blueteam_ip_intel_bulk(ips=["185.220.101.1", "103.46.186.148"])``
    2. ``blueteam_ip_intel_bulk(ips=["171.25.193.25"], response_format="json")``
    3. ``blueteam_ip_intel_bulk(ips=[...])`` with the srcip list from
       ``three_sum_correlation`` to triage a whole incident in one request.
    """
    unique = sorted(dict.fromkeys(params.ips))
    # The posture is recorded per call. Never the values: the audit log stays count-only.
    _audit_log("blueteam_ip_intel_bulk", {"count": len(unique),
                                          "whois": "raw" if RAPIDAPI_RAW_WHOIS else "allowlisted"})
    try:
        raw = await _rapidapi_post(_IP_INTEL_HOST, "/v1/ip-intel/bulk", {"ips": unique})
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError, ValueError) as e:
        _handle_api_error(e, context="blueteam_ip_intel_bulk")

    body = raw if RAPIDAPI_RAW_WHOIS else _scrub_whois_deep(raw)
    if params.response_format == "json":
        return _envelope(", ".join(unique), "rapidapi_ip_intel_bulk", body, params=params)
    rendered = _dynamic_markdown(f"IP Threat Intel (bulk) - {len(unique)} IP(s)", body)
    if RAPIDAPI_RAW_WHOIS and "whois" in rendered.lower():
        rendered = _WHOIS_RAW_NOTE + rendered
    return _redact_alert_data(rendered, params=params)
