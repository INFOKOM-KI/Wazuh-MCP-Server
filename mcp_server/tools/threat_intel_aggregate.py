#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Unified threat intelligence aggregator.

Queries all available threat-intel providers concurrently for a single IOC
(IP / domain / hash) and returns a normalized, aggregated verdict.

Provider coverage:
- CrowdSec CTI       (IP only)             - reputation, behaviors, MITRE
- ThreatFox           (IP/domain/hash)     - malware families, confidence
- AlienVault OTX      (IP/domain/hash/url) - pulses, adversaries, industries
- GreyNoise           (IP only)            - scanner vs business service
- AbuseIPDB           (IP only)            - abuse confidence score
- VirusTotal          (hash/domain/IP)     - detection ratio

Normalizes each into TIProviderResult, then aggregates into TIQueryOutput.
"""
from __future__ import annotations
import json, asyncio, os, logging
from typing import Optional, Literal, get_args
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp.server.fastmcp import Context
from mcp_server import (mcp, CROWDSEC_API_KEY_ENV, OTX_API_KEY_ENV,
                        THREATFOX_API_KEY_ENV, VIRUSTOTAL_API_KEY)
from mcp_server.core.http_client import (_api_call, _classify_api_error,
                                         normalize_public_ip)
from mcp_server.threat_intel.virustotal import (issue_consent, normalize_domain,
                                                normalize_hash)
from mcp_server.threat_intel.virustotal_consent import (consent_message,
                                                        request_ioc_sharing)
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.threat_intel.greynoise import _NO_DATA_MESSAGE, _greynoise_lookup
from mcp_server.threat_intel.otx import (_classify_indicator, _normalize_adversary,
                                         _normalize_str_list)

logger = logging.getLogger("blue_team_mcp.threat_intel_aggregate")

# Risk level ordering for aggregation
_RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, None: 0}


ErrorKind = Literal[
    "rate_limited", "cooldown", "not_configured", "unsupported_type",
    "upstream_error", "timeout", "auth_error", "not_found", "bad_request",
    "circuit_open", "plan_limit", "budget_closed", "not_armed", "arm_expired",
    "consent_required",
    "budget_exhausted", "daily_exhausted", "storage_unavailable",
    "state_corrupt", "state_missing", "policy_mismatch", "state_exists",
    "config_invalid",
]
_ERROR_KINDS = frozenset(get_args(ErrorKind))
VT_HOST_REFUSAL = (
    "host approval was not granted; the client must support Context.elicit on "
    "protocol 2025-06-18 or 2025-11-25, and the operator must approve the prompt")
_LOCAL_REFUSAL_KINDS = frozenset({
    "not_configured", "unsupported_type", "bad_request", "circuit_open",
    "plan_limit", "budget_closed", "not_armed", "arm_expired", "consent_required",
    "budget_exhausted",
    "daily_exhausted", "storage_unavailable", "state_corrupt", "state_missing",
    "policy_mismatch", "state_exists", "config_invalid", "cooldown",
})


class TIProviderResult(BaseModel):
    """Normalized result from a single threat-intel provider."""
    provider: str = ""
    indicator: str = ""
    indicator_type: str = "unknown"
    risk_level: Optional[str] = None
    reputation_score: Optional[int] = Field(
        default=None,
        description=("Provider-normalized 0-100 score. For VirusTotal this is "
                     "the engine detection percentage; community reputation is "
                     "reported separately in detail.community_reputation."))
    is_malicious: Optional[bool] = None
    tags: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    adversaries: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    pulses: list[dict] = Field(default_factory=list)
    detail: dict = Field(default_factory=dict)
    error: Optional[str] = None
    error_kind: Optional[ErrorKind] = None


class TIQueryOutput(BaseModel):
    """Aggregated multi-provider result.

    ``aggregated_risk_level`` is the highest risk any single provider reported,
    not a vote. The verdict tally below it exists so a reader can tell
    "one provider said high" from "the providers agree", and so a provider that
    failed, was skipped, or returned no determinate answer is never counted clean.
    """
    indicator: str
    indicator_type: str
    results: list[TIProviderResult] = Field(default_factory=list)
    aggregated_risk_level: Optional[str] = None
    consensus_malicious: int = 0
    providers_total: int = 0
    providers_ok: int = 0
    errors: list[str] = Field(default_factory=list)
    # Expanded accounting; additive, so existing JSON consumers keep working.
    providers_configured: int = 0
    providers_queried: int = 0
    verdicts_malicious: int = 0
    verdicts_clean: int = 0
    verdicts_inconclusive: int = 0
    providers_failed: int = 0
    providers_skipped: int = 0
    verdict_basis: str = "no_provider_answered"


class ThreatIntelAggregateInput(BaseModel):
    """Input model for blueteam_threat_intel_aggregate."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicator: str = Field(
        ..., min_length=3, max_length=256,
        description="IOC to analyze: IP address, domain, or file hash (MD5/SHA1/SHA256).",
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    acknowledge_ioc_sharing: bool = Field(
        default=False,
        description=("Request host confirmation before querying VirusTotal. This flag is a "
                     "request to prompt, not proof of human consent; the MCP host must return "
                     "an explicit approval. Default false."),
    )

    @field_validator("indicator")
    @classmethod
    def validate_indicator(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("indicator must not be empty")
        ind_type = _classify_indicator(v)
        if not ind_type:
            raise ValueError(f"Unrecognized IOC type: '{v}'. Supported: IP, domain, hostname, URL, MD5/SHA1/SHA256.")
        if ind_type in ("IPv4", "IPv6"):
            return normalize_public_ip(v)
        return v


# Provider adapters (each returns TIProviderResult, never raises)
async def _crowdsec_provider(indicator: str, ind_type: str) -> TIProviderResult:
    configured = bool(os.environ.get(CROWDSEC_API_KEY_ENV))
    if ind_type != "IPv4" or not configured:
        return TIProviderResult(provider="crowdsec", indicator=indicator,
                                indicator_type=ind_type,
                                error="not configured" if not configured else "unsupported type",
                                error_kind="not_configured" if not configured else "unsupported_type")
    try:
        from mcp_server.threat_intel.crowdsec import _crowdsec_request
        r = await _crowdsec_request(f"/v2/smoke/{indicator}")
        if not isinstance(r, dict):
            raise ValueError("malformed CrowdSec response (not a JSON object)")
        rep = r.get("reputation", "unknown")
        score = {"malicious": 100, "suspicious": 60, "known": 30, "unknown": 10, "safe": 0}.get(rep, 10)
        risk = {"malicious": "high", "suspicious": "medium", "known": "low", "unknown": "low", "safe": "none"}.get(rep, "low")
        return TIProviderResult(
            provider="crowdsec", indicator=indicator, indicator_type=ind_type,
            risk_level=risk, reputation_score=score,
            is_malicious=(rep == "malicious"),
            tags=[b.get("name", "?") for b in r.get("behaviors", [])[:5]],
            attack_techniques=[m.get("name", "?") for m in r.get("mitre_techniques", [])[:10]],
            detail={"reputation": rep, "as_name": r.get("as_name", "")},
        )
    except Exception as e:
        return TIProviderResult(provider="crowdsec", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


async def _threatfox_provider(indicator: str, ind_type: str) -> TIProviderResult:
    configured = bool(os.environ.get(THREATFOX_API_KEY_ENV))
    if not configured:
        return TIProviderResult(provider="threatfox", indicator=indicator,
                                indicator_type=ind_type, error="not configured",
                                error_kind="not_configured")
    try:
        from mcp_server.threat_intel.threatfox import (_NO_MATCH_STATUSES,
                                                       _threatfox_request)
        r = await _threatfox_request(indicator, False)
        if not isinstance(r, dict):
            raise ValueError("malformed ThreatFox response (not a JSON object)")
        # Only these statuses are a decisive answer. An error status must never be
        # read as "no matches" and then down-scored to a clean verdict.
        status = r.get("query_status")
        if status != "ok" and status not in _NO_MATCH_STATUSES:
            raise ValueError(f"ThreatFox returned query_status={status!r}")
        if "data" not in r:
            raise ValueError("malformed ThreatFox response (data missing)")
        items = r.get("data")
        if not isinstance(items, list):
            raise ValueError("malformed ThreatFox response (data is not a list)")
        if not items:
            # No match is absence of data, not a clean verdict.
            return TIProviderResult(provider="threatfox", indicator=indicator,
                                    indicator_type=ind_type, tags=["no_results"],
                                    detail={"match_count": 0,
                                            "query_status": "no_results"})
        conf = max((e.get("confidence_level", 0) for e in items), default=0)
        risk = "high" if conf >= 75 else "medium" if conf >= 50 else "low"
        return TIProviderResult(
            provider="threatfox", indicator=indicator, indicator_type=ind_type,
            risk_level=risk, reputation_score=conf, is_malicious=(conf >= 50),
            malware_families=list({e.get("malware_printable", "?") for e in items if e.get("malware_printable")})[:5],
            tags=[e.get("threat_type_desc", "?") for e in items[:3]],
            detail={"match_count": len(items)},
        )
    except Exception as e:
        return TIProviderResult(provider="threatfox", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


async def _otx_provider(indicator: str, ind_type: str) -> TIProviderResult:
    configured = bool(os.environ.get(OTX_API_KEY_ENV))
    if not configured:
        return TIProviderResult(provider="otx", indicator=indicator,
                                indicator_type=ind_type, error="not configured",
                                error_kind="not_configured")
    try:
        from mcp_server.threat_intel.otx import _otx_request
        r = await _otx_request(indicator, "general")
        if not isinstance(r, dict) or not isinstance(r.get("pulse_info"), dict):
            raise ValueError("malformed OTX response (pulse_info missing)")
        pulse_info = r["pulse_info"]
        pulses = pulse_info.get("pulses", [])
        if not isinstance(pulses, list):
            raise ValueError("malformed OTX response (pulse_info.pulses is not a list)")
        count = pulse_info.get("count", 0)
        if count and not pulses:
            raise ValueError("malformed OTX response (pulse count without pulses)")

        # Enrich hashes with the malware section (sample detections, no pulses needed)
        malware_hits = []
        if ind_type == "file":
            try:
                m = await _otx_request(indicator, "malware")
                samples = m.get("data", []) if isinstance(m, dict) else []
                for sample in samples if isinstance(samples, list) else []:
                    if isinstance(sample, dict) and sample.get("hash"):
                        malware_hits.append(str(sample.get("hash", ""))[:12])
            except Exception:
                pass  # malware section optional

        if count == 0 and not malware_hits:
            return TIProviderResult(provider="otx", indicator=indicator,
                                    indicator_type=ind_type, risk_level="none",
                                    reputation_score=0, is_malicious=False)
        mf = _normalize_str_list(
            [m for p in pulses if isinstance(p, dict)
             for m in (p.get("malware_families") or [])], 5)
        adv = _normalize_str_list(
            [_normalize_adversary(p.get("adversary")) for p in pulses
             if isinstance(p, dict)], 5)
        attack = _normalize_str_list(
            [a for p in pulses if isinstance(p, dict)
             for a in (p.get("attack_ids") or [])], 10, prefer_id=True)
        industries = _normalize_str_list(
            [i for p in pulses if isinstance(p, dict)
             for i in (p.get("industries") or [])], 5)
        # Malicious if malware families/adversaries OR direct malware sample hits.
        is_mal = bool(mf or adv or malware_hits)
        risk = "high" if is_mal else "medium"
        return TIProviderResult(
            provider="otx", indicator=indicator, indicator_type=ind_type,
            risk_level=risk,
            reputation_score=min(50 + count * 5 + len(malware_hits) * 10, 100),
            is_malicious=is_mal,
            malware_families=mf, adversaries=adv, attack_techniques=attack,
            industries=industries,
            pulses=[{"name": p.get("name", "?"), "author": (p.get("author") or {}).get("username", "?")}
                    for p in pulses[:5]],
            detail={"pulse_count": count, "malware_samples": malware_hits[:5]},
        )
    except Exception as e:
        return TIProviderResult(provider="otx", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


async def _greynoise_provider(indicator: str, ind_type: str) -> TIProviderResult:
    if ind_type != "IPv4":
        return TIProviderResult(provider="greynoise", indicator=indicator,
                                indicator_type=ind_type, error="unsupported type",
                                error_kind="unsupported_type")
    try:
        raw = await _greynoise_lookup(indicator)
        if not isinstance(raw, dict):
            raise ValueError("malformed GreyNoise response (not a JSON object)")
        if raw.get("message") == _NO_DATA_MESSAGE:
            # No community data is an absence of signal, not a clean verdict.
            return TIProviderResult(
                provider="greynoise", indicator=indicator, indicator_type=ind_type,
                tags=["no_data"],
                detail={"classification": raw.get("classification", "unknown"),
                        "message": raw["message"]})
        classification = raw.get("classification", "unknown")
        is_mal = classification == "malicious"
        return TIProviderResult(
            provider="greynoise", indicator=indicator, indicator_type=ind_type,
            risk_level="high" if is_mal else "low" if classification == "unknown" else "none",
            reputation_score=100 if is_mal else 0,
            is_malicious=is_mal,
            tags=[classification, "scanner" if raw.get("noise") else "",
                  "business" if raw.get("riot") else ""],
            detail={"name": raw.get("name", ""), "last_seen": raw.get("last_seen", "")},
        )
    except Exception as e:
        return TIProviderResult(provider="greynoise", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


async def _abuseipdb_provider(indicator: str, ind_type: str) -> TIProviderResult:
    # /check accepts IPv4 and IPv6 alike; only the value differs.
    if ind_type not in ("IPv4", "IPv6"):
        return TIProviderResult(provider="abuseipdb", indicator=indicator,
                                indicator_type=ind_type, error="unsupported type",
                                error_kind="unsupported_type")
    try:
        from mcp_server.threat_intel.abuseipdb import AbuseIPDBError, check_ip
        try:
            data = await check_ip(indicator, max_age_days=90)
        except AbuseIPDBError as exc:
            return TIProviderResult(provider="abuseipdb", indicator=indicator,
                                    indicator_type=ind_type, error=exc.message,
                                    error_kind=exc.kind)
        return TIProviderResult(
            provider="abuseipdb", indicator=indicator, indicator_type=ind_type,
            risk_level=data["risk_band"], reputation_score=data["abuse_confidence_score"],
            is_malicious=data["is_malicious"],
            detail={"total_reports": data["total_reports"],
                    "last_reported": data["last_reported_at"] or ""},
        )
    except Exception as e:
        return TIProviderResult(provider="abuseipdb", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


async def _virustotal_provider(indicator: str, ind_type: str,
                               consent_token: str | None = None,
                               denied_reason: str | None = None) -> TIProviderResult:
    vt_types = {"file": "files", "domain": "domains",
                "IPv4": "ip_addresses", "IPv6": "ip_addresses"}
    configured = bool(VIRUSTOTAL_API_KEY)
    if ind_type not in vt_types or not configured:
        return TIProviderResult(provider="virustotal", indicator=indicator,
                                indicator_type=ind_type,
                                error="not configured" if not configured else "unsupported type",
                                error_kind="not_configured" if not configured else "unsupported_type")
    # The host was asked and declined; lookup() would blame the caller instead.
    if consent_token is None and denied_reason:
        return TIProviderResult(provider="virustotal", indicator=indicator,
                                indicator_type=ind_type, error=denied_reason,
                                error_kind="consent_required")
    from mcp_server.threat_intel.virustotal import VirusTotalError, lookup
    try:
        data = await lookup(vt_types[ind_type], indicator,
                            consent_token=consent_token)
        mal = data["malicious"]
        complete = bool(data.get("stats_complete", False))
        total = data.get("total_engines")
        score = data.get("detection_percent")
        if complete and score is not None:
            risk = ("high" if score >= 50 else "medium" if score >= 20
                    else "low" if mal > 0 else "none")
            is_malicious = risk in ("high", "medium")
        else:
            risk = None
            is_malicious = None
        return TIProviderResult(
            provider="virustotal", indicator=indicator, indicator_type=ind_type,
            risk_level=risk, reputation_score=score if complete else None,
            is_malicious=is_malicious,
            detail={
                "detections": (f"{mal}/{total}" if complete and total is not None
                               else f"{mal}/? (incomplete)"),
                "detection_percent": score,
                "stats_complete": complete,
                "missing_stats": data.get("missing_stats", []),
                "analysis_stats": data.get("analysis_stats"),
                "total_engines": total,
                "community_reputation": data.get("community_reputation"),
                "as_owner": data.get("as_owner"),
                "asn": data.get("asn"),
                "network": data.get("network"),
                "country": data.get("country"),
                "total_votes": data.get("total_votes"),
                "tags": data.get("tags"),
                "last_analysis_date": data.get("last_analysis_date"),
                "http_status": data.get("http_status"),
                "any_detection": data.get("any_detection", mal > 0),
                "cached": data.get("cached", False),
                "retrieved_at": data.get("retrieved_at"),
                "cache_age_seconds": data.get("cache_age_seconds"),
                "cache_ttl_seconds": data.get("cache_ttl_seconds"),
                "cache_expired": data.get("cache_expired"),
            },
        )
    except VirusTotalError as e:
        kind = e.kind if e.kind in _ERROR_KINDS else "upstream_error"
        return TIProviderResult(provider="virustotal", indicator=indicator,
                                indicator_type=ind_type, error=e.message,
                                error_kind=kind)
    except Exception as e:
        return TIProviderResult(provider="virustotal", indicator=indicator,
                                indicator_type=ind_type, error=str(e),
                                error_kind=_classify_api_error(e))


# Aggregation
def _aggregate(results: list[TIProviderResult]) -> TIQueryOutput:
    """Aggregate per-provider results into a single verdict."""
    # Ignore results with errors for scoring
    valid = [r for r in results if r.error is None]
    errors = [f"{r.provider}: {r.error}" for r in results if r.error]
    # Configuration answers are not attempts: a provider that is unconfigured or
    # does not support the indicator type never left the process.
    attempted = [r for r in results
                 if r.error_kind not in _LOCAL_REFUSAL_KINDS]
    coverage = {"providers_total": len(attempted), "providers_ok": len(valid)}

    configured = [r for r in results
                  if r.error_kind not in ("not_configured", "unsupported_type")]
    # "Queried" means the process actually sent a request: the same set as
    # attempted. Failed is the subset that never produced a usable answer.
    queried = attempted
    failed = [r for r in results
              if r.error is not None and r.error_kind not in _LOCAL_REFUSAL_KINDS]
    skipped = [r for r in results
               if r.error is not None and r.error_kind in _LOCAL_REFUSAL_KINDS]
    malicious_votes = sum(1 for r in valid if r.is_malicious is True)
    clean_votes = sum(1 for r in valid if r.is_malicious is False)
    inconclusive = sum(1 for r in valid if r.is_malicious is None)
    tally = {
        "providers_configured": len(configured),
        "providers_queried": len(queried),
        "verdicts_malicious": malicious_votes,
        "verdicts_clean": clean_votes,
        "verdicts_inconclusive": inconclusive,
        "providers_failed": len(failed),
        "providers_skipped": len(skipped),
    }

    if not valid:
        return TIQueryOutput(indicator=results[0].indicator if results else "",
                             indicator_type=results[0].indicator_type if results else "unknown",
                             results=results, aggregated_risk_level=None,
                             consensus_malicious=0, errors=errors,
                             verdict_basis="no_provider_answered",
                             **coverage, **tally)

    highest = max(valid, key=lambda r: _RISK_ORDER.get(r.risk_level, 0))
    aggregated = highest.risk_level
    if malicious_votes:
        basis = "provider_detection"
    elif inconclusive and not clean_votes:
        basis = "inconclusive"
    elif inconclusive:
        basis = "mixed_clean_and_inconclusive"
    else:
        basis = "all_clean"

    return TIQueryOutput(
        indicator=valid[0].indicator,
        indicator_type=valid[0].indicator_type,
        results=results,
        aggregated_risk_level=aggregated,
        consensus_malicious=malicious_votes,
        errors=errors,
        verdict_basis=basis,
        **coverage,
        **tally,
    )


def _clip(text: object, limit: int) -> str:
    """One-line Markdown scalar capped at ``limit``, with an explicit ellipsis."""
    value = " ".join(str(text if text is not None else "").split()) or "-"
    return value if len(value) <= limit else value[:max(0, limit - 1)] + "\u2026"


def _malicious_mark(is_malicious: bool | None) -> str:
    """Render a tri-state vote without turning unknown into a negative."""
    if is_malicious is None:
        return "?"
    return "✅" if is_malicious else "❌"


def _vt_consent_target(ind_type: str, indicator: str) -> tuple[str, str] | None:
    if ind_type in ("IPv4", "IPv6"):
        return "ip_addresses", normalize_public_ip(indicator)
    if ind_type == "domain":
        return "domains", normalize_domain(indicator)
    if ind_type == "file":
        return "files", normalize_hash(indicator)
    return None


# MCP Tool
@mcp.tool(
    name="blueteam_threat_intel_aggregate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_threat_intel_aggregate(params: ThreatIntelAggregateInput,
                                           ctx: Context | None = None) -> str:
    """Aggregate threat intelligence from all available providers for one IOC.

    Queries CrowdSec, ThreatFox, AlienVault OTX, GreyNoise, AbuseIPDB, and
    VirusTotal **concurrently** for a single indicator (IP / domain / hash),
    normalizes each into a unified result, and returns an aggregated verdict.

    This replaces 6 sequential tool calls with one faster and gives a consensus view across independent sources.

    **Worked Examples**

    1. *Full aggregation for a suspicious IP*:
       ``blueteam_threat_intel_aggregate(indicator="140.82.0.86", acknowledge_ioc_sharing=true)``

    2. *Aggregate a domain*:
       ``blueteam_threat_intel_aggregate(indicator="evil-c2.example.com", acknowledge_ioc_sharing=true)``

    3. *Aggregate a file hash*:
       ``blueteam_threat_intel_aggregate(indicator="<sha256>", acknowledge_ioc_sharing=true)``

    VirusTotal is queried only when ``acknowledge_ioc_sharing=true`` requests
    host confirmation and the MCP host returns an explicit approval. The boolean
    alone is not consent. Queried indicators are added to VirusTotal's community
    dataset. Without host approval, VT returns ``consent_required`` with the
    refusal reason (no elicitation support, an older protocol revision, or an
    operator who declined), and no request or quota reservation is made.

    **Error Handling**: Providers without API keys are skipped and reported in
    ``errors[]``. Each result also carries ``error_kind`` for JSON consumers. Upstream
    failures include ``rate_limited`` (HTTP 429), ``auth_error``, ``not_found``,
    ``timeout``, and ``upstream_error``. Local refusals include ``cooldown``,
    ``budget_closed``, ``not_armed``, ``arm_expired``, ``budget_exhausted``,
    ``daily_exhausted``, ``storage_unavailable``, ``state_corrupt``,
    ``state_missing``, ``policy_mismatch``, ``state_exists``, ``config_invalid``,
    ``bad_request``, ``circuit_open``, ``plan_limit``, ``not_configured``, and
    ``unsupported_type``; ``error`` keeps the human-readable text. Per-provider
    failures never block the overall aggregation. ``providers_ok``/``providers_total``
    count attempted upstream providers. A provider that is not configured, does not
    support the indicator type, is refused locally before transport, or fails its
    input validation is excluded from the ratio and stays in ``errors[]``.
    """
    _audit_log("blueteam_threat_intel_aggregate", {"indicator": params.indicator})
    ind_type = _classify_indicator(params.indicator)

    vt_token = None
    vt_denial: str | None = None
    if params.acknowledge_ioc_sharing and VIRUSTOTAL_API_KEY:
        try:
            consent_target = _vt_consent_target(ind_type, params.indicator)
        except ValueError:
            consent_target = None
        if consent_target is None:
            vt_denial = "no VirusTotal consent target for this indicator type"
        else:
            vt_kind, vt_value = consent_target
            if await request_ioc_sharing(
                    ctx, consent_message(vt_kind, vt_value)):
                vt_token = issue_consent(vt_kind, vt_value)
            else:
                vt_denial = VT_HOST_REFUSAL

    # Query all applicable providers concurrently
    tasks = [
        _crowdsec_provider(params.indicator, ind_type),
        _threatfox_provider(params.indicator, ind_type),
        _otx_provider(params.indicator, ind_type),
        _greynoise_provider(params.indicator, ind_type),
        _abuseipdb_provider(params.indicator, ind_type),
        _virustotal_provider(params.indicator, ind_type, vt_token, vt_denial),
    ]
    results: list[TIProviderResult] = await asyncio.gather(*tasks)
    output = _aggregate(results)

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(output.model_dump(), indent=2, default=str))

    # Markdown
    lines = [f"# Threat Intel Aggregate — `{params.indicator}`", "",
             f"**Type**: `{ind_type}` | **Aggregated Risk**: **{output.aggregated_risk_level or 'unknown'}** "
             f"| **Malicious votes**: {output.consensus_malicious}/{len([r for r in results if r.error is None])}",
             f"**Provider coverage**: {output.providers_ok}/{output.providers_total} attempted providers answered",
             "", "| Provider | Risk | Score | Malicious | Malware / Adversary |",
             "|----------|------|-------|-----------|---------------------|"]
    for r in results:
        if r.error:
            lines.append(f"| `{r.provider}` | — | — | — | "
                         f"⚠️ {_clip(r.error, 40)} |")
        else:
            mf = ", ".join(r.malware_families[:2]) or ""
            adv = ", ".join(r.adversaries[:2]) or ""
            detail = f"{mf} {adv}".strip()
            if r.provider == "virustotal" and r.detail.get("detections"):
                rep = r.detail.get("community_reputation")
                detail = (f"{r.detail['detections']} engines; "
                          f"rep {rep if rep is not None else '-'}")
            detail = detail or "-"
            lines.append(
                f"| `{r.provider}` | {r.risk_level or '?'} | "
                f"{r.reputation_score if r.reputation_score is not None else '?'} "
                f"| {_malicious_mark(r.is_malicious)} | {_clip(detail, 40)} |")

    lines.append("")
    lines.append("`Score` is the provider's normalized 0-100 score. For VirusTotal it is the engine "
                 "detection percentage; `rep` in the detail is community reputation.")

    lines.append("")
    lines.append("### Verdict accounting")
    lines.append("")
    lines.append(
        f"- **Aggregated risk**: `{output.aggregated_risk_level or 'unknown'}` — the highest "
        f"risk any single provider reported, not a vote."
    )
    lines.append(
        f"- **Providers**: {output.providers_configured} configured, "
        f"{output.providers_total} queried, {output.providers_ok} answered, "
        f"{output.providers_failed} failed, {output.providers_skipped} skipped "
        f"(never sent — not part of the queried count)")
    lines.append(
        f"- **Verdicts**: {output.verdicts_malicious} malicious, "
        f"{output.verdicts_clean} clean, {output.verdicts_inconclusive} inconclusive")
    if output.verdicts_inconclusive or output.providers_failed or output.providers_skipped:
        lines.append(
            "- A failed, skipped, or inconclusive provider is not a clean verdict. "
            "Treat this IOC as partially assessed.")

    vt_rows = [r for r in results if r.provider == "virustotal" and r.error is None]
    if vt_rows:
        lines.append("")
        lines.append("### VirusTotal retrieval")
        for row in vt_rows:
            detail = row.detail
            source = "cache" if detail.get("cached") else "live API"
            age = detail.get("cache_age_seconds")
            ttl = detail.get("cache_ttl_seconds")
            lines.append(
                f"- `{row.indicator}`: {source}, retrieved {detail.get('retrieved_at') or '-'}, "
                f"age {age if age is not None else '-'}s/TTL {ttl if ttl is not None else '-'}s, "
                f"expired {'yes' if detail.get('cache_expired') else 'no'}, "
                f"HTTP {detail.get('http_status') or '-'}")
        # Network attributes are shown only when VirusTotal returned them. An
        # absent field prints as "-", never as a guessed value.
        lines.append("")
        lines.append("### VirusTotal network attributes")
        lines.append("")
        lines.append("| Indicator | ASN | AS owner | Country | Network |")
        lines.append("|---|---|---|---|---|")
        for row in vt_rows:
            detail = row.detail or {}
            asn = detail.get("asn")
            lines.append(
                f"| `{_clip(row.indicator, 45)}` "
                f"| {('AS' + str(asn)) if isinstance(asn, int) else '-'} "
                f"| {_clip(detail.get('as_owner'), 40)} "
                f"| {_clip(detail.get('country'), 20)} "
                f"| {_clip(detail.get('network'), 40)} |")

    if output.errors:
        lines.append("")
        lines.append("### ⚠️ Failed or skipped providers")
        for e in output.errors:
            lines.append(f"- {e}")

    # MITRE techniques across providers
    all_techniques = sorted({t for r in results if not r.error for t in r.attack_techniques})
    if all_techniques:
        lines.append("")
        lines.append(f"### 🎯 MITRE ATT&CK Techniques ({len(all_techniques)})")
        lines.append(" | ".join(f"`{t}`" for t in all_techniques[:20]))

    # OTX pulses (campaign context)
    pulses = [p for r in results if not r.error for p in r.pulses]
    if pulses:
        lines.append("")
        lines.append(f"### 🕵️ Campaign Pulses ({len(pulses)})")
        for p in pulses[:5]:
            lines.append(f"- **{p.get('name','?')}** — {p.get('author','?')}")

    return _truncate_if_needed("\n".join(lines))
