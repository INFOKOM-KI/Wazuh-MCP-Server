#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
offensive.agency client: bulk IOC membership and single-host detail.

The provider is a read-only tracker of exposed agent consoles. It has no API key
and no published quota. The client sends only the values the caller selected as
attacker-related, and only for the three types the provider documents: IP, CIDR,
and domain. Other IOC strings are classified, preserved, and returned as
``unsupported_indicator_type`` instead of being sent.

Contract checked live on 2026-11-25:
- ``POST /lookup`` with ``{"indicators": [...]}`` (10,000 items, 200 networks)
- ``GET /hosts/<ip>``
- ``200`` carries ``data`` and ``meta``; ``404`` on a host means no record
- ``active`` means seen in the last 7 days; the bulk lookup searches all history
- a domain lookup also matches subdomains
- ``network.kind=cdn`` is shared fronting infrastructure
- attribution: data by ONYPHE, published by offensive.agency
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from mcp_server.core.config import config
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.http_client import (CircuitOpenError, ResponseTooLargeError,
                                         _api_call, _handle_api_error)
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter
from mcp_server.threat_intel.virustotal import normalize_domain

logger = logging.getLogger("blue_team_mcp.offensive_agency")

PROVIDER = "offensive_agency"
SUPPORTED_TYPES = ("ip", "cidr", "domain")
DEFAULT_BASE_URL = "https://www.offensive.agency/api/v1"
ALLOWED_HOST = "www.offensive.agency"
ATTRIBUTION = ("Data by ONYPHE (https://www.onyphe.io), published by "
               "offensive.agency. Free to use, please credit both.")

MAX_INDICATORS = 10_000
MAX_NETWORKS = 200
MAX_ITEM_CHARS = 2_048
MAX_HOST_ROWS = 500
MAX_AGENTS = 20
MAX_CLUSTERS = 20
MAX_DOMAINS = 50
MAX_DOMAIN_IPS = 10
MAX_RDNS = 10
MAX_PROSE = 200
MAX_SERVICES = 100
MAX_CACHE_ENTRY_BYTES = 256_000
MAX_UNSUPPORTED_ROWS = 100
MAX_REJECTED_ROWS = 100

_LIMITER = get_limiter(PROVIDER, max_concurrent=1, min_interval=1.0)

# IANA special-purpose ranges. is_global alone is not enough: multicast is
# global, 64:ff9b::/96 is global and reserved, and 172.0.0.0/10 has global
# endpoints while containing 172.16.0.0/12. Keep this list explicit so a stdlib
# change cannot silently open egress.
_SPECIAL_USE = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96",
    "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
    "2001:db8::/32", "2001:20::/28", "2001:30::/28", "2002::/16",
    "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)
_SPECIAL_USE_NETS = tuple(ipaddress.ip_network(n) for n in _SPECIAL_USE)

_RESERVED_TLDS = frozenset({
    "local", "localhost", "internal", "lan", "test", "invalid", "example",
    "onion", "alt", "arpa",
})

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)
_REGISTRY_RE = re.compile(r"^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\", re.IGNORECASE)
_DEFANGED_RE = re.compile(r"\[\.\]|\(\.\)|\[:\]|^hxxps?://", re.IGNORECASE)
_IPV4_PORT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$")
_IPV6_PORT_RE = re.compile(r"^\[[0-9A-Fa-f:]+\]:\d{1,5}$")
_DOMAIN_PORT_RE = re.compile(r"^[^:\s]+:\d{1,5}$")
_IPV4_LIKE_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
_USER_AGENT_RE = re.compile(
    r"(?:Mozilla|curl|Wget|python-requests|Go-http-client)/", re.IGNORECASE)


class _IndicatorError(ValueError):
    """A supported type that failed validation, with a stable reason code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(detail or reason)


@dataclass
class PreparedBatch:
    """Local classification of one caller-supplied IOC list."""
    groups: list[dict[str, Any]] = field(default_factory=list)
    raw_count: int = 0
    unique_count: int = 0
    duplicates_removed: int = 0
    send_queries: list[str] = field(default_factory=list)


def _cfg():
    if config is None:
        raise ThreatIntelError("Config not initialised; offensive.agency unavailable.")
    return config.threat_intel


def _base_url() -> str:
    url = getattr(_cfg(), "offensive_agency_base_url", DEFAULT_BASE_URL)
    return (url or DEFAULT_BASE_URL).rstrip("/")


def _cache_ttl() -> int:
    return max(0, int(getattr(_cfg(), "offensive_agency_cache_ttl", 21_600)))


def _max_response_bytes() -> int:
    return max(1, int(getattr(_cfg(), "offensive_agency_max_response_bytes", 2_000_000)))


def _headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }


def _net_overlaps_special(net: ipaddress._BaseNetwork) -> bool:
    return any(net.version == item.version and net.overlaps(item)
               for item in _SPECIAL_USE_NETS)


def _normalize_public_ip(value: str) -> str:
    text = (value or "").strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise _IndicatorError("invalid_ip", f"'{text}' is not an IP address.") from exc
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        parsed = mapped
    if parsed.is_multicast:
        raise _IndicatorError("multicast_ip", f"'{text}' is a multicast address.")
    if parsed.is_reserved or not parsed.is_global:
        raise _IndicatorError("private_or_reserved_ip",
                              f"'{text}' is private, reserved, or special-use.")
    if any(parsed.version == item.version and parsed in item
           for item in _SPECIAL_USE_NETS):
        raise _IndicatorError("special_use_ip",
                              f"'{text}' is in an IANA special-purpose range.")
    return str(parsed)


def _normalize_network(value: str) -> str:
    text = (value or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise _IndicatorError("invalid_network",
                              f"'{text}' is not a CIDR network.") from exc
    if _net_overlaps_special(net):
        raise _IndicatorError("special_use_network",
                              f"'{text}' overlaps an IANA special-purpose range.")
    if net.network_address.is_multicast or net.broadcast_address.is_multicast:
        raise _IndicatorError("multicast_network", f"'{text}' is multicast.")
    if net.network_address.is_reserved or net.broadcast_address.is_reserved:
        raise _IndicatorError("private_or_reserved_network",
                              f"'{text}' is reserved.")
    if not net.network_address.is_global or not net.broadcast_address.is_global:
        raise _IndicatorError("private_or_reserved_network",
                              f"'{text}' is private, reserved, or special-use.")
    return str(net)


def _normalize_domain_value(value: str) -> str:
    try:
        domain = normalize_domain(value)
    except ValueError as exc:
        raise _IndicatorError("invalid_domain", str(exc)) from exc
    tld = domain.rsplit(".", 1)[-1]
    if tld in _RESERVED_TLDS or not _TLD_RE.fullmatch(tld):
        raise _IndicatorError("reserved_tld",
                              f"'{domain}' uses a reserved or non-public TLD.")
    return domain


def _send(detected_type: str, query: str) -> dict[str, Any]:
    return {"outcome": "send", "detected_type": detected_type,
            "query": query, "reason": ""}


def _unsupported(detected_type: str) -> dict[str, Any]:
    return {"outcome": "unsupported", "detected_type": detected_type,
            "query": None, "reason": "unsupported_indicator_type"}


def _rejected(detected_type: str, reason: str) -> dict[str, Any]:
    return {"outcome": "rejected", "detected_type": detected_type,
            "query": None, "reason": reason}


def _is_ipv6_like(text: str) -> bool:
    return (text.count(":") >= 2
            and all(ch in "0123456789abcdefABCDEF:" for ch in text))


def _is_file_path(text: str) -> bool:
    return (text.startswith(("/", "./", "../", "~", "\\\\"))
            or bool(re.match(r"^[A-Za-z]:[\\/]", text)))


def _classify(text: str) -> dict[str, Any]:
    """Classify one IOC string. Only ip, cidr, and domain are sendable."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        if _MAC_RE.fullmatch(text):
            return _unsupported("mac_address")
        if _IPV4_LIKE_RE.fullmatch(text) or _is_ipv6_like(text):
            return _rejected("ip", "invalid_ip")
    else:
        try:
            return _send("ip", _normalize_public_ip(text))
        except _IndicatorError as exc:
            return _rejected("ip", exc.reason)

    if "/" in text:
        left = text.split("/", 1)[0]
        try:
            ipaddress.ip_address(left)
        except ValueError:
            if _IPV4_LIKE_RE.fullmatch(left) or _is_ipv6_like(left):
                return _rejected("cidr", "invalid_network")
        else:
            try:
                return _send("cidr", _normalize_network(text))
            except _IndicatorError as exc:
                return _rejected("cidr", exc.reason)

    if _DEFANGED_RE.search(text):
        return _unsupported("defanged")
    if "://" in text or text.lower().startswith(("http://", "https://")):
        return _unsupported("url")
    if _EMAIL_RE.fullmatch(text):
        return _unsupported("email")
    if _HASH_RE.fullmatch(text):
        return _unsupported("hash")
    if _CVE_RE.fullmatch(text):
        return _unsupported("cve")
    if _ASN_RE.fullmatch(text):
        return _unsupported("asn")
    if _is_file_path(text):
        return _unsupported("file_path")
    if _REGISTRY_RE.match(text):
        return _unsupported("registry_key")
    if "*" in text:
        return _unsupported("wildcard")
    if _IPV4_PORT_RE.fullmatch(text) or _IPV6_PORT_RE.fullmatch(text):
        return _unsupported("ip_with_port")
    if _DOMAIN_PORT_RE.fullmatch(text):
        return _unsupported("domain_with_port")
    if " " in text and _USER_AGENT_RE.search(text):
        return _unsupported("user_agent")

    if "." in text and not any(ch in text for ch in "/\\?#@:%*[] \t\r\n"):
        try:
            return _send("domain", _normalize_domain_value(text))
        except _IndicatorError as exc:
            return _rejected("domain", exc.reason)

    return _unsupported("unknown")


def prepare_batch(items: list[str]) -> PreparedBatch:
    """Classify, deduplicate, and count one IOC batch without sending anything."""
    if len(items) > MAX_INDICATORS:
        raise ThreatIntelError(
            f"batch_limit_exceeded: {len(items)} indicators; the provider accepts "
            f"at most {MAX_INDICATORS} per request.")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for raw in items:
        original = (raw or "").strip()
        if not original:
            info = _rejected("unknown", "empty_indicator")
        elif len(original) > MAX_ITEM_CHARS:
            info = _rejected("unknown", "indicator_too_long")
        elif any(not ch.isprintable() for ch in original):
            info = _rejected("unknown", "invalid_characters")
        else:
            info = _classify(original)
        key = (info["outcome"], info["query"] or original)
        if key in groups:
            groups[key]["original_indicators"].append(original)
            continue
        groups[key] = {
            "original_indicators": [original],
            "outcome": info["outcome"],
            "detected_type": info["detected_type"],
            "query_indicator": info["query"],
            "reason": info["reason"],
        }
        order.append(key)

    ordered = [groups[key] for key in order]
    send_queries = [g["query_indicator"] for g in ordered if g["outcome"] == "send"]
    network_count = sum(1 for g in ordered
                        if g["outcome"] == "send" and g["detected_type"] == "cidr")
    if network_count > MAX_NETWORKS:
        raise ThreatIntelError(
            f"network_limit_exceeded: {network_count} CIDRs; the provider accepts "
            f"at most {MAX_NETWORKS} per request.")
    return PreparedBatch(
        groups=ordered,
        raw_count=len(items),
        unique_count=len(ordered),
        duplicates_removed=len(items) - len(ordered),
        send_queries=send_queries,
    )


def _cache_key(endpoint: str, values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(values):
        digest.update(value.encode("utf-8"))
        digest.update(b"\x00")
    return f"{endpoint}:{digest.hexdigest()}"


def _cache_put(key: str, payload: dict[str, Any]) -> None:
    ttl = _cache_ttl()
    if ttl <= 0:
        return
    try:
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return
    if size <= MAX_CACHE_ENTRY_BYTES:
        cache_set(PROVIDER, key, payload, ttl)


def _parse_json(resp: httpx.Response, context: str) -> dict[str, Any]:
    try:
        payload = resp.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ThreatIntelError(
            f"upstream_error: {context} returned a non-JSON body.") from exc
    if not isinstance(payload, dict):
        raise ThreatIntelError(f"upstream_error: {context} returned a non-object body.")
    return payload


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        return f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            code = str(error.get("code") or "").strip()
            message = str(error.get("message") or "").strip()
            detail = ": ".join(part for part in (code, message) if part)
            if detail:
                return detail[:300]
    return f"HTTP {resp.status_code}"


def _require_envelope(payload: dict[str, Any], context: str) -> None:
    if not isinstance(payload.get("data"), dict) or not isinstance(payload.get("meta"), dict):
        raise ThreatIntelError(
            f"upstream_error: {context} response is missing the data/meta envelope.")


async def lookup(queries: list[str]) -> dict[str, Any]:
    """POST one normalized IOC batch. Caller decides what is sent."""
    from mcp_server.core.external_egress import egress_check
    egress_check()
    if not queries:
        return {}
    key = _cache_key("lookup", queries)
    cached = cache_get(PROVIDER, key)
    if cached is not None:
        return cached
    try:
        async with _LIMITER:
            resp = await _api_call(
                "post", f"{_base_url()}/lookup",
                headers=_headers(),
                json={"indicators": queries},
                client_name=PROVIDER,
                max_response_bytes=_max_response_bytes(),
            )
    except ResponseTooLargeError as exc:
        raise ThreatIntelError(
            "response_too_large: the lookup response exceeded the 2 MB cap; "
            "split the batch or narrow the CIDR.") from exc
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 400:
            raise ThreatIntelError(
                f"bad_request: offensive.agency rejected the batch "
                f"({_error_message(exc.response)}).") from exc
        _handle_api_error(exc, context="offensive_agency_lookup")
    except (httpx.TimeoutException, CircuitOpenError, RuntimeError) as exc:
        _handle_api_error(exc, context="offensive_agency_lookup")
    payload = _parse_json(resp, "offensive_agency_lookup")
    _require_envelope(payload, "offensive_agency_lookup")
    _cache_put(key, payload)
    return payload


async def host(ip: str) -> dict[str, Any]:
    """GET one host. A 404 is returned as a result, not raised."""
    key = _cache_key("host", [ip])
    cached = cache_get(PROVIDER, key)
    if cached is not None:
        return cached
    try:
        async with _LIMITER:
            resp = await _api_call(
                "get", f"{_base_url()}/hosts/{quote(ip, safe='')}",
                headers=_headers(),
                client_name=PROVIDER,
                max_response_bytes=_max_response_bytes(),
            )
    except ResponseTooLargeError as exc:
        raise ThreatIntelError(
            "response_too_large: the host response exceeded the 2 MB cap.") from exc
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"_not_found": True, "message": _error_message(exc.response)}
        if exc.response.status_code == 400:
            raise ThreatIntelError(
                f"bad_request: offensive.agency rejected the host "
                f"({_error_message(exc.response)}).") from exc
        _handle_api_error(exc, context="offensive_agency_host")
    except (httpx.TimeoutException, CircuitOpenError, RuntimeError) as exc:
        _handle_api_error(exc, context="offensive_agency_host")
    payload = _parse_json(resp, "offensive_agency_host")
    if payload.get("_not_found"):
        return payload
    _require_envelope(payload, "offensive_agency_host")
    if not isinstance(payload.get("data"), dict):
        raise ThreatIntelError("upstream_error: host response has no data object.")
    _cache_put(key, payload)
    return payload
