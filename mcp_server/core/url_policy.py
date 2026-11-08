#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Validated HTTPS base URLs for authenticated provider endpoints.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def _normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        raise ValueError("host is empty")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid host: {host!r}") from exc


def validate_https_base_url(url: str, allowed_hosts: str,
                            required_path: str = "/api/v3") -> str:
    """Return ``url`` normalized, or raise ValueError.

    The URL must use HTTPS, carry no credentials, query, or fragment, target an
    allowlisted DNS hostname on port 443, and end at ``required_path``. IP
    literals are rejected because the API key must never follow a host that was
    supplied as an address rather than an approved DNS name.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("base URL is empty")
    try:
        parsed = urlsplit(url.strip())
    except ValueError as exc:
        raise ValueError(f"malformed base URL: {url!r}") from exc

    if parsed.scheme != "https":
        raise ValueError("base URL must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("base URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain a query or fragment")
    host = parsed.hostname
    if not host:
        raise ValueError("base URL has no host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base URL has a malformed port") from exc
    if port not in (None, 443):
        raise ValueError("base URL must use port 443")

    normalized_host = _normalize_host(host)
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        raise ValueError("base URL host must be a DNS name, not an IP literal")
    allowed = {_normalize_host(item) for item in (allowed_hosts or "").split(",")
               if item.strip()}
    if not allowed:
        allowed = {"www.virustotal.com"}
    if normalized_host not in allowed:
        raise ValueError(f"base URL host {normalized_host!r} is not allowlisted")

    path = parsed.path.rstrip("/")
    if path != required_path.rstrip("/"):
        raise ValueError(f"base URL path must be {required_path!r}")
    return f"https://{normalized_host}{required_path}"
