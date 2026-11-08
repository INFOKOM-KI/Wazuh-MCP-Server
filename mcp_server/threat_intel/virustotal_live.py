#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Opt-in live VirusTotal validation.

This is an operator-run command, not an MCP tool and not part of test
collection. It uses the normal lookup path, so it reserves quota exactly once
and never creates or changes the quota policy. It prints no API key.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from mcp_server import VIRUSTOTAL_API_KEY
from mcp_server.core.http_client import normalize_public_ip
from mcp_server.threat_intel import virustotal as vt
from mcp_server.threat_intel.virustotal import issue_consent


def _quota_snapshot() -> dict[str, Any]:
    try:
        state = vt._get_quota().state()
        return {
            "budget": state.get("budget"),
            "spent": state.get("spent"),
            "remaining": state.get("remaining"),
            "daily_spent": state.get("daily_spent"),
            "daily_limit": state.get("daily_limit"),
            "rate_spent": state.get("rate_spent"),
            "rate_limit": state.get("rate_limit"),
            "window_open": state.get("window_open"),
        }
    except Exception as exc:  # quota state is operational, not the API result
        return {
            "error": getattr(exc, "kind", "quota_state_unavailable"),
            "detail": str(exc),
        }


def _one_lookup(ip: str, label: str) -> dict[str, Any]:
    before = _quota_snapshot()
    try:
        data = vt.lookup("ip_addresses", ip,
                         consent_token=issue_consent("ip_addresses", ip))
    except vt.VirusTotalError as exc:
        return {
            "input": label,
            "ip": ip,
            "outcome": "error",
            "error_kind": exc.kind,
            "message": exc.message,
            "http_status": exc.http_status,
            "retry_after_seconds": exc.retry_after_seconds,
            "quota_before": before,
            "quota_after": _quota_snapshot(),
            "source": "real API",
        }
    after = _quota_snapshot()
    return {
        "input": label,
        "ip": ip,
        "outcome": "success",
        "http_status": data.get("http_status", 200),
        "analysis_stats": data.get("analysis_stats"),
        "malicious": data.get("malicious"),
        "suspicious": data.get("suspicious"),
        "harmless": data.get("harmless"),
        "undetected": data.get("undetected"),
        "timeout": data.get("timeout"),
        "total_engines": data.get("total_engines"),
        "detection_percent": data.get("detection_percent"),
        "stats_complete": data.get("stats_complete"),
        "missing_stats": data.get("missing_stats"),
        "community_reputation": data.get("community_reputation"),
        **vt.cache_metadata(data),
        "quota_before": before,
        "quota_after": after,
        "source": "cache" if data.get("cached") else "real API",
    }


def run(ip: str, ipv6: str | None = None, *, confirm: bool = False,
        acknowledge_sharing: bool = False,
        api_key_configured: bool | None = None) -> dict[str, Any]:
    """Run one controlled IPv4 lookup and an optional IPv6 lookup."""
    if not confirm:
        return {
            "validation": "not_performed",
            "reason": "confirmation_required",
            "detail": "rerun with --confirm-live after operator approval",
        }
    configured = bool(VIRUSTOTAL_API_KEY) if api_key_configured is None else api_key_configured
    if not configured:
        return {
            "validation": "not_performed",
            "reason": "api_key_not_configured",
            "detail": "VIRUSTOTAL_API_KEY is not set; no request was made",
        }
    if not acknowledge_sharing:
        return {
            "validation": "not_performed",
            "reason": "ioc_sharing_acknowledgement_required",
            "detail": "VirusTotal adds queried IoCs to its dataset; rerun with "
                      "--acknowledge-ioc-sharing after confirming the indicators are safe to share",
        }
    try:
        public_ip = normalize_public_ip(ip)
    except ValueError as exc:
        return {
            "validation": "not_performed",
            "reason": "invalid_or_non_public_ip",
            "detail": str(exc),
        }
    results = [_one_lookup(public_ip, "ipv4")]
    if ipv6:
        try:
            public_ipv6 = normalize_public_ip(ipv6)
        except ValueError as exc:
            results.append({
                "input": "ipv6",
                "ip": ipv6,
                "outcome": "not_performed",
                "reason": "invalid_or_non_public_ip",
                "detail": str(exc),
            })
        else:
            results.append(_one_lookup(public_ipv6, "ipv6"))
    return {
        "validation": "performed",
        "source": "real API or cache",
        "live_api_observed": any(
            item.get("outcome") == "success" and item.get("source") == "real API"
            for item in results),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Controlled live VirusTotal validation. Requires operator approval.")
    parser.add_argument("--ip", required=True,
                        help="operator-provided public IPv4 address to query")
    parser.add_argument("--ipv6", default=None,
                        help="optional operator-provided public IPv6 address to query")
    parser.add_argument("--confirm-live", action="store_true",
                        help="explicitly approve one live API request (and optional IPv6)")
    parser.add_argument("--acknowledge-ioc-sharing", action="store_true",
                        help="acknowledge that queried IoCs are added to VirusTotal's dataset")
    args = parser.parse_args(argv)
    if not args.confirm_live:
        print(json.dumps(run(args.ip, args.ipv6, confirm=False), indent=2))
        return 2
    output = run(args.ip, args.ipv6, confirm=True,
                 acknowledge_sharing=args.acknowledge_ioc_sharing)
    print(json.dumps(output, indent=2))
    return 0 if output.get("validation") == "performed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
