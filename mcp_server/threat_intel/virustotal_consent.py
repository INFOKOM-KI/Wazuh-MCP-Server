#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Standing operator consent for VirusTotal IoC sharing.

VirusTotal adds every queried indicator to its community dataset. Sharing is
therefore a deployment decision, taken once through
``BLUETEAM_VIRUSTOTAL_IOC_SHARING`` and enforced at the single request choke
point in ``virustotal.lookup``.

An MCP host serves one elicitation at a time, so a per-call dialog could not
survive two concurrent lookups: the second one failed with
``elicitation_error``. The tool call is the operator's intent, and the scope
check below is the control.

Public indicators only. Private, loopback, link-local, CGNAT, ULA, multicast, and
reserved addresses are refused before the cache and before quota reservation, so
an RFC 1918 address cannot leave the host even when a caller bypasses the input
model.

Provenance is the second gate. A lookup needs an entry in the attacker registry
whose source proves Wazuh alert analysis, so an arbitrary public address typed
into a tool cannot become a VirusTotal submission.
"""
from __future__ import annotations

import ipaddress

from mcp_server import (VIRUSTOTAL_ATTRIBUTION_EXCLUDE, VIRUSTOTAL_IOC_SHARING)
from mcp_server.core.attacker_registry import attacker_ioc_provenance
from mcp_server.core.http_client import normalize_public_ip


def authorize_ioc_sharing(kind: str, value: str) -> None:
    """Allow one lookup, or raise the refusal the tool will report.

    ``kind`` and ``value`` arrive normalized from ``virustotal.lookup``. The IP
    check is the egress boundary: it runs after normalization and before the
    cache, quota, or transport.
    """
    from mcp_server.threat_intel.virustotal import VirusTotalError

    if not VIRUSTOTAL_IOC_SHARING:
        raise VirusTotalError(
            "VirusTotal IoC sharing is disabled "
            "(BLUETEAM_VIRUSTOTAL_IOC_SHARING=off)", "consent_required")
    if kind == "ip_addresses":
        try:
            normalize_public_ip(value)
        except ValueError as exc:
            raise VirusTotalError(
                "a non-public address is never sent to VirusTotal", "bad_request"
            ) from exc
        network = excluded_infrastructure(value)
        if network is not None:
            raise VirusTotalError(
                f"address is in the configured shared-infrastructure exclusion "
                f"({network})", "excluded_infrastructure")


def excluded_infrastructure(value: str) -> str | None:
    """Return the matching exclusion CIDR, or ``None``.

    Shared CDN, WAF, NAT, and proxy ranges are never sent, whatever source
    registered them. A bad token is ignored, which cannot open egress because
    startup validation rejects it first.
    """
    try:
        parsed = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    parsed = getattr(parsed, "ipv4_mapped", None) or parsed
    for token in (VIRUSTOTAL_ATTRIBUTION_EXCLUDE or "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if parsed.version == network.version and parsed in network:
            return str(network)
    return None


def ioc_sharing_enabled() -> bool:
    """True when the deployment allows sharing, so callers skip provenance work.

    With sharing off, ``lookup()`` reports ``consent_required`` and no Indexer
    query is needed to decide that.
    """
    return VIRUSTOTAL_IOC_SHARING


def authorize_attacker_scope(value: str) -> str:
    """Return the provenance source, or raise the refusal.

    Runs immediately before transport, after the public-address check and
    before the response cache. The tool layer is expected to establish the
    entry first (``ensure_attacker_provenance``); this call is the gate that
    holds when a new caller forgets. Operator attestations are not accepted
    here: the CLI passes ``operator_attested=True`` to its own check.
    """
    from mcp_server.threat_intel.virustotal import VirusTotalError

    source = attacker_ioc_provenance(value)
    if source is None:
        raise VirusTotalError(
            "indicator has no Wazuh attacker-IOC provenance "
            "(BLUETEAM_ATTACKER_REGISTRY is the source of truth)",
            "not_attacker_ioc")
    return source
