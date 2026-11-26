#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Global control for outbound threat-intelligence requests.

An API key is a capability, not an authorization to send an IOC to a third
party. `BLUETEAM_EXTERNAL_ENRICHMENT` (default false) is the deployment
decision: while it is off, every provider client refuses before a DNS lookup,
and no configured key can change that.

Wazuh Indexer/Manager calls, the organization's MISP instance, and AbuseIPDB
reporting are not "enrichment lookups" and do not use this gate. Reporting has
its own explicit authorization.
"""
from __future__ import annotations

from mcp_server import EXTERNAL_ENRICHMENT_ENABLED


class ExternalEgressDisabled(RuntimeError):
    """Raised when the deployment has not enabled external enrichment."""

    kind = "disabled"

    def __init__(self) -> None:
        super().__init__("external enrichment is disabled "
                         "(BLUETEAM_EXTERNAL_ENRICHMENT=false)")


def egress_enabled() -> bool:
    """True when outbound provider lookups are authorized."""
    return EXTERNAL_ENRICHMENT_ENABLED


def egress_check() -> None:
    """Raise ``ExternalEgressDisabled`` unless provider egress is authorized."""
    if not EXTERNAL_ENRICHMENT_ENABLED:
        raise ExternalEgressDisabled()
