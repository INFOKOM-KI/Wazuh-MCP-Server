#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Dynamic tool registration — 68 tools across 14 modules.
Each module's @mcp.tool decorator auto-registers with the shared FastMCP instance.
One import per module — zero manual registry.
"""
from mcp_server import mcp, logger

def register_all_tools() -> None:
    """Import all tool modules. @mcp.tool decorators fire on import."""
    from ..threat_intel import crowdsec, greynoise, threatfox  # noqa: F401

    from . import (  # noqa: F401
        host_forensics,       # 23 tools
        fail2ban,             # 3 tools
        wazuh_siem,           # 10 tools (+5 Wazuh core)
        alert_enrichment,     # 13 tools (+7 threat intel)
        baseline,             # 3 tools
        investigation,        # 5 tools (+2 correlation/aggregate)
        geo,                  # 1 tool
        dsl_query,            # 1 tool
        wazuh_email,          # 1 tool
        wazuh_domain,         # 1 tool
        wazuh_compromised,    # 1 tool
        wazuh_timeline,       # 1 tool
        wazuh_velocity,       # 1 tool
        wazuh_focused,        # 1 tool
        threat_hunt,           # 1 tool (11 templates)
        ioc_tools,             # 1 tool
    )

    logger.info("79 tools + 2 resources registered.")
