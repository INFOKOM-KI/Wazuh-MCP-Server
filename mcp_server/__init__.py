#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Blue Team MCP Server — shared FastMCP instance, env config, and constants
"""
from __future__ import annotations
import os, sys, logging

# Logging (stderr only - stdout is the MCP JSON-RPC channel)
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("blue_team_mcp")

from mcp.server.fastmcp import FastMCP

_SERVER_NAME = os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "blue_team_mcp").strip().lower()
if os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "").strip() and os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "").strip() != _SERVER_NAME:
    logger.warning("BLUE_TEAM_MCP_SERVER_NAME normalized to '%s'.", _SERVER_NAME)
mcp = FastMCP(_SERVER_NAME)

# Threat Intelligence API keys
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
CROWDSEC_API_KEY_ENV = "CROWDSEC_API_KEY"
CROWDSEC_CACHE_TTL = int(os.environ.get("CROWDSEC_CACHE_TTL", "900"))
GREYNOISE_COMMUNITY_BASE_URL = "https://api.greynoise.io/v3/community"
NETRA_API_KEY_ENV = "NETRA_API_KEY"
NETRA_VERIFY_SSL = os.environ.get("NETRA_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
ARGUS_API_KEY_ENV = "ARGUS_API_KEY"
ARGUS_VERIFY_SSL = os.environ.get("ARGUS_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
THREATFOX_API_KEY_ENV = "THREATFOX_API_KEY"
THREATFOX_CACHE_TTL = int(os.environ.get("THREATFOX_CACHE_TTL", "900"))

# Wazuh Manager API
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "").rstrip("/")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
WAZUH_API_VERIFY_SSL = os.environ.get("WAZUH_API_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
if not WAZUH_API_VERIFY_SSL:
    logger.warning("WAZUH_API_VERIFY_SSL disabled - TLS OFF for Wazuh Manager API")

# Wazuh Indexer / OpenSearch
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_VERIFY_SSL = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
if not WAZUH_INDEXER_VERIFY_SSL:
    logger.warning("WAZUH_INDEXER_VERIFY_SSL disabled — TLS OFF for Wazuh Indexer")

# Sangfor Blocklist
SANGFOR_BLOCKLIST_URL = os.environ.get("SANGFOR_BLOCKLIST_URL", "").rstrip("/")
SANGFOR_BLOCKLIST_TOKEN = os.environ.get("SANGFOR_BLOCKLIST_TOKEN", "")
SANGFOR_BLOCKLIST_TIMEOUT = float(os.environ.get("SANGFOR_BLOCKLIST_TIMEOUT", "15"))
SANGFOR_BLOCKLIST_VERIFY_SSL = os.environ.get("SANGFOR_BLOCKLIST_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# Performance & Limits
MAX_LOG_LINES = 2000
CHARACTER_LIMIT = int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "100000"))
_WAZUH_INDEXER_MAX_SIZE = int(os.environ.get("WAZUH_INDEXER_MAX_SIZE", "10000"))
HTTP_TIMEOUT = 30.0
BLUETEAM_ALLOW_UNTRUNCATED = os.environ.get("BLUETEAM_ALLOW_UNTRUNCATED", "false").lower() in ("1", "true", "yes")
if BLUETEAM_ALLOW_UNTRUNCATED:
    logger.warning("BLUETEAM_ALLOW_UNTRUNCATED=true - character-limit bypass ENABLED")

# Redaction Layers
BLUETEAM_REDACT_PII = os.environ.get("BLUETEAM_REDACT_PII", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_EMAILS = os.environ.get("BLUETEAM_REDACT_EMAILS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_DOMAINS = os.environ.get("BLUETEAM_REDACT_DOMAINS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_LOCATIONS = os.environ.get("BLUETEAM_REDACT_LOCATIONS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_UAS = os.environ.get("BLUETEAM_REDACT_UAS", "true").lower() in ("1", "true", "yes")

# Audit & Rate Limiting
BLUETEAM_AUDIT_LOG = os.environ.get("BLUETEAM_AUDIT_LOG", "")
BLUETEAM_RATE_LIMIT = int(os.environ.get("BLUETEAM_RATE_LIMIT", "0"))
_INVESTIGATION_HISTORY_FILE = os.environ.get("BLUETEAM_INVESTIGATION_HISTORY", "")

# Startup validation
_MISSING_CRITICAL: list[str] = []
if not WAZUH_INDEXER_URL:
    _MISSING_CRITICAL.append("WAZUH_INDEXER_URL")
if not WAZUH_INDEXER_PASSWORD:
    _MISSING_CRITICAL.append("WAZUH_INDEXER_PASSWORD")

_MISSING_OPTIONAL: list[str] = []
if not WAZUH_API_URL:
    _MISSING_OPTIONAL.append("WAZUH_API_URL (Manager API tools disabled)")
if not CROWDSEC_API_KEY_ENV or not os.environ.get(CROWDSEC_API_KEY_ENV):
    _MISSING_OPTIONAL.append(f"{CROWDSEC_API_KEY_ENV} (CrowdSec tools disabled)")
if not ABUSEIPDB_API_KEY:
    _MISSING_OPTIONAL.append("ABUSEIPDB_API_KEY (AbuseIPDB lookup disabled)")
if not VIRUSTOTAL_API_KEY:
    _MISSING_OPTIONAL.append("VIRUSTOTAL_API_KEY (VirusTotal lookups disabled)")

if _MISSING_CRITICAL:
    logger.critical("CRITICAL: Required env vars not set: %s — server will fail on Indexer tools.",
                     ", ".join(_MISSING_CRITICAL))
if _MISSING_OPTIONAL:
    logger.warning("Optional env vars not set: %s", ", ".join(_MISSING_OPTIONAL))

# Shared Field Descriptions
_BYPASS_REDACTION_DESC = "When true, skip PII/credential redaction for audit investigations."
_RESPONSE_FORMAT_DESC = "Output format: 'markdown' (default) or 'json'."
_SINCE_DESC = "ISO 8601 start time in UTC. Defaults to 365 days ago."
_UNTIL_DESC = "ISO 8601 end time in UTC. Defaults to now."
_AGENT_NAME_DESC = "Optional agent name filter."
