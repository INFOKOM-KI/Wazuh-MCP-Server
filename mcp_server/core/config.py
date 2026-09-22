#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Typed configuration for Blue Team MCP Server.
Replaces the ~60 import-time os.environ reads in mcp_server/__init__.py
with structured dataclasses that validate at startup and raise
ConfigurationError on invalid values.
All defaults are production-safe: localhost bind, TLS on, redaction on.
"""
from __future__ import annotations
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from mcp_server.core.exceptions import ConfigurationError

logger = logging.getLogger("blue_team_mcp.config")


# Helper
def _bool(v: str, default: bool = False) -> bool:
    """Parse an env-var string as a boolean."""
    if not v:
        return default
    return v.strip().lower() in ("1", "true", "yes")

# Nested config groups, one dataclass per trust domain.
@dataclass
class ServerConfig:
    """MCP transport and binding configuration."""
    host: str = "127.0.0.1"
    port: int = 8000
    server_name: str = "blue_team_mcp"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "ServerConfig":
        name = os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "blue_team_mcp").strip().lower()
        return cls(
            host=os.environ.get("MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("MCP_PORT", "8000")),
            server_name=name,
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )

    def validate(self) -> None:
        if not self.server_name:
            raise ConfigurationError("BLUE_TEAM_MCP_SERVER_NAME must not be empty")


@dataclass
class WazuhManagerConfig:
    """Wazuh Manager API connection parameters."""
    url: str = ""
    username: str = "wazuh-wui"
    password: str = ""
    verify_ssl: bool = True

    @classmethod
    def from_env(cls) -> "WazuhManagerConfig":
        return cls(
            url=os.environ.get("WAZUH_API_URL", "").rstrip("/"),
            username=os.environ.get("WAZUH_API_USER", "wazuh-wui"),
            password=os.environ.get("WAZUH_API_PASSWORD", ""),
            verify_ssl=_bool(os.environ.get("WAZUH_API_VERIFY_SSL", "true"), True),
        )

    def validate(self) -> None:
        """Manager API is optional - tools degrade gracefully when unset."""
        if self.url and not self.password:
            raise ConfigurationError(
                "WAZUH_API_URL is set but WAZUH_API_PASSWORD is empty -"
                "Manager API tools will fail."
            )


@dataclass
class WazuhIndexerConfig:
    """Wazuh Indexer / OpenSearch connection parameters."""
    url: str = ""
    username: str = "admin"
    password: str = ""
    verify_ssl: bool = True
    max_size: int = 10000

    @classmethod
    def from_env(cls) -> "WazuhIndexerConfig":
        return cls(
            url=os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/"),
            username=os.environ.get("WAZUH_INDEXER_USER", "admin"),
            password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
            verify_ssl=_bool(os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "true"), True),
            max_size=int(os.environ.get("WAZUH_INDEXER_MAX_SIZE", "10000")),
        )

    def validate(self) -> None:
        if not self.url:
            raise ConfigurationError(
                "WAZUH_INDEXER_URL is required - Indexer tools cannot function without it."
            )
        if not self.password:
            raise ConfigurationError(
                "WAZUH_INDEXER_PASSWORD is required - Indexer tools cannot authenticate."
            )


@dataclass
class ThreatIntelConfig:
    """External threat-intelligence API keys and endpoints."""
    # CrowdSec
    crowdsec_api_key: str = ""
    crowdsec_cache_ttl: int = 900
    crowdsec_base_url: str = "https://cti.api.crowdsec.net"
    # GreyNoise
    greynoise_base_url: str = "https://api.greynoise.io/v3/community"
    # ThreatFox
    threatfox_api_key: str = ""
    threatfox_cache_ttl: int = 900
    threatfox_base_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    # AbuseIPDB
    abuseipdb_api_key: str = ""
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    # VirusTotal
    virustotal_api_key: str = ""
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    # Netra
    netra_api_key: str = ""
    netra_verify_ssl: bool = False
    netra_base_url: str = "https://netra.fbi.gov:8013/api/v1"
    netra_min_interval: float = 30.0     # seconds between Netra lookups
    # Argus
    argus_api_key: str = ""
    argus_verify_ssl: bool = False
    argus_base_url: str = "http://localhost:8088/lookup-jobs"
    argus_min_interval: float = 30.0     # seconds between Argus lookups
    # RDAP / crt.sh
    rdap_base_url: str = "https://rdap.org"
    crtsh_base_url: str = "https://crt.sh"
    # AlienVault OTX
    otx_api_key: str = ""
    otx_cache_ttl: int = 1800
    otx_base_url: str = "https://otx.alienvault.com"
    # URLhaus
    urlhaus_api_key: str = ""
    urlhaus_cache_ttl: int = 1800
    urlhaus_base_url: str = "https://urlhaus-api.abuse.ch/v1/"
    # HudsonRock (stealer logs)
    hudsonrock_api_key: str = ""
    hudsonrock_base_url: str = "https://cavalier.hudsonrock.com/api/json/v2"
    # RapidAPI capability lookups (IP blacklist, IOC search, breach check, bulk IP intel)
    rapidapi_key: str = ""
    rapidapi_cache_ttl: int = 604800          # 7 days: the binding limit is 100/month, not staleness
    rapidapi_monthly_cap: int = 100           # account-wide hard limit, shared by every product
    rapidapi_budget: int = 0                  # 0 = fail-closed, armed per incident window
    rapidapi_budget_hours: float = 8.0            # one shift; a restart mid-incident is worse than a long window
    rapidapi_cache_path: str = ""
    rapidapi_raw_whois: bool = True                # documented PII exemption, bulk only.

    @classmethod
    def from_env(cls) -> "ThreatIntelConfig":
        return cls(
            crowdsec_api_key=os.environ.get("CROWDSEC_API_KEY", ""),
            crowdsec_cache_ttl=int(os.environ.get("CROWDSEC_CACHE_TTL", "900")),
            crowdsec_base_url=os.environ.get("CROWDSEC_BASE_URL", "https://cti.api.crowdsec.net"),
            greynoise_base_url=os.environ.get("GREYNOISE_BASE_URL", "https://api.greynoise.io/v3/community"),
            threatfox_api_key=os.environ.get("THREATFOX_API_KEY", ""),
            threatfox_cache_ttl=int(os.environ.get("THREATFOX_CACHE_TTL", "900")),
            threatfox_base_url=os.environ.get("THREATFOX_BASE_URL", "https://threatfox-api.abuse.ch/api/v1/"),
            abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY", ""),
            abuseipdb_base_url=os.environ.get("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2"),
            virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY", ""),
            virustotal_base_url=os.environ.get("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"),
            netra_api_key=os.environ.get("NETRA_API_KEY", ""),
            netra_verify_ssl=_bool(os.environ.get("NETRA_VERIFY_SSL", "false")),
            netra_base_url=os.environ.get("NETRA_BASE_URL", "https://netra.fbi.gov:8013/api/v1"),
            netra_min_interval=float(os.environ.get("NETRA_MIN_INTERVAL", "30")),
            argus_api_key=os.environ.get("ARGUS_API_KEY", ""),
            argus_verify_ssl=_bool(os.environ.get("ARGUS_VERIFY_SSL", "false")),
            argus_base_url=os.environ.get("ARGUS_BASE_URL", "http://localhost:8088/lookup-jobs"),
            argus_min_interval=float(os.environ.get("ARGUS_MIN_INTERVAL", "30")),
            rdap_base_url=os.environ.get("RDAP_BASE_URL", "https://rdap.org"),
            crtsh_base_url=os.environ.get("CRTSH_BASE_URL", "https://crt.sh"),
            otx_api_key=os.environ.get("OTX_API_KEY", ""),
            otx_cache_ttl=int(os.environ.get("OTX_CACHE_TTL", "1800")),
            otx_base_url=os.environ.get("OTX_BASE_URL", "https://otx.alienvault.com"),
            urlhaus_api_key=os.environ.get("URLHAUS_API_KEY", ""),
            urlhaus_cache_ttl=int(os.environ.get("URLHAUS_CACHE_TTL", "1800")),
            urlhaus_base_url=os.environ.get("URLHAUS_BASE_URL", "https://urlhaus-api.abuse.ch/v1/"),
            hudsonrock_api_key=os.environ.get("HUDSONROCK_API_KEY", ""),
            hudsonrock_base_url=os.environ.get("HUDSONROCK_BASE_URL", "https://cavalier.hudsonrock.com/api/json/v2"),
            rapidapi_key=os.environ.get("RAPIDAPI_KEY", ""),
            rapidapi_cache_ttl=int(os.environ.get("RAPIDAPI_CACHE_TTL", "604800")),
            rapidapi_monthly_cap=int(os.environ.get("BLUETEAM_RAPIDAPI_MONTHLY_CAP", "100")),
            rapidapi_budget=int(os.environ.get("BLUETEAM_RAPIDAPI_BUDGET", "0")),
            rapidapi_budget_hours=float(os.environ.get("BLUETEAM_RAPIDAPI_BUDGET_HOURS", "8")),
            rapidapi_cache_path=os.environ.get("BLUETEAM_RAPIDAPI_CACHE", ""),
            rapidapi_raw_whois=_bool(os.environ.get("BLUETEAM_RAPIDAPI_RAW_WHOIS", "true")),
        )

    def validate(self) -> None:
        """Threat-intel keys are all optional - tools degrade gracefully."""
        if self.netra_min_interval < 0:
            raise ConfigurationError("NETRA_MIN_INTERVAL must be >= 0")
        if self.argus_min_interval < 0:
            raise ConfigurationError("ARGUS_MIN_INTERVAL must be >= 0")
        if self.rapidapi_budget < 0:
            raise ConfigurationError("BLUETEAM_RAPIDAPI_BUDGET must be >= 0")
        if self.rapidapi_budget_hours <= 0:
            raise ConfigurationError("BLUETEAM_RAPIDAPI_BUDGET_HOURS must be > 0")
        if self.rapidapi_monthly_cap <= 0:
            raise ConfigurationError("BLUETEAM_RAPIDAPI_MONTHLY_CAP must be > 0")
        if self.rapidapi_budget > self.rapidapi_monthly_cap:
            raise ConfigurationError(
                f"BLUETEAM_RAPIDAPI_BUDGET ({self.rapidapi_budget}) exceeds the account wide "
                f"BLUETEAM_RAPIDAPI_MONTHLY_CAP ({self.rapidapi_monthly_cap}); the excess would "
                f"be spent against a 429."
            )


@dataclass
class MispConfig:
    """MISP threat-intelligence instance connection parameters.
    MISP is operator-owned internal infrastructure (same trust class as the
    Wazuh Manager / Indexer), so the public-IP SSRF guard is intentionally NOT
    applied to it.
    ``api_key`` is the MISP automation key. Both ``url`` and ``api_key`` must be
    present for the tools to run; ``enabled`` encodes that. ``verify_ssl`` maps
    to the per-pool ``verify`` flag in ``_get_client`` (the flag is part of the
    pool key), so pointing at a self-signed internal MISP never relaxes TLS
    verification for any other upstream.
    """
    url: str = ""
    api_key: str = ""
    verify_ssl: bool = True
    cache_ttl: int = 900          # reputation data does not change second-to-second
    min_interval: float = 1.0     # seconds between any two MISP requests
    max_concurrent: int = 2
    timeout: float = 20.0

    @classmethod
    def from_env(cls) -> "MispConfig":
        return cls(
            url=os.environ.get("MISP_URL", "").rstrip("/"),
            api_key=os.environ.get("MISP_API_KEY", ""),
            verify_ssl=_bool(os.environ.get("MISP_VERIFYCERT", "true"), True),
            cache_ttl=int(os.environ.get("MISP_CACHE_TTL", "900")),
            min_interval=float(os.environ.get("MISP_MIN_INTERVAL", "1.0")),
            max_concurrent=int(os.environ.get("MISP_MAX_CONCURRENT", "2")),
            timeout=float(os.environ.get("MISP_TIMEOUT", "20.0")),
        )

    def validate(self) -> None:
        """MISP is optional, only a half configured instance is fatal.
        A URL with no key makes every MISP tool fail at call time with a message
        that looks like an outage, so it is rejected at startup instead.
        """
        if self.url and not self.api_key:
            raise ConfigurationError(
                "MISP_URL is set but MISP_API_KEY is empty, MISP tools will fail."
            )
        if self.cache_ttl < 0:
            raise ConfigurationError("MISP_CACHE_TTL must be >= 0")
        if self.min_interval < 0:
            raise ConfigurationError("MISP_MIN_INTERVAL must be >= 0")
        if self.max_concurrent < 1:
            raise ConfigurationError("MISP_MAX_CONCURRENT must be >= 1")
        if self.timeout <= 0:
            raise ConfigurationError("MISP_TIMEOUT must be > 0")

    @property
    def enabled(self) -> bool:
        """True when both the URL and the API key are configured."""
        return bool(self.url and self.api_key)


@dataclass
class SangforConfig:
    """Sangfor blocklist integration parameters."""
    url: str = ""
    token: str = ""
    timeout: float = 15.0
    verify_ssl: bool = False
    min_interval: float = 5.0   # in seconds

    @classmethod
    def from_env(cls) -> "SangforConfig":
        return cls(
            url=os.environ.get("SANGFOR_BLOCKLIST_URL", "").rstrip("/"),
            token=os.environ.get("SANGFOR_BLOCKLIST_TOKEN", ""),
            timeout=float(os.environ.get("SANGFOR_BLOCKLIST_TIMEOUT", "15")),
            verify_ssl=_bool(os.environ.get("SANGFOR_BLOCKLIST_VERIFY_SSL", "false")),
            min_interval=float(os.environ.get("SANGFOR_MIN_INTERVAL", "5")),
        )

    def validate(self) -> None:
        if self.min_interval < 0:
            raise ConfigurationError("SANGFOR_MIN_INTERVAL must be >= 0")


@dataclass
class RedactionConfig:
    """PII redaction policy and layer toggles."""
    policy: str = "full"     # full | protect_victim | raw
    redact_pii: bool = True
    redact_emails: bool = True
    redact_domains: bool = True
    redact_locations: bool = True
    redact_uas: bool = True
    owned_domains: str = ""
    allow_runtime_domains: bool = False   # gate for blueteam_set_owned_domains
    allow_forensic_bypass: bool = False
    forensic_token: str = ""

    _VALID_POLICIES = frozenset({"full", "protect_victim", "raw"})

    @classmethod
    def from_env(cls) -> "RedactionConfig":
        return cls(
            policy=os.environ.get("BLUETEAM_REDACTION_POLICY", "full").strip().lower(),
            redact_pii=_bool(os.environ.get("BLUETEAM_REDACT_PII", "true"), True),
            redact_emails=_bool(os.environ.get("BLUETEAM_REDACT_EMAILS", "true"), True),
            redact_domains=_bool(os.environ.get("BLUETEAM_REDACT_DOMAINS", "true"), True),
            redact_locations=_bool(os.environ.get("BLUETEAM_REDACT_LOCATIONS", "true"), True),
            redact_uas=_bool(os.environ.get("BLUETEAM_REDACT_UAS", "true"), True),
            owned_domains=os.environ.get("BLUETEAM_OWNED_DOMAINS", ""),
            allow_runtime_domains=_bool(os.environ.get("BLUETEAM_ALLOW_RUNTIME_DOMAINS", "false")),
            allow_forensic_bypass=_bool(os.environ.get("BLUETEAM_ALLOW_FORENSIC_BYPASS", "false")),
            forensic_token=os.environ.get("BLUETEAM_FORENSIC_TOKEN", ""),
        )

    def validate(self) -> None:
        if self.policy not in self._VALID_POLICIES:
            raise ConfigurationError(
                f"BLUETEAM_REDACTION_POLICY={self.policy!r} is invalid. "
                f"Must be one of: {', '.join(sorted(self._VALID_POLICIES))}."
            )
        if self.policy == "raw" and not self.allow_forensic_bypass:
            raise ConfigurationError(
                "BLUETEAM_REDACTION_POLICY='raw' requires "
                "BLUETEAM_ALLOW_FORENSIC_BYPASS=true."
            )
        # Fail-safe: 'protect_victim' with no owned domains masks NOTHING (every
        # email/domain is treated as attacker). Fall back to 'full' to prevent
        # accidental PII leaks, so operators know to set owned domains.
        if self.policy == "protect_victim" and not self.owned_domains.strip():
            logger.warning(
                "BLUETEAM_REDACTION_POLICY='protect_victim' requires BLUETEAM_OWNED_DOMAINS, "
                "but it is empty - falling back to 'full' to prevent accidental PII leaks. "
                "Set BLUETEAM_OWNED_DOMAINS to a comma-separated list of your owned domains "
                "(e.g. tangerangkota.go.id)."
            )
            self.policy = "full"
        if self.allow_forensic_bypass and self.forensic_token:
            # Token is set, validate it's non-empty and reasonable length.
            if len(self.forensic_token) < 8:
                raise ConfigurationError(
                    "BLUETEAM_FORENSIC_TOKEN must be at least 8 characters."   # use openssl rand fot generate it.
                )


@dataclass
class AttackerRegistryConfig:
    """Attacker-IOC registry persistence (JSONL)."""
    path: str = ""
    ttl: int = 604800     # 7 days; 0 = never expire
    max_entries: int = 10000

    @classmethod
    def from_env(cls) -> "AttackerRegistryConfig":
        return cls(
            path=os.environ.get("BLUETEAM_ATTACKER_REGISTRY", ""),
            ttl=int(os.environ.get("BLUETEAM_ATTACKER_REGISTRY_TTL", "604800")),
            max_entries=int(os.environ.get("BLUETEAM_ATTACKER_REGISTRY_MAX", "10000")),
        )

    def validate(self) -> None:
        pass


@dataclass
class IOCStoreConfig:
    """IOC lifecycle store persistence (JSONL)."""
    path: str = ""
    max_entries: int = 50000

    @classmethod
    def from_env(cls) -> "IOCStoreConfig":
        return cls(
            path=os.environ.get("BLUETEAM_IOC_STORE", ""),
            max_entries=int(os.environ.get("BLUETEAM_IOC_STORE_MAX", "50000")),
        )

    def validate(self) -> None:
        pass


@dataclass
class OperationalConfig:
    """Operational hardening and lifecycle parameters."""
    export_retention_days: int = 0       # 0 = keep forever
    auto_promote_ips: bool = False
    export_dir: str = "/var/log/blue-team-mcp/exports"

    @classmethod
    def from_env(cls) -> "OperationalConfig":
        return cls(
            export_retention_days=int(os.environ.get("BLUETEAM_EXPORT_RETENTION_DAYS", "0")),
            auto_promote_ips=_bool(os.environ.get("BLUETEAM_AUTO_PROMOTE_IPS", "false")),
            export_dir=os.environ.get("BLUETEAM_EXPORT_DIR", "/var/log/blue-team-mcp/exports"),
        )

    def validate(self) -> None:
        if self.export_retention_days < 0:
            raise ConfigurationError("BLUETEAM_EXPORT_RETENTION_DAYS must be >= 0")


@dataclass
class AuditConfig:
    """Audit logging and rate-limiting parameters."""
    audit_log_path: str = ""
    rate_limit: int = 0                  # 0 = no rate limiting
    investigation_history: str = ""
    mitre_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "refs/heads/master/enterprise-attack/enterprise-attack.json"
    )

    @classmethod
    def from_env(cls) -> "AuditConfig":
        return cls(
            audit_log_path=os.environ.get("BLUETEAM_AUDIT_LOG", ""),
            rate_limit=int(os.environ.get("BLUETEAM_RATE_LIMIT", "0")),
            investigation_history=os.environ.get("BLUETEAM_INVESTIGATION_HISTORY", ""),
            mitre_stix_url=os.environ.get(
                "MITRE_ATTACK_STIX",
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                "refs/heads/master/enterprise-attack/enterprise-attack.json",
            ),
        )

    def validate(self) -> None:
        if self.rate_limit < 0:
            raise ConfigurationError("BLUETEAM_RATE_LIMIT must be >= 0")


@dataclass
class LimitsConfig:
    """Performance and safety limits."""
    character_limit: int = 100000
    http_timeout: float = 30.0
    allow_untruncated: bool = False
    max_log_lines: int = 2000

    @classmethod
    def from_env(cls) -> "LimitsConfig":
        return cls(
            character_limit=int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "100000")),
            http_timeout=float(os.environ.get("HTTP_TIMEOUT", "30.0")),
            allow_untruncated=_bool(os.environ.get("BLUETEAM_ALLOW_UNTRUNCATED", "false")),
            max_log_lines=2000,
        )

    def validate(self) -> None:
        if self.character_limit < 1000:
            raise ConfigurationError("BLUETEAM_CHARACTER_LIMIT must be at least 1000")
        if self.http_timeout <= 0:
            raise ConfigurationError("HTTP_TIMEOUT must be > 0")


@dataclass
class ToolGatingConfig:
    """Tool enable/disable and read-only enforcement."""
    disabled_tools: list[str] = field(default_factory=list)
    disabled_categories: list[str] = field(default_factory=list)
    read_only: bool = False

    @classmethod
    def from_env(cls) -> "ToolGatingConfig":
        tools_str = os.environ.get("WAZUH_DISABLED_TOOLS", "")
        categories_str = os.environ.get("WAZUH_DISABLED_CATEGORIES", "")
        return cls(
            disabled_tools=[t.strip() for t in tools_str.split(",") if t.strip()],
            disabled_categories=[c.strip() for c in categories_str.split(",") if c.strip()],
            read_only=_bool(os.environ.get("WAZUH_READ_ONLY", "false")),
        )

    def validate(self) -> None:
        pass


def _fastembed_rerank_models() -> Optional[set[str]]:
    """Cross-encoder model ids fastembed can actually load.
    Returns ``None`` when fastembed is not installed, so callers can tell
    "dependency absent" apart from "model name not in the registry". Only the
    installed fastembed's registry counts: a model on Hugging Face but absent
    here can never load, and the failure would otherwise only appear as a
    per-call ``unavailable:`` status.
    """
    try:
        from fastembed.rerank.cross_encoder import TextCrossEncoder
    except ImportError:
        return None
    return {entry["model"] for entry in TextCrossEncoder.list_supported_models()}


@dataclass
class RerankConfig:
    """Two stage retrieval reranker (BM25 recall -> cross-encoder rerank), ON by default.
    Tools expose a ``rerank`` flag whose default is per tool (see each tool's field) that
    re-scores BM25 candidates with a local ONNX cross-encoder
    (``BAAI/bge-reranker-base``, MIT, ~1.0 GB).
    Never a hosted API: query and document text never leave the process.
    Startup is fail-closed. With ``enabled=True``, an unsupported model name or a
    missing fastembed raises ConfigurationError at boot instead of silently
    ranking with BM25. Set ``BLUETEAM_RERANK_ENABLED=false`` to accept BM25-only.
    ``sha256`` pins the exact cached ONNX file; when set the model is never
    downloaded at runtime (air-gapped hosts stay air-gapped).
    ``model_path`` points at a VENDORED model directory already on disk (the layout
    ``huggingface_hub.snapshot_download`` writes: ``config.json`` plus ``onnx/model.onnx``
    and its tokenizer files). When set it is handed to fastembed as
    ``specific_model_path``, so the weights are read from that path and no download path
    is reachable at all, pinned or not. Combine with ``sha256`` for a vendor-and-pin
    deployment: the pin proves the file has not changed since it was hashed.
    """
    enabled: bool = True
    model: str = "BAAI/bge-reranker-base"
    cache_path: str = ""            # empty = fastembed default cache dir
    model_path: str = ""            # vendored model dir; empty = resolve via fastembed
    max_candidates: int = 100       # hard ceiling for the rerank_candidates tool param
    sha256: str = ""                # supply chain pin: sha256 of the cached ONNX fastembed loads

    @classmethod
    def from_env(cls) -> "RerankConfig":
        return cls(
            enabled=_bool(os.environ.get("BLUETEAM_RERANK_ENABLED", "true")),
            model=os.environ.get("BLUETEAM_RERANK_MODEL", "BAAI/bge-reranker-base").strip(),
            cache_path=os.environ.get("BLUETEAM_RERANK_CACHE_PATH", ""),
            model_path=os.environ.get("BLUETEAM_RERANK_MODEL_PATH", "").strip(),
            max_candidates=int(os.environ.get("BLUETEAM_RERANK_MAX_CANDIDATES", "100")),
            sha256=os.environ.get("BLUETEAM_RERANK_MODEL_SHA256", "").strip().lower(),
        )

    def validate(self) -> None:
        if self.enabled:
            from mcp_server.core.rerank import register_custom_models
            register_custom_models()
            supported = _fastembed_rerank_models()
            if supported is None:
                raise ConfigurationError(
                    "BLUETEAM_RERANK_ENABLED=true but fastembed is not installed, so "
                    "no cross-encoder can load. Install it (setup.sh does: "
                    "pip install 'fastembed>=0.5.0,<1.0.0') or set "
                    "BLUETEAM_RERANK_ENABLED=false to accept BM25-only ranking."
                )
            if self.model not in supported:
                raise ConfigurationError(
                    "BLUETEAM_RERANK_MODEL=%r is not in fastembed's cross-encoder "
                    "registry, so it can never load and the server would silently "
                    "rank with BM25 only. Supported models: %s. "
                    "Note BAAI/bge-reranker-v2-m3 is NOT supported by fastembed; "
                    "BAAI/bge-reranker-base (MIT) is the in-registry equivalent."
                    % (self.model, ", ".join(sorted(supported)))
                )
        if self.max_candidates < 1:
            raise ConfigurationError("BLUETEAM_RERANK_MAX_CANDIDATES must be >= 1")
        if self.model_path and not os.path.isdir(self.model_path):
            raise ConfigurationError(
                "BLUETEAM_RERANK_MODEL_PATH=%r is not an existing directory. Point it at a "
                "vendored model dir (the snapshot_download layout: config.json plus "
                "onnx/model.onnx and its tokenizer files)." % self.model_path
            )
        if self.model_path and not os.path.isfile(os.path.join(self.model_path, "onnx", "model.onnx")):
            raise ConfigurationError(
                "BLUETEAM_RERANK_MODEL_PATH=%r has no onnx/model.onnx. A flat copy of the "
                "ONNX file alone is not enough: fastembed also reads config.json and the "
                "tokenizer files from the same directory." % self.model_path
            )
        if self.sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ConfigurationError(
                "BLUETEAM_RERANK_MODEL_SHA256 must be a 64-char hex sha256 digest "
                "(got %r); regenerate with: sha256sum <cached .onnx>" % self.sha256
            )


@dataclass
class RAGConfig:
    """Local case-knowledge retrieval store (ONNX embeddings + SQLite).
    Retrieval over analyst-authored cases, confirmed false positives and
    converted IR playbooks. Two independent off-switches, mirroring the
    optional-store convention used by BLUETEAM_CASE_STORE:

    - ``enabled=False`` (default) keeps the whole subsystem dormant.
    - ``db_path=""`` (default) means no store is configured.

    Setting ``enabled=True`` with an empty ``db_path`` is a startup error, not
    a silent no-op: an operator who flipped the flag expects retrieval to work,
    so failing at boot beats returning empty results forever.

    **Egress guarantee**: embeddings are computed in-process by fastembed's
    ONNX runtime. The model is pre-downloaded by setup.sh into ``cache_path``;
    when ``allow_download`` is False (default) the embedder is constructed with
    ``local_files_only=True`` so no query or document text can reach HuggingFace.
    ``allow_download`` is the one knob that permits network access, and it is
    only needed for the first bootstrap.

    **The SQLite file holds attacker IOCs.** It must not be committed; see
    .gitignore. Chunks are stored unredacted on purpose, they are embedded
    locally and never leave the process. Redaction belongs on the output path.
    """
    enabled: bool = False
    # No default path: a store the operator did not configure is a store that
    # never silently accumulates attacker IOCs under a guessed location.
    db_path: str = ""
    model: str = "BAAI/bge-small-en-v1.5"
    cache_path: str = ""            # empty = fastembed default model cache
    max_candidates: int = 100       # Stage 1 recall (high recall, wide net)
    top_k: int = 10                 # Stage 3 default after rerank (high precision)
    max_chunks: int = 50000         # hard ceiling on corpus size
    chunk_chars: int = 1200
    chunk_overlap: int = 200
    allow_download: bool = False    # False = local_files_only, no network
    sha256: str = ""                # supply chain pin: sha256 of the cached ONNX

    @classmethod
    def from_env(cls) -> "RAGConfig":
        return cls(
            enabled=_bool(os.environ.get("BLUETEAM_RAG_ENABLED", "false")),
            db_path=os.environ.get("BLUETEAM_RAG_DB", "").strip(),
            model=os.environ.get("BLUETEAM_RAG_MODEL", "BAAI/bge-small-en-v1.5").strip(),
            cache_path=os.environ.get("BLUETEAM_RAG_CACHE_PATH", "").strip(),
            max_candidates=int(os.environ.get("BLUETEAM_RAG_MAX_CANDIDATES", "100")),
            top_k=int(os.environ.get("BLUETEAM_RAG_TOP_K", "10")),
            max_chunks=int(os.environ.get("BLUETEAM_RAG_MAX_CHUNKS", "50000")),
            chunk_chars=int(os.environ.get("BLUETEAM_RAG_CHUNK_CHARS", "1200")),
            chunk_overlap=int(os.environ.get("BLUETEAM_RAG_CHUNK_OVERLAP", "200")),
            allow_download=_bool(os.environ.get("BLUETEAM_RAG_ALLOW_DOWNLOAD", "false")),
            sha256=os.environ.get("BLUETEAM_RAG_MODEL_SHA256", "").strip().lower(),
        )

    def validate(self) -> None:
        if self.enabled and not self.db_path:
            raise ConfigurationError(
                "BLUETEAM_RAG_ENABLED=true requires BLUETEAM_RAG_DB to be set "
                "(an enabled retrieval store with no path can only return empty results)."
            )
        if self.db_path and not os.path.isabs(self.db_path):
            raise ConfigurationError(
                f"BLUETEAM_RAG_DB must be an absolute path (got {self.db_path!r})"
            )
        if self.enabled and not self.model:
            raise ConfigurationError(
                "BLUETEAM_RAG_MODEL must not be empty when BLUETEAM_RAG_ENABLED=true"
            )
        if self.top_k < 1:
            raise ConfigurationError("BLUETEAM_RAG_TOP_K must be >= 1")
        if self.max_candidates < self.top_k:
            raise ConfigurationError(
                f"BLUETEAM_RAG_MAX_CANDIDATES ({self.max_candidates}) must be >= "
                f"BLUETEAM_RAG_TOP_K ({self.top_k}) - recall stage cannot be "
                "narrower than the precision stage."
            )
        if self.max_chunks < 1:
            raise ConfigurationError("BLUETEAM_RAG_MAX_CHUNKS must be >= 1")
        if self.chunk_chars < 200:
            raise ConfigurationError("BLUETEAM_RAG_CHUNK_CHARS must be >= 200")
        if not (0 <= self.chunk_overlap < self.chunk_chars):
            raise ConfigurationError(
                f"BLUETEAM_RAG_CHUNK_OVERLAP must be 0 <= overlap < chunk_chars "
                f"(got {self.chunk_overlap} vs {self.chunk_chars})"
            )
        if self.sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ConfigurationError(
                "BLUETEAM_RAG_MODEL_SHA256 must be a 64-char hex sha256 digest "
                "(got %r); regenerate with: sha256sum <cached .onnx>" % self.sha256
            )


@dataclass
class SSRFConfig:
    """Outbound URL / SSRF guard configuration.
    ``allowed_internal_domains`` is a comma separated allowlist of internal
    domains the webshell checker (and future URL fetchers) may reach even when
    they resolve to non-public IPs (e.g. ``tangerangkota.go.id``). Any host not
    in this list must resolve only to public (``is_global``) IPs.
    """
    allowed_internal_domains: list[str] = field(default_factory=list)
    @classmethod
    def from_env(cls) -> "SSRFConfig":
        raw = os.environ.get("ALLOWED_INTERNAL_DOMAINS", "")
        return cls(
            allowed_internal_domains=[d.strip().lower() for d in raw.split(",") if d.strip()]
        )

    def validate(self) -> None:
        for d in self.allowed_internal_domains:
            if not re.fullmatch(r"[a-z0-9.-]+", d):
                raise ConfigurationError(
                    f"ALLOWED_INTERNAL_DOMAINS entry {d!r} is not a valid domain name."
                )


@dataclass
class YaraConfig:
    """YARA rule synthesis settings (blueteam_yara_rule_generate / _save).
    ``rules_dir`` is a STAGING directory. Rules written there are not loaded by
    Wazuh until an operator promotes them. Pointing this at a live rules.d path
    defeats the manual review step, so it defaults to a dedicated staging dir.
    """

    rules_dir: str = "/opt/yara_rules/yara_staging"

    @classmethod
    def from_env(cls) -> "YaraConfig":
        return cls(
            rules_dir=os.environ.get(
                "BLUETEAM_YARA_RULES_DIR", "/opt/yara_rules/yara_staging"
            ).strip(),
        )

    def validate(self) -> None:
        if not self.rules_dir:
            raise ConfigurationError("BLUETEAM_YARA_RULES_DIR must not be empty")
        if not os.path.isabs(self.rules_dir):
            raise ConfigurationError(
                f"BLUETEAM_YARA_RULES_DIR must be an absolute path (got {self.rules_dir!r})"
            )


@dataclass
class SigmaConfig:
    """Sigma rule synthesis settings (blueteam_sigma_rule_generate / _save).
    ``rules_dir`` is a STAGING directory, same contract as YaraConfig: nothing
    written there is loaded by an engine until an operator promotes the file.
    ``verify_fields`` and ``check_existing`` are the operator-level defaults for
    the per-call flags. Turn them off globally only if the Indexer or Manager API
    is unreachable and the drafts are still wanted.
    """

    rules_dir: str = "/opt/sigma_rules/sigma_staging"
    verify_fields: bool = True
    check_existing: bool = True
    # OpenSearch artifact target for blueteam_sigma_rule_convert. The pySigma
    # backend defaults to 'beats-*', which is wrong for Wazuh on every format
    # that embeds an index name (monitor, saved_search).
    index_pattern: str = "wazuh-alerts-*"
    monitor_interval: int = 5

    @classmethod
    def from_env(cls) -> "SigmaConfig":
        return cls(
            rules_dir=os.environ.get(
                "BLUETEAM_SIGMA_RULES_DIR", "/opt/sigma_rules/sigma_staging"
            ).strip(),
            verify_fields=_bool(os.environ.get("BLUETEAM_SIGMA_VERIFY_FIELDS", ""), True),
            check_existing=_bool(os.environ.get("BLUETEAM_SIGMA_CHECK_EXISTING", ""), True),
            index_pattern=os.environ.get(
                "BLUETEAM_SIGMA_INDEX_PATTERN", "wazuh-alerts-*"
            ).strip(),
            monitor_interval=int(
                os.environ.get("BLUETEAM_SIGMA_MONITOR_INTERVAL", "5")
            ),
        )

    def validate(self) -> None:
        if not self.rules_dir:
            raise ConfigurationError("BLUETEAM_SIGMA_RULES_DIR must not be empty")
        if not os.path.isabs(self.rules_dir):
            raise ConfigurationError(
                f"BLUETEAM_SIGMA_RULES_DIR must be an absolute path (got {self.rules_dir!r})"
            )
        if not self.index_pattern:
            raise ConfigurationError("BLUETEAM_SIGMA_INDEX_PATTERN must not be empty")
        if not (1 <= self.monitor_interval <= 1440):
            raise ConfigurationError(
                f"BLUETEAM_SIGMA_MONITOR_INTERVAL must be 1-1440 minutes "
                f"(got {self.monitor_interval})"
            )


# Top level Config aggregating all groups
@dataclass
class Config:
    """Master configuration aggregating all sub-config groups.
    Usage:
        config = Config.from_env()
        config.validate()          # raises ConfigurationError on invalid values
        config.emit_warnings()     # logs warnings for non-fatal issues
    """

    server: ServerConfig = field(default_factory=ServerConfig)
    wazuh_manager: WazuhManagerConfig = field(default_factory=WazuhManagerConfig)
    wazuh_indexer: WazuhIndexerConfig = field(default_factory=WazuhIndexerConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    misp: MispConfig = field(default_factory=MispConfig)
    sangfor: SangforConfig = field(default_factory=SangforConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    attacker_registry: AttackerRegistryConfig = field(default_factory=AttackerRegistryConfig)
    ioc_store: IOCStoreConfig = field(default_factory=IOCStoreConfig)
    operational: OperationalConfig = field(default_factory=OperationalConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    tool_gating: ToolGatingConfig = field(default_factory=ToolGatingConfig)
    rerank: RerankConfig = field(default_factory=RerankConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    ssrf: SSRFConfig = field(default_factory=SSRFConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    sigma: SigmaConfig = field(default_factory=SigmaConfig)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a fully-populated Config from environment variables."""
        return cls(
            server=ServerConfig.from_env(),
            wazuh_manager=WazuhManagerConfig.from_env(),
            wazuh_indexer=WazuhIndexerConfig.from_env(),
            threat_intel=ThreatIntelConfig.from_env(),
            misp=MispConfig.from_env(),
            sangfor=SangforConfig.from_env(),
            redaction=RedactionConfig.from_env(),
            attacker_registry=AttackerRegistryConfig.from_env(),
            ioc_store=IOCStoreConfig.from_env(),
            operational=OperationalConfig.from_env(),
            audit=AuditConfig.from_env(),
            limits=LimitsConfig.from_env(),
            tool_gating=ToolGatingConfig.from_env(),
            rerank=RerankConfig.from_env(),
            rag=RAGConfig.from_env(),
            ssrf=SSRFConfig.from_env(),
            yara=YaraConfig.from_env(),
            sigma=SigmaConfig.from_env(),
        )

    def validate(self) -> None:
        """Validate all config groups. Raises ConfigurationError on the first fatal issue."""
        self.server.validate()
        self.wazuh_manager.validate()
        self.wazuh_indexer.validate()
        self.threat_intel.validate()
        self.misp.validate()
        self.sangfor.validate()
        self.redaction.validate()
        self.attacker_registry.validate()
        self.ioc_store.validate()
        self.operational.validate()
        self.audit.validate()
        self.limits.validate()
        self.tool_gating.validate()
        self.rerank.validate()
        self.rag.validate()
        self.ssrf.validate()
        self.yara.validate()
        self.sigma.validate()

    def emit_warnings(self) -> None:
        """Log warnings for non-fatal configuration issues.
        Call AFTER validate() succeeds - these are advisory, not blocking.
        """
        if not self.wazuh_manager.url:
            logger.warning("WAZUH_API_URL not set - Manager API tools disabled.")
        if not self.wazuh_manager.verify_ssl:
            logger.warning("WAZUH_API_VERIFY_SSL disabled - TLS OFF for Wazuh Manager API.")
        if not self.wazuh_indexer.verify_ssl:
            logger.warning("WAZUH_INDEXER_VERIFY_SSL disabled - TLS OFF for Wazuh Indexer.")
        if not self.threat_intel.crowdsec_api_key:
            logger.warning("CROWDSEC_API_KEY not set - CrowdSec tools disabled.")
        if not self.threat_intel.abuseipdb_api_key:
            logger.warning("ABUSEIPDB_API_KEY not set - AbuseIPDB lookup disabled.")
        if not self.threat_intel.virustotal_api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set - VirusTotal lookups disabled.")
        if not self.threat_intel.rapidapi_key:
            logger.warning("RAPIDAPI_KEY not set - RapidAPI lookups (IP blacklist / IOC search / breach check) disabled.")
        else:
            logger.info(
                "RapidAPI budget: %d/%d armed for %.1fh; %s; WHOIS %s.",
                self.threat_intel.rapidapi_budget, self.threat_intel.rapidapi_monthly_cap,
                self.threat_intel.rapidapi_budget_hours,
                ("persistent cache " + self.threat_intel.rapidapi_cache_path)
                if self.threat_intel.rapidapi_cache_path else "in-memory cache only",
                "raw in blueteam_ip_intel_bulk" if self.threat_intel.rapidapi_raw_whois
                else "allowlisted everywhere",
            )
            if not self.threat_intel.rapidapi_budget:
                logger.warning(
                    "BLUETEAM_RAPIDAPI_BUDGET=0 - every RapidAPI call is refused "
                    "(fail-closed). Arm it for an incident window."
                )
        if not self.misp.enabled:
            logger.warning("MISP_URL / MISP_API_KEY not set - MISP tools disabled.")
        elif not self.misp.verify_ssl:
            logger.warning("MISP_VERIFYCERT disabled - TLS verification OFF for MISP only.")
        if self.limits.allow_untruncated:
            logger.warning("BLUETEAM_ALLOW_UNTRUNCATED=true - character-limit bypass ENABLED.")
        if self.redaction.allow_forensic_bypass:
            logger.warning(
                "BLUETEAM_ALLOW_FORENSIC_BYPASS=true - forensic raw output enabled "
                "(bypass_redaction/redaction_policy='raw' will be honored)."
            )
        # Reranker availability is enforced hard in RerankConfig.validate()
        # (fail closed at startup), so it is deliberately not warned about here.
        if self.rag.enabled:
            import importlib.util
            if importlib.util.find_spec("fastembed") is None:
                logger.warning(
                    "BLUETEAM_RAG_ENABLED=true but fastembed is not installed - "
                    "retrieval will report unavailable, not result in empty hits."
                )
            elif not os.path.exists(self.rag.db_path):
                logger.warning(
                    "BLUETEAM_RAG_DB=%s does not exist yet - ingest a corpus to "
                    "create it (setup.sh does not seed the store).", self.rag.db_path
                )


# Module-level singleton, initialized by mcp_server/__init__.py at startup.
config: Optional[Config] = None
def init_config() -> Config:
    """Build, validate, and store the global Config singleton.
    Called once at server startup, before any tools are registered.
    Returns the config instance (also available as module-level ``config``).
    """
    global config
    config = Config.from_env()
    config.validate()
    config.emit_warnings()
    logger.info(
        "Configuration validated - Manager=%s, Indexer=%s, %d threat-intel providers.",
        "enabled" if config.wazuh_manager.url else "disabled",
        "enabled" if config.wazuh_indexer.url else "disabled",
        sum(1 for k in [
            config.threat_intel.crowdsec_api_key,
            config.threat_intel.threatfox_api_key,
            config.threat_intel.abuseipdb_api_key,
            config.threat_intel.virustotal_api_key,
            config.threat_intel.netra_api_key,
            config.threat_intel.argus_api_key,
            config.threat_intel.rapidapi_key,
        ] if k),
    )
    return config
