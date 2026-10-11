#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
PII redaction pipeline. Layer 1 (credentials) is never bypassable.
Three redaction policies (BLUETEAM_REDACTION_POLICY env / per-call param):
- "full" (default):    Shape-based masking - emails, private IPs, ALL domains,
                        paths, identity fields. Registered attacker IOCs are exempt.
- "protect_victim":    Mask ONLY victim-owned indicators - emails/domains at
                        owned domains (BLUETEAM_OWNED_DOMAINS), private IPs,
                        paths, identity fields, agent names. Attacker domains,
                        attacker emails and payload contents stay intact.
- "raw":               Layer 1 credential strip ONLY. Hard-gated behind
                        BLUETEAM_ALLOW_FORENSIC_BYPASS (default false).
"""
from __future__ import annotations
import hashlib, os, re, logging
from typing import Any
from collections import Counter, OrderedDict
from mcp_server import (BLUETEAM_REDACT_PII, BLUETEAM_REDACT_EMAILS, BLUETEAM_REDACT_DOMAINS,
                         BLUETEAM_REDACT_LOCATIONS, BLUETEAM_REDACT_IDENTITIES,
                         BLUETEAM_ALLOW_FORENSIC_BYPASS, BLUETEAM_ALLOW_IDENTITY_REVEAL,
                         BLUETEAM_REDACTION_POLICY,
                         BLUETEAM_OWNED_DOMAINS, BLUETEAM_FORENSIC_TOKEN)
from mcp_server.core.attacker_registry import is_attacker_ioc
from mcp_server.core import metrics

logger = logging.getLogger("blue_team_mcp.redact")

_REDACT_SALT = os.environ.get(
    "BLUETEAM_REDACT_SALT",
    hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:16]
)

# Bounded quantifiers and a local-part boundary: an unbounded local part makes
# the layer quadratic on long attacker payloads (50k chars took 11s).
_REDACT_EMAIL_RE = re.compile(
    r"(?<![a-zA-Z0-9._%+-])([a-zA-Z0-9._%+-]{1,64})@([a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,})")

# Memoize string redaction results. The string path is pure given (data, policy,
# reveal, layer toggles), so repeated identical payloads are redacted once.
# Bounded LRU - the redaction boundary is a hot path (called per tool + audit),
# and identical alert text recurs constantly across batch lookups.
_REDACT_MEMO: OrderedDict = OrderedDict()
_REDACT_MEMO_MAX = 2000
_REDACT_MEMO_MAX_STR = 50_000  # don't memoize very large strings (memory)

# Owned parent domains (victim infrastructure) - mask these subdomains/emails
_OWNED_DOMAINS: set[str] = {d.strip().lower().rstrip(".")
                            for d in BLUETEAM_OWNED_DOMAINS.split(",") if d.strip()}


def get_owned_domains() -> set[str]:
    """Return the current runtime owned-domains set (read-only view)."""
    return set(_OWNED_DOMAINS)


def set_owned_domains(domains: str) -> set[str]:
    """Update the runtime owned-domains set (comma-separated), clearing the redaction memo.

    In-memory only - the persistent default is the BLUETEAM_OWNED_DOMAINS env var.
    Call this to switch which domains are treated as victim infrastructure without
    a restart. The redaction memo is cleared because cached masks may reflect the
    previous owned-domain set.
    """
    global _OWNED_DOMAINS
    _OWNED_DOMAINS = {d.strip().lower().rstrip(".")
                      for d in (domains or "").split(",") if d.strip()}
    _REDACT_MEMO.clear()
    return set(_OWNED_DOMAINS)

# Legacy key-name fallback for dynamic fields that never made it into the template.
_IDENTITY_KEYS = ("account", "srcuser", "dstuser", "user", "username")

# Template-derived identity paths masked in full AND protect_victim.
_IDENTITY_PATHS: frozenset[str] = frozenset({
    "data.srcuser", "data.dstuser", "data.osquery.columns.user", "data.osquery.columns.username",
    "data.win.eventdata.subjectUserName", "data.win.eventdata.subjectUserSid",
    "data.win.eventdata.targetUserName", "data.win.eventdata.targetUserSid",
    "data.win.system.userID", "data.win.system.securityUserID",
    "data.audit.acct", "data.audit.auid", "data.audit.uid", "data.audit.euid",
    "data.audit.suid", "data.audit.fsuid", "data.audit.gid", "data.audit.egid",
    "data.audit.sgid", "data.audit.fsgid", "data.audit.old-auid",
    "data.aws.userIdentity.userName", "data.aws.userIdentity.accountId",
    "data.aws.userIdentity.accessKeyId",
    "data.aws.resource.accessKeyDetails.userName",
    "data.aws.resource.accessKeyDetails.principalId",
    "data.aws.responseElements.loginProfile.userName",
    "data.aws.responseElements.user.userName", "data.aws.responseElements.user.userId",
    "data.aws.responseElements.ownerId",
    "data.ms-graph.userPrincipalName", "data.ms-graph.userId", "data.ms-graph.userDisplayName",
    "data.ms-graph.actor.userPrincipalName", "data.ms-graph.actor.userId",
    "data.ms-graph.actor.servicePrincipalName",
    "data.office365.UserId", "data.office365.Actor.ID",
    "data.osquery.columns.gid",
    "data.process.euser", "data.process.ruser", "data.process.suser",
    "data.process.egroup", "data.process.sgroup", "data.process.fgroup", "data.process.rgroup",
    "syscheck.uid_before", "syscheck.uid_after", "syscheck.uname_before", "syscheck.uname_after",
    "syscheck.gid_before", "syscheck.gid_after", "syscheck.gname_before", "syscheck.gname_after",
    "syscheck.audit.user.id", "syscheck.audit.user.name",
    "syscheck.audit.login_user.id", "syscheck.audit.login_user.name",
    "syscheck.audit.effective_user.id", "syscheck.audit.effective_user.name",
    "syscheck.audit.group.id", "syscheck.audit.group.name",
    "syscheck.audit.login_group.id", "syscheck.audit.login_group.name",
})

# Layer 1 credential keys. The suffix list is mandatory; the path set covers
# secret-bearing keys the suffix cannot match (no secret in the key name).
_CREDENTIAL_SUFFIX_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|accesskey|privatekey)$", re.IGNORECASE)
_CREDENTIAL_PATHS: frozenset[str] = frozenset({
    "data.aws.requestParameters.masterUsername",
    "data.aws.requestParameters.accessKeyId",
    "data.aws.resource.accessKeyDetails.accessKeyId",
    "data.ms-graph.activationLockBypassCode",
    "data.ms-graph.deviceHealthAttestationState.attestationIdentityKey",
})
# Legitimate fields whose names look credential-like but carry no secret value.
_CREDENTIAL_KEY_ALLOWLIST: frozenset[str] = frozenset({
    "data.audit.key",
    "data.win.eventdata.keyName",
    "data.win.system.keywords",
})


def _is_credential_path(path: str) -> bool:
    if path in _CREDENTIAL_KEY_ALLOWLIST:
        return False
    if path in _CREDENTIAL_PATHS:
        return True
    return bool(_CREDENTIAL_SUFFIX_RE.search(path.rsplit(".", 1)[-1]))

_POLICIES = ("full", "protect_victim", "raw")

# Layer 6 (protect_victim): bare hostname/agent-name candidates in aggregation
# bucket "key" values and hostname-context dict keys. Narrow pattern - lowercase
# single-label, must contain a digit or hyphen - so common words ("web", "high",
# rule descriptions, countries) and CVE-style tokens never get masked.
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOSTNAME_CONTEXT_KEYS = ("host", "hostname", "server", "node", "host_name")

# Attacker-supplied forensic fields. The location layer must not shorten these
# or inject a hash marker; security layers (emails, IPs, domains) still apply.
_FORENSIC_PAYLOAD_PATHS = ("full_log", "data.url", "data.user_agent")


def _is_forensic_payload_path(path: str) -> bool:
    """True when a node path ends at a forensic payload field."""
    return any(path == p or path.endswith("." + p) for p in _FORENSIC_PAYLOAD_PATHS)


def _is_hostname_candidate(v: str) -> bool:
    if not (3 <= len(v) <= 63):
        return False
    if not _HOSTNAME_RE.match(v):
        return False
    if v.isalpha():
        return False  # require a digit or hyphen - "web" / "admin" pass through
    if v.isdigit():
        return False
    return True

# Layer 1: Credential stripping
_CREDENTIAL_STRIP_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r'Authorization:\s*Bearer\s+\S+', re.IGNORECASE),
     'Authorization: Bearer <BEARER_REDACTED>'),
    (re.compile(r'Authorization:\s*Basic\s+\S+', re.IGNORECASE),
     'Authorization: Basic <BASIC_REDACTED>'),
    (re.compile(r'x-api-key:\s*\S+', re.IGNORECASE),
     'x-api-key: <API_KEY_REDACTED>'),
    (re.compile(r'(?:api[_-]?key)\s*[=:]\s*\S+', re.IGNORECASE),
     'api_key=<API_KEY_REDACTED>'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{0,1000}\b'),
     '<JWT_REDACTED>'),
    (re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----'
        r'.*?'
        r'-----END (?:RSA |EC |OPENSSH |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----',
        re.DOTALL,
    ), '<PRIVATE_KEY_REDACTED>'),
    (re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16}|sk_(?:live|test)_[a-zA-Z0-9]{24,})\b'),
     '<CLOUD_API_KEY_REDACTED>'),
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,}|glpat-[A-Za-z0-9_-]{20,})\b'),
     '<VCS_TOKEN_REDACTED>'),
    (re.compile(r'\b(?:sk-(?!live|test)|sk-ant-)[a-zA-Z0-9_-]{20,}\b'),
     '<AI_API_KEY_REDACTED>'),
    (re.compile(r'(password|passwd|pwd|secret)\s*[=:]\s*\S+', re.IGNORECASE),
     r'\1=<PASSWORD_REDACTED>'),
    (re.compile(r'\b(xox[abpro]-[0-9]+-[0-9]+-[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?|AIza[0-9A-Za-z_-]{35})\b'),
     '<PLATFORM_TOKEN_REDACTED>'),
]


# Forensic hashing
def _hash_email_for_audit(email: str) -> str:
    """Return 8-char hex hash prefix for forensic cross-referencing."""
    return hashlib.sha256(f"{_REDACT_SALT}:{email}".encode()).hexdigest()[:8]


def _mask_domain(domain: str) -> str:
    """Mask subdomain part, keep TLD visible. Internal/parent domains fully masked."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return domain
    # Internal TLDs - mask the entire domain
    if parts[-1] in ("local", "internal", "corp", "lan", "home", "test"):
        return parts[0][0] + "*" * (len(parts[0]) - 1) + "." + parts[-1] if len(parts) == 2 else \
               parts[0][0] + "*" * (len(parts[0]) - 2) + parts[0][-1] + ".***." + parts[-1]
    if len(parts) < 3:
        return domain
    sub = parts[0]
    if len(sub) <= 2:
        masked = sub[0] + "*" * (len(sub) - 1)
    else:
        masked = sub[0] + "*" * (len(sub) - 2) + sub[-1]
    return f"{masked}." + ".".join(parts[1:])


def _mask_username(v: str) -> str:
    """Mask a username/account value, keeping first/last char + forensic hash."""
    if len(v) <= 1:
        return "***"
    return f"{v[0]}***{v[-1]} [h:{_hash_email_for_audit(v)}]"


def _is_owned_domain(domain: str) -> bool:
    """True if domain is owned infrastructure (exact or subdomain of owned parent)."""
    d = (domain or "").strip().lower().rstrip(".")
    return any(d == o or d.endswith("." + o) for o in _OWNED_DOMAINS)


def _should_mask_domain(domain: str, policy: str, reveal_owned: bool = False) -> bool:
    """Layer 4 decision: mask this domain under the active policy?"""
    if policy == "raw":
        return False
    if is_attacker_ioc(domain):
        return False  # registered attacker IOC - never mask
    if reveal_owned and _is_owned_domain(domain):
        return False  # forensic: owned-domain values exposed unmasked
    if policy == "protect_victim":
        return _is_owned_domain(domain)
    return True  # full: shape-based (legacy)


def _should_mask_email(email: str, policy: str, reveal_owned: bool = False) -> bool:
    """Layer 2 decision: mask this email under the active policy?"""
    if policy == "raw":
        return False
    if is_attacker_ioc(email):
        return False
    domain = email.rsplit("@", 1)[-1] if "@" in email else email
    if is_attacker_ioc(domain):
        return False
    if reveal_owned and _is_owned_domain(domain):
        return False  # forensic: owned domain emails exposed unmasked
    if policy == "protect_victim":
        return _is_owned_domain(domain)
    return True  # full


def _should_mask_ip(ip: str, policy: str) -> bool:
    """Layer 3 decision: mask this (private) IP under the active policy?"""
    if policy == "raw":
        return False
    if is_attacker_ioc(ip):
        return False  # registered attacker IP - never mask
    return True


def _resolve_policy(bypass: bool, params: Any, policy: str | None) -> str:
    """Resolve the effective redaction policy for one call.

    Precedence: explicit policy arg > params.redaction_policy field >
    params.bypass_redaction / bypass flag > BLUETEAM_REDACTION_POLICY env.
    """
    if policy is not None:
        if policy not in _POLICIES:
            raise ValueError(f"redaction_policy must be one of {_POLICIES}, got {policy!r}")
        return policy
    if params is not None:
        p = getattr(params, "redaction_policy", None)
        if p is not None:
            return _resolve_policy(False, None, p)
        if getattr(params, "bypass_redaction", False):
            return "raw"
    if bypass:
        return "raw"
    return BLUETEAM_REDACTION_POLICY


def _strip_credentials(data: Any, path: str = "") -> Any:
    """Layer 1 only - recursive credential strip (raw policy path)."""
    if isinstance(data, str):
        for pattern, replacement in _CREDENTIAL_STRIP_RULES:
            data = pattern.sub(replacement, data)
        return data
    if isinstance(data, dict):
        out: dict = {}
        for k, v in data.items():
            child_path = f"{path}.{k}" if path else k
            out[k] = ("<CREDENTIAL_REDACTED>" if _is_credential_path(child_path)
                      else _strip_credentials(v, child_path))
        return out
    if isinstance(data, list):
        return [_strip_credentials(item, path) for item in data]
    return data


# Composable string redaction layers; layer functions live in redact_layers.py.
from mcp_server.core.redact_layers import (_apply_email_layer, _apply_ip_layer,
    _apply_domain_layer, _apply_location_layer)

# Main redaction pipeline
def _redact_alert_data(data: Any, *, bypass: bool = False, params: Any = None,
                       policy: str | None = None, reveal_owned: bool = False,
                       reveal_identities: bool = False,
                       forensic_token: str | None = None, path: str = "",
                       skip_location: bool = False) -> Any:
    """Apply layered PII and credential masking. Layer 1 NEVER bypassable.

    Policies:
      - "full": shape-based masking (legacy default).
      - "protect_victim": mask victim-owned indicators only; attacker IOCs,
        attacker domains/emails and payload contents stay intact.
      - "raw": Layer 1 credential strip only - HARD-GATED behind
        BLUETEAM_ALLOW_FORENSIC_BYPASS (default false).

    reveal_owned (forensic): expose emails/subdomains at owned domains
    (BLUETEAM_OWNED_DOMAINS) unmasked while all other masking stays on.
    Layer 1 credentials remain masked. Ignored under policy="raw".

    reveal_identities (forensic): expose identity-layer values (identity paths,
    usernames, agent/host bucket names) unmasked. Hard-gated behind
    BLUETEAM_ALLOW_IDENTITY_REVEAL (default false) and a matching
    BLUETEAM_FORENSIC_TOKEN. Layer 1 credentials remain masked.

    Forensic payload fields (full_log, data.url, data.user_agent) skip the
    location layer so the attacker-supplied value is never shortened; the other
    security layers still apply.

    Layers:
      1. Credential stripping (MANDATORY - never configurable; value patterns
         plus credential-suffix/key-name masking)
      2. Email redaction (BLUETEAM_REDACT_EMAILS)
      3. Internal IP masking (BLUETEAM_REDACT_PII)
      4. Domain/hostname masking (BLUETEAM_REDACT_DOMAINS)
      5. Log location masking (BLUETEAM_REDACT_LOCATIONS)
      6. Hostname/agent-name masking (protect_victim, bucket-key contexts)
      7. Template-path identity masking - full and protect_victim, gated by
         BLUETEAM_REDACT_IDENTITIES (BLUETEAM_REDACT_PII=false disables it too)

    Layer chain: layers 2-5 are composed as a registry of
    (name, enabled_check, apply_fn). Add new string layers by appending to
    ``_STRING_REDACTION_LAYERS`` - the dispatcher applies them in order. Layers
    6-7 act on dict keys and paths during the recursive walk.
    """
    pol = _resolve_policy(bypass, params, policy)
    reveal = reveal_owned or (getattr(params, "reveal_owned", False) if params is not None else False)
    reveal_ident = reveal_identities or (
        getattr(params, "reveal_identities", False) if params is not None else False)
    caller_token = forensic_token or (
        getattr(params, "forensic_token", None) if params is not None else None)
    forensic_payload = skip_location or _is_forensic_payload_path(path)

    if pol == "raw":
        if not BLUETEAM_ALLOW_FORENSIC_BYPASS:
            metrics.record_gate_failure()
            raise ValueError(
                "bypass_redaction / redaction_policy='raw' requested but "
                "BLUETEAM_ALLOW_FORENSIC_BYPASS is not enabled. "
                "Set BLUETEAM_ALLOW_FORENSIC_BYPASS=true to allow forensic raw output."
            )
        if BLUETEAM_FORENSIC_TOKEN:
            caller_token = forensic_token or (getattr(params, "forensic_token", None) if params is not None else None)
            if not caller_token or caller_token != BLUETEAM_FORENSIC_TOKEN:
                metrics.record_gate_failure()
                raise ValueError(
                    "raw/forensic bypass requires the operator forensic token "
                    "(BLUETEAM_FORENSIC_TOKEN). Pass forensic_token=<token>."
                )
        logger.warning("REDACTION BYPASSED (raw) - Layer 1 credential strip only")
        return _strip_credentials(data)

    if reveal_ident:
        if not BLUETEAM_ALLOW_IDENTITY_REVEAL:
            metrics.record_gate_failure()
            raise ValueError(
                "reveal_identities requested but BLUETEAM_ALLOW_IDENTITY_REVEAL is not "
                "enabled. Set BLUETEAM_ALLOW_IDENTITY_REVEAL=true to allow identity reveal."
            )
        if not BLUETEAM_FORENSIC_TOKEN or caller_token != BLUETEAM_FORENSIC_TOKEN:
            metrics.record_gate_failure()
            raise ValueError(
                "reveal_identities requires the operator forensic token "
                "(BLUETEAM_FORENSIC_TOKEN). Pass forensic_token=<token>."
            )

    if pol == "protect_victim":
        logger.debug("redaction policy=protect_victim")

    # Layer chain entries: (name, enabled_check, apply_fn).
    _STRING_REDACTION_LAYERS: list[tuple[str, object, object]] = [
        ("emails", lambda: BLUETEAM_REDACT_EMAILS, _apply_email_layer),
        ("ips", lambda: BLUETEAM_REDACT_PII, _apply_ip_layer),
        ("domains", lambda: BLUETEAM_REDACT_DOMAINS, _apply_domain_layer),
        ("locations", lambda: BLUETEAM_REDACT_LOCATIONS, _apply_location_layer),
    ]
    active_layers = _STRING_REDACTION_LAYERS
    if forensic_payload:
        active_layers = [entry for entry in _STRING_REDACTION_LAYERS if entry[0] != "locations"]

    def _apply_credential_layer(data: str) -> str:
        """Layer 1: Credential stripping (ALWAYS)."""
        for pattern, replacement in _CREDENTIAL_STRIP_RULES:
            data = pattern.sub(replacement, data)
        return data

    # Pre-define layer functions (closures capture pol/reveal from outer scope)

    if isinstance(data, str):
        if not data or len(data) > _REDACT_MEMO_MAX_STR:
            # Too large to memoize (or empty) - redact directly.
            data = _apply_credential_layer(data)
            for layer_name, check, apply_fn in active_layers:
                if not check():
                    continue
                try:
                    data = apply_fn(data, pol, reveal)
                except Exception:
                    logger.debug("redaction layer '%s' failed - continuing", layer_name)
            return data
        memo_key = (data, pol, reveal, BLUETEAM_REDACT_EMAILS, BLUETEAM_REDACT_PII,
                    BLUETEAM_REDACT_DOMAINS, BLUETEAM_REDACT_LOCATIONS,
                    BLUETEAM_REDACT_IDENTITIES, reveal_ident, forensic_payload)
        cached = _REDACT_MEMO.get(memo_key)
        if cached is not None:
            _REDACT_MEMO.move_to_end(memo_key)
            return cached

        # Layer 1: Credential stripping (never bypassed)
        data = _apply_credential_layer(data)

        # Apply enabled layers in order; append to _STRING_REDACTION_LAYERS to add one.
        for layer_name, check, apply_fn in active_layers:
            if not check():
                continue
            try:
                data = apply_fn(data, pol, reveal)
            except Exception:
                logger.debug("redaction layer '%s' failed - continuing", layer_name)

        _REDACT_MEMO[memo_key] = data
        _REDACT_MEMO.move_to_end(memo_key)
        if len(_REDACT_MEMO) > _REDACT_MEMO_MAX:
            _REDACT_MEMO.popitem(last=False)
        return data

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            child_path = f"{path}.{k}" if path else k
            if _is_credential_path(child_path):
                result[k] = "<CREDENTIAL_REDACTED>"
                continue
            if BLUETEAM_REDACT_PII and BLUETEAM_REDACT_IDENTITIES and not reveal_ident \
                    and child_path in _IDENTITY_PATHS and isinstance(v, str) and v:
                result[k] = _mask_username(v)
                continue
            if k == "domain" and isinstance(v, str) and BLUETEAM_REDACT_DOMAINS \
                    and _should_mask_domain(v, pol, reveal):
                v = _mask_domain(v)
            elif k == "location" and isinstance(v, str) and BLUETEAM_REDACT_LOCATIONS:
                parts = v.rstrip("/").split("/")
                leaf = parts[-1] if len(parts) > 1 else v
                path_hash = hashlib.sha256(f"{_REDACT_SALT}:{v}".encode()).hexdigest()[:6]
                v = f".../{leaf} [h:{path_hash}]"
            masked_v = _redact_alert_data(v, policy=pol, reveal_owned=reveal,
                                          reveal_identities=reveal_ident,
                                          forensic_token=caller_token, path=child_path,
                                          skip_location=forensic_payload)
            # protect_victim: mask victim identity fields, agent names, and
            # hostname-shaped aggregation bucket keys (payload fields like
            # data.url / full_log keep attacker content intact via the layers above)
            if pol == "protect_victim" and not reveal_ident:
                if k in _IDENTITY_KEYS and isinstance(masked_v, str) and masked_v and BLUETEAM_REDACT_PII:
                    masked_v = _mask_username(masked_v)
                elif k == "agent" and isinstance(masked_v, dict) \
                        and isinstance(masked_v.get("name"), str) and BLUETEAM_REDACT_PII:
                    masked_v = {**masked_v, "name": _mask_username(masked_v["name"])}
                elif k == "key" and isinstance(masked_v, str) and _is_hostname_candidate(masked_v) \
                        and child_path not in _CREDENTIAL_KEY_ALLOWLIST:
                    masked_v = _mask_username(masked_v)  # aggregation bucket hostname
                elif k in _HOSTNAME_CONTEXT_KEYS and isinstance(masked_v, str) \
                        and _is_hostname_candidate(masked_v) and BLUETEAM_REDACT_PII:
                    masked_v = _mask_username(masked_v)
                elif k == "name" and isinstance(masked_v, str) and masked_v \
                        and BLUETEAM_REDACT_PII \
                        and path.rsplit(".", 1)[-1] in ("agents", "top_agents"):
                    masked_v = _mask_username(masked_v)  # agent bucket name
            result[k] = masked_v
        return result

    if isinstance(data, list):
        return [_redact_alert_data(item, policy=pol, reveal_owned=reveal,
                                   reveal_identities=reveal_ident,
                                   forensic_token=caller_token, path=path,
                                   skip_location=forensic_payload)
                for item in data]

    return data
