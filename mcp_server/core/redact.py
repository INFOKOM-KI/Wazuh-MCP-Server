#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
PII redaction pipeline 6 layers. Layer 1 (credentials) NEVER bypassable.
"""
from __future__ import annotations
import hashlib, os, re, logging
from typing import Any
from collections import Counter

from mcp_server import (BLUETEAM_REDACT_PII, BLUETEAM_REDACT_EMAILS, BLUETEAM_REDACT_DOMAINS,
                         BLUETEAM_REDACT_LOCATIONS, BLUETEAM_REDACT_UAS)

logger = logging.getLogger("blue_team_mcp.redact")

_REDACT_SALT = os.environ.get(
    "BLUETEAM_REDACT_SALT",
    hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:16]
)

_REDACT_EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

# Layer 1: Credential stripping (MANDATORY, never configurable)
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
    (re.compile(r'\b(AKIA[0-9A-Z]{16}|sk_(?:live|test)_[a-zA-Z0-9]{24,})\b'),
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
    """Mask subdomain part, keep parent domain + TLD visible."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 3:
        return domain
    sub = parts[0]
    if len(sub) <= 2:
        masked = sub[0] + "*" * (len(sub) - 1)
    else:
        masked = sub[0] + "*" * (len(sub) - 2) + sub[-1]
    return f"{masked}." + ".".join(parts[1:])


# Main redaction pipeline
def _redact_alert_data(data: Any, *, bypass: bool = False) -> Any:
    """Apply 6-layer PII and credential masking. Layer 1 NEVER bypassable.

    Layers:
      1. Credential stripping (MANDATORY — never configurable)
      2. Email redaction (BLUETEAM_REDACT_EMAILS)
      3. Internal IP masking (BLUETEAM_REDACT_PII)
      4. Domain/hostname masking (BLUETEAM_REDACT_DOMAINS)
      5. Log location masking (BLUETEAM_REDACT_LOCATIONS)
      6. User-agent truncation (BLUETEAM_REDACT_UAS)
    """
    if bypass:
        logger.warning("REDACTION BYPASSED — raw PII/internal IPs exposed to caller")

    if isinstance(data, str):
        # Layer 1: Credential stripping (ALWAYS)
        for pattern, replacement in _CREDENTIAL_STRIP_RULES:
            data = pattern.sub(replacement, data)

        if not bypass:
            # Layer 2: Email redaction
            if BLUETEAM_REDACT_EMAILS:
                def _redact_email(m: re.Match) -> str:
                    local, domain = m.group(1), m.group(2)
                    full_email = f"{local}@{domain}"
                    forensic_hash = _hash_email_for_audit(full_email)
                    if len(local) <= 2:
                        rlocal = local[0] + "*" * (len(local) - 1)
                    else:
                        rlocal = local[0] + "*" * max(1, len(local) - 2) + local[-1]
                    return f"{rlocal}@{domain} [h:{forensic_hash}]"
                data = _REDACT_EMAIL_RE.sub(_redact_email, data)

            # Layer 3: Internal IP masking
            if BLUETEAM_REDACT_PII:
                def _redact_internal_ip(m: re.Match) -> str:
                    ip = m.group(0)
                    octets = ip.split(".")
                    if octets[0] == "10":
                        return f"10.{'***'}.{'***'}.{octets[3]}"
                    elif octets[0] == "172" and 16 <= int(octets[1]) <= 31:
                        return f"172.{octets[1]}.{'***'}.{octets[3]}"
                    elif octets[0] == "192" and octets[1] == "168":
                        return f"192.168.{'***'}.{octets[3]}"
                    elif octets[0] == "127":
                        return f"127.{'***'}.{'***'}.{octets[3]}"
                    elif octets[0] == "169" and octets[1] == "254":
                        return f"169.254.{'***'}.{octets[3]}"
                    return ip
                data = re.sub(
                    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                    r"192\.168\.\d{1,3}\.\d{1,3}|"
                    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"169\.254\.\d{1,3}\.\d{1,3})\b",
                    _redact_internal_ip, data,
                )
                data = re.sub(r"\b::1\b", "<LOOPBACK_REDACTED>", data)

            # Layer 4: Domain masking
            if BLUETEAM_REDACT_DOMAINS:
                data = re.sub(
                    r"(?<![@\w])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
                    r"\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+))\b",
                    lambda m: _mask_domain(m.group(1)), data,
                )

            # Layer 5: Location masking in full_log
            if BLUETEAM_REDACT_LOCATIONS:
                def _redact_log_path(m: re.Match) -> str:
                    path = m.group(0)
                    parts = path.rstrip("/").split("/")
                    leaf = parts[-1] if len(parts) > 1 else path
                    path_hash = hashlib.sha256(f"{_REDACT_SALT}:{path}".encode()).hexdigest()[:6]
                    return f".../{leaf} [h:{path_hash}]"
                data = re.sub(r"/(?:[a-zA-Z0-9._-]+/){2,}[a-zA-Z0-9._-]+", _redact_log_path, data)

            # Layer 6: UA truncation
            if BLUETEAM_REDACT_UAS:
                if len(data) > 80 and re.search(r"Mozilla|Chrome|Safari|Firefox|curl|wget|python", data):
                    data = data[:80] + "..."

        return data

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            if not bypass:
                if k == "domain" and isinstance(v, str) and BLUETEAM_REDACT_DOMAINS:
                    v = _mask_domain(v)
                elif k == "location" and isinstance(v, str) and BLUETEAM_REDACT_LOCATIONS:
                    parts = v.rstrip("/").split("/")
                    leaf = parts[-1] if len(parts) > 1 else v
                    path_hash = hashlib.sha256(f"{_REDACT_SALT}:{v}".encode()).hexdigest()[:6]
                    v = f".../{leaf} [h:{path_hash}]"
                elif k == "user_agent" and isinstance(v, str) and BLUETEAM_REDACT_UAS and len(v) > 80:
                    v = v[:80] + "..."
            result[k] = _redact_alert_data(v, bypass=bypass)
        return result

    if isinstance(data, list):
        return [_redact_alert_data(item, bypass=bypass) for item in data]

    return data
