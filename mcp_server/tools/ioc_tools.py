#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
IOC extraction tool — structured indicator extraction from alert text/logs.
"""
from __future__ import annotations
import json, re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log

# IOC Patterns
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"'{}|\\^`[\]]+", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# IPs that are noise - never flag these
_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "8.8.8.8", "8.8.4.4",
             "1.1.1.1", "1.0.0.1"}


def _extract_iocs(text: str) -> dict:
    """Extract and deduplicate IOCs from text. Returns structured dict."""
    ips = [m.group(0) for m in _IPV4_RE.finditer(text)
           if m.group(0) not in _SKIP_IPS
           and not m.group(0).startswith(("10.", "172.16.", "172.17.", "172.18.",
                                           "172.19.", "172.20.", "172.21.", "172.22.",
                                           "172.23.", "172.24.", "172.25.", "172.26.",
                                           "172.27.", "172.28.", "172.29.", "172.30.",
                                           "172.31.", "192.168."))]
    domains_raw = [m.group(0).lower() for m in _DOMAIN_RE.finditer(text)]
    emails = list(dict.fromkeys(m.group(0).lower() for m in _EMAIL_RE.finditer(text)))
    urls = list(dict.fromkeys(m.group(0) for m in _URL_RE.finditer(text)))
    md5s = list(dict.fromkeys(m.group(0).lower() for m in _MD5_RE.finditer(text)))
    sha1s = list(dict.fromkeys(m.group(0).lower() for m in _SHA1_RE.finditer(text)
                if not _MD5_RE.fullmatch(m.group(0))))
    sha256s = list(dict.fromkeys(m.group(0).lower() for m in _SHA256_RE.finditer(text)
                  if not _SHA1_RE.fullmatch(m.group(0)) and not _MD5_RE.fullmatch(m.group(0))))

    # Deduplicate domains (exclude email domains that only appear in emails)
    email_domains = {e.split("@", 1)[1] for e in emails if "@" in e}
    domains = list(dict.fromkeys(d for d in domains_raw if d not in email_domains or domains_raw.count(d) > emails.count(d)))

    # Deduplicate IPs keeping order
    seen_ips = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)

    return {
        "ips": unique_ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "hashes": {
            "md5": md5s,
            "sha1": sha1s,
            "sha256": sha256s,
        },
    }


class IocExtractInput(BaseModel):
    """Input model for blueteam_extract_iocs."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    text: str = Field(..., min_length=1, max_length=100000,
                      description="Raw alert text, log line, or full_log field to extract IOCs from.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_extract_iocs",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_extract_iocs(params: IocExtractInput) -> str:
    """Extract structured Indicators of Compromise from raw text.

    Parses alert text, log lines, or full_log fields and returns deduplicated
    lists of IPs, domains, URLs, email addresses, and file hashes (MD5/SHA1/SHA256).

    **Filters noise**: skips private IPs (10.x, 192.168.x, 172.16-31.x),
    loopback, broadcast, and common DNS resolvers.

    Use this BEFORE calling threat intel tools — extract IOCs from alerts, then
    feed the results to CrowdSec, ThreatFox, VirusTotal, or WHOIS.

    **Worked Examples**

    1. *Extract from a full_log field*:
       ``blueteam_extract_iocs(text="srcip=103.107.116.202 dst=10.0.0.5 url=http://evil.com/payload.exe md5=d41d8cd98f00b204e9800998ecf8427e")``

    2. *Parse multi-line alert data*:
       ``blueteam_extract_iocs(text=alert_data, response_format="json")``

    3. *Extract from Wazuh alert summary*:
       ``blueteam_extract_iocs(text=summary_text)``
    """
    _audit_log("blueteam_extract_iocs", {"text_len": len(params.text)})
    iocs = _extract_iocs(params.text)

    total = len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["urls"]) + \
            len(iocs["emails"]) + len(iocs["hashes"]["md5"]) + \
            len(iocs["hashes"]["sha1"]) + len(iocs["hashes"]["sha256"])

    if params.response_format == "json":
        return json.dumps({"total_iocs": total, **iocs}, indent=2, ensure_ascii=False)

    lines = [f"# 🔍 IOC Extraction — {total} indicators found", ""]

    if iocs["ips"]:
        lines.append(f"## IPs ({len(iocs['ips'])})")
        for ip in iocs["ips"][:20]:
            lines.append(f"- `{ip}`")
        if len(iocs["ips"]) > 20:
            lines.append(f"- ... and {len(iocs['ips']) - 20} more")
        lines.append("")

    if iocs["domains"]:
        lines.append(f"## Domains ({len(iocs['domains'])})")
        for d in iocs["domains"][:20]:
            lines.append(f"- `{d}`")
        if len(iocs["domains"]) > 20:
            lines.append(f"- ... and {len(iocs['domains']) - 20} more")
        lines.append("")

    if iocs["urls"]:
        lines.append(f"## URLs ({len(iocs['urls'])})")
        for u in iocs["urls"][:10]:
            lines.append(f"- {u}")
        if len(iocs["urls"]) > 10:
            lines.append(f"- ... and {len(iocs['urls']) - 10} more")
        lines.append("")

    if iocs["emails"]:
        lines.append(f"## Emails ({len(iocs['emails'])})")
        for e in iocs["emails"][:10]:
            lines.append(f"- `{e}`")
        lines.append("")

    hashes = iocs["hashes"]
    hash_total = len(hashes["md5"]) + len(hashes["sha1"]) + len(hashes["sha256"])
    if hash_total:
        lines.append(f"## Hashes ({hash_total})")
        for h in hashes["md5"][:5]:
            lines.append(f"- MD5: `{h}`")
        for h in hashes["sha1"][:5]:
            lines.append(f"- SHA1: `{h}`")
        for h in hashes["sha256"][:5]:
            lines.append(f"- SHA256: `{h}`")
        if hash_total > 15:
            lines.append(f"- ... and {hash_total - 15} more")
        lines.append("")

    if total == 0:
        lines.append("✅ No IOCs detected in the provided text.")

    return "\n".join(lines)
