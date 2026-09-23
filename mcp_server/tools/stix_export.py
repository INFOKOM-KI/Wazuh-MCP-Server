#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
STIX 2.1 bundle producer - the egress half of threat-intel sharing.

Everything else in this repository reads threat intelligence; this module is the
only place that writes it back out in a standard, machine-consumable format. The
bundle it produces is a plain STIX 2.1 JSON document that a peer CSIRT can feed to
MISP / OpenCTI / any conformant consumer, with no TAXII server involved.

EGRESS CONTRACT (read before changing)
A bundle is shared, not masked. Masking a value (`1**.***.1`) inside a STIX pattern
would publish a *wrong* indicator - worse than publishing nothing - so unshareable
values are EXCLUDED, never obfuscated, and the exclusion is reported per reason:

  1. Type allowlist - only ipv4-addr / ipv6-addr / domain-name / url / file-hash
     are ever emitted. Anything else (hostnames, emails, registry keys, free text)
     is dropped. An allowlist cannot be widened by an unexpected input shape.
  2. RFC1918 / loopback / link-local / CGNAT / reserved / unspecified / multicast
     addresses are dropped, including IPv4-mapped IPv6 (``::ffff:10.0.0.1``).
     Checked BEFORE anything else, so an attacker-registered internal IP is still
     dropped.
  3. Owned domains (BLUETEAM_OWNED_DOMAINS, plus internal TLDs .local/.internal/
     .corp/.lan and single-label hostnames) are dropped. With an empty owned-domain
     set the export REFUSES to run: without it, victim domains cannot be told apart
     from attacker domains, and guessing would leak internal infrastructure.
  4. Emails are never emitted (victim PII; the IOC value is not worth the exposure).
  5. Fixed-point assertion - the serialized bundle is re-run through
     ``_redact_alert_data(policy="protect_victim")``. If that changes a single byte,
     a private value reached the serializer and the export is refused instead of
     written. This is the independent second layer behind rules 1-4: it catches a
     filter bug, a credential pattern inside a description, or a path-like value.

That is why the tool sets ``redact=False`` on the decorator: the boundary is the
pre-serialization filter plus the fixed-point gate, not post-hoc masking of the
return value (which would corrupt the JSON the peer parses). Layer 1 credential
stripping still runs inside the fixed-point pass.

Audit: the tool logs path, TLP, counts and bundle sha256, never the indicator list.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) leaves the wrapper signature holding string annotations and FastMCP
      fails to build the arguments model with PydanticUserError. Same constraint as
      mcp_server/tools/sigma_rules.py.
"""
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import CHARACTER_LIMIT
from mcp_server.core.audit import _audit_log
from mcp_server.core.config import config
from mcp_server.core.ioc_store import query_iocs
from mcp_server.core.redact import _is_owned_domain, _redact_alert_data, get_owned_domains
from mcp_server.core.stix_objects import (STIX_SPEC_VERSION, default_tlp, egress_enabled,
                                         identity_config_error, identity_from_env,
                                         load_markings_file, new_bundle_id, stix_id,
                                         tlp_marking_definition, tlp_ref, utcnow_z)
from mcp_server.core.subprocess import _validate_path
from mcp_server.core.tool_decorator import blueteam_tool

logger = logging.getLogger("blue_team_mcp.stix_export")

_INTERNAL_TLDS = {"local", "internal", "corp", "lan", "home", "test", "localhost",
                  "invalid", "home.arpa"}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
                        re.IGNORECASE)
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_HASH_ALGOS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_LABELS = ["malicious-activity"]
_MAX_DESCRIPTION = 2000
_MAX_PATTERN_VALUE = 2048


def _ip_shareable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """False for any address that is not globally routable.
    IPv4-mapped IPv6 is unwrapped by the caller first otherwise ::ffff:10.0.0.1
    has the shape of a public v6 address while addressing a private v4 one.
    """
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    return bool(ip.is_global)


def _host_shareable(host: str) -> tuple[str, str]:
    """Classify a hostname/URL host: (stix_kind, reason). kind == "" means dropped."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not _ip_shareable(ip):
            return "", "private/reserved address"
        return ("ipv4-addr" if ip.version == 4 else "ipv6-addr"), ""

    domain = host.strip().lower().rstrip(".")
    if "." not in domain:
        return "", "single-label hostname (internal asset name)"
    if domain.rsplit(".", 1)[-1] in _INTERNAL_TLDS:
        return "", "internal TLD"
    if not _DOMAIN_RE.match(domain):
        return "", "malformed domain"
    if _is_owned_domain(domain):
        return "", "owned domain (victim infrastructure)"
    return "domain-name", ""


def classify_indicator(value: str) -> tuple[str, str]:
    """Map one raw value to (stix_kind, reason). kind == "" means not shareable.
    Order matters: hashes, then URLs (scheme + userinfo gates), then IPs and
    domains. Every branch is deny-by-default an unrecognized shape falls through
    to ("", "unsupported indicator type").
    """
    v = (value or "").strip().strip(",")
    if not v:
        return "", "empty value"
    if len(v) > _MAX_PATTERN_VALUE:
        return "", "value too long"

    if len(v) in _HASH_ALGOS and _HEX_RE.match(v):
        return "file", ""

    if "@" in v and "://" not in v:
        return "", "email excluded by egress policy"

    if "://" in v:
        parts = urllib.parse.urlsplit(v)
        if parts.scheme.lower() not in ("http", "https"):
            return "", f"non-http scheme ({parts.scheme!r})"
        if parts.username or parts.password:
            return "", "URL contains credentials"
        host = parts.hostname or ""
        if not host:
            return "", "URL without a host"
        kind, reason = _host_shareable(host)
        return ("url", "") if kind else ("", reason)

    kind, reason = _host_shareable(v)
    return (kind, "") if kind else ("", reason)


def pattern_for(kind: str, value: str) -> str:
    """STIX pattern string for one indicator value.
    Single quotes and backslashes are escaped, otherwise a URL containing an
    apostrophe produces a pattern that fails to parse at the peer.
    """
    v = value.strip().replace("\\", "\\\\").replace("'", "\\'")
    if kind == "file":
        algo = _HASH_ALGOS[len(value.strip())]
        return f"[file:hashes.'{algo}' = '{v.lower()}']"
    if kind == "url":
        return f"[url:value = '{v}']"
    return f"[{kind}:value = '{v.lower()}']"


def _refs_for_sources(sources: list[str]) -> list[dict]:
    """external_references provenance entries.
    STIX 2.1 requires at least one of description/external_id/url on every
    ExternalReference, and ``description`` is the only one we can populate from a
    provider name alone.
    """
    out: list[dict] = []
    for s in sources:
        name = (s or "").strip()
        if name and not any(r["source_name"] == name for r in out):
            out.append({"source_name": name,
                        "description": f"Indicator reported as malicious by {name}"})
    return out


def _build_bundle(*, rows: list[dict], meta: dict) -> dict:
    """Assemble the STIX 2.1 bundle from pre-classified rows and bundle metadata.
    rows: [{"kind", "value", "reference"}]
    meta: {"identity", "tlp", "report_name", "description", "created", "sources",
           "confidence", "techniques", "extra_markings"}
    """
    created = meta["created"]
    identity = meta["identity"]
    marking_ref = tlp_ref(meta["tlp"])
    created_by = identity["id"]
    confidence = meta["confidence"]
    references = _refs_for_sources(meta["sources"])

    indicators: list[dict] = []
    relationships: list[dict] = []
    for row in rows:
        pattern = pattern_for(row["kind"], row["value"])
        ind_id = stix_id("indicator", pattern)
        indicator = {
            "type": "indicator", "spec_version": STIX_SPEC_VERSION, "id": ind_id,
            "created": created, "modified": created,
            "created_by_ref": created_by,
            "name": row["value"],
            "pattern": pattern, "pattern_type": "stix",
            "pattern_version": STIX_SPEC_VERSION,
            "valid_from": created,
            "labels": list(_LABELS),
            "object_marking_refs": [marking_ref],
        }
        ref = (row.get("reference") or "").strip()
        if ref:
            indicator["description"] = ref[:_MAX_DESCRIPTION]
        if confidence is not None:
            indicator["confidence"] = confidence
        if references:
            indicator["external_references"] = [dict(r) for r in references]
        indicators.append(indicator)

        for tid, target in sorted(meta["techniques"].items()):
            relationships.append({
                "type": "relationship", "spec_version": STIX_SPEC_VERSION,
                "id": stix_id("relationship", f"indicates:{ind_id}:{target}"),
                "created": created, "modified": created,
                "created_by_ref": created_by,
                "relationship_type": "indicates",
                "source_ref": ind_id, "target_ref": target,
                "description": f"{row['value']} indicates {tid}",
                "object_marking_refs": [marking_ref],
            })

    objects: list[dict] = [identity, tlp_marking_definition(meta["tlp"])]
    objects.extend(meta["extra_markings"])
    report = {
        "type": "report", "spec_version": STIX_SPEC_VERSION,
        "id": stix_id("report", f"{meta['report_name']}:{created}"),
        "created": created, "modified": created,
        "created_by_ref": created_by,
        "name": meta["report_name"],
        "published": created,
        "report_types": ["threat-report"],
        "object_refs": [i["id"] for i in indicators] + [r["id"] for r in relationships],
        "object_marking_refs": [marking_ref],
    }
    if meta["description"]:
        report["description"] = meta["description"][:_MAX_DESCRIPTION]
    objects.append(report)
    objects.extend(indicators)
    objects.extend(relationships)

    return {"type": "bundle", "id": new_bundle_id(), "objects": objects}


def _write_bundle(path: str, payload: str) -> None:
    """Atomically write the bundle (tmp + os.replace), cleaning up on failure."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class StixExportInput(BaseModel):
    """Input model for blueteam_stix_export."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicators: list[str] = Field(default_factory=list, max_length=2000,
        description="Indicator values to share: public IPv4/IPv6, domains, http(s) URLs, "
                    "or file hashes. Internal/private values are dropped and reported.")
    include_ioc_store: bool = Field(default=False,
        description="Also export ranked indicators already in the IOC store "
                    "(blueteam_extract_iocs populates it).")
    ioc_store_since_days: int = Field(default=30, ge=1, le=365,
        description="Recency window for include_ioc_store.")
    ioc_store_kind: Optional[Literal["ip", "domain", "url", "hash"]] = Field(default=None,
        description="Optional IOC-store kind filter (email is never exportable).")
    report_name: str = Field(default="Threat intelligence sharing bundle", max_length=200,
        description="STIX report name (also the bundle filename slug).")
    description: str = Field(default="", max_length=2000,
        description="Analyst context for the report. Do NOT put hostnames, usernames, "
                    "or internal paths here - the fixed-point gate refuses the export.")
    tlp: Optional[Literal["WHITE", "GREEN", "AMBER", "RED"]] = Field(default=None,
        description="TLP marking for every object. Defaults to BLUETEAM_STIX_DEFAULT_TLP (AMBER).")
    confidence: Optional[int] = Field(default=None, ge=0, le=100,
        description="STIX confidence 0-100 applied to each indicator.")
    sources: list[str] = Field(default_factory=list, max_length=20,
        description="Provenance names for external_references, e.g. ['crowdsec','threatfox'].")
    attack_technique_ids: list[str] = Field(default_factory=list, max_length=50,
        description="MITRE technique IDs (e.g. ['T1071.001']) to link via 'indicates' "
                    "relationships. Unknown IDs are reported, never invented.")
    path: Optional[str] = Field(default=None, max_length=500,
        description="Absolute output path under BLUETEAM_EXPORT_DIR. Defaults to "
                    "<export_dir>/stix/<utc>-<slug>.json.")
    include_bundle: bool = Field(default=False,
        description="Also return the bundle inline (for handing straight to a MISP API). "
                    "Refused above the character limit - use the written file instead.")
    max_indicators: int = Field(default=500, ge=1, le=2000,
        description="Cap on emitted indicators (bounded output).")
    response_format: Literal["markdown", "json"] = Field(default="markdown",
        description="'markdown' summary (default) or 'json'.")


@blueteam_tool(
    name="blueteam_stix_export",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
    audit=False, redact=False,
)
async def blueteam_stix_export(params: StixExportInput) -> str:
    """Export vetted indicators as a STIX 2.1 bundle for sharing with a peer CSIRT.

    Produces a conformant STIX 2.1 bundle (identity + TLP marking-definition +
    report + indicator + optional 'indicates' relationship to ATT&CK techniques)
    and writes it to disk. Nothing leaves the network here: the bundle is a file
    drop / MISP-compatible payload; pushing it to a peer is a separate, deliberate
    step. Deterministic UUIDv5 ids mean re-exporting the same indicator yields the
    same id, so a peer deduplicates instead of accumulating copies.
    **Exclusion, not masking**: private IPs (including IPv4-mapped IPv6), owned
    domains, internal TLDs, single-label hostnames, emails, non-http URLs and
    credential-bearing URLs are dropped from the bundle and reported per reason.
    If the owned-domain set is empty the export refuses to run, because victim and
    attacker infrastructure cannot be told apart. The serialized bundle must also
    survive a ``protect_victim`` redaction pass byte-for-byte, or the export is
    refused (see this module's egress contract).
    **Requires**: BLUETEAM_STIX_EGRESS_ENABLED=true and BLUETEAM_STIX_IDENTITY_NAME,
    plus BLUETEAM_OWNED_DOMAINS. Optional: BLUETEAM_STIX_DEFAULT_TLP (AMBER),
    BLUETEAM_STIX_NAMESPACE, BLUETEAM_STIX_MARKINGS_FILE (extra markings such as
    TLP:CLEAR / TLP:AMBER+STRICT), BLUETEAM_EXPORT_DIR (write scope).

    **Limits**: 500 indicators by default (2000 max) -> pass ``include_ioc_store=true``
    for store-driven export. No external API calls, so no upstream rate limits.
    A bundle above the character limit is only written to disk, never returned inline.

    **Worked Examples**

    1. *Share two vetted indicators at TLP:AMBER*:
       ``blueteam_stix_export(indicators=["45.61.136.7", "evil-c2.example.com"],
         report_name="Zimbra brute-force C2", sources=["crowdsec","threatfox"], tlp="AMBER")``

    2. *Export what the IOC store learned in the last week, with ATT&CK links*:
       ``blueteam_stix_export(include_ioc_store=true, ioc_store_since_days=7,
         attack_technique_ids=["T1110.001"], confidence=70)``

    3. *Hand a small bundle straight to MISP without reading the file*:
       ``blueteam_stix_export(indicators=["evil-c2.example.com"], include_bundle=true,
         response_format="json")``
    """
    if not egress_enabled():
        return json.dumps({"error": "STIX egress is disabled. Set "
                                    "BLUETEAM_STIX_EGRESS_ENABLED=true to allow bundle production."}, indent=2)
    id_err = identity_config_error()
    if id_err:
        return json.dumps({"error": id_err}, indent=2)
    if not get_owned_domains():
        return json.dumps({"error": "BLUETEAM_OWNED_DOMAINS is empty - refusing to export. "
                                    "Without the owned-domain list, victim infrastructure cannot "
                                    "be distinguished from attacker infrastructure."}, indent=2)

    values: list[str] = list(params.indicators)
    if params.include_ioc_store:
        values.extend(row["ioc"] for row in query_iocs(kind=params.ioc_store_kind,
                                                       since_days=params.ioc_store_since_days,
                                                       top_n=params.max_indicators))

    rows: list[dict] = []
    dropped: dict[str, int] = {}
    seen: set[str] = set()
    for raw in values:
        value = (raw or "").strip().strip(",")
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        kind, reason = classify_indicator(value)
        if not kind:
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        if len(rows) >= params.max_indicators:
            dropped["over max_indicators"] = dropped.get("over max_indicators", 0) + 1
            continue
        rows.append({"kind": kind, "value": value, "reference": params.description})

    if not rows:
        return json.dumps({"error": "No shareable indicators in this request.",
                           "dropped": dropped}, indent=2)

    # ATT&CK technique resolution against the already-loaded STIX bundle. Only IDs
    # that resolve to a real attack-pattern object are linked an unresolvable ID
    # is reported, never turned into a fabricated reference.
    techniques: dict[str, str] = {}
    unresolved: list[str] = []
    if params.attack_technique_ids:
        from mcp_server.tools import stix_correlation as _sc
        await asyncio.to_thread(_sc._load_stix)
        patterns = (_sc._stix_data or {}).get("by_type", {}).get("attack-pattern", [])
        by_ext: dict[str, str] = {}
        for obj in patterns:
            ext = _sc._mitre_id(obj).upper()
            if ext:
                by_ext.setdefault(ext, obj.get("id", ""))
        for tid in params.attack_technique_ids:
            key = (tid or "").strip().upper()
            if not key:
                continue
            if by_ext.get(key):
                techniques[key] = by_ext[key]
            else:
                unresolved.append(key)

    tlp_level = params.tlp or default_tlp()
    extra_markings, markings_err = load_markings_file()
    if markings_err:
        return json.dumps({"error": f"markings file rejected: {markings_err}"}, indent=2)

    identity = identity_from_env()
    if identity is None:
        return json.dumps({"error": identity_config_error()}, indent=2)

    created = utcnow_z()
    bundle = _build_bundle(rows=rows, meta={
        "identity": identity, "tlp": tlp_level, "report_name": params.report_name,
        "description": params.description, "created": created, "sources": params.sources,
        "confidence": params.confidence, "techniques": techniques,
        "extra_markings": extra_markings,
    })
    payload = json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=True)

    # The identity contact is the operator's own published address, so an owned
    # domain there is intentional; everything else must survive the gate.
    check_objects = [
        ({k: v for k, v in obj.items() if k != "contact_information"}
         if obj.get("type") == "identity" and "contact_information" in obj else obj)
        for obj in bundle.get("objects", [])
    ]
    check_payload = json.dumps({**bundle, "objects": check_objects},
                               indent=2, ensure_ascii=False, sort_keys=True)
    if _redact_alert_data(check_payload, policy="protect_victim") != check_payload:
        logger.warning("STIX egress refused: bundle is not a fixed point of the redaction pipeline")
        return json.dumps({"error": "Egress refused: the bundle still contains a value the redaction "
                                    "pipeline would mask (internal host, path, credential pattern, or "
                                    "owned domain). Remove it from description/sources and retry.",
                           "dropped": dropped}, indent=2)

    export_dir = config.operational.export_dir
    slug = re.sub(r"[^a-z0-9]+", "-", params.report_name.lower()).strip("-")[:60] or "bundle"
    default_path = os.path.join(export_dir, "stix",
                                f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{slug}.json")
    target = os.path.abspath(params.path) if params.path else default_path
    ok, err = _validate_path(target, [export_dir])
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}", "allowed": [export_dir]}, indent=2)

    try:
        _write_bundle(target, payload)
    except OSError as e:
        logger.error("STIX bundle write failed (%s): %s", target, e)
        return json.dumps({"error": f"Failed to write bundle: {e}"}, indent=2)

    digest = hashlib.sha256(payload.encode()).hexdigest()
    _audit_log("blueteam_stix_export", {
        "path": target, "sha256": digest, "tlp": tlp_level, "indicators": len(rows),
        "relationships": sum(1 for o in bundle["objects"] if o["type"] == "relationship"),
        "dropped_reasons": sorted(dropped), "bypassed_redaction": False,
    })

    summary = {
        "status": "written", "path": target, "sha256": digest, "bundle_id": bundle["id"],
        "tlp": tlp_level, "spec_version": STIX_SPEC_VERSION, "report": params.report_name,
        "identity": identity["name"], "indicators": len(rows),
        "relationships": sum(1 for o in bundle["objects"] if o["type"] == "relationship"),
        "objects": len(bundle["objects"]), "valid_from": created,
        "dropped": dropped, "unresolved_techniques": unresolved,
    }

    if params.response_format == "json":
        if params.include_bundle:
            if len(payload) > CHARACTER_LIMIT:
                summary["note"] = ("bundle exceeds the character limit and was not returned inline - "
                                   "read the file at path")
            else:
                summary["bundle"] = bundle
        return json.dumps(summary, indent=2, ensure_ascii=False)

    lines = [
        f"# STIX 2.1 bundle written ({tlp_level})", "",
        f"**Path**: `{target}`  ",
        f"**SHA-256**: `{digest}`  ",
        f"**Report**: {params.report_name}  ",
        f"**Producer**: {identity['name']}  ",
        f"**Objects**: {summary['objects']} "
        f"({summary['indicators']} indicators, {summary['relationships']} relationships)",
        "", "| Kind | Count |", "|------|-------|",
    ]
    kinds: dict[str, int] = {}
    for row in rows:
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
    for kind, count in sorted(kinds.items()):
        lines.append(f"| `{kind}` | {count} |")
    if dropped:
        lines += ["", "### Excluded (never masked - dropped)", "",
                  "| Reason | Count |", "|--------|-------|"]
        for reason, count in sorted(dropped.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {reason} | {count} |")
    if unresolved:
        lines += ["", f"**Unresolved ATT&CK techniques** (no attack-pattern in the loaded bundle): "
                      f"{', '.join(unresolved)}"]
    lines += ["", "Next: hand the file to the peer (MISP STIX2 import) or review it before transport."]
    return "\n".join(lines)
