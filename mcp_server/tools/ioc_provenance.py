#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh attacker attribution for VirusTotal submissions.

VirusTotal publishes every queried indicator, so a lookup may only send an
attacker IOC that Wazuh alert data supports. Presence in an alert is not enough:
a source address can be a partner's health check, a scanner that was blocked at
level 3, or the destination of another rule. This module reads the alert
semantics (severity, groups, direction, MITRE technique) and records a hit only
when they point at the actor.

Supported kinds:

* ``ip_addresses``: verified here against the Indexer.
* ``domains`` and ``files``: no automatic attribution. The Wazuh template has no
  verified attacker-side field for a hash, and ``data.domain`` on a web alert is
  usually the monitored host, which is the victim. Both need an entry another
  trusted tool or an analyst verdict recorded first.

The gate inside ``virustotal.lookup`` repeats the registry check before
transport, so a caller that skips this module still cannot send an IOC.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

from mcp_server import BLUETEAM_OWNED_DOMAINS
from mcp_server.core.attacker_registry import (attacker_ioc_evidence,
                                               attacker_ioc_provenance,
                                               register_attacker_ioc)
from mcp_server.core.audit import _audit_log
from mcp_server.threat_intel.virustotal_consent import excluded_infrastructure
from mcp_server.threat_intel.virustotal import _normalize
from mcp_server.wazuh.indexer import _wazuh_indexer_post

logger = logging.getLogger("blue_team_mcp.ioc_provenance")

PROVENANCE_WINDOW = "now-7d"
# A level-7 alert is suspicious; level 10 is the usual attack threshold. Below 10
# the alert also needs an attack group or a MITRE technique.
MIN_LEVEL = 7
STRONG_LEVEL = 10

# Healthy-host and inventory rules. An address in one of these is not an actor.
NOISE_GROUPS = frozenset({
    "authentication_success", "sca", "vulnerability-detector", "syscheck",
    "rootcheck", "fim", "ossec", "inventory",
})
# Groups whose appearance at MIN_LEVEL or above implies hostile intent.
ATTACK_GROUPS = frozenset({
    "attack", "web_attack", "web_scan", "scanner", "bruteforce", "brute_force",
    "authentication_failed", "authentication_failures", "ids", "malware",
    "exploit", "cve", "sql_injection", "xss", "suricata", "snort", "firewall",
})

_IP_SOURCE_FIELDS = ("data.srcip", "srcip", "data.src_ip")
_IP_DEST_FIELDS = ("data.dstip", "dstip", "data.dst_ip")
_ALERT_FIELDS = ["@timestamp", "rule.id", "rule.level", "rule.groups",
                 "rule.mitre.id", "data.srcip", "srcip", "data.src_ip",
                 "data.dstip", "dstip", "data.dst_ip", "agent.name"]
_AUTO_KINDS = frozenset({"ip_addresses"})


def _first(mapping: dict[str, Any], fields: tuple[str, ...]) -> str:
    for field in fields:
        value = (mapping.get("data") or {}).get(field.rsplit(".", 1)[-1])
        if value in (None, ""):
            value = mapping.get(field.rsplit(".", 1)[-1])
        if value not in (None, ""):
            return str(value).strip().lower()
    return ""


def _level(rule: dict[str, Any]) -> int:
    try:
        return int(rule.get("level"))
    except (TypeError, ValueError):
        return 0


def _groups(rule: dict[str, Any]) -> set[str]:
    raw = rule.get("groups") or []
    if isinstance(raw, str):
        raw = [raw]
    return {str(group).strip().lower() for group in raw if str(group).strip()}


def _has_mitre(rule: dict[str, Any]) -> bool:
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") if isinstance(mitre, dict) else mitre
    return bool(ids)


def _same_ip(raw: str, value: str) -> bool:
    """Compare as addresses, so an expanded IPv6 form still matches."""
    try:
        return ipaddress.ip_address(raw) == ipaddress.ip_address(value)
    except ValueError:
        return False


def _attacker_evidence(hit: dict[str, Any], value: str) -> dict | None:
    """Return the attribution evidence when this alert shows ``value`` as the actor.

    Two signals are required: an attack group or a MITRE technique, plus
    severity. Level alone never qualifies, because a high-level rule can be
    about a shared client or a monitoring probe.
    """
    source = hit.get("_source") or {}
    rule = source.get("rule") or {}
    level = _level(rule)
    groups = _groups(rule)
    if level < MIN_LEVEL or groups & NOISE_GROUPS:
        return None
    if not _same_ip(_first(source, _IP_SOURCE_FIELDS), value):
        return None
    if _same_ip(_first(source, _IP_DEST_FIELDS), value):
        return None
    attack_group = bool(groups & ATTACK_GROUPS)
    mitre = _has_mitre(rule)
    if not (attack_group or mitre):
        return None
    if level < STRONG_LEVEL and not (attack_group and mitre):
        return None
    return {
        "decision": "accepted",
        "via": "wazuh_alerts",
        "alert_id": str(hit.get("_id") or ""),
        "alert_ts": str(source.get("@timestamp") or ""),
        "rule_id": str(rule.get("id") or ""),
        "rule_level": level,
        "groups": sorted(groups)[:5],
        "matched_field": "data.srcip",
        "signal": "attack_group+mitre" if attack_group and mitre
                  else "attack_group" if attack_group else "mitre",
    }


def _owned_domains() -> set[str]:
    return {d.strip().lower().rstrip(".")
            for d in (BLUETEAM_OWNED_DOMAINS or "").split(",") if d.strip()}


def _owned(value: str) -> bool:
    return any(value == domain or value.endswith("." + domain)
               for domain in _owned_domains())


async def ensure_attacker_provenance(
        kind: str, indicator: str, *,
        since: str | None = None) -> tuple[str | None, str]:
    """Return ``(source, detail)``; ``source`` is ``None`` when the lookup must stop.

    ``detail`` names the evidence or the reason it is missing, and never the
    indicator. A registry entry answers without an Indexer call. For an IP, one
    Indexer search returns the alert semantics that decide attribution.
    """
    try:
        value = _normalize(kind, indicator)
    except ValueError as exc:
        return None, f"indicator did not normalize: {exc}"

    if kind == "ip_addresses":
        network = excluded_infrastructure(value)
        if network is not None:
            _audit_log("virustotal_attribution",
                       {"indicator": value, "result": "rejected"},
                       detail={"reason": "shared-infrastructure exclusion",
                               "network": network})
            return None, f"address is in the shared-infrastructure exclusion ({network})"

    if kind == "domains" and _owned(value):
        return None, "domain is in BLUETEAM_OWNED_DOMAINS"

    known = attacker_ioc_provenance(value)
    if known is not None:
        return known, f"registered from {known}"

    if kind not in _AUTO_KINDS:
        _audit_log("virustotal_attribution",
                   {"indicator": value, "result": "rejected"},
                   detail={"reason": "no automatic attribution for this type"})
        return None, ("this indicator type needs an analyst verdict or a trusted "
                      "tool finding; Wazuh alert presence alone is not attribution")

    # The alert may hold the caller's spelling of an IPv6 address; match both.
    terms = list(dict.fromkeys([value, (indicator or "").strip()]))
    body = {
        "size": 50,
        "_source": _ALERT_FIELDS,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since or PROVENANCE_WINDOW}}},
            {"bool": {"should": [{"term": {field: term}}
                                 for field in _IP_SOURCE_FIELDS
                                 for term in terms if term],
                      "minimum_should_match": 1}},
        ]}},
    }
    data = await _wazuh_indexer_post(body)
    if "error" in data:
        return None, f"indexer unavailable: {data['error']}"
    hits = (data.get("hits") or {}).get("hits") or []
    if not hits:
        return None, f"no alert names this address as a source in {since or PROVENANCE_WINDOW}"
    for hit in hits:
        evidence = _attacker_evidence(hit, value)
        if evidence:
            register_attacker_ioc(value, source="wazuh_alerts", evidence=evidence)
            _audit_log("virustotal_attribution",
                       {"indicator": value, "result": "accepted"},
                       detail={"source": "wazuh_alerts",
                               "rule_id": evidence["rule_id"],
                               "rule_level": evidence["rule_level"],
                               "alert_id": evidence["alert_id"]})
            logger.info("VirusTotal attribution accepted: rule=%s level=%s",
                        evidence["rule_id"], evidence["rule_level"])
            return "wazuh_alerts", (f"attacker-side evidence: rule "
                                    f"{evidence['rule_id']} level "
                                    f"{evidence['rule_level']} "
                                    f"({evidence['signal']})")
    _audit_log("virustotal_attribution",
               {"indicator": value, "result": "rejected"},
               detail={"reason": "no attacker-side alert semantics"})
    return None, ("alerts match this address, but none is attacker-side evidence "
                  "(severity, groups, or direction)")


def attribution_summary(value: str) -> dict | None:
    """Operator-facing evidence for a proven indicator, with no raw alert text."""
    evidence = attacker_ioc_evidence(value)
    if not evidence:
        return None
    return {key: evidence[key] for key in
            ("source", "alert_id", "alert_ts", "rule_id", "rule_level",
             "groups", "matched_field", "signal") if key in evidence}


def provenance_refusal(detail: str) -> tuple[str, str]:
    """Map a resolver detail onto the ``(error_kind, message)`` pair to report."""
    if detail.startswith("indexer unavailable"):
        return "provenance_unchecked", detail
    if detail.startswith("address is in the shared-infrastructure exclusion"):
        return "excluded_infrastructure", detail
    return "not_attacker_ioc", detail
