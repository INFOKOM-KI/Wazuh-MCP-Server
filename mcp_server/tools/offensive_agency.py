#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
offensive.agency tools: bulk attacker-IOC membership and single-host detail.

The lookup is an enrichment step for IOCs that Wazuh MCP analysis already
identified as attacker-related. It is not a feed harvester: the caller supplies
the list, and the tool sends only the IP, CIDR, and domain values that the
provider documents. Selection metadata stays local.
"""
import hashlib
import json
import logging
import secrets
import time
from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mcp_server.core.audit import _audit_log, _escape_md_table
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.threat_intel.offensive_agency import (
    ATTRIBUTION, DEFAULT_BASE_URL, MAX_AGENTS, MAX_CLUSTERS, MAX_DOMAIN_IPS,
    MAX_DOMAINS, MAX_HOST_ROWS, MAX_INDICATORS, MAX_PROSE,
    MAX_REJECTED_ROWS, MAX_SERVICES, MAX_UNSUPPORTED_ROWS, SUPPORTED_TYPES,
    PreparedBatch, _base_url, _normalize_public_ip, host as _host_lookup,
    lookup as _bulk_lookup, prepare_batch,
)

MAX_RAW_ITEM_CHARS = 10_000
LOOKUP_REF_TTL_SECONDS = 1_800
LOOKUP_REF_MAX = 256
_LOOKUP_REFS: dict[str, tuple[float, frozenset[str]]] = {}

logger = logging.getLogger("blue_team_mcp.offensive_agency_tool")

SelectionBasis = Literal[
    "confirmed_malicious_source",
    "attacker_c2",
    "malicious_destination",
    "malicious_domain",
    "attacker_network",
    "attacker_infrastructure",
]

_SELECTION_CRITERIA = (
    "Confirmed malicious source IPs",
    "Attacker C2 IPs",
    "Malicious destination IPs associated with attacker infrastructure",
    "Malicious domains",
    "Attacker-associated CIDR networks",
    "Other attacker infrastructure identified by Wazuh MCP analysis",
)

_CAVEATS = (
    "A match means an exposed agent console was observed; it does not identify "
    "the operator or prove intent.",
    "active=false is a historical record, not a clean result.",
    "network.kind=cdn is shared infrastructure; match the domain, not the IP.",
    "A domain match can be a subdomain; check match_scope.",
    "Absence from the tracker is not a clean verdict.",
    "unsupported_indicator_type means the provider cannot query that type; it "
    "was not checked.",
)


def _clip(value: Any, limit: int = MAX_PROSE) -> str:
    if value is None:
        return ""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return " ".join(text.split())[:limit]


def _capped_list(values: Any, limit: int, transform=None) -> dict[str, Any]:
    raw = values if isinstance(values, (list, tuple)) else []
    items: list[Any] = []
    for value in raw[:limit]:
        item = transform(value) if transform is not None else value
        if item is not None:
            items.append(item)
    return {
        "items": items,
        "total_count": len(raw),
        "returned_count": len(items),
        "truncated": len(items) < len(raw),
    }


def _capped_dict(value: Any, limit: int, transform) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    items: dict[str, Any] = {}
    for key, item in list(raw.items())[:limit]:
        transformed = transform(item)
        if transformed is not None:
            items[_clip(key, 80)] = transformed
    return {
        "items": items,
        "total_count": len(raw),
        "returned_count": len(items),
        "truncated": len(items) < len(raw),
    }


def _capped_strings(values: Any, limit: int) -> dict[str, Any]:
    return _capped_list(
        values, limit,
        lambda v: _clip(v, 120) if isinstance(v, (str, int, float)) else None)


def _capped_ints(values: Any, limit: int) -> dict[str, Any]:
    def _int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return _capped_list(values, limit, _int)


def _network(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "asn": _clip(value.get("asn"), 32),
        "country": _clip(value.get("country"), 8),
        "kind": _clip(value.get("kind"), 32),
        "org": _clip(value.get("org")),
        "rdns": _capped_strings(value.get("rdns"), 10),
    }


def _agent(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "name": _clip(value.get("name"), 120),
        "slug": _clip(value.get("slug"), 80),
        "level": _clip(value.get("level"), 32),
        "families": _capped_strings(value.get("families"), 10),
        "ports": _capped_ints(value.get("ports"), 20),
    }


def _domain(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "name": _clip(value.get("name"), 253),
        "behind_cdn": value.get("behind_cdn") is True,
        "first_seen": _clip(value.get("first_seen"), 32),
        "last_seen": _clip(value.get("last_seen"), 32),
        "ips": _capped_strings(value.get("ips"), MAX_DOMAIN_IPS),
        "agents": _capped_dict(value.get("agents"), MAX_AGENTS,
                               lambda v: _clip(v, 32)),
    }


def _host(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    network = _network(value.get("network"))
    cohosting = value.get("cohosting")
    if not isinstance(cohosting, dict):
        cohosting = {}
    return {
        "ip": _clip(value.get("ip"), 64),
        "active": value.get("active") if isinstance(value.get("active"), bool) else None,
        "first_seen": _clip(value.get("first_seen"), 32),
        "last_seen": _clip(value.get("last_seen"), 32),
        "network": network,
        "agents": _capped_list(
            value.get("agents"), MAX_AGENTS,
            lambda a: _agent(a) if isinstance(a, dict) else None),
        "clusters": _capped_strings(value.get("clusters"), MAX_CLUSTERS),
        "cohosting": {
            "c2": _capped_strings(cohosting.get("c2"), MAX_CLUSTERS),
            "classes": _capped_strings(cohosting.get("classes"), MAX_CLUSTERS),
        },
        "shared_cdn": network.get("kind") == "cdn",
    }


def _service(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "port": value.get("port") if isinstance(value.get("port"), int) else None,
        "products": _capped_strings(value.get("products"), 20),
        "titles": _capped_strings(value.get("titles"), 10),
        "cert_cn": _capped_strings(value.get("cert_cn"), 10),
        "classes": _capped_strings(value.get("classes"), 10),
        "tls": value.get("tls") is True,
        "last_seen": _clip(value.get("last_seen"), 32),
        "agents": _capped_strings(value.get("agents"), 10),
    }


def _match_scope(detected_type: str, query: str, domains: list[dict[str, Any]]) -> str:
    if detected_type == "cidr":
        return "cidr"
    if detected_type == "ip":
        return "ip"
    names = [d.get("name", "") for d in domains if isinstance(d.get("name"), str)]
    if any(name != query and name.endswith("." + query) for name in names):
        return "domain_subdomain"
    return "domain_exact"


def _project_match(match: dict[str, Any], group: dict[str, Any],
                   max_hosts: int) -> dict[str, Any]:
    raw_hosts = match.get("hosts") if isinstance(match.get("hosts"), list) else []
    raw_domains = match.get("domains") if isinstance(match.get("domains"), list) else []
    hosts = _capped_list(
        raw_hosts, max_hosts,
        lambda h: _host(h) if isinstance(h, dict) else None)
    domains = _capped_list(
        raw_domains, MAX_DOMAINS,
        lambda d: _domain(d) if isinstance(d, dict) else None)
    active = sum(1 for h in raw_hosts
                 if isinstance(h, dict) and h.get("active") is True)
    inactive = sum(1 for h in raw_hosts
                   if isinstance(h, dict) and h.get("active") is False)
    shared_cdn = sum(1 for h in raw_hosts
                     if isinstance(h, dict)
                     and isinstance(h.get("network"), dict)
                     and h["network"].get("kind") == "cdn")
    query = group["query_indicator"]
    detected_type = group["detected_type"]
    return {
        "original_indicators": group["original_indicators"],
        "query_indicator": query,
        "type": detected_type,
        "match_scope": _match_scope(detected_type, query, raw_domains),
        "active_hosts": active,
        "inactive_hosts": inactive,
        "unknown_active_hosts": len(raw_hosts) - active - inactive,
        "shared_cdn_hosts": shared_cdn,
        "hosts": hosts,
        "domains": domains,
    }


def _group_originals(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "original_indicators": group["original_indicators"],
        "detected_type": group["detected_type"],
        "reason": group["reason"],
    }


def _not_found(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "original_indicators": group["original_indicators"],
        "query_indicator": group["query_indicator"],
        "type": group["detected_type"],
    }


def _invalid(group: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "original_indicators": group["original_indicators"],
        "query_indicator": group["query_indicator"],
        "type": group["detected_type"],
        "reason": reason,
    }


def _selection(basis: str, evidence_ref: str) -> dict[str, Any]:
    return {
        "basis": basis,
        "evidence_ref": evidence_ref,
        "source": "wazuh_mcp_analysis",
        "caller_asserted": True,
        "criteria": list(_SELECTION_CRITERIA),
    }


def _interpretation(ref_day: str | None) -> dict[str, Any]:
    return {
        "basis": "third_party_observation",
        "is_verdict": False,
        "active_window_days": 7,
        "reference_day": ref_day,
        "caveats": list(_CAVEATS),
    }


def _attribution(meta: dict[str, Any]) -> str:
    value = meta.get("attribution") if isinstance(meta, dict) else None
    if isinstance(value, str) and value.strip():
        return _clip(value, 500)
    return ATTRIBUTION


def _destination() -> str:
    try:
        return _base_url()
    except ThreatIntelError:
        return DEFAULT_BASE_URL


def _transmission(sent: int, unsupported: int, rejected: int) -> dict[str, Any]:
    return {
        "destination": _destination(),
        "third_party": True,
        "indicators_sent": sent,
        "unsupported_not_sent": unsupported,
        "rejected_not_sent": rejected,
        "data_processor": "ONYPHE / offensive.agency",
        "provenance": "caller_asserted",
    }


def _digest(values: list[str]) -> str:
    return hashlib.sha256("\x00".join(sorted(values)).encode("utf-8")).hexdigest()


def _issue_lookup_reference(ips: list[str]) -> str:
    """Issue a short-lived local capability for matched public hosts."""
    now = time.monotonic()
    for key, (expiry, _) in list(_LOOKUP_REFS.items()):
        if expiry <= now:
            _LOOKUP_REFS.pop(key, None)
    while len(_LOOKUP_REFS) >= LOOKUP_REF_MAX:
        _LOOKUP_REFS.pop(next(iter(_LOOKUP_REFS)))
    token = secrets.token_urlsafe(18)
    _LOOKUP_REFS[token] = (now + LOOKUP_REF_TTL_SECONDS, frozenset(ips))
    return token


def _verify_lookup_reference(token: str, ip: str) -> None:
    entry = _LOOKUP_REFS.get(token)
    if entry is None:
        raise ThreatIntelError(
            "lookup_reference_invalid: host enrichment requires the lookup_reference "
            "returned by a successful offensive.agency lookup.")
    expiry, ips = entry
    if time.monotonic() > expiry:
        _LOOKUP_REFS.pop(token, None)
        raise ThreatIntelError(
            "lookup_reference_expired: the lookup reference has expired; run the "
            "lookup again.")
    if ip not in ips:
        raise ThreatIntelError(
            "lookup_reference_mismatch: this IP was not a matched host in the "
            "referenced lookup.")


def _display_caps(max_hosts: int | None) -> dict[str, int | None]:
    return {
        "hosts_per_indicator": max_hosts,
        "agents_per_host": MAX_AGENTS,
        "clusters_per_host": MAX_CLUSTERS,
        "services_per_host": MAX_SERVICES,
        "domains_per_match": MAX_DOMAINS,
        "ips_per_domain": MAX_DOMAIN_IPS,
        "agents_per_domain": MAX_AGENTS,
        "rdns_per_host": 10,
        "families_per_agent": 10,
        "ports_per_agent": 20,
        "products_per_service": 20,
        "titles_per_service": 10,
        "cert_cn_per_service": 10,
        "classes_per_service": 10,
        "agents_per_service": 10,
        "timeline_keys": 20,
        "prose_chars": MAX_PROSE,
        "unsupported_rows_per_page": MAX_UNSUPPORTED_ROWS,
        "rejected_rows_per_page": MAX_REJECTED_ROWS,
    }


def _build_lookup_result(batch: PreparedBatch, payload: dict[str, Any],
                         params: Any, input_digest: str) -> dict[str, Any]:
    groups = batch.groups
    send_groups = [g for g in groups if g["outcome"] == "send"]
    unsupported = [g for g in groups if g["outcome"] == "unsupported"]
    rejected = [g for g in groups if g["outcome"] == "rejected"]

    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    matches_by_query: dict[str, dict[str, Any]] = {}
    for item in data.get("matches") or []:
        if isinstance(item, dict) and isinstance(item.get("indicator"), str):
            matches_by_query.setdefault(item["indicator"], item)
    not_found_set = {item for item in (data.get("not_found") or [])
                     if isinstance(item, str)}
    invalid_by_query: dict[str, str] = {}
    for item in data.get("invalid") or []:
        if isinstance(item, str):
            invalid_by_query[item] = "upstream marked the indicator invalid"
        elif isinstance(item, dict) and isinstance(item.get("indicator"), str):
            invalid_by_query[item["indicator"]] = "upstream marked the indicator invalid"

    matches: list[dict[str, Any]] = []
    not_found: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    matched_ips: list[str] = []
    for group in send_groups:
        query = group["query_indicator"]
        if query in matches_by_query:
            raw_match = matches_by_query[query]
            matches.append(_project_match(raw_match, group,
                                          params.max_hosts_per_indicator))
            for host in raw_match.get("hosts") or []:
                if isinstance(host, dict) and isinstance(host.get("ip"), str):
                    matched_ips.append(host["ip"])
        elif query in not_found_set:
            not_found.append(_not_found(group))
        elif query in invalid_by_query:
            invalid.append(_invalid(group, invalid_by_query[query]))
        else:
            invalid.append(_invalid(group, "upstream_omitted"))

    u_offset = min(params.unsupported_offset, len(unsupported))
    r_offset = min(params.rejected_offset, len(rejected))
    unsupported_rows = unsupported[u_offset:u_offset + MAX_UNSUPPORTED_ROWS]
    rejected_rows = rejected[r_offset:r_offset + MAX_REJECTED_ROWS]
    u_remaining = max(0, len(unsupported) - (u_offset + len(unsupported_rows)))
    r_remaining = max(0, len(rejected) - (r_offset + len(rejected_rows)))
    unsupported_types = Counter(g["detected_type"] for g in unsupported)

    return {
        "status": "ok" if send_groups else "nothing_sent",
        "provider_supported_types": list(SUPPORTED_TYPES),
        "input_digest": input_digest,
        "lookup_reference": (_issue_lookup_reference(matched_ips)
                             if matched_ips else None),
        "display_caps": _display_caps(params.max_hosts_per_indicator),
        "submitted_raw": batch.raw_count,
        "submitted_unique": batch.unique_count,
        "duplicates_removed": batch.duplicates_removed,
        "matched_count": len(matches),
        "not_found_count": len(not_found),
        "invalid_count": len(invalid),
        "unsupported_count": len(unsupported),
        "rejected_count": len(rejected),
        "sent_count": len(send_groups),
        "matches": matches,
        "not_found": not_found,
        "invalid": invalid,
        "unsupported": [_group_originals(g) for g in unsupported_rows],
        "unsupported_offset": u_offset,
        "unsupported_total": len(unsupported),
        "unsupported_remaining": u_remaining,
        "unsupported_next_offset": (u_offset + len(unsupported_rows)
                                    if u_remaining else None),
        "unsupported_truncated": u_remaining,
        "unsupported_by_type": dict(sorted(unsupported_types.items())),
        "rejected": [_group_originals(g) for g in rejected_rows],
        "rejected_offset": r_offset,
        "rejected_total": len(rejected),
        "rejected_remaining": r_remaining,
        "rejected_next_offset": (r_offset + len(rejected_rows)
                                 if r_remaining else None),
        "rejected_truncated": r_remaining,
        "selection": _selection(params.selection_basis, params.evidence_ref),
        "transmission": _transmission(len(send_groups), len(unsupported), len(rejected)),
        "interpretation": _interpretation(_clip(meta.get("ref_day"), 32) or None),
        "meta": {
            "ref_day": _clip(meta.get("ref_day"), 32),
            "active_since": _clip(meta.get("active_since"), 32),
        },
        "attribution": _attribution(meta),
    }


def _host_line(host: dict[str, Any]) -> str:
    network = host.get("network") or {}
    active = host.get("active")
    state = "active" if active is True else "historical" if active is False else "unknown"
    parts = [f"- `{host.get('ip', '')}`: {state}"]
    if host.get("last_seen"):
        parts.append(f"last seen {host['last_seen']}")
    network_bits = [network.get("kind"), network.get("country"),
                    network.get("asn"), network.get("org")]
    network_text = " ".join(bit for bit in network_bits if bit)
    if network_text:
        parts.append(network_text)
    line = "; ".join(parts)
    agents_block = host.get("agents") or {}
    agents = [a.get("name") for a in agents_block.get("items") or []
              if a.get("name")]
    if agents:
        line += f", agents: {', '.join(agents)}"
    if host.get("shared_cdn"):
        line += ", shared CDN front"
    return line


def _render_lookup_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# offensive.agency IOC lookup",
        "",
        f"**Submitted**: {result['submitted_raw']} raw, "
        f"{result['submitted_unique']} unique, "
        f"{result['duplicates_removed']} duplicate(s)",
        f"**Sent**: {result['sent_count']} | **Matched**: {result['matched_count']} | "
        f"**Not found**: {result['not_found_count']} | "
        f"**Invalid**: {result['invalid_count']} | "
        f"**Unsupported**: {result['unsupported_count']} | "
        f"**Rejected**: {result['rejected_count']}",
        "",
        f"**Selection**: {result['selection']['basis']} (caller-asserted from "
        "Wazuh MCP analysis)",
    ]
    evidence = result["selection"].get("evidence_ref")
    if evidence:
        lines.append(f"**Evidence reference**: {evidence}")
    lines.append(f"**Transmission**: {result['transmission']['indicators_sent']} "
                 f"indicator(s) sent to {result['transmission']['destination']}; "
                 f"{result['unsupported_total']} unsupported and "
                 f"{result['rejected_total']} rejected were not sent.")
    lines.append("")

    for match in result["matches"]:
        lines.append(f"## `{match['query_indicator']}` ({match['type']}): "
                     f"{match['active_hosts']} active / "
                     f"{match['inactive_hosts']} historical")
        if match["shared_cdn_hosts"]:
            lines.append("> Shared CDN front. Match the domain, not the IP.")
        if match["type"] == "domain":
            lines.append(f"- Match scope: `{match['match_scope']}`")
        hosts = match["hosts"]
        if hosts["items"]:
            for host in hosts["items"]:
                lines.append(_host_line(host))
            if hosts["truncated"]:
                lines.append(
                    f"- ... {hosts['total_count'] - hosts['returned_count']} more "
                    "host(s) not shown")
        domains = match["domains"]
        if domains["items"]:
            names = ", ".join(f"`{d['name']}`" for d in domains["items"]
                              if d.get("name"))
            lines.append(f"- Matched domains: {names}")
            if domains["truncated"]:
                lines.append(
                    f"- ... {domains['total_count'] - domains['returned_count']} "
                    "more domain(s) not shown")
        lines.append("")

    if result["not_found"]:
        lines.append("## Not in the tracker")
        for item in result["not_found"]:
            originals = item["original_indicators"]
            suffix = ""
            if len(originals) > 1 or originals[0] != item["query_indicator"]:
                suffix = f" (original: {', '.join(f'`{o}`' for o in originals)})"
            lines.append(f"- `{item['query_indicator']}`{suffix}")
        lines.append("")

    if result["invalid"]:
        lines.append("## Invalid or incomplete upstream result")
        for item in result["invalid"]:
            lines.append(f"- `{item['query_indicator']}`: {item['reason']}")
        lines.append("")

    if result["unsupported"]:
        lines.append("## Not queried (unsupported type)")
        lines.append("offensive.agency supports IP, CIDR, and domain only. "
                     "These values were not sent.")
        for item in result["unsupported"]:
            originals = ", ".join(f"`{o}`" for o in item["original_indicators"])
            lines.append(f"- {originals}: {item['detected_type']}")
        if result["unsupported_next_offset"] is not None:
            lines.append(f"- ... {result['unsupported_remaining']} more; call again "
                         f"with unsupported_offset={result['unsupported_next_offset']}")
        lines.append("")

    if result["rejected"]:
        lines.append("## Not sent (validation)")
        for item in result["rejected"]:
            originals = ", ".join(f"`{o}`" for o in item["original_indicators"])
            lines.append(f"- {originals}: {item['reason']}")
        if result["rejected_next_offset"] is not None:
            lines.append(f"- ... {result['rejected_remaining']} more; call again "
                         f"with rejected_offset={result['rejected_next_offset']}")
        lines.append("")

    lines.extend([
        "## How to read this",
        "- External observation, not independently verified by this server.",
        f"- `active=true` means seen in the last 7 days as of "
        f"{result['meta'].get('ref_day') or 'the provider reference day'}; "
        "`active=false` is historical.",
        "- `network.kind=cdn` is shared infrastructure; match the domain, not the IP.",
        "- A domain match can be a subdomain; check `match_scope`.",
        "- A match means an exposed agent console was observed; it does not "
        "identify the operator or prove intent.",
        "- Absence from the tracker is not a clean verdict.",
        "- Unsupported types were not checked. They are not clean.",
        "",
        result["attribution"],
    ])
    return "\n".join(lines)


def _render_host_markdown(result: dict[str, Any]) -> str:
    lines = [f"# offensive.agency host: `{result['ip']}`", ""]
    if result["status"] == "not_found":
        lines.extend([
            "No tracker record. This is not a clean verdict.",
            "",
            result["attribution"],
        ])
        return "\n".join(lines)

    state = "active" if result.get("active") is True else (
        "historical" if result.get("active") is False else "unknown")
    lines.extend([
        f"**State**: {state}",
        f"**First seen**: {result.get('first_seen') or '-'}",
        f"**Last seen**: {result.get('last_seen') or '-'}",
    ])
    network = result.get("network") or {}
    network_text = " ".join(str(network.get(key) or "") for key in
                            ("kind", "country", "asn", "org")).strip()
    if network_text:
        lines.append(f"**Network**: {network_text}")
    agents_block = result.get("agents") or {}
    agents = [a.get("name") for a in agents_block.get("items") or []
              if a.get("name")]
    if agents:
        suffix = (" (showing "
                  f"{agents_block.get('returned_count')} of "
                  f"{agents_block.get('total_count')})"
                  if agents_block.get("truncated") else "")
        lines.append(f"**Agents**: {', '.join(agents)}{suffix}")
    clusters_block = result.get("clusters") or {}
    if clusters_block.get("items"):
        suffix = (" (showing "
                  f"{clusters_block.get('returned_count')} of "
                  f"{clusters_block.get('total_count')})"
                  if clusters_block.get("truncated") else "")
        lines.append(f"**Clusters**: {', '.join(clusters_block['items'])}{suffix}")
    cohosting = result.get("cohosting") or {}
    c2_block = cohosting.get("c2") or {}
    classes_block = cohosting.get("classes") or {}
    c2 = c2_block.get("items") or []
    classes = classes_block.get("items") or []
    if c2 or classes:
        lines.append(f"**Cohosting**: C2 {', '.join(c2) or '-'}; "
                     f"classes {', '.join(classes) or '-'}")
    lines.append("")

    services = result["services"]
    if services["items"]:
        lines.extend([
            "## Services",
            "| Port | Products | Classes | TLS | Last seen | Titles |",
            "|---|---|---|---|---|---|",
        ])
        for service in services["items"]:
            titles = "; ".join(_escape_md_table(t) for t in service["titles"]["items"])
            products = ", ".join(service["products"]["items"])
            classes_text = ", ".join(service["classes"]["items"])
            lines.append(
                f"| {service['port'] if service['port'] is not None else '-'} "
                f"| {_escape_md_table(products)} "
                f"| {_escape_md_table(classes_text)} "
                f"| {'yes' if service['tls'] else 'no'} "
                f"| {service['last_seen']} "
                f"| {titles} |")
        if services["truncated"]:
            lines.append(
                f"\n... {services['total_count'] - services['returned_count']} "
                "more service(s) not shown")
        lines.append("")

    domains = result["domains"]
    if domains["items"]:
        lines.append("## Domains")
        for domain in domains["items"]:
            cdn = " (behind CDN)" if domain["behind_cdn"] else ""
            lines.append(f"- `{domain['name']}`{cdn}: last seen "
                         f"{domain['last_seen'] or '-'}")
        if domains["truncated"]:
            lines.append(
                f"- ... {domains['total_count'] - domains['returned_count']} "
                "more not shown")
        lines.append("")

    timeline = result["timeline"]
    if timeline["items"]:
        lines.append("## Timeline")
        for slug, days in timeline["items"].items():
            lines.append(f"- `{slug}`: {', '.join(days)}")
        if timeline["truncated"]:
            lines.append(
                f"- ... {timeline['total_count'] - timeline['returned_count']} "
                "more timeline key(s) not shown")
        lines.append("")

    sources = result["sources"]
    if sources["items"]:
        suffix = (" (showing "
                  f"{sources['returned_count']} of {sources['total_count']})"
                  if sources["truncated"] else "")
        lines.append(f"**Sources**: {', '.join(sources['items'])}{suffix}")

    lines.extend([
        "",
        "## How to read this",
        "- External observation, not independently verified by this server.",
        f"- `active=true` means seen in the last 7 days as of "
        f"{result['meta'].get('ref_day') or 'the provider reference day'}; "
        "`active=false` is historical.",
        "- `network.kind=cdn` is shared infrastructure; match the domain, not the IP.",
        "- A match means an exposed agent console was observed; it does not "
        "identify the operator or prove intent.",
        "- A listed host can be a compromised victim, not an attacker.",
        "",
        result["attribution"],
    ])
    return "\n".join(lines)


def _project_host_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    raw_services = data.get("services") if isinstance(data.get("services"), list) else []
    raw_domains = data.get("domains") if isinstance(data.get("domains"), list) else []
    services = _capped_list(
        raw_services, MAX_SERVICES,
        lambda s: _service(s) if isinstance(s, dict) else None)
    domains = _capped_list(
        raw_domains, MAX_DOMAINS,
        lambda d: _domain(d) if isinstance(d, dict) else None)
    timeline_raw = data.get("timeline") if isinstance(data.get("timeline"), dict) else {}
    timeline = _capped_dict(
        timeline_raw, 20,
        lambda days: ([_clip(day, 32) for day in days]
                      if isinstance(days, list) else None))
    cohosting = data.get("cohosting")
    if not isinstance(cohosting, dict):
        cohosting = {}
    return {
        "status": "ok",
        "tracked": True,
        "ip": _clip(data.get("ip"), 64),
        "display_caps": _display_caps(None),
        "active": data.get("active") if isinstance(data.get("active"), bool) else None,
        "active_window_days": 7,
        "first_seen": _clip(data.get("first_seen"), 32),
        "last_seen": _clip(data.get("last_seen"), 32),
        "network": _network(data.get("network")),
        "agents": _capped_list(
            data.get("agents"), MAX_AGENTS,
            lambda a: _agent(a) if isinstance(a, dict) else None),
        "clusters": _capped_strings(data.get("clusters"), MAX_CLUSTERS),
        "cohosting": {
            "c2": _capped_strings(cohosting.get("c2"), MAX_CLUSTERS),
            "classes": _capped_strings(cohosting.get("classes"), MAX_CLUSTERS),
        },
        "domains": domains,
        "services": services,
        "sources": _capped_strings(data.get("sources"), 20),
        "timeline": timeline,
        "titles": _capped_strings(data.get("titles"), 20),
        "transmission": _transmission(1, 0, 0),
        "interpretation": _interpretation(_clip(meta.get("ref_day"), 32) or None),
        "meta": {
            "ref_day": _clip(meta.get("ref_day"), 32),
            "active_since": _clip(meta.get("active_since"), 32),
        },
        "attribution": _attribution(meta),
    }


def _not_found_host(ip: str, message: str, meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_found",
        "tracked": False,
        "ip": ip,
        "message": _clip(message, 300) or "No tracker record.",
        "transmission": _transmission(1, 0, 0),
        "interpretation": _interpretation(_clip(meta.get("ref_day"), 32) or None),
        "meta": {
            "ref_day": _clip(meta.get("ref_day"), 32),
            "active_since": _clip(meta.get("active_since"), 32),
        },
        "attribution": _attribution(meta),
    }


class OffensiveAgencyLookupInput(BaseModel):
    """Input for ``blueteam_offensive_agency_lookup``."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicators: list[str] = Field(
        ..., min_length=1,
        description=("Attacker-related IOCs from Wazuh MCP analysis. IP, CIDR, "
                     "and domain are queried; other types are returned as "
                     "unsupported and are never sent."),
    )
    selection_basis: SelectionBasis = Field(
        ...,
        description=("Why these indicators qualify as attacker-related: "
                     "confirmed_malicious_source, attacker_c2, "
                     "malicious_destination, malicious_domain, attacker_network, "
                     "or attacker_infrastructure."),
    )
    evidence_ref: str = Field(
        default="", max_length=200,
        description=("Local reference to the Wazuh MCP analysis (case ID, rule "
                     "IDs, report ID). Not sent to offensive.agency."),
    )
    max_hosts_per_indicator: int = Field(
        default=25, ge=1, le=MAX_HOST_ROWS,
        description="Maximum host rows rendered per matched indicator.",
    )
    unsupported_offset: int = Field(
        default=0, ge=0, le=MAX_INDICATORS,
        description="Pagination offset for the unsupported[] list.",
    )
    rejected_offset: int = Field(
        default=0, ge=0, le=MAX_INDICATORS,
        description="Pagination offset for the rejected[] list.",
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("indicators")
    @classmethod
    def _check_indicators(cls, value: list[str]) -> list[str]:
        if len(value) > MAX_INDICATORS:
            raise ValueError(
                f"batch_limit_exceeded: {len(value)} indicators; the provider "
                f"accepts at most {MAX_INDICATORS} per request.")
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("each indicator must be a string")
            text = item.strip()
            if len(text) > MAX_RAW_ITEM_CHARS:
                raise ValueError(
                    f"indicator_too_long: an indicator exceeds the raw safety "
                    f"bound of {MAX_RAW_ITEM_CHARS} characters")
            cleaned.append(text)
        return cleaned

    @field_validator("evidence_ref")
    @classmethod
    def _clean_evidence(cls, value: str) -> str:
        if any(not ch.isprintable() for ch in value):
            raise ValueError("evidence_ref must not contain control characters")
        return value.strip()


class OffensiveAgencyHostInput(BaseModel):
    """Input for ``blueteam_offensive_agency_host``."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(..., min_length=2, max_length=64,
                    description="Public IPv4/IPv6 attacker host from a lookup match.")
    lookup_reference: str = Field(
        ..., min_length=8, max_length=64,
        description=("The lookup_reference returned by a successful "
                     "blueteam_offensive_agency_lookup; it authorizes host detail "
                     "only for matched public IPs."),
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return _normalize_public_ip(value)


@blueteam_tool(
    name="blueteam_offensive_agency_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
    audit=False, redact=False,
)
async def blueteam_offensive_agency_lookup(params: OffensiveAgencyLookupInput) -> str:
    """Look up attacker-related IPs, CIDRs, and domains against offensive.agency.

    Use this after Wazuh MCP analysis has identified attacker infrastructure:
    confirmed malicious source IPs, C2 addresses, malicious destinations tied
    to attacker infrastructure, malicious domains, or attacker-associated
    networks. Do not pass victim IPs, internal ranges,
    normal destination IPs, benign domains, or every indicator in an alert. The
    tool cannot verify attribution; it records the caller's selection basis and
    treats the result as enrichment evidence.

    The tool sends only the supported values (IP, CIDR, domain) to
    ``https://www.offensive.agency/api/v1/lookup``. Other IOC types are accepted,
    preserved in ``unsupported[]`` with the original value, and never sent. No
    API key is required. The provider asks for fair use; this client sends at
    most one request per second and caches a response for six hours.

    A match means an exposed agent console was observed. It does not identify the
    operator, prove intent, or prove the host attacked you. ``active=false`` is a
    historical record. ``network.kind=cdn`` is shared infrastructure. A domain
    match can be a subdomain; read ``match_scope``. Absence from the tracker is
    not a clean verdict. Data by ONYPHE, published by offensive.agency.

    Worked examples:
    1. Confirmed malicious source IPs from a case:
       ``blueteam_offensive_agency_lookup(indicators=["49.51.141.166", "8.134.122.188"], selection_basis="confirmed_malicious_source", evidence_ref="case IR-2026-001")``
    2. Attacker C2 infrastructure:
       ``blueteam_offensive_agency_lookup(indicators=["92.255.57.87"], selection_basis="attacker_c2")``
    3. A malicious domain and an attacker network:
       ``blueteam_offensive_agency_lookup(indicators=["artex.h1xx.net", "5.39.0.0/16"], selection_basis="attacker_infrastructure", response_format="json")``

    Permissions: read-only, no Wazuh role, no provider credential.
    Every capped collection is an object with ``items``, ``total_count``,
    ``returned_count``, and ``truncated``. Unsupported and rejected lists are
    paged 100 rows at a time; use ``unsupported_offset`` or ``rejected_offset``
    to read the rest, and the totals stay exact.

    Rate limit: 1 request/second, 6-hour process-local cache, 2 MB response cap.
    """
    input_digest = _digest([item.strip() for item in params.indicators])
    batch = prepare_batch(params.indicators)
    _audit_log(
        "blueteam_offensive_agency_lookup",
        {
            "count": batch.raw_count,
            "unique": batch.unique_count,
            "sent": len(batch.send_queries),
            "selection_basis": params.selection_basis,
            "evidence_ref": params.evidence_ref,
        },
        detail={
            "types": dict(sorted(Counter(g["detected_type"] for g in batch.groups).items())),
            "input_digest": input_digest,
            "sent_digest": _digest(batch.send_queries),
        },
    )
    payload = await _bulk_lookup(batch.send_queries) if batch.send_queries else {}
    result = _build_lookup_result(batch, payload, params, input_digest)
    if params.response_format == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)
    return _render_lookup_markdown(result)


@blueteam_tool(
    name="blueteam_offensive_agency_host",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
    audit=False, redact=False,
)
async def blueteam_offensive_agency_host(params: OffensiveAgencyHostInput) -> str:
    """Show one host's exposed agents, services, domains, and observation timeline.

    Use this for a public IP returned by ``blueteam_offensive_agency_lookup`` and
    pass the ``lookup_reference`` from that result. The server verifies that the IP
    was a matched host in the referenced lookup; an unknown, expired, or unmatched
    reference is refused. The host detail comes from ``GET /hosts/<ip>`` and adds
    the services, domains, sources, and timeline that the bulk lookup omits. A 404
    returns ``tracked: false``; it means no tracker record, not a clean verdict.

    A listed host can be a compromised victim. A match means an exposed agent
    console was observed; it does not identify the operator or prove intent.
    ``active=false`` is historical. ``network.kind=cdn`` is shared infrastructure.
    Every capped collection is an object with ``items``, ``total_count``,
    ``returned_count``, and ``truncated``.

    Worked examples:
    1. Detail for a matched host:
       ``blueteam_offensive_agency_host(ip="49.51.141.166", lookup_reference="<from lookup>")``
    2. A host with no tracker record:
       ``blueteam_offensive_agency_host(ip="8.8.8.8", lookup_reference="<from lookup>")`` returns ``tracked: false``.
    3. JSON for an analyst pipeline:
       ``blueteam_offensive_agency_host(ip="92.255.57.87", lookup_reference="<from lookup>", response_format="json")``

    Permissions: read-only, no Wazuh role, no provider credential.
    Rate limit: 1 request/second, 6-hour process-local cache, 2 MB response cap.
    Data by ONYPHE, published by offensive.agency.
    """
    _verify_lookup_reference(params.lookup_reference, params.ip)
    _audit_log("blueteam_offensive_agency_host", {"ip": params.ip},
               detail={"lookup_reference_verified": True})
    payload = await _host_lookup(params.ip)
    if payload.get("_not_found"):
        result = _not_found_host(params.ip, str(payload.get("message") or ""), {})
    else:
        result = _project_host_payload(payload)
    if params.response_format == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)
    return _render_host_markdown(result)
