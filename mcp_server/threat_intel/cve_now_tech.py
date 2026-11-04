#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Technology identification across every allowlisted alert field.

The previous map matched whole `rule.groups` tokens plus a handful of URL markers,
so an alert whose description said "Joomla component file upload" produced no
technology at all. This module reads the fields Wazuh actually populates and
records where each name came from.

Identification is not correlation. A technology found here seeds CVE discovery; it
never promotes a candidate. Ambiguous mentions stay ambiguous: a rule that lists
three CMS platforms has not identified which one was attacked.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_server.threat_intel.cve_now import TECH_SLUGS
from mcp_server.threat_intel.cve_now_assess import ATTACK_CLASSES

# name -> catalogue entry. `slug` is the cve.now technology slug when one exists;
# None means the technology is identifiable but has no discoverable catalogue feed.
CATALOG: dict[str, dict[str, Any]] = {
    "wordpress": {"slug": "wordpress", "kind": "cms",
                  "names": ("wordpress", "wp-content", "wp-login", "xmlrpc.php", "woocommerce")},
    "joomla": {"slug": None, "kind": "cms", "names": ("joomla",)},
    "drupal": {"slug": None, "kind": "cms", "names": ("drupal",)},
    "magento": {"slug": None, "kind": "cms", "names": ("magento", "adobe commerce")},
    "typo3": {"slug": None, "kind": "cms", "names": ("typo3",)},
    "laravel": {"slug": None, "kind": "framework",
                "names": ("laravel", "vendor/laravel", "laravel/framework", "artisan")},
    "phpunit": {"slug": None, "kind": "framework",
                "names": ("phpunit", "vendor/phpunit", "eval-stdin.php")},
    "symfony": {"slug": None, "kind": "framework", "names": ("symfony",)},
    "django": {"slug": "django", "kind": "framework", "names": ("django",)},
    "flask": {"slug": "flask", "kind": "framework", "names": ("flask",)},
    "rails": {"slug": "rails", "kind": "framework", "names": ("ruby on rails", "rails")},
    "spring": {"slug": "spring", "kind": "framework", "names": ("spring boot", "spring framework", "spring")},
    "nextjs": {"slug": "nextjs", "kind": "framework", "names": ("next.js", "nextjs", "_next/")},
    "react": {"slug": "react", "kind": "framework", "names": ("react", "reactjs", "react server component")},
    "express": {"slug": "express", "kind": "framework", "names": ("express.js", "expressjs")},
    "apache-httpd": {"slug": "apache-httpd", "kind": "server",
                     "names": ("apache http server", "apache httpd", "httpd", "apache")},
    "nginx": {"slug": "nginx", "kind": "server", "names": ("nginx",)},
    "iis": {"slug": None, "kind": "server", "names": ("internet information services", "iis", "windows iis")},
    "tomcat": {"slug": None, "kind": "server", "names": ("apache tomcat", "tomcat", "catalina")},
    "php": {"slug": "php", "kind": "runtime", "names": ("php", "php-fpm")},
    "aspnet": {"slug": None, "kind": "runtime", "names": ("asp.net core", "asp.net", "aspnet", "aspx")},
    "dotnet": {"slug": None, "kind": "runtime", "names": (".net framework", ".net core", "dotnet")},
    "node": {"slug": "node", "kind": "runtime", "names": ("node.js", "nodejs")},
    "python": {"slug": None, "kind": "runtime", "names": ("python", "wsgi", "gunicorn")},
    "java": {"slug": None, "kind": "runtime", "names": ("java", "jvm", "jndi")},
    "ruby": {"slug": None, "kind": "runtime", "names": ("ruby", "puma", "unicorn")},
    "log4j": {"slug": "log4j", "kind": "component", "names": ("log4j", "log4shell", "log4j2")},
    "openssl": {"slug": "openssl", "kind": "component", "names": ("openssl",)},
    "mysql": {"slug": "mysql", "kind": "database", "names": ("mysql",)},
    "mariadb": {"slug": "mariadb", "kind": "database", "names": ("mariadb",)},
    "postgresql": {"slug": "postgresql", "kind": "database", "names": ("postgresql", "postgres")},
    "microsoft-sql-server": {"slug": "microsoft-sql-server", "kind": "database",
                             "names": ("microsoft sql server", "mssql", "sql server")},
    "mongodb": {"slug": "mongodb", "kind": "database", "names": ("mongodb", "mongo")},
    "redis": {"slug": "redis", "kind": "database", "names": ("redis",)},
    "kubernetes": {"slug": "kubernetes", "kind": "platform", "names": ("kubernetes", "k8s")},
    "docker": {"slug": "docker", "kind": "platform", "names": ("docker",)},
    "jenkins": {"slug": "jenkins", "kind": "app", "names": ("jenkins",)},
    "gitlab": {"slug": "gitlab", "kind": "app", "names": ("gitlab",)},
    "fortinet": {"slug": "fortinet", "kind": "app", "names": ("fortinet", "fortigate")},
    "citrix": {"slug": "citrix", "kind": "app", "names": ("citrix", "netscaler")},
    "vmware": {"slug": "vmware", "kind": "platform", "names": ("vmware", "vcenter", "esxi")},
    "microsoft-exchange": {"slug": "microsoft-exchange", "kind": "app",
                           "names": ("microsoft exchange", "exchange server", "owa")},
}

# Fields read for evidence, in priority order. Every one is already allowlisted by
# extract_alert_context; full_log is absent by design.
EVIDENCE_FIELDS = (
    ("rule.groups", "groups"),
    ("rule.description", "description"),
    ("data.url", "path"),
    ("data.command", "path"),
    ("decoder.name", "runtime"),
    ("location", "runtime"),
    ("data.user_agent", "runtime"),
)

_ATTACK_WORDS = tuple({token for _, tokens in ATTACK_CLASSES for token in tokens
                       if len(token) > 3})
# Nouns that mark the sentence as an attack description even when no classifier
# token matched ("request validation bypass" names no verb we track).
ATTACK_CONTEXT_WORDS = ("attack", "exploit", "bypass", "injection", "upload", "traversal",
                        "inclusion", "deserial", "execution", "brute", "scan", "probe",
                        "enumeration", "shell", "malware", "rce", "xss", "sqli")

# What the technology is in this alert: attacked software, runtime, surrounding
# platform, or merely the log writer.
ROLE_BY_KIND = {
    "cms": "target_application",
    "app": "target_application",
    "framework": "target_framework",
    "runtime": "runtime",
    "database": "infrastructure",
    "server": "infrastructure",
    "platform": "infrastructure",
    "component": "runtime",
}
LOG_ONLY_FIELDS = {"location", "decoder.name", "data.user_agent"}

# A generic attack word is not enough for a server: "server returned" and "access log"
# say where the event came from, not what was attacked.
CLASSIFICATION_STRENGTH = {
    "explicit_target": 4,
    "inferred_pattern": 3,
    "inferred_runtime": 2,
    "runtime_hint": 1,
    "mentioned": 1,
    "ambiguous": 0,
}

LOGGING_WINDOW = 24  # characters between a server name and the log phrase

SERVER_LOG_PHRASES = ("access log", "error log", "log source", "logs", "logging", "log")
SERVER_VULN_PHRASES = ("vulnerability", "vulnerable", "unpatched", "cve-")
SERVER_EXPLOIT_PHRASES = ("exploit", "remote code execution", "rce", "attack against")
SERVER_INFRA_PHRASES = ("response", "header", "returned", "proxy", "upstream", "gateway")


def _positions(text: str, token: str, start: int = 0, end: int | None = None) -> list[int]:
    end = len(text) if end is None else end
    found, position = [], text.find(token, start, end)
    while position != -1:
        found.append(position)
        position = text.find(token, position + 1, end)
    return found


def _clause(text: str, position: int) -> tuple[int, int]:
    """Sentence/clause bounds around a position."""
    start = 0
    for separator in ";.!?":
        index = text.rfind(separator, 0, position)
        if index != -1:
            start = max(start, index + 1)
    end = len(text)
    for separator in ";.!?":
        index = text.find(separator, position)
        if index != -1:
            end = min(end, index)
    return start, end


def _clause_distance(text: str, phrase: str, technology: str,
                     window: int | None = None) -> int | None:
    """Characters between a phrase and this technology, inside one clause.

    None when the phrase is in another clause, when a competing technology is closer,
    or when the gap exceeds ``window``. That is what stops an unrelated "log" elsewhere
    in the sentence from overriding a real target statement.
    """
    best = None
    for position in _positions(text, phrase):
        start, end = _clause(text, position)
        own = [p for token in CATALOG[technology]["names"]
               for p in _positions(text, token, start, end)]
        if not own:
            continue
        distance = min(abs(position - p) for p in own)
        if window is not None and distance > window:
            continue
        others = [p for name, entry in CATALOG.items() if name != technology
                  for token in entry["names"] for p in _positions(text, token, start, end)]
        if others and min(abs(position - p) for p in others) < distance:
            continue
        if best is None or distance < best:
            best = distance
    return best


def _min_distance(text: str, phrases: tuple[str, ...], technology: str,
                  window: int | None = None) -> int | None:
    values = [_clause_distance(text, phrase, technology, window) for phrase in phrases]
    present = [value for value in values if value is not None]
    return min(present) if present else None


def _server_relationship(description: str, field: str, same_kind: int,
                         technology: str) -> str:
    if field in LOG_ONLY_FIELDS:
        return "log_source"
    low = description.lower()
    if same_kind > 1:
        return "ambiguous"
    log_distance = _min_distance(low, SERVER_LOG_PHRASES, technology, LOGGING_WINDOW)
    exploit_distance = _min_distance(low, SERVER_EXPLOIT_PHRASES, technology)
    vuln_distance = _min_distance(low, SERVER_VULN_PHRASES, technology)
    attack = [d for d in (exploit_distance, vuln_distance) if d is not None]
    attack_distance = min(attack) if attack else None
    # A log phrase wins only when it is about this server and no attack phrase is closer.
    if log_distance is not None and (attack_distance is None or log_distance <= attack_distance):
        return "log_source"
    if exploit_distance is not None:
        return "explicit_exploitation_target"
    if vuln_distance is not None:
        return "explicit_vulnerability_target"
    return "infrastructure_context"


def _relationship_for(kind: str, best: str, description: str, field: str,
                      same_kind: int, technology: str) -> str:
    if kind == "server":
        return _server_relationship(description, field, same_kind, technology)
    if best == "ambiguous":
        return "ambiguous"
    if best == "mentioned":
        return "mentioned_only"
    if kind in ("cms", "framework", "app"):
        return "explicit_vulnerability_target"
    return "infrastructure_context"


def _match(text: str, token: str) -> bool:
    """Word boundaries for plain words; substring only for punctuated tokens."""
    if token.isalpha():
        return re.search(rf"\b{re.escape(token)}\b", text) is not None
    return token in text


def _is_extension(text: str, matched: str) -> bool:
    position = text.find(matched)
    while position != -1:
        if position > 0 and text[position - 1] == ".":
            return True
        position = text.find(matched, position + 1)
    return False


def _compound_prefixed(text: str, token: str) -> bool:
    """True when every occurrence follows a compound separator such as "/"."""
    position = text.find(token)
    if position == -1:
        return False
    while position != -1:
        if position == 0 or text[position - 1] not in "/-":
            return False
        position = text.find(token, position + 1)
    return True


def _is_runtime_name(matched: str) -> bool:
    return matched in {"php", "php-fpm", "asp.net", "aspx", "jsp", "node.js"}


def _haystacks(alert: dict) -> dict[str, str]:
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    values = {
        "rule.groups": ", ".join(str(g) for g in (rule.get("groups") or []))
        if isinstance(rule.get("groups"), list) else str(rule.get("groups") or ""),
        "rule.description": str(rule.get("description") or ""),
        "data.url": str(data.get("url") or ""),
        "data.command": str(data.get("command") or ""),
        "decoder.name": str((alert.get("decoder") or {}).get("name") or ""),
        "location": str(alert.get("location") or ""),
        "data.user_agent": str(data.get("user_agent") or ""),
    }
    return {field: value.lower() for field, value in values.items() if value}


def _classify(field: str, text: str, matched: str, same_kind_mentions: int,
              has_attack_word: bool) -> str:
    if field == "rule.groups":
        return "explicit_target"
    if field in ("data.url", "data.command"):
        return "runtime_hint" if _is_runtime_name(matched) else "inferred_pattern"
    # A .php filename names the runtime, not the product, wherever it appears.
    if field == "rule.description" and _is_runtime_name(matched) and _is_extension(text, matched):
        return "runtime_hint"
    if field in ("decoder.name", "location", "data.user_agent"):
        return "inferred_runtime"
    if same_kind_mentions > 1:
        return "ambiguous"
    return "explicit_target" if has_attack_word else "mentioned"


def identify_technologies(alert: dict) -> dict:
    """Extract technology evidence from every allowlisted field.

    Returns technologies with per-field evidence, the slugs that may seed CVE
    discovery, unmapped `rule.groups` tokens, and the ambiguous mentions that must
    not be treated as identity.
    """
    haystacks = _haystacks(alert)
    rule = alert.get("rule") or {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else str(rule.get("groups") or "").split(",")
    groups = [str(g).strip().lower() for g in groups if str(g).strip()]

    # Count same-kind mentions in the description, which is what makes a list
    # ("Joomla, Drupal or WordPress") ambiguous rather than identifying.
    description = haystacks.get("rule.description", "")
    mentioned_by_kind: dict[str, set[str]] = {}
    for name, entry in CATALOG.items():
        tokens = [token for token in entry["names"] if _match(description, token)]
        if not tokens:
            continue
        # "React Server Component/Next.js" names one product pair, not a list of
        # alternatives, so a compound prefix does not make the mention ambiguous.
        if all(_compound_prefixed(description, token) for token in tokens):
            continue
        mentioned_by_kind.setdefault(entry["kind"], set()).add(name)

    has_attack_word = any(word in description
                          for word in _ATTACK_WORDS + ATTACK_CONTEXT_WORDS)

    technologies: list[dict] = []
    for name, entry in CATALOG.items():
        evidence = []
        for field, kind in EVIDENCE_FIELDS:
            text = haystacks.get(field)
            if not text:
                continue
            for token in entry["names"]:
                if not _match(text, token):
                    continue
                classification = _classify(
                    field, text, token, len(mentioned_by_kind.get(entry["kind"], set())),
                    has_attack_word)
                evidence.append({"field": field, "matched": token, "kind": kind,
                                 "classification": classification})
                break
        if not evidence:
            continue

        best = max((item["classification"] for item in evidence),
                   key=lambda value: CLASSIFICATION_STRENGTH[value])
        slug = entry["slug"]
        if best == "ambiguous":
            status = "ambiguous"
        elif slug is None or slug not in TECH_SLUGS:
            status = "identified_no_slug"
        elif best == "runtime_hint":
            status = "runtime_hint_only"
        elif best == "mentioned":
            status = "mentioned_only"
        else:
            status = "mapped"

        # Identification, canonical identity, lookup id and discovery are separate facts;
        # a missing slug is not an identification failure.
        log_only = all(item["field"] in LOG_ONLY_FIELDS for item in evidence)
        role = "log_source" if (entry["kind"] == "server" and log_only) else ROLE_BY_KIND[entry["kind"]]
        relationship = _relationship_for(entry["kind"], best, description,
                                         evidence[0]["field"],
                                         len(mentioned_by_kind.get(entry["kind"], set())),
                                         name)
        # Only a target relationship seeds identity. A server that wrote the log, or
        # whose response was observed, stays discovery context.
        target = relationship in ("explicit_vulnerability_target",
                                  "explicit_exploitation_target")
        best_evidence = max(evidence,
                            key=lambda item: CLASSIFICATION_STRENGTH[item["classification"]])
        observation = {
            "data.url": "request_pattern",
            "data.command": "request_pattern",
            "rule.groups": "rule_group",
            "rule.description": "description",
        }.get(best_evidence["field"], "log_metadata")
        technologies.append({
            "technology": name,
            "identified": True,
            "role": role,
            "target": target,
            "target_relationship": relationship,
            "slug": slug if slug in TECH_SLUGS else None,
            "kind": entry["kind"],
            "identity": "canonical" if slug in TECH_SLUGS else "unresolved",
            "cve_lookup": "slug_available" if slug in TECH_SLUGS else "no_slug",
            "discovery": "performed" if status == "mapped" else "not_performed",
            "classification": best,
            "observation": observation,
            "installed_confirmation": "not_established",
            "status": status,
            "evidence": evidence,
            "conflict": len({item["classification"] for item in evidence}) > 1,
        })

    technologies.sort(key=lambda item: (-CLASSIFICATION_STRENGTH[item["classification"]],
                                        item["technology"]))
    discovery = [{"tech": item["slug"], "evidence": item["evidence"],
                  "role": item["role"], "target": item["target"]}
                 for item in technologies
                 if item["status"] == "mapped"]

    from mcp_server.threat_intel.cve_now import _GROUP_MAP
    unmapped_groups = [token for token in groups if token not in _GROUP_MAP]
    ambiguous = [item for item in technologies if item["status"] == "ambiguous"]
    unmapped_mentions = [item for item in technologies
                         if item["status"] == "identified_no_slug"]
    return {
        "technologies": technologies,
        "discovery": discovery,
        "ambiguous": ambiguous,
        "unmapped_mentions": unmapped_mentions,
        "unmapped_groups": unmapped_groups,
    }


LIMITATIONS = [
    "Identification is keyword-based over allowlisted fields. A description that names "
    "no technology yields none, and prose that lists several platforms is marked ambiguous.",
    "A technology with no cve.now slug is still identified: status identified_no_slug, "
    "identity unresolved, cve_lookup no_slug. It is never forced onto a nearby slug.",
    "Identification seeds discovery only. It cannot promote a CVE to attack_specific_match.",
]
