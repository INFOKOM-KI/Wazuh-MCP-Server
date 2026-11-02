#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Attack-to-CVE assessment: classify what the alert did, then test each candidate CVE
against that behaviour instead of against the technology name alone.

Pure functions only. Nothing here performs I/O, so every rule in this file is
testable without a network or an Indexer.

The hierarchy this module enforces, strongest first:

  confirmed_cve_reference  the alert carries the CVE id in a structured field
  attack_specific_match    the attack text names the vulnerable component and the
                           vulnerability class matches the observed behaviour
  vulnerability_exposure   the asset runs a version inside the CVE's affected range
  contextual_candidate     product or class overlap only
  no_supported_match       nothing above holds

A technology match alone never leaves the contextual tier. A public exploit
existing for a CVE is not evidence that this alert used it, and a KEV listing is
not evidence that this host was attacked.
"""
from __future__ import annotations

import re
from typing import Any

# Structured fields only. full_log is deliberately absent: it is attacker-written
# text, and a CVE quoted there is not an attribution.
ALERT_CONTEXT_FIELDS = (
    ("id", ("id",)),
    ("timestamp", ("@timestamp",)),
    ("rule.id", ("rule", "id")),
    ("rule.description", ("rule", "description")),
    ("rule.level", ("rule", "level")),
    ("rule.groups", ("rule", "groups")),
    ("rule.mitre.id", ("rule", "mitre", "id")),
    ("rule.mitre.tactic", ("rule", "mitre", "tactic")),
    ("rule.mitre.technique", ("rule", "mitre", "technique")),
    ("decoder.name", ("decoder", "name")),
    ("agent.id", ("agent", "id")),
    ("agent.name", ("agent", "name")),
    ("location", ("location",)),
)

DATA_CONTEXT_FIELDS = (
    ("data.url", ("data", "url")),
    ("data.method", ("data", "method")),
    ("data.command", ("data", "command")),
    ("data.user_agent", ("data", "user_agent")),
    ("data.protocol", ("data", "protocol")),
    ("data.srcip", ("data", "srcip")),
    ("data.dstip", ("data", "dstip")),
    ("data.dstport", ("data", "dstport")),
    ("data.status", ("data", "status")),
    ("data.error", ("data", "error")),
)

# Highest priority first. A rule that matches both "code execution" and "sqli"
# reports rce as the primary class and keeps every token as evidence.
ATTACK_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssti", ("template injection", "ssti", "jinja2", "jinja", "twig", "freemarker", "velocity template")),
    ("deserialization", ("deserial", "ysoserial", "pickle", "java serial")),
    ("idor", ("insecure direct object", "idor", "object reference")),
    ("command_injection", ("command injection", "cmd injection", "os command", "shell injection", "/bin/sh", "cmd.exe")),
    ("sql_injection", ("sql injection", "sqli", "sql_inject", "union select", "sqlmap")),
    ("xss", ("cross-site scripting", "cross site scripting", "xss", "<script")),
    ("ssrf", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("path_traversal", ("path traversal", "directory traversal", "../", "%2e%2e", "..%2f")),
    ("file_inclusion", ("local file inclusion", "remote file inclusion", "lfi", "rfi")),
    ("file_upload", ("file upload", "upload/execution", "webshell upload", "unrestricted upload")),
    ("auth_bypass", ("authentication bypass", "auth bypass", "login bypass", "improper authentication",
                     "unauthorized access", "authorization bypass")),
    ("misconfiguration", ("misconfiguration", "misconfigured", "exposed admin", "default credential",
                          "unauthenticated access")),
    ("brute_force", ("brute-force", "brute force", "failed login", "login attempt", "password guessing", "credential stuffing")),
    ("rce", ("remote code execution", "rce", "arbitrary code execution", "code execution")),
    ("privesc", ("privilege escalation", "privesc", "sudo", "setuid")),
    ("recon", ("scan", "scans", "scanning", "recon", "probe", "probing", "enumeration",
               "directory listing")),
    ("malware", ("malware", "trojan", "ransomware", "miner", "mirai", "backdoor")),
    ("post_exploitation", ("persistence", "lateral movement", "credential dump", "cron job")),
)

# Same vocabulary applied to the CVE record's own text.
VULN_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssti", ("template injection", "ssti", "server-side template")),
    ("deserialization", ("deserial", "pickle", "ysoserial")),
    ("idor", ("insecure direct object", "idor", "authorization bypass")),
    ("command_injection", ("command injection", "os command injection", "shell injection")),
    ("sql_injection", ("sql injection", "sqli")),
    ("xss", ("cross-site scripting", "xss")),
    ("ssrf", ("server-side request forgery", "ssrf")),
    ("path_traversal", ("path traversal", "directory traversal")),
    ("file_inclusion", ("file inclusion", "lfi", "rfi")),
    ("file_upload", ("unrestricted file upload", "arbitrary file upload", "file upload")),
    ("auth_bypass", ("authentication bypass", "auth bypass", "improper authentication", "missing authentication")),
    ("misconfiguration", ("misconfiguration", "security misconfiguration", "default credential")),
    ("privesc", ("privilege escalation", "improper privilege management")),
    ("rce", ("remote code execution", "arbitrary code execution", "code execution", "execute arbitrary")),
    ("info_disclosure", ("information disclosure", "information exposure", "file disclosure")),
    ("csrf", ("cross-site request forgery", "csrf")),
    ("dos", ("denial of service", "resource exhaustion")),
)

# Which CVE classes can produce which observed behaviour. A pair not listed is a
# mismatch, not a contradiction: the alert may simply be a different attack.
CLASS_COMPATIBILITY: dict[str, set[str]] = {
    "ssti": {"ssti", "rce", "info_disclosure"},
    "idor": {"idor", "auth_bypass", "info_disclosure"},
    "sql_injection": {"sql_injection"},
    "xss": {"xss"},
    "ssrf": {"ssrf"},
    "path_traversal": {"path_traversal", "file_inclusion", "info_disclosure"},
    "file_inclusion": {"file_inclusion", "path_traversal", "rce", "command_injection"},
    "file_upload": {"file_upload", "rce", "command_injection"},
    "command_injection": {"command_injection", "rce", "deserialization"},
    "deserialization": {"deserialization", "rce", "command_injection"},
    "rce": {"rce", "command_injection", "deserialization", "file_inclusion", "file_upload",
            "auth_bypass"},
    "auth_bypass": {"auth_bypass", "privesc", "rce"},
    "misconfiguration": {"misconfiguration", "auth_bypass", "info_disclosure"},
    "privesc": {"privesc", "auth_bypass"},
    "csrf": {"csrf"},
    "info_disclosure": {"info_disclosure", "path_traversal"},
    "dos": {"dos"},
}

# Only for the slugs the map can produce. A slug without an entry falls back to
# itself, which is correct for names that are already the product.
PRODUCT_SYNONYMS: dict[str, tuple[str, ...]] = {
    "wordpress": ("wordpress", "wp-content", "wp-login", "wp-admin", "xmlrpc.php"),
    "nextjs": ("next.js", "nextjs", "_next/"),
    "php": ("php",),
    "nginx": ("nginx",),
    "apache-httpd": ("apache http server", "httpd", "apache"),
    "microsoft-exchange": ("exchange server", "microsoft exchange"),
}

# WordPress plugin/theme directory from the requested path. Two characters minimum,
# so a placeholder like /plugins/x/ is not treated as an identity.
PLUGIN_PATH_RE = re.compile(r"/wp-content/(?:plugins|themes)/([A-Za-z0-9][A-Za-z0-9._-]{1,39})/", re.I)
GENERIC_PLUGIN_SLUGS = frozenset({
    "plugins", "themes", "uploads", "upload", "wp-content", "wordpress", "wp",
    "index", "assets", "static", "includes",
})

IDENTITY_LEVELS = ("none", "platform", "product_family", "exact_product", "exact_component")

# Reviewed aliases only; separators are never folded. Each entry records the record it
# came from and the product scope, so the pairing can be re-checked rather than trusted.
PLUGIN_SLUG_ALIASES: dict[str, dict[str, str]] = {
    "wp-scraper": {
        "canonical": "wp_scraper",
        "source": "CVE-2025-69129 affected[0].package",
        "scope": "WordPress plugin: WordPress & WooCommerce Scraper Plugin (Extendons)",
        "recorded": "2026-11-02",
    },
}

# A file name in the CVE text is the only endpoint evidence cve.now publishes.
DOCUMENTED_FILE_RE = re.compile(r"\b([a-z0-9_-]{2,}\.php)\b", re.I)

# Search phrases for each attack pattern. Fixed vocabulary, never alert prose: the
# only text that leaves the host is one of these strings plus a sanitized slug.
ATTACK_SEARCH_TERMS: dict[str, tuple[str, ...]] = {
    "rce": ("remote code execution",),
    "command_injection": ("command injection",),
    "sql_injection": ("sql injection",),
    "xss": ("cross-site scripting",),
    "ssrf": ("server-side request forgery",),
    "path_traversal": ("path traversal",),
    "file_inclusion": ("file inclusion",),
    "file_upload": ("arbitrary file upload",),
    "auth_bypass": ("authentication bypass",),
    "deserialization": ("deserialization",),
    "ssti": ("server-side template injection",),
    "idor": ("insecure direct object reference",),
    "privesc": ("privilege escalation",),
    "info_disclosure": ("information disclosure",),
    "csrf": ("cross-site request forgery",),
    "misconfiguration": ("security misconfiguration",),
}

# No search phrase on purpose:
#   brute_force        credential guessing is a technique; the CVEs are product-specific.
#   recon              scanning finds no CVE of its own; the technology query covers it.
#   malware            payload families are not catalogued as vulnerabilities.
#   post_exploitation  no CVE class exists for "already inside".


def search_terms_for(attack_class: str | None) -> list[str]:
    """Phrases a cve.now search can use for this behaviour, empty when unspecific."""
    if not attack_class:
        return []
    return list(ATTACK_SEARCH_TERMS.get(attack_class, ()))


RELATIONSHIP_ORDER = ("confirmed_cve_reference", "attack_specific_match",
                      "vulnerability_exposure", "contextual_candidate",
                      "no_supported_match")

STRENGTH_BY_RELATIONSHIP = {
    "confirmed_cve_reference": "strong",
    "attack_specific_match": "moderate",
    "vulnerability_exposure": "moderate",
    "contextual_candidate": "low",
    "no_supported_match": "none",
}

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)$")


def _get_path(node: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def _token_hit(text: str, token: str) -> bool:
    """Short acronyms need word boundaries; 'rce' must not match 'coerce'."""
    if len(token) <= 4 and token.isalpha():
        return re.search(rf"\b{re.escape(token)}\b", text) is not None
    return token in text


def _classify(text: str, table: tuple[tuple[str, tuple[str, ...]], ...]) -> dict:
    lowered = text.lower()
    hits: dict[str, list[str]] = {}
    for name, tokens in table:
        matched = [token for token in tokens if _token_hit(lowered, token)]
        if matched:
            hits[name] = matched
    primary = next((name for name, _ in table if name in hits), None)
    return {"class": primary, "hits": hits,
            "evidence": [f"{name}:{token}" for name, tokens in hits.items() for token in tokens],
            }


def extract_alert_context(alert: dict) -> dict:
    """Pull the allowlisted fields plus the text the classifier reads."""
    values: dict[str, Any] = {}
    for label, path in ALERT_CONTEXT_FIELDS + DATA_CONTEXT_FIELDS:
        found = _get_path(alert, path)
        if found not in (None, "", [], {}):
            values[label] = found

    url = str(values.get("data.url") or "")
    location = str(values.get("location") or "")
    plugin = _plugin_from_path(url) or _plugin_from_path(location)

    return {
        "alert_id": values.get("id"),
        "timestamp": values.get("timestamp"),
        "target": {"plugin": plugin, "path": url or None},
        "rule": {
            "id": values.get("rule.id"),
            "description": values.get("rule.description"),
            "level": values.get("rule.level"),
            "groups": _as_list(values.get("rule.groups")),
            "mitre_id": _as_list(values.get("rule.mitre.id")),
            "mitre_tactic": _as_list(values.get("rule.mitre.tactic")),
        },
        "decoder": values.get("decoder.name"),
        "agent": {"id": values.get("agent.id"), "name": values.get("agent.name")},
        "location": values.get("location"),
        "data": {label: value for label, value in values.items() if label.startswith("data.")},
    }


def classify_attack(context: dict) -> dict:
    """Classify the observed behaviour from the alert's own text.

    Heuristic, and the matched tokens are returned so a wrong classification can
    be traced to the word that caused it.
    """
    rule = context.get("rule") or {}
    # Join groups with commas: a space would let "webshell" + "injection" read as
    # "shell injection" and classify a PHP upload rule as command injection.
    parts = [str(rule.get("description") or ""), ",".join(
        str(g) for g in rule.get("groups") or [])]
    data = context.get("data") or {}
    parts.extend(str(data[key]) for key in ("data.url", "data.command") if key in data)
    result = _classify(" ".join(parts), ATTACK_CLASSES)
    return {
        "attack_class": result["class"],
        "evidence": result["evidence"],
        "mitre": {"technique_ids": rule.get("mitre_id") or [],
                  "tactics": rule.get("mitre_tactic") or []},
    }


def classify_vulnerability(record: dict) -> dict:
    """Classify a CVE from its own title and summary. Never from KEV or CVSS."""
    summary = record.get("summary")
    summary_text = summary.get("text") if isinstance(summary, dict) else summary
    text = " ".join(str(part) for part in (record.get("title"), summary_text) if part)
    result = _classify(text, VULN_CLASSES)
    return {"vulnerability_class": result["class"], "evidence": result["evidence"]}


def _plugin_from_path(path: str) -> str | None:
    """Plugin or theme directory name, when the alert names one."""
    match = PLUGIN_PATH_RE.search(path or "")
    if not match:
        return None
    slug = match.group(1).lower()
    for suffix in (".php", ".js"):
        if slug.endswith(suffix):
            slug = slug[: -len(suffix)]
    if slug in GENERIC_PLUGIN_SLUGS or len(slug) < 2:
        return None
    return slug


def endpoint_evidence(record: dict, context: dict) -> dict:
    """Files the CVE text names, and whether the request path hits one.

    A plugin CVE that says only "arbitrary file upload" documents no endpoint, so a
    generic upload request to that plugin cannot be tied to it.
    """
    summary = record.get("summary")
    summary_text = summary.get("text") if isinstance(summary, dict) else summary
    products = " ".join(str(entry.get("product") or "") for entry in record.get("affected") or [])
    text = " ".join(str(part) for part in (record.get("title"), summary_text, products) if part)
    documented = sorted(set(DOCUMENTED_FILE_RE.findall(text.lower())))
    path = str((context.get("target") or {}).get("path") or "").lower()
    return {"matched": [name for name in documented if name in path],
            "documented_files": documented[:5]}


def product_identity(record: dict, context: dict, technologies: list[str]) -> dict:
    """How much the CVE's own identity says about this alert's software.

    platform        WordPress (or another slug) matches; nothing narrower
    product_family  a WordPress plugin in general, with no identity match
    exact_product   the alert's plugin slug appears verbatim in the CVE text
    exact_component the slug (or a declared alias) equals the CVE's package id

    Separators are not folded. wp-scraper equals wp_scraper only because
    PLUGIN_SLUG_ALIASES declares it, and that alias is itself evidence.
    """
    plugin = ((context.get("target") or {}).get("plugin") or "").lower()
    affected = record.get("affected") or []
    packages = [str(entry.get("package") or "").lower() for entry in affected
                if entry.get("package")]
    products = [str(entry.get("product") or entry.get("vendor") or "").lower()
                for entry in affected]
    products = [value for value in products if value]
    title = str(record.get("title") or "").lower()
    summary = record.get("summary")
    summary_text = summary.get("text") if isinstance(summary, dict) else summary
    body = str(summary_text or "").lower()

    if plugin:
        if plugin in packages:
            return {"level": "exact_component", "plugin": plugin,
                    "evidence": [f"plugin:{plugin} equals package id"]}
        alias = PLUGIN_SLUG_ALIASES.get(plugin)
        if alias and alias["canonical"].lower() in packages:
            return {"level": "exact_component", "plugin": plugin,
                    "evidence": [f"alias:{plugin}->{alias['canonical']} "
                                 f"declared in {alias['source']}"]}
        if plugin in title or plugin in body or plugin in " ".join(products):
            return {"level": "exact_product", "plugin": plugin,
                    "evidence": [f"plugin:{plugin} named in the CVE text"]}

    platform = [slug for slug in technologies
                if slug in title or slug in body or slug in " ".join(products)]
    if platform and "plugin" in title + " " + body + " " + " ".join(products):
        return {"level": "product_family", "plugin": None,
                "evidence": [f"family:wordpress-plugin; platform={platform}"]}
    if platform:
        return {"level": "platform", "plugin": None,
                "evidence": [f"platform:{','.join(platform)}"]}
    return {"level": "none", "plugin": None, "evidence": []}


def _family_matcher():
    """Catalogue names for CMS and framework kinds, plus the matcher.

    Imported at call time: cve_now_tech imports this module, so a module-level import
    would close the cycle.
    """
    from mcp_server.threat_intel.cve_now_tech import CATALOG, _match
    names = {name: entry for name, entry in CATALOG.items()
             if entry["kind"] in ("cms", "framework")}
    return names, _match


def product_families(text: str) -> list[str]:
    """Catalogue platforms named in a piece of text."""
    if not text:
        return []
    names, match = _family_matcher()
    lowered = text.lower()
    return sorted({name for name, entry in names.items()
                   if any(match(lowered, token) for token in entry["names"])})


def record_families(record: dict) -> list[str]:
    summary = record.get("summary")
    summary_text = summary.get("text") if isinstance(summary, dict) else summary
    products = " ".join(str(entry.get("product") or entry.get("vendor") or "")
                        for entry in record.get("affected") or [])
    return product_families(" ".join(str(part) for part in (
        record.get("title"), summary_text, products) if part))


def product_compatibility(target_families: list[str], cve_families: list[str]) -> str:
    """compatible when the platforms overlap, incompatible when they are disjoint."""
    if not target_families or not cve_families:
        return "unknown"
    return "compatible" if set(target_families) & set(cve_families) else "incompatible"


def _parse_version(value: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.match(str(value).strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _package_matches(package_name: str, affected_package: str) -> bool:
    name = package_name.lower()
    candidate = affected_package.lower()
    return (name == candidate or name.startswith(candidate + "-")
            or candidate.startswith(name + "-"))


def compare_version(package_name: str, version: str, record: dict) -> dict:
    """Compare an installed version against the CVE's affected package ranges.

    Returns unknown rather than guessing when a range bound is not numeric.
    """
    if not package_name or not version:
        return {"status": "unknown", "evidence": [], "package_matched": False,
                "reason": "no installed package/version"}

    installed = _parse_version(version)
    if installed is None:
        return {"status": "unknown", "package_matched": True,
                "evidence": [f"installed version {version!r} is not numeric"],
                "reason": "installed version is not numeric"}

    ranges: list[dict] = []
    for entry in record.get("affected") or []:
        package = entry.get("package")
        if package and _package_matches(package_name, str(package)):
            ranges.extend(entry.get("ranges") or [])

    if not ranges:
        return {"status": "unknown", "evidence": [], "package_matched": False,
                "reason": f"{package_name} is not a package in this CVE's affected list"}

    for item in ranges:
        low = _parse_version(str(item.get("introduced") or "0"))
        fixed = _parse_version(item["fixed"]) if item.get("fixed") else None
        last = _parse_version(item["lastAffected"]) if item.get("lastAffected") else None
        if low is None or (item.get("fixed") and fixed is None) or (item.get("lastAffected") and last is None):
            continue
        if installed < low:
            continue
        if fixed is not None and installed >= fixed:
            continue
        if last is not None and installed > last:
            continue
        upper = item.get("fixed") or item.get("lastAffected") or "unfixed"
        return {"status": "in_range", "package_matched": True,
                "evidence": [f"{package_name} {version} in "
                             f"{item.get('introduced') or '0'}..{upper}"],
                "range": item}
    return {"status": "not_in_range", "package_matched": True,
            "evidence": [f"{package_name} {version} outside every listed range"],
            "ranges": ranges[:4]}


def _exploit_state(record: dict) -> dict:
    """Normalise both shapes: a projected record and a raw upstream record."""
    exploit = record.get("exploitation") or {}
    kev = record.get("kev")
    if kev is None:
        kev_listed = None            # not published, not "not listed"
    elif isinstance(kev, bool):
        kev_listed = kev
    else:
        kev_listed = bool((kev or {}).get("listed"))

    metasploit = exploit.get("metasploit_modules")
    if metasploit is None:
        metasploit = (exploit.get("metasploit") or {}).get("modules") or []
    nuclei = exploit.get("nuclei_templates") or (exploit.get("nuclei") or {}).get("templates") or []
    exploitdb = exploit.get("exploitdb_ids") or (exploit.get("exploitDb") or {}).get("ids") or []
    return {"kev": kev_listed, "metasploit": len(metasploit), "nuclei": len(nuclei),
            "exploitdb": len(exploitdb), "public_poc": exploit.get("public_poc_count") or 0}


def _missing_metadata(cvss, kev) -> list[str]:
    return [name for name, value in (("cvss", cvss), ("kev", kev)) if value is None]


def _version_check(record: dict, packages: list[dict]) -> dict:
    """Return the strongest version finding across the inventory.

    ``package_matched`` separates "the inventory holds this package and the version
    is outside the range" from "the inventory never held this package". Only the
    first can support a negative answer.
    """
    best = {"status": "unknown", "evidence": [], "package_matched": False,
            "reason": "no package inventory"}
    for package in packages:
        result = compare_version(str(package.get("name") or ""),
                                 str(package.get("version") or ""), record)
        labelled = {**result, "matched_package": package.get("name"),
                    "matched_version": package.get("version")}
        if result["status"] == "in_range":
            return labelled
        if result["status"] == "not_in_range" and best["status"] == "unknown":
            best = labelled
        elif result.get("package_matched") and best.get("matched_package") is None:
            best = labelled
    return best


def assess_candidate(record: dict, context: dict, attack: dict, technologies: list[str],
                     packages: list[dict], *, direct: bool = False,
                     target_families: list[str] | None = None) -> dict:
    """Test one CVE against the observed attack and classify the relationship."""
    vuln = classify_vulnerability(record)
    identity = product_identity(record, context, technologies)
    strong_identity = identity["level"] in ("exact_product", "exact_component")
    families = record_families(record)
    compatibility = product_compatibility(list(target_families or []), families)
    endpoint = endpoint_evidence(record, context)
    version = _version_check(record, packages)
    exploit = _exploit_state(record)

    attack_class = attack["attack_class"]
    vuln_class = vuln["vulnerability_class"]
    compatible = None
    if attack_class and vuln_class:
        compatible = vuln_class in CLASS_COMPATIBILITY.get(attack_class, set())

    evidence = list(identity["evidence"]) + list(vuln["evidence"])
    contradictions: list[str] = []
    missing: list[str] = []

    if compatible is True:
        evidence.append(f"class:{vuln_class} reachable from {attack_class}")
    elif compatible is False:
        contradictions.append(f"class:{attack_class} does not produce {vuln_class}")
    else:
        missing.append("vulnerability class not stated in the record text")

    if version["status"] == "in_range":
        evidence.extend(version["evidence"])
    elif version["status"] == "not_in_range":
        contradictions.extend(version["evidence"])
    else:
        missing.append(version["reason"])

    if compatibility == "incompatible":
        contradictions.append(
            f"product:{','.join(families)} is not the alert target "
            f"({','.join(target_families or [])})")

    if endpoint["matched"]:
        evidence.append(f"endpoint:{endpoint['matched'][0]} named in the CVE and requested")
    else:
        missing.append("no documented endpoint in the CVE text")

    if exploit["kev"] is True:
        evidence.append("kev:listed")
    if exploit["metasploit"] or exploit["nuclei"] or exploit["public_poc"]:
        evidence.append("exploit:public-code-exists")

    if direct:
        relationship = "confirmed_cve_reference"
    elif compatibility == "incompatible":
        relationship = "no_supported_match"
    elif (strong_identity and compatible is True and version["status"] != "not_in_range"
          and endpoint["matched"]):
        relationship = "attack_specific_match"
    elif version["status"] == "in_range" and (identity["level"] != "none" or compatible is True):
        relationship = "vulnerability_exposure"
    elif identity["level"] != "none" or compatible is True:
        relationship = "contextual_candidate"
    else:
        relationship = "no_supported_match"

    return {
        "id": record.get("id"),
        "title": record.get("title"),
        "relationship": relationship,
        "strength": STRENGTH_BY_RELATIONSHIP[relationship],
        "attack_class": attack_class,
        "vulnerability_class": vuln_class,
        "cwe": None,
        "cwe_note": "cve.now publishes no CWE field; none is inferred",
        "cvss": (record.get("severity") or {}).get("cvss") or record.get("cvss"),
        "severity_source": (record.get("severity") or {}).get("source"),
        "kev": exploit["kev"],
        "metadata_missing": _missing_metadata(
            (record.get("severity") or {}).get("cvss") or record.get("cvss"), exploit["kev"]),
        "exposure": record.get("exposure"),
        "public_exploit": {"metasploit": exploit["metasploit"], "nuclei": exploit["nuclei"],
                           "exploitdb": exploit["exploitdb"], "pocs": exploit["public_poc"]},
        "product_compatibility": compatibility,
        "record_families": families,
        "discovery_relevance": ("explicit_cve" if direct else
                                "component" if identity["level"] == "exact_component" else
                                "exact_product" if identity["level"] == "exact_product" else
                                "technology" if identity["level"] != "none" else
                                "attack_pattern" if compatible is True else "none"),
        "assessment_relevance": {"confirmed_cve_reference": "high",
                                 "attack_specific_match": "high",
                                 "vulnerability_exposure": "medium",
                                 "contextual_candidate": "low",
                                 "no_supported_match": "none"}[relationship],
        "product_identity": identity["level"],
        "product_plugin": identity["plugin"],
        "product_evidence": identity["evidence"],
        "endpoint_evidence": endpoint,
        "version_check": {"status": version["status"], "evidence": version["evidence"],
                          "package_matched": version.get("package_matched", False)},
        "evidence_attributes": {
            "observed_target_product": {
                "value": identity["plugin"],
                "source": "data.url" if identity["plugin"] else "none",
            },
            "installed_product": {
                "value": version.get("matched_package"),
                "version": version.get("matched_version"),
                "source": "package_inventory" if version.get("matched_package") else "none",
            },
            "affected_version": {"status": version["status"], "evidence": version["evidence"]},
        },
        "evidence": evidence,
        "contradictions": contradictions,
        "missing": missing,
        "confidence_explanation": _explain(relationship, identity, compatible, version, endpoint),
        "url": record.get("url") or f"https://cve.now/{record.get('id')}",
    }


def _explain(relationship: str, identity: dict, compatible, version: dict,
             endpoint: dict) -> str:
    if relationship == "confirmed_cve_reference":
        return ("The alert carries this CVE id in a structured field. That is a reference, "
                "not proof the vulnerability was reached.")
    if relationship == "attack_specific_match":
        requested = endpoint["matched"][0] if endpoint.get("matched") else "n/a"
        return (f"The request names the vulnerable product ({identity['level']}: "
                f"{identity['plugin']}) and targets {requested}, which the CVE documents; "
                f"the class matches and version range is {version['status']}. "
                "Plausible, not established.")
    if relationship == "vulnerability_exposure":
        return ("The asset runs a version inside the affected range. No evidence in this "
                "alert links the activity to this CVE.")
    if relationship == "contextual_candidate":
        parts = [f"product identity: {identity['level']}",
                 "class matches" if compatible else "class does not match"]
        return "Technology or class overlap only: " + ", ".join(parts) + "."
    return "No dimension connects this CVE to the observed activity."


def exploitation_state(attack: dict, candidates: list[dict]) -> dict:
    """Report post-exploitation indicators without claiming success.

    ``successful_exploitation_established`` stays false: an alert describes what was
    attempted or observed, and no field here proves the exploit worked. Indicators are
    reported separately, scoped to this one alert.
    """
    observed = attack.get("attack_class") == "post_exploitation"
    linked = next((c for c in candidates
                   if c["relationship"] in ("confirmed_cve_reference", "attack_specific_match")),
                  None)
    if observed and linked:
        basis = f"post-exploitation behaviour with a linked {linked['id']} in the same alert"
    elif observed:
        basis = "post-exploitation behaviour without a linked CVE"
    else:
        basis = "attempt-type alert; no field records a compromise"
    return {
        "successful_exploitation_established": False,
        "exploitation_basis": basis,
        "post_exploitation_indicators": {
            "observed": observed,
            "evidence": list(attack.get("evidence") or []),
            "linked_candidate": linked["id"] if linked else None,
            "correlation_scope": "same_alert",
            "note": "Indicators do not establish success; host-side confirmation is required.",
        },
    }


def summarize(candidates: list[dict], attack: dict, packages_source: str) -> dict:
    """Final assessment block. Ordering never invents confidence."""
    supported = [c for c in candidates if c["relationship"] != "no_supported_match"]
    ordered = sorted(supported, key=lambda c: (RELATIONSHIP_ORDER.index(c["relationship"]),
                                               c["version_check"]["status"] != "in_range",
                                               -(c.get("cvss") or 0)))
    top = ordered[0] if ordered else None
    in_range = [c for c in supported if c["version_check"]["status"] == "in_range"]
    checked = [c for c in supported if c["version_check"].get("package_matched")]
    unparsable = [c for c in checked if c["version_check"]["status"] == "unknown"]
    if in_range:
        confirmed = True
    elif checked and not unparsable and packages_source not in ("none", "inventory_empty"):
        # A negative answer needs the package to have been in the inventory. A plugin
        # that Syscollector never lists is not proven absent.
        confirmed = False
    else:
        confirmed = "unknown"
    exposure = confirmed is True
    exploitation = exploitation_state(attack, supported)
    return {
        "relationship": top["relationship"] if top else "no_supported_match",
        "attack_class": attack["attack_class"],
        "attack_consistent_with_exploitation":
            "possible" if attack["attack_class"] else "not_established",
        "vulnerable_software_confirmed": confirmed,
        "version_evidence": {"candidates": len(supported), "package_present": len(checked),
                             "in_range": len(in_range)},
        "successful_exploitation_established": exploitation["successful_exploitation_established"],
        "exploitation_status": "not_established",  # analyst input may set the negative case

        "post_exploitation_indicators": exploitation["post_exploitation_indicators"],
        "exploitation_basis": exploitation["exploitation_basis"],
        "exploitation_note": (
            "A reference, a product-identity match, an affected version and a public exploit "
            "raise plausibility; none of them proves the exploit worked. "
            "successful_exploitation_established stays false; post-exploitation indicators are "
            "reported separately and remain indicators."
        ),
        "selected": ({"id": top["id"], "why": top["confidence_explanation"]} if top else None),
        "recommended_actions": _actions(top["relationship"] if top else "no_supported_match", exposure),
    }


def _actions(relationship: str, exposure: bool) -> list[str]:
    actions = []
    if relationship == "confirmed_cve_reference":
        actions.append("Verify the affected package version on the agent before patching.")
    if relationship in ("confirmed_cve_reference", "attack_specific_match"):
        actions.append("Check the host for post-exploitation artifacts in the same window.")
    if exposure:
        actions.append("Patch or mitigate the affected package; exposure is confirmed, not exploitation.")
    if relationship == "contextual_candidate":
        actions.append("Collect the request payload and response status before attributing a CVE.")
    actions.append("Keep the CVE link as an assessment until a host-side check confirms it.")
    return actions


LIMITATIONS = [
    "Attack classification is keyword-based over rule.description, rule.groups and the "
    "allowlisted data fields. A rule that describes nothing specific yields no class.",
    "cve.now publishes no CWE field, so CWE is reported as null rather than guessed.",
    "No exploit signature is matched: public exploit availability is recorded as context, "
    "never as proof that this alert used it.",
    "Version checks use the CVE's affected ranges and the package inventory. A version that "
    "is absent or non-numeric is reported unknown, never assumed vulnerable.",
    "Technology feeds return the newest entries, so a candidate list is not the whole catalog. "
    "Candidate search uses the catalog-wide search endpoint, not the feed.",
    "Product identity is derived from the requested path (/wp-content/plugins/<slug>/) and "
    "compared verbatim with the CVE's package id or text. Hyphen and underscore are not folded; "
    "wp-scraper equals wp_scraper only because PLUGIN_SLUG_ALIASES declares it. A platform match "
    "such as WordPress is never treated as identity for a specific plugin.",
    "Attack-specific promotion needs an exact product identity, a compatible vulnerability class, "
    "a version that is not out of range, and a file the request targets that the CVE text names. "
    "A plugin-specific upload with no documented endpoint stays contextual.",
    "A request path proves which product was addressed, not which product is installed. "
    "installed_product is filled only from package inventory.",
]
