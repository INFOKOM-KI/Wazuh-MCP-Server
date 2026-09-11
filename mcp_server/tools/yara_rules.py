#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
YARA rule synthesis + validation for blue_team_mcp.

Three tools:
  blueteam_yara_rule_validate - compile an existing rule, run yaraQA-style checks.
  blueteam_yara_rule_generate - build a candidate rule from a Wazuh alert pattern,
                                a local sample file, or raw text.
  blueteam_yara_rule_save     - write a VALIDATED rule to the staging directory
                                (BLUETEAM_YARA_RULES_DIR). Requires wazuh:write.

Engine: ``yara-x`` (required import) for compile + scan with offsets.
``yara-python`` is deliberately NOT required, yara-x's Scanner already returns
(offset, length) per pattern, and dragging in a second native lib buys nothing
for MVP. Add it only when XOR ``plaintext()``/``matched_data`` is actually needed.

REDACTION CONTRACT (read before changing):
Both tools set ``redact=False``. The default @blueteam_tool pipeline redacts the
RETURN VALUE, which for a YARA rule means masking domain/IP string literals
inside the rule body, producing a rule that compiles but matches nothing.
Silent false negative. Instead:
  * audit=False + a manual ``_audit_log`` that logs only rule name + sha256,
    never the rule body (Layer-1 credential stripping would otherwise have to
    run on text we cannot safely mutate).
  * generate() embeds attacker-side fields only (data.url / data.domain /
    data.command / data.file.*). ``full_log`` is never used as an atom source -
    it carries victim usernames and paths.
  * file mode embeds a sha256 + basename-derived descriptor, never the full
    local path.
Nothing raw is written to the audit log, so there is no credential leak to
mitigate; that is what makes redact=False safe here.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.

The write boundary (filename validation, traversal guard, atomic replace) lives
in ``core/rule_staging.py`` and is shared with ``tools/sigma_rules.py``. Staging
dir + atom caps come from ``core/config.py`` (YaraConfig).
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.rule_staging import save_rule_file, short_digest, staging_dir
from mcp_server.core.subprocess import ALLOWED_PATH_PREFIXES, _validate_path
from mcp_server.core.tool_decorator import blueteam_tool

logger = logging.getLogger("blue_team_mcp.yara")

_MAX_SAMPLE_BYTES = 32 * 1024 * 1024
_MAX_ATOMS = 10
_MIN_ATOM_CHARS = 4
_MAX_ATOM_CHARS = 120
_MAX_TEXT_CHARS = 262144       # 256 KB of rule source accepted by validate
_DEFAULT_SCAN_TIMEOUT = 10

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,%d}" % (_MIN_ATOM_CHARS, _MAX_ATOM_CHARS))
_YARA_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STRING_LINE_RE = re.compile(r'^\s*(\$\w+)\s*=\s*(.+?)\s*$', re.MULTILINE)

# Byte magic (platform token, family prefix, condition pre-selector)
_MAGIC: list[tuple[bytes, str, str, str]] = [
    (b"MZ", "WIN", "SUSP", "uint16(0) == 0x5a4d"),
    (b"\x7fELF", "LNX", "SUSP", "uint32(0) == 0x464c457f"),
    (b"PK\x03\x04", "ZIP", "SUSP", 'uint32(0) == 0x04034b50'),
]

# Generic tokens that are pre-selectors ($a*), not detection atoms.
_PRESELECTORS = {
    b"<?php", b"<%", b"<%@", b"<html", b"<!DOCTYPE", b"#!/bin/", b"#!/usr/bin/env",
}

# Tokens too common to be atoms, dropped, never put in $x*/$s*.
_GENERIC_TOKENS = {
    b"http://", b"https://", b"Copyright", b"Microsoft", b"Windows",
    b"Mozilla", b"Content-Type", b"User-Agent", b"localhost",
}


class YaraEngineError(BlueTeamMCPError):
    """Raised when the yara-x engine is unavailable or fails unexpectedly."""


class YaraRuleValidateInput(BaseModel):
    """Input for blueteam_yara_rule_validate.
    Args:
        rule_source: YARA rule text to compile and check.
        error_on_warning: Treat compiler warnings as failures.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(extra="forbid")

    rule_source: str = Field(min_length=1, max_length=_MAX_TEXT_CHARS,
                             description="YARA rule source text to validate")
    error_on_warning: bool = Field(default=False,
                                   description="Treat compiler warnings as errors")
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)


class YaraRuleSaveInput(BaseModel):
    """Input for blueteam_yara_rule_save.
    Writes to the staging directory only (BLUETEAM_YARA_RULES_DIR). A SOC Engineer must
    promote the file to a live rules.d path; this tool never touches production.

    Args:
        rule_source: Rule text. Must compile, or the save is refused.
        filename: Optional .yar filename. Defaults to <rule_name>.yar.
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


class YaraRuleGenerateInput(BaseModel):
    """Input for blueteam_yara_rule_generate.
    Mode determines the atom source:
        'file'  - a local sample under BLUETEAM_ALLOWED_PATHS (highest fidelity)
        'text'  - raw text supplied by the analyst
        'alert' - Wazuh Indexer alerts for a srcip and/or rule id (draft fidelity)

    Args:
        mode: 'file', 'text' or 'alert'.
        file_path: Required for mode='file'.
        text: Required for mode='text'.
        srcip: Source IP filter for mode='alert' (Indexer API).
        rule_id: Wazuh rule id filter for mode='alert' (Indexer API).
        since: Relative or ISO time window for mode='alert' (e.g. '24h').
        limit: Max alert documents to harvest in mode='alert'.
        family: Rule name prefix; MAL/HKTL/SUSP/WEBSHELL/EXPL/PUA.
        description: Overrides the generated description.
        self_scan: Match the generated rule against the sample (file mode).
        scan_timeout: yara-x scan timeout in seconds.
        response_format: 'markdown' (default) or 'json'.
        bypass_character_limit: Allow the response past BLUETEAM_CHARACTER_LIMIT.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mode: Literal["file", "text", "alert"] = Field(default="text")
    file_path: Optional[str] = Field(default=None, max_length=4096)
    text: Optional[str] = Field(default=None, max_length=_MAX_TEXT_CHARS)
    srcip: Optional[str] = Field(default=None, max_length=45)
    rule_id: Optional[str] = Field(default=None, max_length=64)
    since: str = Field(default="24h", max_length=24)
    limit: int = Field(default=200, ge=1, le=1000)
    family: Optional[str] = Field(default=None, max_length=32)
    description: Optional[str] = Field(default=None, max_length=400)
    self_scan: bool = Field(default=True)
    scan_timeout: int = Field(default=_DEFAULT_SCAN_TIMEOUT, ge=1, le=60)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_character_limit: bool = Field(default=False)

    @model_validator(mode="after")
    def _require_source(self) -> "YaraRuleGenerateInput":
        if self.mode == "file" and not self.file_path:
            raise ValueError("mode='file' requires file_path")
        if self.mode == "text" and not self.text:
            raise ValueError("mode='text' requires text")
        if self.mode == "alert" and not (self.srcip or self.rule_id):
            raise ValueError("mode='alert' requires srcip and/or rule_id")
        return self


# Engine layer, import keeps tool registration working without yara-x.
def _yara_x():
    """Import yara-x on first use. Raises YaraEngineError with an install hint."""
    try:
        import yara_x  # noqa: PLC0415 intentional import
    except ImportError as e:
        raise YaraEngineError(
            "yara-x is not installed. Install with: pip install 'yara-x>=1.20,<2'"
        ) from e
    return yara_x


def _clean_compile_error(text: str) -> str:
    """Collapse a yara-x diagnostic block into one readable line."""
    lines = [ln.rstrip() for ln in text.strip().splitlines() if ln.strip()]
    return " | ".join(lines[:3])[:500]


def _compile(rule_source: str, error_on_warning: bool = False) -> tuple[Any, list[str], list[str]]:
    """Compile rule source. Returns (rules|None, errors, warnings)."""
    yara_x = _yara_x()
    errors: list[str] = []
    warnings: list[str] = []
    compiler = yara_x.Compiler()
    try:
        compiler.add_source(rule_source)
    except yara_x.CompileError as e:
        return None, [_clean_compile_error(str(e))], warnings
    except Exception as e:  # yara-x surfaces non-syntax faults here too
        return None, [f"{type(e).__name__}: {e}"], warnings

    try:
        for w in compiler.warnings():
            warnings.append(f"{w.get('title', 'warning')}: {str(w.get('text', ''))[:200]}")
        if error_on_warning and warnings:
            return None, [f"warnings treated as errors: {warnings[0]}"], warnings
        rules = compiler.build()
    except Exception as e:
        return None, [f"{type(e).__name__}: {e}"], warnings
    return rules, errors, warnings


def _scan(rules: Any, data: bytes, timeout: int = _DEFAULT_SCAN_TIMEOUT,
          max_matches: int = 50) -> list[dict]:
    """Scan bytes, returning per-rule pattern matches with offsets."""
    yara_x = _yara_x()
    scanner = yara_x.Scanner(rules)
    try:
        scanner.set_timeout(timeout)
    except (AttributeError, TypeError):
        pass
    try:
        scanner.max_matches_per_pattern = max_matches
    except (AttributeError, TypeError):
        pass
    result = scanner.scan(data)
    out: list[dict] = []
    for m in result.matching_rules:
        patterns = []
        for p in m.patterns:
            patterns.append({
                "identifier": p.identifier,
                "matches": [{"offset": mm.offset, "length": mm.length} for mm in p.matches],
            })
        out.append({"rule": m.identifier, "patterns": patterns})
    return out


# Atom extraction + scoring.
def _atom_score(b: bytes) -> float:
    """Deterministic specificity score. Longer + more varied + digits/punct wins."""
    if len(b) < _MIN_ATOM_CHARS:
        return 0.0
    distinct = len(set(b))
    digits = sum(1 for c in b if 48 <= c <= 57)
    punct = sum(1 for c in b if not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122))
    return round(min(len(b), 40) + (distinct / len(b)) * 10 + (5 if digits else 0) + min(punct, 4), 3)


def _extract_from_bytes(data: bytes, cap: int = _MAX_ATOMS) -> tuple[list[bytes], list[bytes]]:
    """Return (atoms, preselectors) from raw bytes, deterministically ordered."""
    atoms: dict[bytes, float] = {}
    prese: set[bytes] = set()
    for run in _PRINTABLE_RE.findall(data):
        # A pre-selector is a marker embedded in a longer run ("<?php echo ..."),
        # not necessarily a run on its own.
        for token in _PRESELECTORS:
            if token in run:
                prese.add(token)
                break
        if run in _GENERIC_TOKENS:
            continue
        if len(set(run)) == 1:  # "AAAA"
            continue
        atoms[run] = _atom_score(run)
    ordered = sorted(atoms.items(), key=lambda kv: (-kv[1], kv[0]))
    return [a for a, _ in ordered[:cap]], sorted(prese)


def _extract_from_docs(docs: list[dict], cap: int = _MAX_ATOMS) -> tuple[list[bytes], list[bytes]]:
    """Harvest attacker-side fields from Wazuh alert docs. Never full_log."""
    fields = ("data.url", "data.domain", "data.command", "data.file.path", "data.file.name")
    chunks: list[bytes] = []
    for doc in docs:
        for path in fields:
            node: Any = doc
            for part in path.split("."):
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, str) and node:
                chunks.append(node.encode("utf-8", "ignore"))
    return _extract_from_bytes(b"\n".join(chunks), cap=cap)


def _detect_magic(data: bytes) -> tuple[str, str, str]:
    """Return (platform, family, preselector_condition) for the sample."""
    for magic, platform, family, cond in _MAGIC:
        if data.startswith(magic):
            return platform, family, cond
    head = data[:4096].lower()
    if b"<?php" in head:
        return "PHP", "WEBSHELL", ""
    if b"<%@ " in head or b"<%@\t" in head:
        return "ASP", "WEBSHELL", ""
    if b"<% " in head or b"<%=" in head:
        return "JSP", "WEBSHELL", ""
    return "", "SUSP", ""


def _yara_literal(b: bytes) -> str:
    """Escape bytes into a double-quoted YARA string literal (ASCII only)."""
    text = b.decode("ascii", "ignore").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _sanitize_name(family: str, platform: str, digest: str) -> str:
    fam = re.sub(r"[^A-Za-z0-9]", "", family).upper() or "SUSP"
    plat = re.sub(r"[^A-Za-z0-9]", "", platform).upper()
    when = datetime.now(timezone.utc).strftime("%b%y")
    parts = [fam]
    if plat:
        parts.append(plat)
    parts += ["Wazuh", when, digest]
    name = "_".join(parts)
    return name if _YARA_NAME_RE.match(name) else f"SUSP_Wazuh_{when}_{digest}"


def _render_rule(name: str, description: str, reference: str, score: int,
                 atoms: list[bytes], prese: list[bytes], preselector_cond: str,
                 filesize_mb: int, digest: str, coverage: str = "draft") -> str:
    """Assemble the rule text. All atoms are attacker-side or sample-derived."""
    lines: list[str] = [f"rule {name} {{", "meta:", f'description = "{description}"',
                        'author = "TangerangKota-CSIRT"',
                        f'date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
                        f'reference = "{reference}"', f"score = {score}",
                        f'hash = "{digest}"', f'coverage = "{coverage}"']
    if atoms or prese:
        lines += ["", "strings:"]
        for i, p in enumerate(prese[:2], 1):
            lines.append(f"$a{i} = {_yara_literal(p)} // pre-selection")
        for i, a in enumerate(atoms, 1):
            prefix = "x" if i == 1 and len(atoms) > 1 else "s"
            lines.append(f"${prefix}{i} = {_yara_literal(a)}")
    else:
        # yara-x rejects a declared-but-unreferenced pattern (E022), so emit no
        # strings block at all when nothing was harvested.
        lines += ["", "// no atom harvested from this source"]

    parts: list[str] = []
    if preselector_cond:
        parts.append(preselector_cond)
    parts.append(f"filesize < {filesize_mb}MB")
    n_atoms = len(atoms)
    if n_atoms >= 3:
        parts.append("(1 of ($x*) or 2 of ($s*))")
    elif n_atoms == 2:
        parts.append("all of them")
    elif n_atoms == 1:
        parts.append("$s1")
    if prese:
        parts.append("1 of ($a*)")
    cond_block = parts[0] + "".join("\n and " + p for p in parts[1:])
    if not atoms and not prese:
        cond_block += "\n // TODO: no atom harvested - filter condition is always true"

    lines += ["", "   condition:", "      " + cond_block, "}", ""]
    return "\n".join(lines)


# yaraQA-style static checks (cheap subset; no full parser).
def _static_checks(rule_source: str) -> list[str]:
    """Return human-readable quality findings, yaraQA IDs where known."""
    findings: list[str] = []
    name_match = re.search(r"^\s*rule\s+(\w+)", rule_source, re.MULTILINE)
    name = name_match.group(1) if name_match else ""
    if name and not re.match(r"^[A-Z][A-Z0-9]*(_[A-Za-z0-9]+)+$", name):
        findings.append(f"SV1 naming: '{name}' lacks CATEGORY_ descriptor form "
                        "(e.g. MAL_APT_Family_Win_Loader_Mar25)")

    for field in ("description", "author", "date", "reference"):
        if not re.search(rf"^\s*{field}\s*=", rule_source, re.MULTILINE):
            findings.append(f"meta: missing mandatory field '{field}'")

    string_lines = _STRING_LINE_RE.findall(rule_source)
    if len(string_lines) > _MAX_ATOMS:
        findings.append(f"HS1 resources: {len(string_lines)} strings, keep <= {_MAX_ATOMS}")
    for ident, value in string_lines:
        if value.startswith("{"):
            continue
        literal = value.split("//")[0].strip().strip('"')
        if len(literal) < _MIN_ATOM_CHARS and "uint" not in value:
            findings.append(f"PA2 {ident}: atom '{literal}' shorter than {_MIN_ATOM_CHARS} bytes")
        if "fullword" in value and re.search(r"[._\\()\-]", literal):
            findings.append(f"SM5 {ident}: 'fullword' with punctuation breaks matching")
    return findings


def _alert_field_coverage(docs: list[dict]) -> dict:
    """Diagnostic: how many matched docs populated each harvested field.
    A live run with 0 coverage on every field means the deployment's decoders
    do not populate the attacker-side fields this tool reads; the draft rule
    would be built from nothing.
    """
    from mcp_server.wazuh.indexer import _ATTACKER_FIELDS, field_coverage

    return field_coverage(docs, list(_ATTACKER_FIELDS))


def _rules_dir() -> Path:
    """Staging directory from the config singleton, with a safe fallback."""
    return staging_dir("yara", "/opt/yara_rules/yara_staging")


def _save_rule_file(rule_source: str, filename: str, overwrite: bool,
                    rules_dir: Path) -> Path:
    """Write rule_source into rules_dir atomically. Refuses traversal/escape."""
    return save_rule_file(rule_source, filename, overwrite, rules_dir, ".yar")


def _digest(atoms: list[bytes]) -> str:
    """Stable short digest over the atom set - deterministic across runs."""
    return short_digest(*set(atoms))


def _read_sample(path: str) -> bytes:
    """Validate path against ALLOWED_PATH_PREFIXES, enforce size cap, read bytes."""
    ok, err = _validate_path(path, ALLOWED_PATH_PREFIXES)
    if not ok:
        raise BlueTeamMCPError(f"Sample path rejected: {err}")
    p = Path(path)
    if not p.is_file():
        raise BlueTeamMCPError(f"Sample path is not a regular file: {path}")
    size = p.stat().st_size
    if size > _MAX_SAMPLE_BYTES:
        raise BlueTeamMCPError(
            f"Sample is {size} bytes, over the {_MAX_SAMPLE_BYTES} byte cap"
        )
    if size == 0:
        raise BlueTeamMCPError("Sample file is empty")
    return p.read_bytes()


async def _fetch_alert_docs(srcip: Optional[str], rule_id: Optional[str],
                            since: str, limit: int) -> list[dict]:
    """Pull attacker side alert fields from the Wazuh Indexer API (not Manager).
    Thin delegate: the query builder lives in ``wazuh/indexer.py`` so the Sigma
    synthesizer can reuse it without importing this tool module (a cross-tool
    import would defeat category gating, since it registers this module's tools).
    """
    from mcp_server.wazuh.indexer import (_ATTACKER_CONTEXT_FIELDS, _ATTACKER_FIELDS,
                                          _fetch_attacker_alert_docs)

    return await _fetch_attacker_alert_docs(
        srcip, rule_id, since, limit,
        list(_ATTACKER_FIELDS) + list(_ATTACKER_CONTEXT_FIELDS))


# Tools.
@blueteam_tool(
    name="blueteam_yara_rule_validate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_yara_rule_validate(params: YaraRuleValidateInput) -> str:
    """Validate a YARA rule with yara-x and run yaraQA-style quality checks.
    Read-only, no network, no filesystem access. Nothing is executed.

    Args:
        params.rule_source: Rule text to compile.
        params.error_on_warning: Fail when the compiler emits warnings.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with valid (bool), errors, warnings, findings, engine.

    Examples:
        1. python: params(rule_source="rule t { condition: true }") -> valid=true
        2. A rule using `fullword` on a path literal reports an SM5 finding.
        3. A rule named `test` reports an SV1 naming finding.

    Permissions: none. Rate limits: none (local CPU only).
    """
    _, errors, warnings = _compile(params.rule_source, params.error_on_warning)
    findings = _static_checks(params.rule_source)
    rule_name = (re.search(r"^\s*rule\s+(\w+)", params.rule_source, re.MULTILINE) or [None, "unknown"])[1]
    _audit_log("blueteam_yara_rule_validate", {
        "rule_name": rule_name,
        "sha256": hashlib.sha256(params.rule_source.encode()).hexdigest()[:16],
    })
    payload = {
        "valid": not errors,
        "rule_name": rule_name,
        "errors": errors,
        "warnings": warnings,
        "findings": findings,
        "engine": "yara-x",
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)
    status = "PASSED" if payload["valid"] else "FAILED"
    lines = [f"## YARA validation: {status}", "", f"Rule: `{rule_name}`", ""]
    if errors:
        lines += ["**Errors**"] + [f"- {e}" for e in errors] + [""]
    if warnings:
        lines += ["**Warnings**"] + [f"- {w}" for w in warnings] + [""]
    if findings:
        lines += ["**Quality findings**"] + [f"- {f}" for f in findings] + [""]
    if payload["valid"] and not findings:
        lines.append("Compiles clean; no findings.")
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@blueteam_tool(
    name="blueteam_yara_rule_generate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_yara_rule_generate(params: YaraRuleGenerateInput) -> str:
    """Generate a candidate YARA rule from a Wazuh alert pattern, sample file, or text.
    Wazuh target: mode='alert' reads the **Indexer API** (wazuh-alerts-* via
    _wazuh_indexer_post). The Manager API is not used.

    Coverage levels (never claim more than the data supports):
        verified   - file mode, self-scan matched the sample.
        unverified - file mode, rule compiled but did not match its own sample.
        draft      - alert/text mode. Needs a real sample before deployment.

    Args:
        params.mode: 'file' | 'text' | 'alert'.
        params.file_path: Sample under BLUETEAM_ALLOWED_PATHS (mode='file').
        params.text: Raw text (mode='text').
        params.srcip / params.rule_id / params.since / params.limit: alert filters.
        params.family: MAL/HKTL/SUSP/WEBSHELL/EXPL/PUA name prefix.
        params.description: Override generated description.
        params.self_scan: Match the generated rule against the sample.
        params.scan_timeout: yara-x scan timeout, seconds.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown with the rule in a ```yara block, or json with
        rule_source, coverage, validation, scan, atoms.

    Examples:
        1. file mode on a dropped PHP webshell -> WEBSHELL_* rule, coverage=verified.
        2. alert mode with srcip='10.0.0.5', since='24h' -> draft rule from URL/command atoms.
        3. text mode on a suspicious one-liner -> draft rule, yaraQA findings included.

    Permissions: read on Wazuh Indexer and on BLUETEAM_ALLOWED_PATHS directories.
    Rate limits: none locally; alert mode issues one bounded Indexer search.
    """
    atoms: list[bytes] = []
    prese: list[bytes] = []
    preselector_cond = ""
    platform = ""
    filesize_mb = 10
    reference = ""
    coverage = "draft"
    sample: Optional[bytes] = None
    derived_family = "SUSP"
    alert_coverage: Optional[dict] = None

    if params.mode == "file":
        sample = _read_sample(params.file_path or "")
        atoms, prese = _extract_from_bytes(sample)
        platform, derived_family, preselector_cond = _detect_magic(sample)
        filesize_mb = max(1, min(50, (len(sample) // (1024 * 1024) + 1) * 4))
        reference = f"Internal sample sha256:{hashlib.sha256(sample).hexdigest()[:16]}"
        coverage = "verified" if params.self_scan else "draft"
    elif params.mode == "text":
        raw = (params.text or "").encode("utf-8", "ignore")
        atoms, prese = _extract_from_bytes(raw)
        reference = "Analyst-supplied text"
    else:
        docs = await _fetch_alert_docs(params.srcip, params.rule_id, params.since, params.limit)
        if not docs:
            raise BlueTeamMCPError("No alerts matched the given srcip/rule_id/since window")
        alert_coverage = _alert_field_coverage(docs)
        atoms, prese = _extract_from_docs(docs)
        sample = b"\n".join(
            str(d.get("data", {}).get("url", "")).encode("utf-8", "ignore") for d in docs
        ) or None
        ref_bits = [b for b in (params.srcip, params.rule_id) if b]
        reference = "Wazuh Indexer " + ("/".join(ref_bits) if ref_bits else "query")
        if params.family:
            derived_family = params.family.upper()

    digest = _digest(atoms)
    name = _sanitize_name(params.family or derived_family, platform, digest)
    description = params.description or (
        f"Detects patterns observed in {params.mode} source; generated from Wazuh "
        f"attack context. coverage={coverage}, atoms={len(atoms)}"
    )[:400]
    score = 75 if coverage == "verified" else 60
    rule_source = _render_rule(name, description, reference, score, atoms, prese,
                               preselector_cond, filesize_mb, digest, coverage)

    rules, errors, warnings = _compile(rule_source)
    scan_result: list[dict] = []
    if rules is not None and params.self_scan and sample:
        try:
            scan_result = _scan(rules, sample, params.scan_timeout)
        except BlueTeamMCPError:
            raise
        except Exception as e:  # yara-x timeout surfaces as an engine error
            errors.append(f"self-scan failed: {type(e).__name__}: {e}")
        if not scan_result and coverage == "verified":
            coverage = "unverified"
    if rules is None:
        coverage = "invalid"

    _audit_log("blueteam_yara_rule_generate", {
        "mode": params.mode,
        "rule_name": name,
        "coverage": coverage,
        "atom_digest": digest,
        "rule_sha256": hashlib.sha256(rule_source.encode()).hexdigest()[:16],
    })

    payload = {
        "rule_name": name,
        "rule_source": rule_source,
        "coverage": coverage,
        "atoms": [a.decode("ascii", "ignore") for a in atoms],
        "validation": {"valid": not errors, "errors": errors, "warnings": warnings},
        "self_scan": scan_result,
        "findings": _static_checks(rule_source),
        "alert_field_coverage": alert_coverage,
        "engine": "yara-x",
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)

    lines = [f"## YARA rule: `{name}`", "", f"Coverage: **{coverage}** | "
             f"valid: {not errors} | atoms: {len(atoms)}", ""]
    if coverage == "draft":
        lines += ["> Draft quality: derived from logs, not a sample. "
                  "Validate against a real artifact before deploying.", ""]
    lines += ["```yara", rule_source.rstrip(), "```", ""]
    if errors:
        lines += ["**Errors**"] + [f"- {e}" for e in errors] + [""]
    if warnings:
        lines += ["**Warnings**"] + [f"- {w}" for w in warnings] + [""]
    if scan_result:
        hits = ", ".join(f"{s['rule']} (offsets: " +
                         ", ".join(str(m['offset']) for p in s['patterns'] for m in p['matches']) + ")"
                         for s in scan_result)
        lines += [f"**Self-scan**: matched -> {hits}", ""]
    elif params.self_scan and sample:
        lines += ["**Self-scan**: no match on the source sample", ""]
    if alert_coverage is not None:
        populated = [f for f, n in alert_coverage.items() if n]
        lines += [f"**Alert field coverage**: {alert_coverage}", ""]
        if not populated:
            lines += ["> No harvested field was populated in any matched alert. "
                      "Check the deployment's decoder field paths before trusting this draft.", ""]
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@blueteam_tool(
    name="blueteam_yara_rule_save",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=False,
)
async def blueteam_yara_rule_save(params: YaraRuleSaveInput) -> str:
    """Save a validated YARA rule to the staging directory for human review.

    Writes only under BLUETEAM_YARA_RULES_DIR (default
    /opt/yara_rules/yara_staging). Never writes to a live rules.d path.
    Requires the ``wazuh:write`` scope on the streamable_http transport
    (derived automatically because readOnlyHint=False).

    Args:
        params.rule_source: Rule text. Compile failure aborts the save.
        params.filename: Optional .yar filename; defaults to <rule_name>.yar.
        params.overwrite: Replace an existing staging file.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with saved=true, path, rule_name, valid=true.

    Examples:
        1. Save a generated rule -> path under BLUETEAM_YARA_RULES_DIR.
        2. Saving the same filename twice without overwrite=true returns an error.
        3. A rule with a syntax error is rejected before any file is written.

    Permissions: write on BLUETEAM_YARA_RULES_DIR. Rate limits: none.
    """
    rules, errors, warnings = _compile(params.rule_source)
    if rules is None:
        raise BlueTeamMCPError(
            f"Refusing to save an invalid rule: {errors[0] if errors else 'compile failed'}"
        )
    name_match = re.search(r"^\s*rule\s+(\w+)", params.rule_source, re.MULTILINE)
    rule_name = name_match.group(1) if name_match else "untitled"
    filename = params.filename or f"{rule_name}.yar"
    target = _save_rule_file(params.rule_source, filename, params.overwrite, _rules_dir())

    _audit_log("blueteam_yara_rule_save", {
        "rule_name": rule_name,
        "filename": target.name,
        "rule_sha256": hashlib.sha256(params.rule_source.encode()).hexdigest()[:16],
    })
    payload = {
        "saved": True,
        "path": str(target),
        "rule_name": rule_name,
        "bytes": target.stat().st_size,
        "validation": {"valid": True, "errors": [], "warnings": warnings},
        "engine": "yara-x",
    }
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(payload, indent=2),
                                   bypass=params.bypass_character_limit)
    lines = [f"## YARA rule saved: `{rule_name}`", "", f"Path: `{target}`",
             f"Bytes: {payload['bytes']}",
             "", "> Staging only. Promote manually after review.", ""]
    if warnings:
        lines += ["**Warnings**"] + [f"- {w}" for w in warnings]
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


if __name__ == "__main__":
    # Self-check: the pure pipeline must produce a compiling, self-matching rule.
    import asyncio

    sample_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40 + b"Usage: evilstager --target [IP] --port [PORT]" + b"\x00" * 8
    atoms, prese = _extract_from_bytes(sample_bytes)
    assert atoms, "expected atoms from synthetic ELF"
    plat, fam, cond = _detect_magic(sample_bytes)
    assert (plat, fam) == ("LNX", "SUSP"), (plat, fam)
    src = _render_rule("SUSP_LNX_Wazuh_Test_abc123", "self-check", "unit", 60,
                       atoms, prese, cond, 1, _digest(atoms))
    rules, errs, _ = _compile(src)
    assert rules is not None, errs
    hits = _scan(rules, sample_bytes, 5)
    assert hits and hits[0]["rule"].startswith("SUSP_LNX"), hits
    assert _scan(rules, b"\x00" * 100) == [], "must not match empty data"
    assert any("SV1" in f for f in _static_checks("rule bad_name { condition: true }"))
    print("yara_rules self-check OK:", hits[0]["rule"], "atoms:", len(atoms))
