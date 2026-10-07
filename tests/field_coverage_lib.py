#!/usr/bin/env python3
"""Field-coverage measurement for the Wazuh alert template (W0 harness).

Derives field facts from the pinned template fixture and checks quoted field
references under ``mcp_server/`` against ``tests/fixtures/field_manifest.json``.
The manifest is the only place a reference's class and rationale live; an
unlisted literal fails.

Baseline debt (dead ``.keyword`` aliases, mapping conflicts) stays valid until
the workstreams that remove it land; ``strict=True`` flips the harness to
zero-tolerance for the post-W2/W4 target.

Single-token generic names (``location``, ``message``, ``host``, ``id``, ...)
are not scanned: they collide with unrelated dict keys and separating them needs
AST context this harness deliberately avoids. They still count in the
fixture-derived leaf totals.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wazuh-template.json"
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "field_manifest.json"
SCAN_ROOT = REPO_ROOT / "mcp_server"

CLASSES = (
    "template_native",
    "allowlisted_dynamic",
    "states_index",
    "dead_keyword",
    "mapping_conflict",
    "unclassified",
)
DEBT_CLASSES = ("dead_keyword", "mapping_conflict", "unclassified")
# Every class except template_native carries a rationale in the manifest.
RATIONALE_CLASSES = DEBT_CLASSES + ("allowlisted_dynamic", "states_index")

_PREFIXES = ("agent", "rule", "data", "syscheck", "GeoLocation", "decoder",
             "predecoder", "vulnerability", "manager", "cluster")
_DOTTED_RE = re.compile(r'"((?:' + "|".join(_PREFIXES) + r')\.[A-Za-z0-9_@.\-]+)"')
_KEYWORD_RE = re.compile(r'"([A-Za-z0-9_@.\-]+\.keyword)"')
_SPECIAL_RE = re.compile(r'"(@timestamp|full_log|previous_log|previous_output|program_name)"')


@dataclass(frozen=True)
class TemplateIndex:
    """Field facts derived from the pinned fixture."""

    mapping_leaves: frozenset
    default_fields: frozenset
    containers: frozenset
    unique_leaves: frozenset
    keyword_subfields: frozenset
    nested_paths: frozenset
    types: dict

    def nested_descendants(self) -> frozenset:
        return frozenset(
            leaf for leaf in self.unique_leaves
            if any(leaf == n or leaf.startswith(n + ".") for n in self.nested_paths)
        )

    def ancestors(self, literal: str) -> list:
        parts = literal.split(".")
        return [".".join(parts[:i]) for i in range(1, len(parts))]


def _walk(prefix: str, props: dict, mapping_leaves: set, keyword_subfields: set,
          nested_paths: set, types: dict) -> None:
    for name, spec in props.items():
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(spec, dict) and "properties" in spec:
            if spec.get("type") == "nested":
                nested_paths.add(path)
            _walk(path, spec["properties"], mapping_leaves, keyword_subfields,
                  nested_paths, types)
        else:
            mapping_leaves.add(path)
            types[path] = (spec or {}).get("type", "?") if isinstance(spec, dict) else "?"
            if isinstance(spec, dict) and "keyword" in (spec.get("fields") or {}):
                keyword_subfields.add(path)


def load_template_index(path: Path = FIXTURE_PATH) -> TemplateIndex:
    template = json.loads(path.read_text())
    default_fields = set(template["settings"]["index.query.default_field"])
    mapping_leaves: set = set()
    keyword_subfields: set = set()
    nested_paths: set = set()
    types: dict = {}
    _walk("", template["mappings"]["properties"], mapping_leaves,
          keyword_subfields, nested_paths, types)
    union = mapping_leaves | default_fields
    # A default-field entry that prefixes another path is a parent, not a leaf.
    containers = {d for d in default_fields
                  if any(o != d and o.startswith(d + ".") for o in union)}
    return TemplateIndex(
        mapping_leaves=frozenset(mapping_leaves),
        default_fields=frozenset(default_fields),
        containers=frozenset(containers),
        unique_leaves=frozenset(union - containers),
        keyword_subfields=frozenset(keyword_subfields),
        nested_paths=frozenset(nested_paths),
        types=types,
    )


def fixture_sha256(path: Path = FIXTURE_PATH) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observed_class(literal: str, index: TemplateIndex) -> str:
    """Resolution class the fixture proves for a literal, before the manifest."""
    if literal.endswith(".keyword"):
        return ("template_native" if literal[:-8] in index.keyword_subfields
                else "dead_keyword")
    if literal in index.unique_leaves:
        return "template_native"
    if any(a in index.mapping_leaves for a in index.ancestors(literal)):
        return "mapping_conflict"
    if literal.startswith("vulnerability."):
        return "states_index"
    return "unknown"


def _iter_literals(line: str) -> set:
    found = set()
    for rx in (_DOTTED_RE, _KEYWORD_RE, _SPECIAL_RE):
        found.update(m.group(1) for m in rx.finditer(line))
    return found


def scan_references(root: Path = SCAN_ROOT) -> dict:
    """Map every scanned literal to its ``file:line`` call sites."""
    refs: dict = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            for literal in _iter_literals(line):
                refs.setdefault(literal, []).append(
                    (path.relative_to(REPO_ROOT).as_posix(), lineno))
    return refs


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    return json.loads(path.read_text())


@dataclass
class ValidationResult:
    errors: list = field(default_factory=list)   # (code, message)
    counts: dict = field(default_factory=dict)   # class -> scanned count
    debt: dict = field(default_factory=dict)     # class -> literals
    scanned_total: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def codes(self) -> set:
        return {code for code, _ in self.errors}


def validate_fixture(manifest: dict, index: TemplateIndex,
                     path: Path = FIXTURE_PATH) -> list:
    """Errors where the pinned fixture no longer matches the manifest snapshot."""
    errors = []
    declared = manifest.get("template", {})
    actual_sha = fixture_sha256(path)
    if declared.get("sha256") != actual_sha:
        errors.append(("fixture_hash_mismatch",
                       f"{path.name} sha256 {actual_sha} != manifest {declared.get('sha256')}"))
    derived = declared.get("derived", {})
    actual = {
        "default_field_entries": len(index.default_fields),
        "mapping_leaves": len(index.mapping_leaves),
        "container_entries": len(index.containers),
        "unique_leaves": len(index.unique_leaves),
    }
    for key, value in actual.items():
        if derived.get(key) != value:
            errors.append(("derived_count_mismatch",
                           f"{key}: fixture={value} manifest={derived.get(key)}"))
    return errors


def _call_sites(refs: dict, literal: str, limit: int = 3) -> str:
    sites = refs.get(literal, [])
    shown = ", ".join(f"{f}:{n}" for f, n in sites[:limit])
    return shown + (" ..." if len(sites) > limit else "")


def validate_references(manifest: dict, index: TemplateIndex, refs: dict,
                        strict: bool = False) -> ValidationResult:
    """Check every scanned reference against the manifest and the fixture facts."""
    result = ValidationResult(scanned_total=len(refs))
    declared_refs = manifest.get("references", {})
    classes = manifest.get("classes", {})
    counts = {cls: 0 for cls in CLASSES}
    debt = {cls: [] for cls in DEBT_CLASSES}

    for literal in sorted(refs):
        entry = declared_refs.get(literal)
        if entry is None:
            result.errors.append((
                "new_reference",
                f"unclassified reference '{literal}' at {_call_sites(refs, literal)} "
                "- add a manifest entry with class + rationale"))
            continue
        cls = entry.get("class")
        if cls not in classes:
            result.errors.append((
                "invalid_class", f"'{literal}': class {cls!r} not declared in manifest classes"))
            continue
        counts[cls] = counts.get(cls, 0) + 1
        if cls in DEBT_CLASSES:
            debt[cls].append(literal)

        if cls in RATIONALE_CLASSES and not str(entry.get("rationale") or "").strip():
            result.errors.append((
                "missing_rationale", f"'{literal}': class {cls} requires a rationale"))

        observed = observed_class(literal, index)
        if cls == "template_native" and observed != "template_native":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared template_native but fixture says {observed}"))
        elif cls == "allowlisted_dynamic" and observed != "unknown":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared allowlisted_dynamic but fixture says {observed}"))
        elif cls == "states_index" and observed != "states_index":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared states_index but fixture says {observed}"))
        elif cls == "dead_keyword" and observed != "dead_keyword":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared dead_keyword but fixture says {observed}"))
        elif cls == "mapping_conflict" and observed != "mapping_conflict":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared mapping_conflict but fixture says {observed}"))
        elif cls == "unclassified" and observed != "unknown":
            result.errors.append((
                "class_mismatch",
                f"'{literal}' declared unclassified but fixture says {observed}"))

        flagged = bool(entry.get("baseline_debt"))
        if cls in DEBT_CLASSES and not flagged:
            result.errors.append((
                "new_debt",
                f"'{literal}': {cls} is baseline debt and must carry "
                '"baseline_debt": true until the fixing workstream removes it'))
        if flagged and cls not in DEBT_CLASSES:
            result.errors.append((
                "new_debt", f"'{literal}': baseline_debt flag on non-debt class {cls}"))

    for literal, entry in sorted(declared_refs.items()):
        if literal not in refs:
            result.errors.append((
                "stale_reference",
                f"manifest lists '{literal}' ({entry.get('class')}) but no code reference "
                "was scanned - remove the entry in the same change that removes the code"))

    baseline = manifest.get("baseline", {})
    for cls in DEBT_CLASSES:
        expected = baseline.get(cls)
        if expected is not None and expected != len(debt[cls]):
            result.errors.append((
                "baseline_count_mismatch",
                f"baseline {cls}: manifest={expected} flagged={len(debt[cls])}"))

    if strict:
        for cls in DEBT_CLASSES:
            if debt[cls]:
                result.errors.append((
                    "strict_debt",
                    f"strict mode: {len(debt[cls])} {cls} reference(s) remain "
                    f"({', '.join(debt[cls][:5])}{' ...' if len(debt[cls]) > 5 else ''})"))

    result.counts = counts
    result.debt = debt
    return result


def build_report(manifest: dict, index: TemplateIndex, refs: dict,
                 fixture_errors: list, result: ValidationResult) -> str:
    """Human-readable baseline summary for the report script and test failures."""
    lines = [
        "Wazuh alert-template field coverage (W0 baseline)",
        f"fixture : {FIXTURE_PATH.relative_to(REPO_ROOT).as_posix()}",
        f"sha256  : {fixture_sha256()}",
        f"derived : default_field={len(index.default_fields)} "
        f"mapping_leaves={len(index.mapping_leaves)} "
        f"containers={len(index.containers)} unique_leaves={len(index.unique_leaves)}",
        "",
        f"scanned code references: {result.scanned_total}",
    ]
    labels = {
        "template_native": "",
        "allowlisted_dynamic": "intentionally dynamic",
        "states_index": "states-index only",
        "dead_keyword": "BASELINE DEBT -> W2",
        "mapping_conflict": "BASELINE DEBT -> W4",
        "unclassified": "BASELINE DEBT",
    }
    for cls in CLASSES:
        note = labels[cls]
        lines.append(f"  {cls:20s}: {result.counts.get(cls, 0):3d}"
                     + (f"   [{note}]" if note else ""))
    if result.debt:
        for cls in DEBT_CLASSES:
            entries = result.debt.get(cls) or []
            if not entries:
                continue
            lines.append("")
            lines.append(f"{cls} register ({len(entries)}):")
            for literal in entries:
                lines.append(f"  {literal:32s} {_call_sites(refs, literal, 2)}")
    errors = fixture_errors + result.errors
    lines.append("")
    if errors:
        lines.append(f"status: FAILED ({len(errors)} issue(s))")
        for code, message in errors:
            lines.append(f"  [{code}] {message}")
    else:
        debt_total = sum(len(v) for v in result.debt.values())
        lines.append(f"status: OK (baseline mode; {debt_total} grandfathered entr"
                     f"{'y' if debt_total == 1 else 'ies'})")
    return "\n".join(lines)


def write_csv(path: Path, index: TemplateIndex, refs: dict, manifest: dict) -> None:
    """Leaf-level and reference-level table."""
    import csv
    declared = manifest.get("references", {})
    nested = index.nested_descendants()
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["kind", "path", "class", "type", "in_mapping",
                         "in_default_field", "container", "nested_descendant",
                         "code_files", "rationale"])
        for leaf in sorted(index.unique_leaves):
            writer.writerow(["leaf", leaf, "template_leaf", index.types.get(leaf, ""),
                             leaf in index.mapping_leaves, leaf in index.default_fields,
                             leaf in index.containers, leaf in nested, "", ""])
        for literal in sorted(refs):
            entry = declared.get(literal, {})
            writer.writerow(["reference", literal, entry.get("class", "unclassified"),
                             index.types.get(literal, ""), "", "", "", "",
                             ";".join(sorted({f for f, _ in refs[literal]})),
                             entry.get("rationale", "")])


# Retrieval is uniform for every alert-document field. The dimensions that
# differ per leaf come from the fixture (type, nested parent) plus the overlay.

OVERLAY_PATH = REPO_ROOT / "tests" / "fixtures" / "field_capability_overlay.json"
CAPABILITY_STATUSES = (
    "fully_handled",
    "specialized_handled",
    "generically_handled",
    "privacy_restricted",
    "intentionally_unsupported",
    "defective",
)
GENERIC_ANALYSIS_PATH = ("generic_analysis: wazuh_alert_dsl_query (filter + aggs), "
                         "blueteam_index_schema (agg-safety), blueteam_wazuh_alerts (retrieval)")
EVIDENCE_SOURCES = ("mapping_derived", "generic_implementation",
                    "specialized_implementation", "executable_test")
_NON_STRING_TYPES = ("long", "integer", "double", "boolean", "date", "geo_point")
_PRIVACY_OK = ("identity_key_masked", "identity_path_masked", "credential_field_l1",
               "not_applicable_non_string", "ioc_by_design", "value_shape_regex")


def load_overlay(path: Path = OVERLAY_PATH) -> dict:
    return json.loads(path.read_text())


def _family(path: str) -> str:
    parts = path.split(".")
    return f"data.{parts[1]}" if parts[0] == "data" and len(parts) > 1 else parts[0]


def _nested_parent(leaf: str, index: TemplateIndex):
    parents = [n for n in index.nested_paths if leaf == n or leaf.startswith(n + ".")]
    if not parents:
        return None, 0
    best = max(parents, key=len)
    depth = sum(1 for n in index.nested_paths if best == n or best.startswith(n + "."))
    return best, depth


def _query_agg(mapping_type: str, nested_path) -> tuple:
    if nested_path:
        return "nested_required", "nested_terms_required"
    if mapping_type == "text":
        return "analyzed_match_only", "not_aggregatable"
    if mapping_type == "geo_point":
        return "geo_shape_or_bbox", "geo_metrics"
    if mapping_type == "date":
        return "range", "date_histogram"
    if mapping_type in ("long", "integer", "double"):
        return "range", "stats_terms_histogram"
    if mapping_type in ("keyword", "ip", "boolean"):
        return "exact_term", "terms"
    return "exact_term_dynamic", "terms_dynamic"


def _defect_map(manifest: dict, index: TemplateIndex) -> dict:
    """Attach dead/conflicting reference literals to their template leaf, when one exists."""
    defects: dict = {}
    for literal, entry in manifest.get("references", {}).items():
        if entry.get("class") not in DEBT_CLASSES:
            continue
        base = literal[:-8] if literal.endswith(".keyword") else literal
        if base in index.unique_leaves:
            defects.setdefault(base, []).append(
                {"literal": literal, "class": entry["class"],
                 "impact": entry.get("impact", "unknown")})
    return defects


def _privacy(leaf: str, mapping_type: str, overlay: dict) -> str:
    privacy = overlay.get("privacy", {})
    if leaf in privacy.get("credential_fields", []):
        return "credential_field_l1"
    if leaf in privacy.get("identity_key_masked", []):
        return "identity_key_masked"
    if leaf in privacy.get("identity_path_masked", []):
        return "identity_path_masked"
    if mapping_type in _NON_STRING_TYPES or mapping_type == "object":
        return "not_applicable_non_string"
    if leaf in privacy.get("ioc_exempt", []):
        return "ioc_by_design"
    return "value_shape_regex"


@dataclass
class CapabilityRow:
    path: str
    family: str
    mapping_type: str
    in_mapping: bool
    nested_path: str
    nested_depth: int
    nested_semantics_enforced: bool
    # what the mapping permits
    mapping_query: str
    mapping_aggregation: str
    # what the MCP server actually exposes
    implemented_retrieval: str
    implemented_query: str
    implemented_aggregation: str
    implemented_analysis: str
    handling_path: str
    # how we know it
    evidence_sources: str
    verified_by: str
    analysis_kind: str
    privacy: str
    defect: str
    defect_refs: str
    status: str


def derive_capabilities(index: TemplateIndex, overlay: dict, manifest: dict) -> list:
    """One row per template leaf; mapping, implemented and verified layers all resolved."""
    defects = _defect_map(manifest, index)
    specialized = overlay.get("specialized", {})
    unsupported = overlay.get("intentionally_unsupported", {})
    privacy_restricted = overlay.get("privacy_restricted", {})
    field_selection = overlay.get("field_selection", {})
    verified_spec = overlay.get("verified", {})
    generic_tests = verified_spec.get("generic_mechanism", [])
    field_tests = verified_spec.get("specialized", {})
    rows = []
    for leaf in sorted(index.unique_leaves):
        mapping_type = index.types.get(leaf) or (
            "keyword(dynamic)" if leaf in index.default_fields else "?")
        nested_path, depth = _nested_parent(leaf, index)
        mapping_query, mapping_aggregation = _query_agg(mapping_type, nested_path)
        privacy = _privacy(leaf, mapping_type, overlay)
        leaf_defects = defects.get(leaf, [])
        spec = specialized.get(leaf)
        if leaf in privacy_restricted:
            status = "privacy_restricted"
        elif leaf in unsupported:
            status = "intentionally_unsupported"
        elif any(d["impact"] == "tool_degrading" for d in leaf_defects):
            status = "defective"
        elif spec:
            status = "fully_handled" if privacy in _PRIVACY_OK else "specialized_handled"
        else:
            status = "generically_handled"

        implemented_query = "generic_dsl_filter"
        implemented_aggregation = "generic_dsl_aggs"
        if nested_path:
            implemented_query = "generic_dsl_nested_query (caller-supplied, unenforced)"
            implemented_aggregation = "generic_dsl_nested_aggs (caller-supplied, unenforced)"
        if mapping_type == "text":
            implemented_aggregation = "none_by_mapping"
        if spec:
            implemented_query += " + specialized"
            # Specialized tools filter on text fields (full_log); they do not aggregate them.
            if mapping_type != "text":
                implemented_aggregation += " + specialized"

        sources = ["mapping_derived", "generic_implementation"]
        if spec:
            sources.append("specialized_implementation")
        leaf_tests = list(field_tests.get(leaf, []))
        if generic_tests or leaf_tests:
            sources.append("executable_test")
        selection = field_selection.get(leaf.split(".")[0])
        analysis = spec["role"] if spec else (
            f"generic + {selection['tool']} {selection['param']} (validated field selection)"
            if selection else GENERIC_ANALYSIS_PATH)
        handling_path = ("privacy_restricted" if leaf in privacy_restricted
                         else "unsupported" if leaf in unsupported
                         else "specialized" if spec else "generic")
        verified_by = ";".join(sorted(set(leaf_tests)))
        rows.append(CapabilityRow(
            path=leaf,
            family=_family(leaf),
            mapping_type=mapping_type,
            in_mapping=leaf in index.mapping_leaves,
            nested_path=nested_path or "",
            nested_depth=depth,
            nested_semantics_enforced=not bool(nested_path),
            mapping_query=mapping_query,
            mapping_aggregation=mapping_aggregation,
            implemented_retrieval=("generic_full_source "
                                   "(blueteam_wazuh_alerts / wazuh_indexer_search)"),
            implemented_query=implemented_query,
            implemented_aggregation=implemented_aggregation,
            implemented_analysis=analysis,
            handling_path=handling_path,
            evidence_sources=",".join(sources),
            verified_by=verified_by,
            analysis_kind="specialized" if spec else "generic",
            privacy=privacy,
            defect=";".join(sorted({d["literal"] for d in leaf_defects})),
            defect_refs=";".join(sorted({f"{d['literal']}[{d['impact']}]" for d in leaf_defects})),
            status=status,
        ))
    return rows


def validate_capabilities(overlay: dict, index: TemplateIndex, manifest: dict,
                          rows: list) -> list:
    """Errors where the capability overlay or derived rows are inconsistent."""
    errors = []
    leaves = index.unique_leaves
    for section in ("specialized", "intentionally_unsupported", "privacy_restricted"):
        for field_name, value in overlay.get(section, {}).items():
            if field_name not in leaves:
                errors.append(("overlay_unknown_field",
                               f"{section}: '{field_name}' is not a template leaf"))
                continue
            if section == "specialized" and not (str(value.get("tool") or "").strip()
                                                 and str(value.get("role") or "").strip()):
                errors.append(("overlay_incomplete",
                               f"specialized: '{field_name}' needs tool + role"))
            if section in ("intentionally_unsupported", "privacy_restricted") and not str(value).strip():
                errors.append(("overlay_reason_missing",
                               f"{section}: '{field_name}' needs a reason"))
    privacy = overlay.get("privacy", {})
    for key in ("identity_key_masked", "identity_path_masked", "credential_fields",
                "non_secret_key_allowlist", "ioc_exempt"):
        for field_name in privacy.get(key, []):
            if field_name not in leaves:
                errors.append(("privacy_unknown_field",
                               f"privacy.{key}: '{field_name}' is not a template leaf"))
    overlap = set(privacy.get("identity_key_masked", [])) & set(
        privacy.get("identity_path_masked", []))
    if overlap:
        errors.append(("privacy_overlap",
                       f"identity key-masked and unmasked overlap: {sorted(overlap)[:5]}"))
    if len(rows) != len(leaves):
        errors.append(("capability_rows_mismatch",
                       f"rows={len(rows)} leaves={len(leaves)}"))
    for family_name, spec in overlay.get("field_selection", {}).items():
        if not str(spec.get("tool") or "").strip() or not str(spec.get("param") or "").strip():
            errors.append(("field_selection_incomplete",
                           f"field_selection[{family_name}]: needs tool + param"))
        if not any(leaf == family_name or leaf.startswith(family_name + ".") for leaf in leaves):
            errors.append(("field_selection_unknown_family",
                           f"field_selection[{family_name}]: no matching leaf"))
    seen = set()
    for row in rows:
        if row.path in seen:
            errors.append(("capability_duplicate", f"duplicate row for '{row.path}'"))
        seen.add(row.path)
        if row.status not in CAPABILITY_STATUSES:
            errors.append(("capability_status_unknown",
                           f"'{row.path}': status {row.status!r}"))
        if row.mapping_type == "text" and row.mapping_aggregation != "not_aggregatable":
            errors.append(("capability_text_agg",
                           f"'{row.path}': text field must not claim aggregation {row.mapping_aggregation}"))
        if row.nested_path and not row.mapping_query.startswith("nested"):
            errors.append(("capability_nested_missing",
                           f"'{row.path}': nested descendant needs nested query semantics"))
        if row.nested_path and row.nested_semantics_enforced:
            errors.append(("capability_nested_enforcement",
                           f"'{row.path}': nested semantics are not enforced by any tool"))
        for source in row.evidence_sources.split(","):
            if source not in EVIDENCE_SOURCES:
                errors.append(("capability_evidence_unknown",
                               f"'{row.path}': evidence source {source!r}"))
        if row.handling_path not in ("generic", "specialized", "unsupported", "privacy_restricted"):
            errors.append(("capability_path_unknown",
                           f"'{row.path}': handling path {row.handling_path!r}"))
        if row.handling_path != "unsupported" \
                and "generic_implementation" not in row.evidence_sources \
                and "specialized_implementation" not in row.evidence_sources:
            errors.append(("capability_no_implementation",
                           f"'{row.path}': no MCP implementation evidence"))
        if row.handling_path == "unsupported" and row.path not in overlay["intentionally_unsupported"]:
            errors.append(("capability_unsupported_undocumented",
                           f"'{row.path}': unsupported without an overlay reason"))
        if row.handling_path == "privacy_restricted" and row.path not in overlay["privacy_restricted"]:
            errors.append(("capability_privacy_undocumented",
                           f"'{row.path}': privacy_restricted without an overlay reason"))
        if row.status == "defective" and not row.defect_refs:
            errors.append(("capability_defect_missing",
                           f"'{row.path}': defective status without a defect reference"))
        if row.status in ("fully_handled", "specialized_handled") \
                and row.analysis_kind != "specialized":
            errors.append(("capability_specialized_missing",
                           f"'{row.path}': {row.status} without a specialized entry"))
    errors.extend(_validate_test_refs(overlay))
    return errors


def _validate_test_refs(overlay: dict) -> list:
    """Every declared executable test must exist in the tree."""
    errors = []
    verified = overlay.get("verified", {})
    refs = list(verified.get("generic_mechanism", []))
    for test_list in verified.get("specialized", {}).values():
        refs.extend(test_list)
    for ref in refs:
        rel, _, func = ref.partition("::")
        path = REPO_ROOT / rel
        if not path.is_file():
            errors.append(("verified_test_missing", f"{ref}: file not found"))
            continue
        if func and f"def {func}" not in path.read_text(errors="replace"):
            errors.append(("verified_test_missing", f"{ref}: function not found"))
    return errors


def capability_summary(rows: list) -> dict:
    def counts(field_name: str) -> dict:
        out: dict = {}
        for row in rows:
            value = getattr(row, field_name)
            out[value] = out.get(value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))
    return {
        "total_leaves": len(rows),
        "status": counts("status"),
        "mapping_query": counts("mapping_query"),
        "mapping_aggregation": counts("mapping_aggregation"),
        "privacy": counts("privacy"),
        "nested_required": sum(1 for r in rows if r.nested_path),
        "defective_leaves": [r.path for r in rows if r.status == "defective"],
        "leaves_with_defect_refs": sum(1 for r in rows if r.defect_refs),
        "evidence": {
            "mapping_only": sum(1 for r in rows if r.evidence_sources == "mapping_derived"),
            "generic_implementation": sum(1 for r in rows
                                          if "generic_implementation" in r.evidence_sources),
            "specialized_implementation": sum(1 for r in rows
                                              if "specialized_implementation" in r.evidence_sources),
            "executable_test": sum(1 for r in rows if "executable_test" in r.evidence_sources),
            "field_level_tests": sum(1 for r in rows if r.verified_by),
            "no_handling_path": sum(1 for r in rows if r.handling_path not in
                                    ("generic", "specialized", "unsupported", "privacy_restricted")),
            "nested_unenforced": sum(1 for r in rows
                                     if r.nested_path and not r.nested_semantics_enforced),
            "text_no_aggregation_path": sum(1 for r in rows if r.mapping_type == "text"
                                            and r.implemented_aggregation == "none_by_mapping"),
        },
    }


def render_capability_summary(rows: list) -> str:
    summary = capability_summary(rows)
    lines = ["", "Per-leaf handling capability (mapping / implemented / verified)"]
    for label, key in (("status", "status"), ("mapping query", "mapping_query"),
                       ("mapping aggregation", "mapping_aggregation"), ("privacy", "privacy")):
        lines.append(f"  {label}:")
        for value, count in summary[key].items():
            lines.append(f"    {value:40s}: {count:4d}")
    lines.append(f"  nested descendants: {summary['nested_required']}")
    lines.append(f"  leaves with defect refs: {summary['leaves_with_defect_refs']}")
    evidence = summary["evidence"]
    lines.append("  implementation evidence:")
    lines.append(f"    mapping-derived only                  : {evidence['mapping_only']}")
    lines.append(f"    generic implementation                : {evidence['generic_implementation']}")
    lines.append(f"    specialized implementation            : {evidence['specialized_implementation']}")
    lines.append(f"    executable verification (mechanism)   : {evidence['executable_test']}")
    lines.append(f"    executable verification (field-level) : {evidence['field_level_tests']}")
    lines.append(f"    no MCP handling path                  : {evidence['no_handling_path']}")
    lines.append(f"    nested leaves without enforced semantics: {evidence['nested_unenforced']}")
    lines.append(f"    text leaves without an aggregation path : {evidence['text_no_aggregation_path']}")
    if summary["defective_leaves"]:
        lines.append("  defective leaves: " + ", ".join(summary["defective_leaves"]))
    return "\n".join(lines)


def write_capability_csv(path: Path, rows: list) -> None:
    import csv
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["path", "family", "mapping_type", "in_mapping", "nested_path",
                         "nested_depth", "nested_semantics_enforced", "mapping_query",
                         "mapping_aggregation", "implemented_retrieval", "implemented_query",
                         "implemented_aggregation", "implemented_analysis", "handling_path",
                         "evidence_sources", "verified_by", "privacy", "defect_refs", "status"])
        for row in rows:
            writer.writerow([row.path, row.family, row.mapping_type, row.in_mapping,
                             row.nested_path, row.nested_depth, row.nested_semantics_enforced,
                             row.mapping_query, row.mapping_aggregation,
                             row.implemented_retrieval, row.implemented_query,
                             row.implemented_aggregation, row.implemented_analysis,
                             row.handling_path, row.evidence_sources, row.verified_by,
                             row.privacy, row.defect_refs, row.status])
