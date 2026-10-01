#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Index schema explorer discover field names/types before building aggregations.
Prevents the most common silent false-negative: querying ``field.keyword``
when the index stores ``field`` as a plain ``keyword`` type (or vice versa).
"""
from __future__ import annotations
import json, re, statistics
from typing import Optional, Literal, Any
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.wazuh.indexer import _wazuh_indexer_mapping, _WAZUH_INDEX_PATTERNS

_COMMON_FIELDS = [
    "data.srcip", "data.srcip2", "data.src_ip", "data.client_ip", "data.remote_ip",
    "data.source_ip", "data.ip", "srcip",
    "data.domain", "data.url", "data.account", "data.error", "data.user_agent",
    "rule.id", "rule.level", "rule.groups", "rule.description", "rule.mitre.id",
    "rule.mitre.tactic", "rule.mitre.technique",
    "agent.name", "agent.id", "agent.ip",
    "GeoLocation.country_name", "GeoLocation.city_name", "GeoLocation.location",
    "GeoLocation.region_name", "GeoLocation.real_region_name",
    "@timestamp", "full_log", "decoder.name", "location",
]


def _flatten_props(prefix: str, props: dict, out: dict) -> None:
    """Recursively flatten nested ``properties`` into dotted field paths."""
    for name, spec in props.items():
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(spec, dict) and "properties" in spec:
            _flatten_props(path, spec["properties"], out)
            continue
        out[path] = spec


def _truncated_templates(field_counts: dict, ratio: float = 0.5,
                         gap: int = 20) -> tuple:
    """Indices carrying far fewer fields than the median.
    A truncated template drops fields outright rather than retyping them, so a
    query on a missing field loses those shards without raising. A shortfall
    under ``gap`` fields is not evidence of one. Returns (summary, outliers).
    """
    if len(field_counts) < 2:
        return {}, []
    median = int(statistics.median(list(field_counts.values())))
    outliers = sorted(((name, n) for name, n in field_counts.items()
                       if n < median * ratio and median - n >= gap),
                      key=lambda item: item[1])
    return {"indices": len(field_counts), "fields_median": median,
            "fields_min": min(field_counts.values()), "outliers": len(outliers)}, outliers


def _field_info(spec: dict) -> dict:
    """Type + keyword sub-field presence for one mapping spec, plus whether the
    field's own name can carry a terms aggregation in that index."""
    ftype = spec.get("type", "object")
    has_keyword = "keyword" in spec.get("fields", {})
    return {"type": ftype, "has_keyword_subfield": has_keyword,
            "agg_safe": _shape_is_agg_safe(_shape(spec))}


_AGG_SAFE_TYPES = ("keyword", "long", "integer", "double", "date", "boolean", "ip")


def _shape(spec: dict) -> str:
    """Mapping shape for one index, e.g. ``text+keyword+fielddata``.
    ``fielddata`` decides aggregatability as much as the type does: a text field
    carrying it aggregates on its bare name, and the mapping tool read both
    shapes identically until this was included.
    """
    parts = [spec.get("type", "object")]
    if "keyword" in spec.get("fields", {}):
        parts.append("keyword")
    if spec.get("fielddata"):
        parts.append("fielddata")
    return "+".join(parts)


def _shape_is_agg_safe(shape: str) -> bool:
    """True when the field's own name aggregates to that field's values.

    A keyword sub-field does not count on its own, and neither does fielddata:
    a text field with fielddata does aggregate, but to analysed tokens.
    """
    return shape.split("+")[0] in _AGG_SAFE_TYPES


def _shape_is_tokenized(shape: str) -> bool:
    """fielddata over a text field buckets individual words, so the same
    `terms` query reads "detected" where a keyword index reads the description."""
    parts = shape.split("+")
    return parts[0] == "text" and "fielddata" in parts[1:]


def _shape_counts(by_shape: dict) -> dict:
    return {shape: len(names) for shape, names in by_shape.items()}


def _minority_indices(by_shape: dict, cap: int = 20) -> list:
    """Indices whose shape differs from the majority, so a divergence can be
    matched against the ``_shards.failures`` array of a failing query."""
    if len(by_shape) < 2:
        return []
    majority = max(by_shape, key=lambda s: len(by_shape[s]))
    odd = sorted(name for shape, names in by_shape.items()
                 if shape != majority for name in names)
    return odd[:cap]


def _agg_safe_field(field: str, by_shape: dict) -> Optional[str]:
    """Field name that aggregates in every matched index, or ``None``.
    A corpus mixing ``keyword`` with ``text+keyword`` has neither: the bare name
    fails on the text indices and ``.keyword`` does not exist on the others.
    """
    if not by_shape:
        return None
    if all(_shape_is_agg_safe(shape) for shape in by_shape):
        return field
    if all("keyword" in shape.split("+")[1:] for shape in by_shape):
        return f"{field}.keyword"
    return None


class IndexSchemaInput(BaseModel):
    """Input model for blueteam_index_schema."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    index: str = Field(
        default="wazuh-alerts-*",
        max_length=128,
        description="Index pattern: 'wazuh-alerts-*' (alerts), 'wazuh-events-*', "
                    "or 'wazuh-states-vulnerabilities-*'.",
    )
    fields: list[str] = Field(
        default=[],
        max_length=50,
        description="Specific dotted fields to inspect (e.g. ['data.srcip', 'rule.groups']). "
                    "Empty = list ALL fields in the index mapping.",
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(
    name="blueteam_index_schema",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_index_schema(params: IndexSchemaInput) -> str:
    """Discover Wazuh Indexer field names and types before building queries.
    Returns each field's type and whether it has a ``.keyword`` sub-field.
    Use this BEFORE aggregation queries to avoid the silent false-negative
    where ``field.keyword`` doesn't exist (index stores plain ``keyword``).

    **Worked Examples**
    1. *Inspect specific fields for aggregation safety*:
       ``blueteam_index_schema(fields=["data.srcip", "rule.groups", "agent.name"])``

    2. *List the full mapping*:
       ``blueteam_index_schema(index="wazuh-alerts-*")``

    3. *JSON output*:
       ``blueteam_index_schema(fields=["rule.id"], response_format="json")``
    """
    _audit_log("blueteam_index_schema", {"index": params.index, "fields": params.fields})

    raw = await _wazuh_indexer_mapping(params.index)
    if isinstance(raw, dict) and "error" in raw:
        return json.dumps(raw, indent=2)

    all_fields: dict[str, dict] = {}
    shape_indices: dict[str, dict[str, list[str]]] = {}
    field_counts: dict[str, int] = {}
    for index_name, index_body in raw.items():
        props = index_body.get("mappings", {}).get("properties", {})
        per_index: dict[str, dict] = {}
        _flatten_props("", props, per_index)
        field_counts[index_name] = len(per_index)
        for field, spec in per_index.items():
            all_fields[field] = spec
            by_shape = shape_indices.setdefault(field, {})
            by_shape.setdefault(_shape(spec), []).append(index_name)

    # Determine target fields
    if params.fields:
        targets = params.fields
    else:
        targets = sorted(all_fields.keys())

    results = []
    for f in targets:
        spec = all_fields.get(f)
        if spec is None:
            results.append({"field": f, "exists": False,
                            "type": None, "has_keyword_subfield": False,
                            "agg_safe": False, "agg_safe_field": None})
        else:
            info = _field_info(spec)
            by_shape = shape_indices.get(f) or {}
            if by_shape:
                info["agg_safe"] = all(_shape_is_agg_safe(s) for s in by_shape)
            row = {"field": f, "exists": True, **info,
                   "agg_safe_field": _agg_safe_field(f, by_shape)}
            if any(_shape_is_tokenized(s) for s in by_shape):
                row["tokenized"] = True
            if len(by_shape) > 1:
                row["mixed_mapping"] = _shape_counts(by_shape)
                row["mixed_indices"] = _minority_indices(by_shape)
            results.append(row)

    if params.response_format == "json":
        payload = {
            "index": params.index,
            "total_fields_in_mapping": len(all_fields),
            "queried_fields": len(results),
            "results": results,
        }
        index_summary, truncated = _truncated_templates(field_counts)
        if index_summary:
            payload["indices"] = index_summary
            payload["truncated_template_indices"] = [
                {"index": name, "fields": count} for name, count in truncated[:20]]
        return _truncate_if_needed(json.dumps(payload, indent=2))

    lines = [f"# Index Schema - `{params.index}`", "",
             f"**Total fields in mapping**: {len(all_fields)}", ""]
    lines.append("| Field | Type | .keyword? | Agg-Safe |")
    lines.append("|-------|------|-----------|----------|")
    for r in results:
        if not r["exists"]:
            lines.append(f"| `{r['field']}` | ❌ NOT FOUND | — | — |")
        elif r.get("mixed_mapping"):
            variants = ", ".join(f"`{s}`×{n}" for s, n in sorted(r["mixed_mapping"].items()))
            note = (f"⚠️ use `{r['agg_safe_field']}`" if r.get("agg_safe_field")
                    else "⚠️ no field name spans every index")
            lines.append(f"| `{r['field']}` | {variants} | — | {note} |")
        else:
            kw = "✅" if r["has_keyword_subfield"] else "—"
            if r["agg_safe"]:
                agg = "✅"
            elif r.get("tokenized"):
                agg = "⚠️ fielddata buckets tokens, not values"
            elif r.get("agg_safe_field"):
                agg = f"⚠️ use `{r['agg_safe_field']}`"
            else:
                agg = "⚠️ not aggregatable as named"
            lines.append(f"| `{r['field']}` | `{r['type']}` | {kw} | {agg} |")
    lines.append("")
    index_summary, truncated = _truncated_templates(field_counts)
    if truncated:
        shown = ", ".join(f"{name} ({count})" for name, count in truncated[:5])
        more = f" and {len(truncated) - 5} more" if len(truncated) > 5 else ""
        lines.append(f"> ⚠️ {len(truncated)} of {index_summary['indices']} indices carry far fewer "
                     f"fields than the median ({index_summary['fields_median']}). A truncated "
                     "template drops fields from those shards entirely, so any query on a "
                     "missing field loses them with no error. Reindex them from source.")
        lines.append(f">   {shown}{more}")
        lines.append("")
    mixed_rows = [r for r in results if r.get("mixed_mapping")]
    if mixed_rows:
        lines.append(f"> ⚠️ {len(mixed_rows)} field(s) are mapped differently across the "
                     "matched indices, so an aggregation on them covers only the shards "
                     "whose mapping allows it and returns no error for the rest. Repair "
                     "the index template and reindex the divergent indices before "
                     "trusting a ranking built on them.")
        for r in mixed_rows[:5]:
            if r.get("mixed_indices"):
                shown = ", ".join(r["mixed_indices"][:10])
                more = " …" if len(r["mixed_indices"]) > 10 else ""
                lines.append(f">   `{r['field']}`: {shown}{more}")
        lines.append("")
    token_rows = [r for r in results if r.get("tokenized")]
    if token_rows:
        names = ", ".join(f"`{r['field']}`" for r in token_rows[:5])
        lines.append(f"> ⚠️ {names} aggregates to analysed tokens on the fielddata indices and to "
                     "whole values everywhere else, so one `terms` bucket mixes words with "
                     "descriptions and no total across them is meaningful.")
    lines.append("_Tip: `agg_safe=✅` means the bare field name works in a `terms` "
                 "aggregation across every matched index; otherwise use `agg_safe_field`._")
    return _truncate_if_needed("\n".join(lines))
