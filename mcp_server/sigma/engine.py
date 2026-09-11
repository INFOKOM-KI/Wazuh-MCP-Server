#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
pySigma bridge Sigma YAML to OpenSearch query conversion.
This is the only module in the server that touches pySigma. Everything else goes
through :func:`convert` and :func:`available`, so the optional dependency has one
import boundary and one place to test.

Verified against pySigma 1.5.0 + pySigma-backend-opensearch 2.0.3:
  backend entry point       ``opensearch_lucene`` (``OpensearchLuceneBackend``)
  constructor               ``(processing_pipeline=None, collect_errors=False,
                              index_names=["beats-*"], monitor_interval=5,
                              monitor_interval_unit="MINUTES")``
  formats                   ``default`` (Lucene string), ``dsl_lucene`` (DSL body),
                              ``monitor_rule`` (Dashboards alerting monitor),
                              ``dashboards_ndjson`` (saved search)
  ``convert`` returns       a list, one entry per rule in the collection
  parse errors              ``SigmaLogsourceError`` (missing logsource),
                              ``SigmaConditionError`` (missing condition),
                              both subclasses of ``sigma.exceptions.SigmaError``

pySigma is OPT-IN. Without it every function here degrades to a named error and
the rest of the server is unaffected. See requirements.txt for the pinned block.
Two behaviour notes worth knowing before trusting a converted query:

  1. ``|cidr`` becomes a literal Lucene term, not a network match. pySigma emits
     ``data.srcip:10.0.0.0\\/8``, which OpenSearch reads as the string
     "10.0.0.0/8". If the deployment needs real CIDR matching, the query needs a
     manual rewrite to a ``term``/``range`` clause on the correct IP field.
  2. ``|base64offset`` IS supported and expands to the three offset-encoded
     variants. It is not an unsupported modifier.

pySigma's diskcache-backed MITRE helpers (``sigma.data.mitre_attack``) only run
when attack-data enrichment is requested. Conversion does not touch them, and no
cache directory is created by parsing or converting.

NOTE: No ``from __future__ import annotations`` for consistency with the rest of
      the package (PEP 563 breaks @blueteam_tool type resolution downstream).
"""

import json
import logging
from typing import Any, Dict, List, Optional
from mcp_server.core.exceptions import BlueTeamMCPError

logger = logging.getLogger("blue_team_mcp.sigma.engine")

# Output format -> pySigma output_format. These are the four the OpenSearch
# backend actually advertises; anything else raises at the backend.
FORMATS: Dict[str, str] = {
    "lucene": "default",
    "dsl": "dsl_lucene",
    "monitor": "monitor_rule",
    "saved_search": "dashboards_ndjson",
}

# Community Sigma field name -> Wazuh alert field. A starting point, not a
# universal mapping: Wazuh decoder fields differ per integration (nginx, Zimbra,
# Suricata, Sysmon), so a deployment with unusual decoders should extend this.
# Plain renames only, no modifiers FieldMappingTransformation matches on the
# bare field name.
DEFAULT_FIELD_MAP: Dict[str, str] = {
    "CommandLine": "data.command",
    "Image": "data.win.eventdata.image",
    "ParentImage": "data.win.eventdata.parentImage",
    "OriginalFileName": "data.win.eventdata.originalFileName",
    "User": "data.win.eventdata.user",
    "EventID": "data.win.system.eventID",
    "SourceIp": "data.srcip",
    "DestinationIp": "data.dstip",
    "Url": "data.url",
    "UserAgent": "data.user_agent",
    "QueryName": "data.dns.question.name",
}

_cache: Dict[str, Any] = {}


def _retarget_saved_search(item: Any, index_pattern: str) -> bool:
    """Point a Dashboards saved search at ``index_pattern``. Returns True on success.
    Works around an upstream defect: ``finalize_query_kibana_ndjson`` in
    pySigma-backend-elasticsearch hardcodes ``index = "beats-*"`` instead of
    using the backend's ``index_names`` (elasticsearch_lucene.py:375, reached via
    the OpenSearch backend's ``dashboards_ndjson`` alias). The monitor format
    honours ``index_names``; this format does not. Without this rewrite every
    exported saved search silently targets the wrong index.
    Fails CLOSED in the sense that matters: if the upstream shape changes so the
    index cannot be read back, this logs a warning and returns False, and the
    caller surfaces ``index_retargeted=False``. The artifact is still returned,
    but it is flagged as targeting the wrong index rather than looking correct.
    """
    if not isinstance(item, dict):
        logger.warning("saved_search retarget skipped: item is not a dict (got %s)",
                       type(item).__name__)
        return False

    retargeted = False
    meta = (item.get("attributes") or {}).get("kibanaSavedObjectMeta")
    if isinstance(meta, dict) and isinstance(meta.get("searchSourceJSON"), str):
        try:
            inner = json.loads(meta["searchSourceJSON"])
        except json.JSONDecodeError as e:
            logger.warning(
                "saved_search retarget failed: searchSourceJSON is not JSON (%s). "
                "The emitted artifact may still target the pySigma default index.", e)
            inner = None
        if isinstance(inner, dict) and "index" in inner:
            inner["index"] = index_pattern
            meta["searchSourceJSON"] = json.dumps(inner)
            retargeted = True
        elif isinstance(inner, dict):
            # Shape changed: no 'index' key to rewrite. Do not invent one.
            logger.warning("saved_search retarget failed: searchSourceJSON has no "
                           "'index' key (keys=%s)", sorted(inner))
    else:
        logger.warning("saved_search retarget failed: kibanaSavedObjectMeta."
                       "searchSourceJSON missing or not a string")

    for ref in item.get("references") or []:
        if isinstance(ref, dict) and ref.get(
                "name") == "kibanaSavedObjectMeta.searchSourceJSON.index":
            ref["id"] = index_pattern
    return retargeted


class SigmaEngineUnavailable(BlueTeamMCPError):
    """Raised when pySigma is not installed but a conversion was requested."""


class SigmaConversionError(BlueTeamMCPError):
    """Raised when pySigma cannot parse or convert the supplied rule."""


def available() -> bool:
    """True when pySigma and the OpenSearch backend are importable."""
    return _load() is not None


def engine_versions() -> Dict[str, str]:
    """Installed pySigma / backend versions, or {} when unavailable."""
    loaded = _load()
    return dict(loaded["versions"]) if loaded else {}


def _load() -> Optional[Dict[str, Any]]:
    """Import and cache pySigma pieces. Returns None when not installed.
    Cached because ``InstalledSigmaPlugins.autodiscover()`` scans entry points,
    which is not free and must not run per call.
    """
    if _cache:
        return _cache
    try:
        from sigma.collection import SigmaCollection  # noqa: PLC0415
        from sigma.exceptions import SigmaError  # noqa: PLC0415
        from sigma.plugins import InstalledSigmaPlugins  # noqa: PLC0415
        from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline  # noqa: PLC0415
        from sigma.processing.transformations import FieldMappingTransformation  # noqa: PLC0415
    except ImportError as e:
        logger.info("pySigma not installed - Sigma conversion unavailable (%s)", e)
        return None

    plugins = InstalledSigmaPlugins.autodiscover()
    backend_cls = plugins.backends.get("opensearch_lucene")
    if backend_cls is None:
        logger.warning("pySigma installed but the opensearch_lucene backend is missing")
        return None

    versions: Dict[str, str] = {}
    try:
        from importlib.metadata import version  # noqa: PLC0415
        versions["pysigma"] = version("pysigma")
        versions["backend_opensearch"] = version("pysigma-backend-opensearch")
    except Exception:
        pass

    _cache.update({
        "SigmaCollection": SigmaCollection,
        "SigmaError": SigmaError,
        "ProcessingItem": ProcessingItem,
        "ProcessingPipeline": ProcessingPipeline,
        "FieldMappingTransformation": FieldMappingTransformation,
        "backend_cls": backend_cls,
        "versions": versions,
    })
    return _cache


def _require() -> Dict[str, Any]:
    loaded = _load()
    if loaded is None:
        raise SigmaEngineUnavailable(
            "pySigma is not installed. Install with: "
            "pip install 'pysigma>=1.5,<2' 'pySigma-backend-opensearch>=2,<3'"
        )
    return loaded


def field_names(rule_source: str) -> List[str]:
    """Bare field names referenced by a rule's detection block, in order.
    Read from the YAML rather than the parsed pySigma objects: the key format
    (``field|modifier``) is stable and this avoids depending on pySigma's
    internal detection object model. Nested detection mappings are walked.
    """
    import yaml  # noqa: PLC0415

    try:
        doc = yaml.safe_load(rule_source)
    except yaml.YAMLError as e:
        # Returning [] here is indistinguishable from "the rule references no
        # fields", which would silently skip the caller's unmapped-field check.
        # Log so the skip is visible rather than looking like a clean result.
        logger.warning(
            "field_names: rule source is not valid YAML (%s). Returning no fields; "
            "the unmapped-field check will not run for this rule.", e)
        return []
    docs = doc if isinstance(doc, list) else [doc]
    out: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "condition":
                    continue
                if isinstance(value, dict):
                    _walk(value)
                    continue
                bare = str(key).split("|")[0].strip()
                if bare and bare not in out:
                    out.append(bare)

    for d in docs:
        if isinstance(d, dict):
            _walk(d.get("detection") or {})
    return out


def convert(rule_source: str, output_format: str = "lucene",
            index_pattern: Optional[str] = None,
            monitor_interval: Optional[int] = None,
            field_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Convert Sigma YAML to an OpenSearch query or Dashboards artifact.
    Args:
        rule_source: Sigma YAML, one rule or a collection.
        output_format: key of :data:`FORMATS`: 'lucene', 'dsl', 'monitor',
            or 'saved_search'.
        index_pattern: index the artifact targets, e.g. 'wazuh-alerts-*'.
            Only used by the 'monitor' and 'saved_search' formats; pySigma
            otherwise hardcodes 'beats-*'.
        monitor_interval: minutes between monitor runs (monitor format).
        field_map: overrides :data:`DEFAULT_FIELD_MAP` entirely when provided.

    Returns:
        dict with queries (one entry per rule), output_format, index_pattern,
        fields (post-mapping field names), field_mapping, versions, errors.

    Raises:
        SigmaEngineUnavailable: pySigma or the backend is not installed.
        SigmaConversionError: pySigma rejected the rule or the format.
    """
    loaded = _require()
    if output_format not in FORMATS:
        raise SigmaConversionError(
            f"Unknown output_format {output_format!r}; choose from {sorted(FORMATS)}")

    fields = field_names(rule_source)
    mapping = dict(DEFAULT_FIELD_MAP if field_map is None else field_map)
    pipeline = loaded["ProcessingPipeline"](
        name="wazuh",
        items=[loaded["ProcessingItem"](
            loaded["FieldMappingTransformation"](mapping))],
    )
    kwargs: Dict[str, Any] = {"processing_pipeline": pipeline, "collect_errors": True}
    if index_pattern:
        kwargs["index_names"] = [index_pattern]
    if monitor_interval is not None:
        kwargs["monitor_interval"] = int(monitor_interval)

    rule_cls = loaded["SigmaCollection"]
    try:
        collection = rule_cls.from_yaml(rule_source)
    except loaded["SigmaError"] as e:
        raise SigmaConversionError(f"pySigma rejected the rule: {type(e).__name__}: {e}") from e

    backend = loaded["backend_cls"](**kwargs)
    try:
        raw = backend.convert(collection, output_format=FORMATS[output_format])
    except loaded["SigmaError"] as e:
        raise SigmaConversionError(
            f"Conversion to {output_format!r} failed: {type(e).__name__}: {e}") from e
    except (KeyError, TypeError, ValueError) as e:
        raise SigmaConversionError(
            f"Conversion to {output_format!r} failed: {type(e).__name__}: {e}") from e

    mapped_fields = [mapping.get(f, f) for f in fields]
    queries = raw if isinstance(raw, list) else [raw]
    effective_index = index_pattern or (kwargs.get("index_names") or ["beats-*"])[0]
    # True when every emitted artifact targets effective_index. For formats that
    # honour the backend index_names this holds by construction; saved_search
    # needs the upstream workaround and can fail, so it reports honestly.
    index_retargeted = True
    if output_format == "saved_search":
        index_retargeted = all(_retarget_saved_search(q, effective_index) for q in queries)
    return {
        "queries": queries,
        "output_format": output_format,
        "index_pattern": effective_index,
        "index_retargeted": index_retargeted,
        "fields": mapped_fields,
        "field_mapping": mapping,
        "versions": dict(loaded["versions"]),
        "errors": [str(e) for e in getattr(backend, "errors", [])],
    }


def parse_check(rule_source: str) -> tuple:
    """Parse ``rule_source`` with pySigma. Returns (ok, messages).
    ``ok=True`` with a note when pySigma is absent, so callers can report a
    schema-only result instead of failing.
    """
    loaded = _load()
    if loaded is None:
        return True, ["pySigma not installed schema check only"]
    try:
        rules = loaded["SigmaCollection"].from_yaml(rule_source)
        if not rules:
            return False, ["pySigma parsed zero rules from the source"]
        return True, []
    except loaded["SigmaError"] as e:
        return False, [f"pySigma rejected the rule: {type(e).__name__}: {str(e)[:300]}"]
    except Exception as e:
        return False, [f"pySigma parse failed: {type(e).__name__}: {str(e)[:300]}"]


class SigmaConversionError(BlueTeamMCPError):
    """Raised when pySigma cannot parse or convert the supplied rule."""


if __name__ == "__main__":
    # Self-check: the pure helpers hold without pySigma; the conversion path is
    # exercised only when the optional dependency is present.
    assert FORMATS["lucene"] == "default" and len(FORMATS) == 4
    assert DEFAULT_FIELD_MAP["Image"] == "data.win.eventdata.image"

    src = ("title: t\nlogsource:\n  product: wazuh\ndetection:\n"
           "  selection:\n    data.url|contains: x\n    data.srcip|cidr: 10.0.0.0/8\n"
           "  condition: selection\n")
    assert field_names(src) == ["data.url", "data.srcip"], field_names(src)
    assert field_names("garbage: [") == []
    nested = ("title: t\ndetection:\n  selection:\n    Image|endswith: cmd.exe\n"
              "  filter:\n    CommandLine|contains: x\n  condition: selection and not filter\n")
    assert field_names(nested) == ["Image", "CommandLine"], field_names(nested)

    if available():
        out = convert(src, output_format="lucene", index_pattern="wazuh-alerts-*")
        assert out["queries"] and isinstance(out["queries"][0], str), out
        assert out["index_pattern"] == "wazuh-alerts-*"
        assert out["fields"] == ["data.url", "data.srcip"]
        dsl = convert(src, output_format="dsl", index_pattern="wazuh-alerts-*")
        assert "query" in dsl["queries"][0], dsl
        mon = convert(src, output_format="monitor", index_pattern="wazuh-alerts-*",
                      monitor_interval=7)
        assert mon["queries"][0]["inputs"][0]["search"]["indices"] == ["wazuh-alerts-*"], mon
        assert mon["queries"][0]["schedule"]["period"]["interval"] == 7
        saved = convert(src, output_format="saved_search", index_pattern="wazuh-alerts-*")
        assert "beats-*" not in json.dumps(saved["queries"][0]), saved
        assert saved["index_retargeted"] is True, saved["index_retargeted"]
        inner = json.loads(saved["queries"][0]["attributes"]["kibanaSavedObjectMeta"
                                                       ]["searchSourceJSON"])
        assert inner["index"] == "wazuh-alerts-*", inner
        assert saved["queries"][0]["references"][0]["id"] == "wazuh-alerts-*"
        # A shape change in the upstream payload must report, not fail open.
        assert _retarget_saved_search({"attributes": {"kibanaSavedObjectMeta": {
            "searchSourceJSON": "not json"}}}, "wazuh-alerts-*") is False
        assert _retarget_saved_search({"attributes": {"kibanaSavedObjectMeta": {
            "searchSourceJSON": '{"filter": []}'}}}, "wazuh-alerts-*") is False
        assert _retarget_saved_search({"attributes": {}}, "wazuh-alerts-*") is False
        # No format may leak the pySigma default index into a Wazuh artifact.
        for fmt in FORMATS:
            got = convert(src, output_format=fmt, index_pattern="wazuh-alerts-*")
            assert "beats-*" not in json.dumps(got["queries"]), (fmt, got)
        ok, msgs = parse_check(src)
        assert ok and msgs == [], (ok, msgs)
        assert field_names("garbage: [") == []
        print("sigma engine self-check OK:", engine_versions(),
              "| lucene:", out["queries"][0])
    else:
        print("sigma engine self-check OK (pySigma absent, conversion path skipped.)")
