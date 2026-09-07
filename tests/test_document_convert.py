#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for blueteam_document_convert (Marker integration).
Marker itself is not required for these tests: the validation surface
(_parse_page_range, _prepare) is pure, and the happy path monkeypatches
_convert_sync so no torch/model download ever happens in CI.
"""
from __future__ import annotations
import json
import os
import pytest

# Env must be set before mcp_server is imported (module import inside tests).
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
os.environ.setdefault("WAZUH_API_URL", "https://manager:55000")
os.environ.setdefault("WAZUH_API_PASSWORD", "test-manager-pass")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")
os.environ.setdefault("BLUETEAM_ALLOWED_PATHS", "/var:/etc:/home:/opt:/usr")


def _module():
    from mcp_server.tools import document_convert

    return document_convert


def _input(**over):
    dc = _module()
    base = {"path": "/opt/playbooks/runbook.pdf"}
    base.update(over)
    return dc.DocumentConvertInput(**base)


# page_range parsing
def test_parse_page_range_single_and_range():
    dc = _module()
    pages, err = dc._parse_page_range("1-3,5")
    assert err is None
    assert pages == [0, 1, 2, 4]  # 1-indexed in, 0-indexed out for Marker


def test_parse_page_range_empty_and_none():
    dc = _module()
    assert dc._parse_page_range(None) == (None, None)
    assert dc._parse_page_range("  ") == (None, None)


def test_parse_page_range_rejects_bad_tokens():
    dc = _module()
    for bad in ("abc", "1-x", "0", "-3", "1-", "2-1", "1,,2", "1,  ,2"):
        pages, err = dc._parse_page_range(bad)
        assert pages is None, f"expected rejection for '{bad}'"
        assert err is not None


# _prepare validation (no Marker needed)
def test_prepare_rejects_path_outside_allowlist():
    dc = _module()
    err, prep = dc._prepare(_input(path="/tmp/escape.pdf"))
    assert prep is None
    assert "Path not allowed" in err


def test_prepare_rejects_non_pdf_extension():
    dc = _module()
    err, prep = dc._prepare(_input(path="/opt/playbooks/runbook.txt"))
    assert prep is None
    assert "Only PDF is supported" in err


def test_prepare_rejects_missing_file():
    dc = _module()
    err, prep = dc._prepare(_input(path="/opt/playbooks/does_not_exist_12345.pdf"))
    assert prep is None
    assert "File not found" in err


def test_prepare_accepts_pdf_and_parses_page_range(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "runbook.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    err, prep = dc._prepare(
        dc.DocumentConvertInput(path=str(pdf), page_range="2-3")
    )
    assert err is None
    assert prep["mode"] == "pdf"
    assert prep["fmt"] == "markdown"
    assert prep["pages"] == [1, 2]


def test_prepare_table_mode_forces_json(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "tables.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    err, prep = dc._prepare(
        dc.DocumentConvertInput(path=str(pdf), mode="table", output_format="markdown")
    )
    assert err is None
    assert prep["fmt"] == "json"


def test_prepare_rejects_oversized_file(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "huge.pdf"
    with open(pdf, "wb") as f:
        f.truncate(dc._SIZE_CAP + 1)

    err, prep = dc._prepare(_input(path=str(pdf)))
    assert prep is None
    assert "size cap" in err


def test_input_model_rejects_bogus_mode_like_llm_hallucination():
    # Mirrors the guardrail that rejected mode='full' on the aggregate tool.
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        _input(mode="full")

def test_parse_page_range_invalid_returns_error_json(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    err, prep = dc._prepare(dc.DocumentConvertInput(path=str(pdf), page_range="bogus"))
    assert prep is None
    assert "page_range" in err


# happy path via decorated tool with patched converter
@pytest.mark.asyncio
async def test_convert_happy_path_returns_markdown(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    monkeypatch.setattr(
        dc, "_convert_sync",
        lambda path, mode, fmt, pages: f"# SOC playbook\nconverted {mode}/{fmt} pages={pages}",
    )
    pdf = tmp_path / "runbook.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    out = await dc.blueteam_document_convert(
        dc.DocumentConvertInput(path=str(pdf))
    )
    assert "SOC playbook" in out
    assert "converted pdf/markdown pages=None" in out


@pytest.mark.asyncio
async def test_convert_surface_blue_team_error_when_marker_missing(tmp_path, monkeypatch):
    dc = _module()
    monkeypatch.setattr(dc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    # _convert_sync not patched: marker is not installed in CI, so the real
    # path must degrade to a typed BlueTeamMCPError response, never a traceback.
    from mcp_server.core.exceptions import BlueTeamMCPError

    out = await dc.blueteam_document_convert(dc.DocumentConvertInput(path=str(pdf)))
    parsed = json.loads(out)
    assert "error" in parsed
    assert parsed.get("type") == BlueTeamMCPError.__name__
