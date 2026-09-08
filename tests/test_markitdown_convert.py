#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for blueteam_markitdown_convert (MarkItDown integration).
MarkItDown itself is not required for these tests: the validation surface
(_prepare) is pure, and the happy path 'monkeypatches' _convert_sync so no
markitdown import ever happens in CI.
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
    from mcp_server.tools import markitdown_convert

    return markitdown_convert


def _input(**over):
    mc = _module()
    base = {"path": "/opt/evidence/advisory.docx"}
    base.update(over)
    return mc.FileToMarkdownInput(**base)


# _prepare validation (no MarkItDown needed)
def test_prepare_rejects_path_outside_allowlist():
    mc = _module()
    err, prep = mc._prepare(_input(path="/tmp/escape.docx"))
    assert prep is None
    assert "Path not allowed" in err


def test_prepare_rejects_path_traversal():
    mc = _module()
    err, prep = mc._prepare(_input(path="/opt/evidence/../../etc/passwd"))
    assert prep is None
    assert "Path not allowed" in err or "traversal" in err


def test_prepare_rejects_unsupported_extensions():
    mc = _module()
    for bad in (".zip", ".epub", ".exe", ".txt", ".eml"):
        err, prep = mc._prepare(_input(path=f"/opt/evidence/file{bad}"))
        assert prep is None, f"expected rejection for '{bad}'"
        assert "Unsupported file type" in err


def test_prepare_rejects_missing_file():
    mc = _module()
    err, prep = mc._prepare(_input(path="/opt/evidence/does_not_exist_12345.docx"))
    assert prep is None
    assert "File not found" in err


def test_prepare_rejects_oversized_file(tmp_path, monkeypatch):
    mc = _module()
    monkeypatch.setattr(mc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    big = tmp_path / "huge.xlsx"
    with open(big, "wb") as f:
        f.truncate(mc._SIZE_CAP + 1)

    err, prep = mc._prepare(_input(path=str(big)))
    assert prep is None
    assert "size cap" in err


def test_prepare_accepts_local_file(tmp_path, monkeypatch):
    mc = _module()
    monkeypatch.setattr(mc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    f = tmp_path / "advisory.docx"
    f.write_bytes(b"PK\x03\x04 fake docx")

    err, prep = mc._prepare(mc.FileToMarkdownInput(path=str(f)))
    assert err is None
    assert prep == {"path": str(f)}


def test_prepare_rejects_url_input_like_llm_hallucination():
    # URLs must never reach MarkItDown's own fetcher (SSRF guard).
    err, prep = _module()._prepare(_input(path="https://evil.example/x.docx"))
    assert prep is None
    assert "URLs are not accepted" in err


def test_input_model_rejects_extra_fields():
    # Mirrors the guardrail that rejects bogus params on other tools.
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        _input(output_format="json")  # markitdown emits markdown only


# via decorated tool with patched converter
@pytest.mark.asyncio
async def test_convert_happy_path_returns_markdown(tmp_path, monkeypatch):
    mc = _module()
    monkeypatch.setattr(mc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    seen: list[str] = []

    def _fake_convert(path: str) -> str:
        seen.append(path)
        return "# SOC advisory\nconverted"

    monkeypatch.setattr(mc, "_convert_sync", _fake_convert)
    f = tmp_path / "advisory.docx"
    f.write_bytes(b"PK\x03\x04 fake docx")

    out = await mc.blueteam_markitdown_convert(
        mc.FileToMarkdownInput(path=str(f))
    )
    assert "SOC advisory" in out
    assert seen == [str(f)]  # the validated path reached the converter


@pytest.mark.asyncio
async def test_convert_surface_blue_team_error_when_markitdown_missing(tmp_path, monkeypatch):
    mc = _module()
    monkeypatch.setattr(mc, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    f = tmp_path / "r.pdf"
    f.write_bytes(b"%PDF-1.4 fake")

    # _convert_sync not patched: markitdown is not installed in CI, so the real
    # path must degrade to a typed BlueTeamMCPError response, never a traceback.
    from mcp_server.core.exceptions import BlueTeamMCPError

    out = await mc.blueteam_markitdown_convert(mc.FileToMarkdownInput(path=str(f)))
    parsed = json.loads(out)
    assert "error" in parsed
    assert parsed.get("type") == BlueTeamMCPError.__name__
