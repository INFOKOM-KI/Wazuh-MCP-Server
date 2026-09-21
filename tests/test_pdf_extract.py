#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for blueteam_pdf_extract (pypdf integration) and the source="pdf" branch of
blueteam_rag_ingest.
pypdf is not required for the validation surface: _prepare, _render_markdown and
_render are pure and are tested without it. The real-pypdf tests build a tiny
one-page PDF with PdfWriter (a Helvetica /F1 resource plus a BT/Tj content
stream) so text extraction is exercised end to end, and skip cleanly when pypdf
is absent.
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
    from mcp_server.tools import pdf_extract

    return pdf_extract


def _input(**over):
    pe = _module()
    base = {"path": "/opt/advisories/advisory.pdf"}
    base.update(over)
    return pe.PdfExtractInput(**base)


def _write_text_pdf(tmp_path, text="Hello Wazuh Advisory 2026", name="advisory.pdf",
                    title="Probe Advisory"):
    """Build a real one-page PDF with a text layer. Returns the path."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(200, 200)
    font = DictionaryObject()
    font.update({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    })
    page[NameObject("/Resources")][NameObject("/Font")] = DictionaryObject(
        {NameObject("/F1"): writer._add_object(font)}
    )
    content = DecodedStreamObject()
    content.set_data(f"BT /F1 18 Tf 20 100 Td ({text}) Tj ET\n".encode("latin-1"))
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.add_metadata({"/Title": title, "/Author": "TangerangKota-CSIRT"})

    path = tmp_path / name
    with open(path, "wb") as fh:
        writer.write(fh)
    return path


def _write_oversized_stream_pdf(tmp_path, stream_len, name="big.pdf"):
    """One page whose decompressed content stream is ``stream_len`` bytes."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(200, 200)
    content = DecodedStreamObject()
    content.set_data(b" " * stream_len)
    page[NameObject("/Contents")] = writer._add_object(content)
    path = tmp_path / name
    with open(path, "wb") as fh:
        writer.write(fh)
    return path


# _prepare validation (no pypdf needed)
def test_prepare_rejects_url():
    pe = _module()
    err, prep = pe._prepare(_input(path="https://evil.example/advisory.pdf"))
    assert prep is None
    assert "URLs are not accepted" in err


def test_prepare_rejects_path_outside_allowlist():
    pe = _module()
    err, prep = pe._prepare(_input(path="/tmp/escape.pdf"))
    assert prep is None
    assert "Path not allowed" in err


def test_prepare_rejects_non_pdf_extension():
    pe = _module()
    err, prep = pe._prepare(_input(path="/opt/advisories/advisory.docx"))
    assert prep is None
    assert "Only PDF is supported" in err


def test_prepare_rejects_missing_file():
    pe = _module()
    err, prep = pe._prepare(_input(path="/opt/advisories/does_not_exist_12345.pdf"))
    assert prep is None
    assert "File not found" in err


def test_prepare_rejects_oversized_file(tmp_path, monkeypatch):
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "huge.pdf"
    with open(pdf, "wb") as fh:
        fh.truncate(pe._SIZE_CAP + 1)

    err, prep = pe._prepare(pe.PdfExtractInput(path=str(pdf)))
    assert prep is None
    assert "size cap" in err


def test_prepare_accepts_pdf_and_parses_page_range(tmp_path, monkeypatch):
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "advisory.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    err, prep = pe._prepare(pe.PdfExtractInput(path=str(pdf), page_range="2-3,5"))
    assert err is None
    assert prep["pages"] == [1, 2, 4]  # 1-indexed in, 0-indexed out (shared with document_convert)
    assert prep["mode"] == "plain"
    assert prep["include_metadata"] is True


def test_prepare_rejects_bad_page_range(tmp_path, monkeypatch):
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pdf = tmp_path / "advisory.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    err, prep = pe._prepare(pe.PdfExtractInput(path=str(pdf), page_range="bogus"))
    assert prep is None
    assert "page_range" in err


def test_input_model_rejects_bogus_extraction_mode():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        _input(extraction_mode="ocr")


# Rendering is pure - no pypdf needed
def _payload(**over):
    base = {
        "file": "advisory.pdf",
        "page_count": 3,
        "pages": [
            {"page": 1, "chars": 11, "text": "Page one text"},
            {"page": 3, "chars": 13, "text": "Page three text"},
        ],
        "skipped": [{"page": 2, "reason": "no content stream"}],
        "metadata": {"title": "Probe Advisory", "author": "TangerangKota-CSIRT"},
        "encrypted": False,
        "chars": 24,
    }
    base.update(over)
    return base


def test_render_markdown_has_page_headers_metadata_and_skips():
    pe = _module()
    out = pe._render_markdown(_payload())
    assert "## Page 1" in out
    assert "## Page 3" in out
    assert "Page one text" in out
    assert "**title**: Probe Advisory" in out
    assert "Page 2: no content stream" in out
    assert "**Skipped**: 1" in out


def test_render_json_round_trips_the_payload():
    pe = _module()
    out = pe._render(_payload(), "json")
    parsed = json.loads(out)
    assert parsed["page_count"] == 3
    assert parsed["metadata"]["author"] == "TangerangKota-CSIRT"
    assert parsed["skipped"][0]["page"] == 2


def test_render_markdown_omits_metadata_section_when_absent():
    pe = _module()
    out = pe._render_markdown(_payload(metadata={}))
    assert "## Metadata" not in out


@pytest.mark.asyncio
async def test_tool_degrades_to_typed_error_when_pypdf_missing(tmp_path, monkeypatch):
    """Mirrors tests/test_markitdown_convert.py: absent dependency -> typed error,
    never a traceback and never a success payload carrying error text."""
    if _pypdf_present():
        pytest.skip("pypdf is installed; covered by test_ensure_pypdf_missing_install_message")
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    pe._PDFREADER = None
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    from mcp_server.core.exceptions import BlueTeamMCPError

    with pytest.raises(BlueTeamMCPError):
        await pe.blueteam_pdf_extract(pe.PdfExtractInput(path=str(pdf)))


def test_ensure_pypdf_missing_install_message(monkeypatch):
    """Poisoning sys.modules makes the import raise ImportError regardless of
    whether pypdf is installed, so the actionable message is always covered."""
    import sys

    pe = _module()
    monkeypatch.setattr(pe, "_PDFREADER", None)
    monkeypatch.setitem(sys.modules, "pypdf", None)

    from mcp_server.core.exceptions import BlueTeamMCPError

    with pytest.raises(BlueTeamMCPError) as exc:
        pe._ensure_pypdf()
    assert "pip install pypdf" in str(exc.value)


def _pypdf_present() -> bool:
    import importlib.util
    return importlib.util.find_spec("pypdf") is not None


@pytest.mark.asyncio
async def test_tool_happy_path_returns_markdown(tmp_path, monkeypatch):
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    seen = []

    def _fake_extract(path, pages, mode, include_metadata):
        seen.append((path, pages, mode, include_metadata))
        return _payload()

    monkeypatch.setattr(pe, "_extract_sync", _fake_extract)
    pdf = tmp_path / "advisory.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    out = await pe.blueteam_pdf_extract(pe.PdfExtractInput(path=str(pdf)))
    assert "## Page 1" in out
    assert seen == [(str(pdf), None, "plain", True)]


@pytest.mark.asyncio
async def test_tool_page_range_reaches_the_extractor(tmp_path, monkeypatch):
    pe = _module()
    monkeypatch.setattr(pe, "ALLOWED_PATH_PREFIXES", [str(tmp_path)])
    seen = []
    monkeypatch.setattr(
        pe, "_extract_sync",
        lambda path, pages, mode, md: (seen.append(pages), _payload())[1],
    )
    pdf = tmp_path / "advisory.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")

    await pe.blueteam_pdf_extract(pe.PdfExtractInput(path=str(pdf), page_range="2-3"))
    assert seen == [[1, 2]]


@pytest.mark.asyncio
async def test_tool_rejects_url_before_touching_the_filesystem():
    pe = _module()
    out = await pe.blueteam_pdf_extract(pe.PdfExtractInput(path="https://x.example/a.pdf"))
    assert "URLs are not accepted" in out


def test_extract_sync_reads_real_text_and_metadata(tmp_path):
    pytest.importorskip("pypdf")
    pe = _module()
    pdf = _write_text_pdf(tmp_path)

    payload = pe._extract_sync(str(pdf), None, "plain", True)
    assert payload["page_count"] == 1
    assert payload["pages"][0]["text"] == "Hello Wazuh Advisory 2026"
    assert payload["pages"][0]["page"] == 1
    assert payload["metadata"]["title"] == "Probe Advisory"
    assert payload["skipped"] == []
    assert payload["encrypted"] is False
    assert payload["chars"] == len("Hello Wazuh Advisory 2026")


def test_extract_sync_layout_mode_reads_real_text(tmp_path):
    pytest.importorskip("pypdf")
    pe = _module()
    pdf = _write_text_pdf(tmp_path, name="layout.pdf")

    payload = pe._extract_sync(str(pdf), None, "layout", False)
    assert "Hello Wazuh Advisory 2026" in payload["pages"][0]["text"]
    assert payload["metadata"] == {}  # include_metadata=False


def test_extract_sync_page_range_selects_pages(tmp_path):
    pytest.importorskip("pypdf")
    pe = _module()
    pdf = _write_text_pdf(tmp_path, name="paged.pdf")

    assert pe._extract_sync(str(pdf), [0], "plain", False)["pages"][0]["page"] == 1
    # An out-of-range index is skipped with a reason, not a crash.
    from mcp_server.core.exceptions import BlueTeamMCPError
    with pytest.raises(BlueTeamMCPError) as exc:
        pe._extract_sync(str(pdf), [9], "plain", False)
    assert "beyond page_count" in str(exc.value)


def test_extract_sync_skips_oversized_content_stream(tmp_path, monkeypatch):
    """The OOM guard: a page whose decompressed stream exceeds the cap is skipped
    with a reason instead of being parsed."""
    pytest.importorskip("pypdf")
    pe = _module()
    monkeypatch.setattr(pe, "_MAX_CONTENT_STREAM", 16)
    pdf = _write_oversized_stream_pdf(tmp_path, stream_len=1024)

    from mcp_server.core.exceptions import BlueTeamMCPError
    with pytest.raises(BlueTeamMCPError) as exc:
        pe._extract_sync(str(pdf), None, "plain", False)
    assert "per-page cap" in str(exc.value)


def test_extract_sync_blank_page_errors_towards_marker(tmp_path):
    pytest.importorskip("pypdf")
    pe = _module()
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    pdf = tmp_path / "blank.pdf"
    with open(pdf, "wb") as fh:
        writer.write(fh)

    from mcp_server.core.exceptions import BlueTeamMCPError
    with pytest.raises(BlueTeamMCPError) as exc:
        pe._extract_sync(str(pdf), None, "plain", False)
    assert "blueteam_document_convert" in str(exc.value)


def test_extract_sync_typed_error_for_non_pdf_bytes(tmp_path):
    pe = _module()
    if not _pypdf_present():
        pytest.skip("pypdf is installed only in some environments")
    pe._PDFREADER = None
    pdf = tmp_path / "junk.pdf"
    pdf.write_bytes(b"not a pdf at all")

    from mcp_server.core.exceptions import BlueTeamMCPError
    with pytest.raises(BlueTeamMCPError):
        pe._extract_sync(str(pdf), None, "plain", False)
