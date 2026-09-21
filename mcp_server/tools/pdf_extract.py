#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
PDF text + metadata extraction (pypdf), the zero dependency middle tier between
blueteam_markitdown_convert (opt-in, pdfminer) and blueteam_document_convert
(Marker, torch + OCR models).

References: https://github.com/py-pdf/pypdf

Design notes:
- Why this exists when MarkItDown already reads PDFs: MarkItDown is opt-in
  (BLUETEAM_INSTALL_MARKITDOWN=1) and Marker drags in torch. A default install
  otherwise has no lightweight PDF path at all. pypdf is pure-Python, no Pillow,
  no model download, and keeps the document metadata MarkItDown's markdown output
  discards.
- pypdf is imported on first call so server boot and tool registration never pay
  the import cost, and a missing install degrades to a typed BlueTeamMCPError
  naming the one-line fix.
- Text-only on purpose: `pypdf[image]` would pull Pillow, which is the exact
  package that fights marker's `pillow<11` pin in setup.sh. Image and annotation
  extraction are deliberately out of v1.
- Memory guard: decompressing a page's content stream is where pypdf blows up
  (a 300 MB uncompressed stream has been observed to need ~10 GB). Every page is
  size-checked via `len(page.get_contents().get_data())` before `extract_text()`
  and skipped with a reason instead of taking the process down. The 50 MB file cap
  is the outer bound; the per-page cap is the inner one.
- Extraction runs inside asyncio.to_thread: pypdf is synchronous CPU work and
  must not stall the event loop (shared breakers/keepalive).
- Input is a server-side PDF path validated by _validate_path against
  ALLOWED_PATH_PREFIXES, same trust boundary as blueteam_markitdown_convert.
  URLs are rejected at the schema level (path only).
- Output goes through the @blueteam_tool uniform boundary: audit -> catch
  BlueTeamMCPError -> PII redaction -> truncation at CHARACTER_LIMIT. For
  documents longer than the cap, request a page_range slice.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution. Same constraint as
      tools/rag_kb.py.
"""
import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.subprocess import _validate_path, ALLOWED_PATH_PREFIXES
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.tools.document_convert import _parse_page_range

_ALLOWED_EXT = (".pdf",)
_SIZE_CAP = 50 * 1024 * 1024  # 50 MB compressed. Same parser-attack ceiling as Marker/MarkItDown.
# Decompressed content-stream ceiling per page. A compressed PDF can expand far
# beyond its on-disk size; Marker and MarkItDown offer no hook to stop that, pypdf does.
_MAX_CONTENT_STREAM = 32 * 1024 * 1024

# pypdf import is cached process-wide. Module-global lock serialises first init only;
# PdfReader objects are per-call, so concurrent extractions share nothing mutable.
_PDFREADER: Any = None
_INIT_LOCK = threading.Lock()


class PdfExtractInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(
        ..., max_length=4096,
        description="Absolute path to the PDF (must be under BLUETEAM_ALLOWED_PATHS). "
                    "Local filesystem paths only URLs are rejected. Max 50 MB.",
    )
    page_range: Optional[str] = Field(
        default=None, max_length=64,
        description='1-indexed page selection, e.g. "1-5,7". Use for documents longer than the '
                    'response character cap so the tail is not truncated away.',
    )
    extraction_mode: Literal["plain", "layout"] = Field(
        default="plain",
        description="'plain' (default) or 'layout' (fixed-width, preserves rendered positioning - "
                    "better for advisories with tables). No extra dependency either way.",
    )
    include_metadata: bool = Field(
        default=True,
        description="Include document metadata (title, author, producer, creation date). "
                    "MarkItDown's markdown output drops these.",
    )
    output_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_redaction: bool = Field(
        default=False,
        description="When true, skip PII/credential redaction for audit investigations.",
    )


def _ensure_pypdf() -> None:
    """Import PdfReader exactly once.
    Raises BlueTeamMCPError with an actionable message when pypdf is absent or
    its own install is broken. Never a traceback.
    """
    global _PDFREADER
    if _PDFREADER is not None:
        return
    try:
        from pypdf import PdfReader
    except ImportError as e:
        import importlib.util
        try:
            present = importlib.util.find_spec("pypdf") is not None
        except (ImportError, ValueError):
            present = False
        if present:
            raise BlueTeamMCPError(
                f"pypdf import failed: {type(e).__name__}: {e}. The package is present "
                "but an internal import broke. Run in the server venv: "
                "pip install --force-reinstall pypdf"
            ) from e
        raise BlueTeamMCPError(
            "pypdf is not installed. Install it into the server venv: pip install pypdf"
        ) from e
    _PDFREADER = PdfReader


def _pypdf_error(e: Exception, *, stage: str) -> BlueTeamMCPError:
    """Wrap pypdf failures as typed errors with an actionable hint."""
    msg = f"pypdf {stage} failed: {type(e).__name__}: {e}"
    lowered = str(e).lower()
    if "encrypted" in lowered or "decrypt" in lowered:
        msg += (
            " Encrypted PDFs open with an empty password only; for a password protected "
            "document, decrypt it on the host first."
        )
    if "stream" in lowered or "corrupt" in lowered or "damaged" in lowered:
        msg += (
            " The file may be malformed. blueteam_document_convert (Marker) is more "
            "tolerant of damaged PDFs."
        )
    return BlueTeamMCPError(msg)


def _open_reader(path: str) -> Any:
    """Open a PdfReader (non-strict) and clear empty-password encryption.
    strict=False on purpose: SOC evidence PDFs are frequently produced by broken
    generators, and strict mode turns recoverable damage into a hard failure.
    """
    PdfReader = _PDFREADER
    try:
        reader = PdfReader(path, strict=False)
    except Exception as e:
        raise _pypdf_error(e, stage="parse") from e
    # decrypt() raises PdfReadError("Not encrypted file") on an unencrypted PDF,
    # so it must never be called unconditionally.
    if getattr(reader, "is_encrypted", False):
        try:
            if not reader.decrypt(""):
                raise BlueTeamMCPError(
                    "PDF is encrypted and does not open with an empty password. "
                    "Decrypt it on the host first."
                )
        except BlueTeamMCPError:
            raise
        except Exception as e:
            raise _pypdf_error(e, stage="decrypt") from e
    return reader


def _read_metadata(reader: Any) -> dict:
    """Normalise the /Info dictionary to {title, author, ...}. Never raises."""
    meta: dict = {}
    try:
        info = reader.metadata
    except Exception:
        return meta
    if info is None:
        return meta
    try:
        for key, val in info.items():
            if val is not None:
                meta[str(key).lstrip("/").lower()] = str(val)
    except Exception:
        return meta
    return meta


def _extract_sync(path: str, pages: Optional[list[int]], mode: str,
                  include_metadata: bool) -> dict:
    """Synchronous pypdf pipeline, run inside asyncio.to_thread only.
    ``pages`` is the 0-indexed list from _parse_page_range (shared contract with
    document_convert.py); None means every page.
    Returns a payload dict:
        {file, page_count, pages: [{page, chars, text}], skipped: [{page, reason}],
         metadata: {...}, encrypted: bool, chars: int}
    Raises BlueTeamMCPError when no page yields text.
    """
    with _INIT_LOCK:
        _ensure_pypdf()
    reader = _open_reader(path)
    try:
        page_count = len(reader.pages)
    except Exception as e:
        raise _pypdf_error(e, stage="page listing") from e

    if pages:
        indices = [i for i in pages if 0 <= i < page_count]
        out_of_range = [
            {"page": i + 1, "reason": f"beyond page_count ({page_count})"}
            for i in pages if not (0 <= i < page_count)
        ]
    else:
        indices = list(range(page_count))
        out_of_range = []

    extracted: list[dict] = []
    skipped: list[dict] = list(out_of_range)
    total_chars = 0

    for idx in indices:
        try:
            page = reader.pages[idx]
        except Exception as e:
            skipped.append({"page": idx + 1, "reason": f"page load failed: {type(e).__name__}"})
            continue
        # Memory guard first: decompression is the expensive step, not extract_text().
        try:
            contents = page.get_contents()
        except Exception as e:
            skipped.append({"page": idx + 1, "reason": f"content stream unreadable: {type(e).__name__}"})
            continue
        if contents is None:
            skipped.append({"page": idx + 1, "reason": "no content stream"})
            continue
        try:
            stream_len = len(contents.get_data())
        except Exception as e:
            skipped.append({"page": idx + 1, "reason": f"content stream decode failed: {type(e).__name__}"})
            continue
        if stream_len > _MAX_CONTENT_STREAM:
            skipped.append({
                "page": idx + 1,
                "reason": f"content stream {stream_len} B exceeds the "
                          f"{_MAX_CONTENT_STREAM} B per-page cap",
            })
            continue

        try:
            text = page.extract_text(extraction_mode=mode) or ""
        except Exception as e:
            skipped.append({"page": idx + 1, "reason": f"text extraction failed: {type(e).__name__}"})
            continue

        if text.strip():
            extracted.append({"page": idx + 1, "chars": len(text), "text": text})
            total_chars += len(text)

    if not extracted:
        detail = skipped[0]["reason"] if skipped else "all pages were empty"
        raise BlueTeamMCPError(
            f"No extractable text in {Path(path).name} ({detail}). If this is a scanned or "
            "image-only PDF, use blueteam_document_convert (Marker OCR) instead; pypdf reads "
            "digital text layers only."
        )

    return {
        "file": Path(path).name,
        "page_count": page_count,
        "pages": extracted,
        "skipped": skipped,
        "metadata": _read_metadata(reader) if include_metadata else {},
        "encrypted": bool(getattr(reader, "is_encrypted", False)),
        "chars": total_chars,
    }


def _render_markdown(payload: dict) -> str:
    """Render an extraction payload as markdown with per-page headers."""
    lines = [
        f"# PDF Extract - `{payload['file']}`",
        "",
        f"**Pages**: {payload['page_count']} | **Extracted**: {len(payload['pages'])} | "
        f"**Skipped**: {len(payload['skipped'])} | **Chars**: {payload['chars']} | "
        f"**Encrypted**: {'yes' if payload['encrypted'] else 'no'}",
        "",
    ]
    meta = payload.get("metadata") or {}
    if meta:
        lines.append("## Metadata")
        for key in sorted(meta):
            lines.append(f"- **{key}**: {meta[key]}")
        lines.append("")
    for page in payload["pages"]:
        lines.append(f"## Page {page['page']}")
        lines.append(page["text"].strip())
        lines.append("")
    if payload["skipped"]:
        lines.append("## Skipped pages")
        for entry in payload["skipped"]:
            lines.append(f"- Page {entry['page']}: {entry['reason']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render(payload: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _render_markdown(payload)


def _prepare(params: PdfExtractInput) -> tuple[Optional[str], Optional[dict]]:
    """Validate params; return (error_json, None) or (None, prep_dict).
    Kept synchronous/plain so the validation surface is unit-testable without
    pypdf and without an event loop.
    """
    # URL schemes are rejected before generic path validation: a URL like
    # https://host/advisory.pdf otherwise resolves as an odd relative path.
    if "://" in params.path:
        return json.dumps(
            {"error": "URLs are not accepted, provide a local filesystem path under BLUETEAM_ALLOWED_PATHS."}
        ), None
    ok, err = _validate_path(params.path, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}"}), None
    p = Path(params.path)
    if p.suffix.lower() not in _ALLOWED_EXT:
        return json.dumps(
            {"error": f"Unsupported file type '{p.suffix}'. Only PDF is supported."}
        ), None
    if not p.exists():
        return json.dumps({"error": f"File not found: {params.path}"}), None
    if not p.is_file():
        return json.dumps({"error": f"Not a regular file: {params.path}"}), None
    try:
        if p.stat().st_size > _SIZE_CAP:
            return json.dumps(
                {"error": f"File exceeds the {_SIZE_CAP // (1024 * 1024)} MB size cap."}
            ), None
    except OSError as e:
        return json.dumps({"error": f"Cannot stat file: {e}"}), None

    pages, perr = _parse_page_range(params.page_range)
    if perr is not None:
        return json.dumps({"error": perr}), None

    return None, {
        "path": str(p),
        "pages": pages,
        "mode": params.extraction_mode.strip().lower(),
        "include_metadata": params.include_metadata,
    }


@blueteam_tool(
    name="blueteam_pdf_extract",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_pdf_extract(params: PdfExtractInput) -> str:
    """Extract text and metadata from a PDF using pypdf (pure-Python, no torch,
    no model download, no OCR). The lightweight tier between
    blueteam_markitdown_convert (opt-in) and blueteam_document_convert (Marker,
    heavy): works on a default install, keeps the /Info metadata MarkItDown
    discards, and skips individual oversized pages instead of running the host
    out of memory.

    Digital text layers only. Scanned / image-only PDFs return an error pointing
    at blueteam_document_convert (Marker OCR). For ingesting a whole PDF into the
    RAG corpus without routing the text through this response, use
    blueteam_rag_ingest(source="pdf", path=...) instead.

    Args:
        params.path: Absolute path to the PDF (must be under
            BLUETEAM_ALLOWED_PATHS, default /var:/etc:/home:/opt:/usr). Local
            filesystem paths only; URLs are rejected. Max 50 MB.
        params.page_range: 1-indexed pages, e.g. '1-5,7'. Use for documents whose
            full text would exceed the response character cap - the tail would
            otherwise be truncated.
        params.extraction_mode: 'plain' (default) or 'layout' (fixed-width,
            preserves rendered positioning - better on advisories with tables).
        params.include_metadata: Include title/author/producer/creationdate
            (default true).
        params.output_format: 'markdown' (default) or 'json'.
        params.bypass_redaction: When true, skip PII/credential redaction for
            audit investigations.

    Returns:
        str: markdown with a per-page header and a Metadata section, or the raw
        extraction payload as JSON. Pages whose decompressed content stream
        exceeds 32 MB are listed under "Skipped pages" rather than failing the
        call. Output is PII-redacted by default and truncated at the server
        character cap (BLUETEAM_CHARACTER_LIMIT, default 100000) with a cursor
        hint.

    Examples:
        1. Extract a digital vendor advisory (defaults):
           blueteam_pdf_extract(path="/opt/advisories/fortinet-jan.pdf")
        2. Structured output for a downstream pipeline, metadata included:
           blueteam_pdf_extract(path="/opt/advisories/cisa-aa24.pdf",
                                output_format="json")
        3. A table-heavy advisory where reading order matters:
           blueteam_pdf_extract(path="/opt/reports/cve-summary.pdf",
                                extraction_mode="layout")
        4. First 5 pages of a long report, redaction skipped for evidence:
           blueteam_pdf_extract(path="/opt/cases/case-4711/report.pdf",
                                page_range="1-5", bypass_redaction=True)

    Permissions/access: server-side filesystem read under
    BLUETEAM_ALLOWED_PATHS. No API key. Does not touch the Wazuh Indexer or
    Manager API.

    Resource notes: no rate limit (local extraction). pypdf is imported lazily on
    the first call. Encrypted PDFs open with an empty password only. Memory is
    bounded per page at 32 MB decompressed; a page over that is skipped, never
    parsed. Missing install returns a typed BlueTeamMCPError, never a traceback.
    """
    err, prep = _prepare(params)
    if err is not None:
        return err
    # pypdf is synchronous CPU work, run off the event loop so shared circuit
    # breakers and the keepalive timer never stall.
    payload = await asyncio.to_thread(
        _extract_sync, prep["path"], prep["pages"], prep["mode"], prep["include_metadata"]
    )
    return _render(payload, params.output_format)
