#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Document conversion (MarkItDown): office / data files to Markdown for LLM
analysis. Sibling of blueteam_document_convert (Marker, PDF/OCR-focused).

References: https://github.com/microsoft/markitdown

Design notes:
- MarkItDown is imported on first call so server boot and tool registration
  never pay the import cost. A bare MarkItDown() is constructed deliberately:
  plugins and LLM clients stay disabled, so conversion never makes a network
  call and never sends document content to a third party.
- Digital (text-layer) PDFs, DOCX/PPTX/XLSX/XLS, Outlook .msg, HTML and
  CSV/JSON/XML convert locally and fast. Scanned / image-only PDFs yield no
  text here - route those to blueteam_document_convert (Marker OCR).
- Conversion runs inside asyncio.to_thread: MarkItDown is synchronous work and
  must not stall the event loop (shared breakers/keepalive).
- Input is a server-side path validated by _validate_path against
  ALLOWED_PATH_PREFIXES, same trust boundary as blueteam_document_convert and
  blueteam_hash_file. URL input is rejected at the schema level (path only).
- Output goes through the @blueteam_tool uniform boundary: audit -> catch
  BlueTeamMCPError -> PII redaction (params.bypass_redaction skips optional
  layers) -> truncation at CHARACTER_LIMIT.
"""
import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.subprocess import _validate_path, ALLOWED_PATH_PREFIXES
from mcp_server.core.tool_decorator import blueteam_tool

# Local formats only. .zip (member expansion bomb surface) and .epub
# (dependency home unverified) are held out of v1, see design notes.
_ALLOWED_EXT = (
    ".pdf", ".docx", ".pptx", ".xlsx", ".xls", ".msg",
    ".html", ".htm", ".csv", ".json", ".xml",
)
_SIZE_CAP = 50 * 1024 * 1024  # 50 MB same parser-attack ceiling as Marker.

# Bare singleton, no plugins, no llm_client, no network egress.
# Module-global lock serialises first init only; concurrent conversions share
# the instance (MarkItDown keeps per-call converter state, not per-conversion
# mutable globals, so a single instance is safe).
_MD: Any = None
_INIT_LOCK = threading.Lock()


class FileToMarkdownInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(
        ..., max_length=4096,
        description=(
            "Absolute path to the file to convert (must be under "
            "BLUETEAM_ALLOWED_PATHS). Local filesystem paths only - URLs are "
            "rejected."
        ),
    )
    bypass_redaction: bool = Field(
        default=False,
        description="When true, skip PII/credential redaction for audit investigations.",
    )


def _ensure_markitdown() -> None:
    """Import MarkItDown and build the bare singleton exactly once.
    Raises BlueTeamMCPError with an actionable message when markitdown is not
    installed or an optional extra is missing.
    """
    global _MD
    if _MD is not None:
        return
    try:
        from markitdown import MarkItDown
    except ImportError as e:
        import importlib.util
        if importlib.util.find_spec("markitdown") is not None:
            raise BlueTeamMCPError(
                f"MarkItDown import failed: {type(e).__name__}: {e}. The package "
                "is present but a dependency import broke (usually a missing "
                "optional extra for the file type). Run in the server venv: "
                'pip install "markitdown[pdf,docx,pptx,xlsx,xls,outlook]"'
            ) from e
        raise BlueTeamMCPError(
            "MarkItDown is not installed. Install it into the server venv "
            "(see setup.sh BLUETEAM_INSTALL_MARKITDOWN=1): "
            'pip install "markitdown[pdf,docx,pptx,xlsx,xls,outlook]"'
        ) from e
    try:
        _MD = MarkItDown()
    except Exception as e:
        raise BlueTeamMCPError(
            f"MarkItDown initialisation failed: {type(e).__name__}: {e}. "
            "It must be constructed without plugins or an LLM client."
        ) from e


def _convert_sync(path: str) -> str:
    """Synchronous MarkItDown pipeline, run inside asyncio.to_thread only."""
    with _INIT_LOCK:
        _ensure_markitdown()
    try:
        result = _MD.convert(path)
    except Exception as e:
        raise _markitdown_error(e, stage="conversion") from e
    text = getattr(result, "markdown", "") or ""
    if not text.strip():
        raise BlueTeamMCPError(
            "MarkItDown returned no extractable text for this file. If it is a "
            "scanned or image-only PDF, use blueteam_document_convert (Marker "
            "OCR) instead; MarkItDown reads digital text only."
        )
    return text


def _markitdown_error(e: Exception, *, stage: str) -> BlueTeamMCPError:
    """Wrap MarkItDown failures as typed errors with an actionable hint."""
    msg = f"MarkItDown {stage} failed: {type(e).__name__}: {e}"
    lowered = str(e).lower()
    if "unsupported" in lowered or "not supported" in lowered or "no converter" in lowered:
        msg += (
            f"Supported local extensions: {', '.join(sorted(_ALLOWED_EXT))}."
            ".zip and .epub are not accepted in v1."
        )
    return BlueTeamMCPError(msg)


def _prepare(params: FileToMarkdownInput) -> tuple[Optional[str], Optional[dict]]:
    """Validate params; return (error_json, None) or (None, prep_dict).
    Kept synchronous/plain so the validation surface is unit-testable without
    MarkItDown and without an event loop.
    """
    # Path trust boundary; same guard as blueteam_document_convert / hash_file.
    # URL schemes are rejected outright before generic path validation: a URL
    # like https://host/x.docx otherwise resolves as an odd relative path.
    if "://" in params.path:
        return json.dumps(
            {"error": "URLs are not accepted - provide a local filesystem path under BLUETEAM_ALLOWED_PATHS."}
        ), None
    ok, err = _validate_path(params.path, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}"}), None
    p = Path(params.path)
    if p.suffix.lower() not in _ALLOWED_EXT:
        return json.dumps(
            {"error": f"Unsupported file type '{p.suffix}'. "
                      f"Supported: {', '.join(sorted(_ALLOWED_EXT))}."}
        ), None
    if not p.exists():
        return json.dumps({"error": f"File not found: {params.path}"}), None
    if not p.is_file():
        return json.dumps({"error": f"Not a regular file: {params.path}"}), None
    try:
        if p.stat().st_size > _SIZE_CAP:
            return json.dumps({"error": f"File exceeds the {_SIZE_CAP // (1024 * 1024)} MB size cap."}), None
    except OSError as e:
        return json.dumps({"error": f"Cannot stat file: {e}"}), None

    return None, {"path": str(p)}


@blueteam_tool(
    name="blueteam_markitdown_convert",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_markitdown_convert(params: FileToMarkdownInput) -> str:
    """Convert an office or data file (DOCX, XLSX, PPTX, PDF, HTML, CSV, JSON,
    XML, Outlook .msg) to Markdown for LLM ingestion using the lightweight
    MarkItDown engine (pdfminer-based; no torch, no OCR, no network egress).

    Marker (blueteam_document_convert) still owns scanned/high-fidelity PDFs:
    MarkItDown's PDF path reads digital text only and returns an error for
    image-only pages, so route scanned documents there instead.

    Args:
        params.path: Absolute path to the file. Must be under
            BLUETEAM_ALLOWED_PATHS (default /var:/etc:/home:/opt:/usr). Local
            filesystem paths only; URL input is rejected. Max 50 MB.
            Supported extensions: .pdf, .docx, .pptx, .xlsx, .xls, .msg,
            .html, .htm, .csv, .json, .xml.
        params.bypass_redaction: When true, skip PII/credential redaction for
            audit investigations.

    Returns:
        str: The file content as Markdown. Output is PII-redacted by default
        and truncated at the server character cap (BLUETEAM_CHARACTER_LIMIT,
        default 100000) with a cursor hint. MarkItDown does not slice pages or
        sheets: for workbooks or documents whose full text would exceed the
        cap, pre-split the source (per-sheet CSVs, per-section documents) or
        the tail is cut.

    Examples:
        1. Convert a vendor advisory .docx to markdown (defaults):
           blueteam_markitdown_convert(path="/opt/advisories/fortinet-jan.docx")
        2. Pull a CVE tracking spreadsheet into markdown for LLM triage:
           blueteam_markitdown_convert(path="/opt/cmdb/cve-backlog.xlsx")
        3. Convert a fast digital PDF (no OCR needed) - scanned pages return
           an error pointing at blueteam_document_convert:
           blueteam_markitdown_convert(path="/opt/reports/threat-report.pdf")
        4. Audit use with redaction skipped (evidence chain preserved in the
           audit log):
           blueteam_markitdown_convert(path="/opt/cases/case-4711/email.msg",
                                       bypass_redaction=True)

    Permissions/access: server-side filesystem read under
    BLUETEAM_ALLOWED_PATHS. No API key. Does not touch the Wazuh Indexer or
    Manager API.

    Resource notes: no rate limit (local conversion). MarkItDown is imported
    lazily on the first call (~1 s import; no model downloads). Missing
    install returns a typed BlueTeamMCPError naming the required extras, never
    a traceback. Install via setup.sh (BLUETEAM_INSTALL_MARKITDOWN=1) or:
    pip install "markitdown[pdf,docx,pptx,xlsx,xls,outlook]"
    """
    err, prep = _prepare(params)
    if err is not None:
        return err
    # MarkItDown is synchronous CPU work - run off the event loop so shared
    # circuit breakers and the keepalive timer never stall.
    return await asyncio.to_thread(_convert_sync, prep["path"])
