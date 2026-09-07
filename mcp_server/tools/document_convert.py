#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Document conversion (Marker), convert SOC PDFs (playbooks, vendor advisories,
scanned IR reports) to markdown / JSON / HTML / chunks.

References: https://github.com/datalab-to/marker

Design notes:
- Marker (torch/surya) is imported on first call so server boot and
  tool registration never pay the model-load cost. Models download from
  HuggingFace on first run - requires egress + disk (see BLUETEAM_INSTALL_MARKER
  in setup.sh / requirements.txt).
- Conversion runs inside asyncio.to_thread: torch is synchronous CPU work and
  must not stall the event loop (shared breakers/keepalive).
- Input is a server-side PDF path validated by _validate_path against
  ALLOWED_PATH_PREFIXES, same trust boundary as blueteam_hash_file.
- Output goes through the @blueteam_tool uniform boundary: audit -> catch
  BlueTeamMCPError -> PII redaction (params.bypass_redaction skips optional
  layers) -> truncation at CHARACTER_LIMIT. For documents longer than the cap,
  request a page_range slice.
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

# PDFs only in v1. Marker PdfConverter also auto-OCRs scanned pages (surya),
# so no separate OCR mode is exposed. Table mode targets spreadsheet-style PDFs.
_MODES = ("pdf", "table")
_OUTPUT_FORMATS = ("markdown", "json", "html", "chunks")
_SIZE_CAP = 50 * 1024 * 1024  # 50 MB untrusted/oversized PDFs are rejected early
_ALLOWED_EXT = (".pdf",)

# Marker model/converters are cached process-wide. Keyed by (mode, fmt, pages)
# because page_range is fixed at converter construction time.
# module-global lock serializes init + converter build only; concurrent
# conversions share the artifact dict. Add a conversion mutex if throughput on one
# host ever matters - CPU inference does not parallelise well anyway.
_ARTIFACT: Any = None
_CONVERTER_CLASSES: dict[str, Any] = {}
_CONVERTERS: dict[tuple[str, str, tuple], Any] = {}
_INIT_LOCK = threading.Lock()


class DocumentConvertInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(
        ..., max_length=4096,
        description="Absolute path to the PDF to convert (must be under BLUETEAM_ALLOWED_PATHS).",
    )
    mode: Literal["pdf", "table"] = Field(
        default="pdf",
        description="'pdf': full document (auto-OCR of scanned pages). 'table': table-only extraction "
                    "(output is JSON regardless of output_format).",
    )
    output_format: Literal["markdown", "json", "html", "chunks"] = Field(
        default="markdown",
        description="'markdown' (default), 'json', 'html', or 'chunks' (page/block segments).",
    )
    page_range: Optional[str] = Field(
        default=None, max_length=64,
        description='1-indexed page selection, e.g. "1-5,7". Use for documents longer than the '
                    'response character cap so the tail is not truncated away.',
    )
    bypass_redaction: bool = Field(
        default=False,
        description="When true, skip PII/credential redaction for audit investigations.",
    )


def _parse_page_range(raw: Optional[str]) -> tuple[Optional[list[int]], Optional[str]]:
    """Parse a 1-indexed range string like '1-5,7' into Marker's 0-indexed page list.
    Returns (pages, None) on success or (None, error_msg) on invalid input.
    """
    if not raw or not raw.strip():
        return None, None
    pages: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            return None, "page_range contains an empty token (e.g. trailing comma)."
        if "-" in token:
            parts = token.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError:
                return None, f"page_range token '{token}' is not a number or range."
            if lo < 1 or hi < lo:
                return None, f"page_range token '{token}' is invalid (pages are 1-indexed, hi >= lo)."
            pages.extend(range(lo, hi + 1))
        else:
            try:
                n = int(token)
            except ValueError:
                return None, f"page_range token '{token}' is not a number."
            if n < 1:
                return None, f"page_range token '{token}' is invalid (pages are 1-indexed)."
            pages.append(n)
    if not pages:
        return None, "page_range did not contain any valid pages."
    return [p - 1 for p in pages], None  # Marker pages are 0 indexed


def _ensure_marker() -> None:
    """Import Marker classes + build the shared artifact dict exactly once.
    Raises BlueTeamMCPError with an actionable message when marker-pdf is not
    installed or model download fails (egress / HF_HOME issues).
    """
    global _ARTIFACT
    if _ARTIFACT is not None:
        return
    try:
        from marker.converters.pdf import PdfConverter  # noqa: F401
        from marker.converters.table import TableConverter  # noqa: F401
        from marker.models import create_model_dict
    except ImportError as e:
        import importlib.util
        if importlib.util.find_spec("marker") is not None:
            raise BlueTeamMCPError(
                f"Marker import failed: {type(e).__name__}: {e}. The package is present "
                "but a dependency import broke (often a numpy/torch version mismatch). "
                "Run in the server venv: pip check && pip install --force-reinstall numpy"
            ) from e
        raise BlueTeamMCPError(
            "Marker is not installed. Install marker-pdf into the server venv "
            "(see setup.sh BLUETEAM_INSTALL_MARKER=1): "
            "pip install torch --index-url https://download.pytorch.org/whl/cpu && "
            "pip install marker-pdf"
        ) from e
    try:
        _ARTIFACT = create_model_dict()
    except Exception as e:
        raise BlueTeamMCPError(
            f"Marker model load failed: {type(e).__name__}: {e}. Models download from "
            "HuggingFace on first run, check outbound egress and HF_HOME disk space."
        ) from e
    _CONVERTER_CLASSES["pdf"] = PdfConverter
    _CONVERTER_CLASSES["table"] = TableConverter


def _get_converter(mode: str, fmt: str, pages: Optional[list[int]]) -> Any:
    """Return a cached Marker converter for (mode, fmt, pages)."""
    key = (mode, fmt, tuple(pages) if pages else ())
    cached = _CONVERTERS.get(key)
    if cached is not None:
        return cached
    config: dict[str, Any] = {"output_format": fmt, "extract_images": False}
    if pages:
        config["page_range"] = pages
    converter = _CONVERTER_CLASSES[mode](config=config, artifact_dict=_ARTIFACT)
    _CONVERTERS[key] = converter
    return converter


def _extract_output(rendered: Any, fmt: str) -> str:
    """Pull text out of a Marker RenderedResult for the requested output format.
    Attribute access is verified against Marker v2 docs: markdown -> .markdown,
    json -> .model_dump(), html via text_from_rendered(), chunks -> .chunks[].html.
    Fallbacks keep a malformed/absent attribute from raising a traceback.
    """
    from marker.output import text_from_rendered  # already imported by _ensure_marker

    if fmt == "markdown":
        md = getattr(rendered, "markdown", None)
        if isinstance(md, str) and md:
            return md
        return text_from_rendered(rendered)[0]
    if fmt == "html":
        return text_from_rendered(rendered)[0]
    if fmt == "json":
        dump = getattr(rendered, "model_dump", None)
        if callable(dump):
            return json.dumps(dump(), indent=2, ensure_ascii=False)
        return text_from_rendered(rendered)[0]
    # chunks
    chunks = getattr(rendered, "chunks", None)
    if chunks:
        lines: list[str] = []
        for c in chunks:
            page_id = getattr(c, "page_id", "?")
            block_type = getattr(c, "block_type", "block")
            html = getattr(c, "html", "")
            lines.append(f"[page {page_id}] [{block_type}]\n{html}")
        return "\n\n".join(lines)
    return text_from_rendered(rendered)[0]


def _convert_sync(path: str, mode: str, fmt: str, pages: Optional[list[int]]) -> str:
    """Synchronous Marker pipeline, run inside asyncio.to_thread only."""
    with _INIT_LOCK:
        _ensure_marker()
        try:
            converter = _get_converter(mode, fmt, pages)
        except Exception as e:
            raise _marker_error(e, stage="converter init") from e
    try:
        rendered = converter(path)
    except Exception as e:
        raise _marker_error(e, stage="conversion") from e
    return _extract_output(rendered, fmt)


def _marker_error(e: Exception, *, stage: str) -> BlueTeamMCPError:
    """Wrap Marker failures as typed errors with an actionable hint.
    Observed on prod: Marker tries to write a 'static' asset dir under the
    read-only venv site-packages ([Errno 30]). That surfaces as a raw OSError
    unless converted here.
    """
    msg = f"Marker {stage} failed: {type(e).__name__}: {e}"
    if "Read-only file system" in str(e) and "static" in str(e):
        msg += (
            "Marker wants to write its 'static' asset folder inside the venv's"
            "site-packages, which is read-only here. Fix on the host: make that dir "
            "writable (bind-mount a writable volume over it) or install marker with "
            "the venv on a writable filesystem."
        )
    return BlueTeamMCPError(msg)


def _prepare(params: DocumentConvertInput) -> tuple[Optional[str], Optional[dict]]:
    """Validate params; return (error_json, None) or (None, prep_dict).
    Kept synchronous/plain so the validation surface is unit-testable without
    Marker and without an event loop.
    """
    # Path trust boundary; same guard as blueteam_hash_file.
    ok, err = _validate_path(params.path, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}"}), None
    p = Path(params.path)
    if p.suffix.lower() not in _ALLOWED_EXT:
        return json.dumps({"error": f"Unsupported file type '{p.suffix}'. Only PDF is supported."}), None
    if not p.exists():
        return json.dumps({"error": f"File not found: {params.path}"}), None
    if not p.is_file():
        return json.dumps({"error": f"Not a regular file: {params.path}"}), None
    try:
        if p.stat().st_size > _SIZE_CAP:
            return json.dumps({"error": f"File exceeds the {_SIZE_CAP // (1024 * 1024)} MB size cap."}), None
    except OSError as e:
        return json.dumps({"error": f"Cannot stat file: {e}"}), None

    mode = params.mode.strip().lower()
    fmt = params.output_format.strip().lower()
    # TableConverter is a JSON-first extractor (Marker default); honour that.
    if mode == "table":
        fmt = "json"
    pages, perr = _parse_page_range(params.page_range)
    if perr is not None:
        return json.dumps({"error": perr}), None

    return None, {"path": str(p), "mode": mode, "fmt": fmt, "pages": pages}


@blueteam_tool(
    name="blueteam_document_convert",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_document_convert(params: DocumentConvertInput) -> str:
    """Convert a SOC PDF (IR playbook, vendor advisory, scanned report) to
    markdown/JSON/HTML/chunks using the Marker engine (surya layout + OCR models).
    SOC IR workflow: drop a playbook or advisory PDF on the server under an
    allowed path, then convert it to markdown for LLM analysis or to JSON for
    structured ingestion. Scanned pages are OCR'd automatically in 'pdf' mode.

    Args:
        params.path: Absolute path to the PDF (must be under BLUETEAM_ALLOWED_PATHS,
            default /var:/etc:/home:/opt:/usr). Max 50 MB, PDF only.
        params.mode: 'pdf' (default) full document with auto-OCR, or 'table'
            table-only extraction. Table mode always returns JSON.
        params.output_format: 'markdown' (default), 'json', 'html', or 'chunks'.
        params.page_range: 1-indexed pages, e.g. '1-5,7'. Required for documents
            whose full text would exceed the response character cap - the tail
            would otherwise be truncated. Range syntax: comma list, N or N-M.
        params.bypass_redaction: When true, skip PII/credential redaction for
            audit investigations.

    Returns:
        str: The converted document text (markdown/html/json/chunks). Output is
        PII-redacted by default (emails, hostnames, internal IPs, locations) and
        truncated at the server character cap with a cursor hint.

    Examples:
        1. Convert an IR playbook to markdown (defaults):
           blueteam_document_convert(path="/opt/playbooks/ransomware-runbook.pdf")
        2. First 3 pages of a long vendor advisory, structured JSON for ingestion:
           blueteam_document_convert(path="/opt/advisories/msrc-jan.pdf",
                                     output_format="json", page_range="1-3")
        3. Extract just the table from a spreadsheet-style PDF:
           blueteam_document_convert(path="/opt/scans/asset-inventory.pdf", mode="table")
        4. Chunked output of a scanned IR report for per-section analysis:
           blueteam_document_convert(path="/opt/reports/scanned-incident.pdf",
                                     output_format="chunks", page_range="1-10")

    Permissions/access: server-side filesystem read under BLUETEAM_ALLOWED_PATHS.
    No API key required - Marker LLM post-processing is disabled.

    Resource notes: first call downloads Marker models from HuggingFace (network
    egress + several GB of cache, HF_HOME). Conversion is CPU-bound, roughly
    5-30 s/page. Install marker-pdf via setup.sh (BLUETEAM_INSTALL_MARKER=1) or
    requirements.txt before first use.
    """
    err, prep = _prepare(params)
    if err is not None:
        return err
    # Marker/torch is synchronous CPU work - run off the event loop so shared
    # circuit breakers and the keepalive timer never stall.
    return await asyncio.to_thread(_convert_sync, **prep)
