#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
SOC report export - writes .docx / .xlsx / .pptx deliverables via the officecli resident pipe,
and .tex / .bib manuscripts directly (no officecli, no compiler).
"""
from __future__ import annotations
import asyncio, json, os
from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.config import config
from mcp_server.core.paper_evidence import CLAIM_TOKEN, load_claims, load_manifest
from mcp_server.core.subprocess import _validate_path

try:
    import officecli
    OFFICECLI_AVAILABLE = True
except ImportError:
    OFFICECLI_AVAILABLE = False


def default_report_dir() -> str:
    """Directory `blueteam_export_report` and the workflow report step write into.
    Read from config so callers default to the same path the write scope allows."""
    return config.operational.export_dir


class DocxSection(BaseModel):
    heading: str = Field(..., max_length=200)
    paragraphs: list[str] = Field(default_factory=list, max_length=50)
    bullets: list[str] = Field(default_factory=list, max_length=50)


class XlsxSheet(BaseModel):
    name: str = Field(..., max_length=40)
    headers: list[str] = Field(..., max_length=50)
    rows: list[list[str]] = Field(..., max_length=5000)


class PptxSlide(BaseModel):
    title: str = Field(..., max_length=200)
    bullets: list[str] = Field(default_factory=list, max_length=20)
    notes: str = Field(default="", max_length=1000)


class BibEntry(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    key: str = Field(..., pattern=r"^[A-Za-z][A-Za-z0-9:_-]{0,63}$")
    title: str = Field(..., max_length=300)
    authors: str = Field(..., max_length=300)
    year: str = Field(..., pattern=r"^\d{4}$")
    venue: str = Field(default="", max_length=200)
    doi: str = Field(default="", max_length=200)


class ReportExportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    format: Literal["docx", "xlsx", "pptx", "latex"] = Field(..., description="Output format.")
    path: str = Field(..., max_length=500, description="Absolute output file path (.docx/.xlsx/.pptx/.tex).")
    docx_sections: list[DocxSection] = Field(default_factory=list,
        description="For format='docx' or 'latex': narrative sections with headings, paragraphs, bullets.")
    xlsx_sheets: list[XlsxSheet] = Field(default_factory=list,
        description="For format='xlsx': sheets with headers and row data.")
    pptx_slides: list[PptxSlide] = Field(default_factory=list,
        description="For format='pptx': slides with title, bullets, speaker notes.")
    title: str = Field(default="SOC Report", max_length=200,
        description="Report title (used in docx heading / pptx first slide / LaTeX \\title).")
    bib_entries: list[BibEntry] = Field(default_factory=list, max_length=100,
        description="For format='latex': bibliography entries written to a sibling .bib file.")
    claims_path: Optional[str] = Field(default=None, max_length=500,
        description="For format='latex': absolute path to an evidence pack claims.json. "
                    "A {{C-001}} token resolves only when that claim is citable.")
    allow_degraded: bool = Field(default=False,
        description="For format='latex': render even when the pack manifest says "
                    "pack_status='degraded'. The flag is recorded in the .tex and the response.")


def _excel_col(idx: int) -> str:
    """Excel column letter for 0-based index: 0->A, 25->Z, 26->AA, 51->AZ, 52->BA."""
    col = ""
    n = idx + 1
    while n:
        n, rem = divmod(n - 1, 26)
        col = chr(65 + rem) + col
    return col



_TEX_ESCAPES = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
    "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
    "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}


def _tex_escape(text: object) -> str:
    """Escape every LaTeX control character. A backslash becomes
    \\textbackslash{}, so a payload like \\input{/etc/passwd} cannot survive as a command."""
    return "".join(_TEX_ESCAPES.get(ch, ch) for ch in str(text))


def _resolve_text(text: str, claims: dict[str, dict], errors: list[dict],
                  where: str) -> tuple[str, int]:
    """Resolve {{C-001}} tokens. A token that is unknown or not citable is an
    error, not a silent omission: a sentence with a hole is worse than a failed
    render."""
    out: list[str] = []
    pos = 0
    resolved = 0
    for match in CLAIM_TOKEN.finditer(text):
        out.append(_tex_escape(text[pos:match.start()]))
        claim_id = match.group(1)
        claim = claims.get(claim_id)
        if claim is None:
            errors.append({"claim_id": claim_id, "field": where,
                           "reason": "unknown claim id"})
        elif claim.get("citable") is not True:
            errors.append({"claim_id": claim_id, "field": where,
                           "reason": claim.get("reason") or "not citable"})
        else:
            out.append(_tex_escape(claim.get("display", "")))
            resolved += 1
        pos = match.end()
    out.append(_tex_escape(text[pos:]))
    return "".join(out), resolved


def _render_bib(entries: list[BibEntry]) -> str:
    blocks = []
    for entry in entries:
        kind = "inproceedings" if entry.venue else "misc"
        fields = [("title", entry.title), ("author", entry.authors), ("year", entry.year)]
        if entry.venue:
            fields.append(("booktitle", entry.venue))
        if entry.doi:
            fields.append(("doi", entry.doi))
        lines = [f"@{kind}{{{entry.key},"]
        lines += [f"  {name} = {{{_tex_escape(value)}}}," for name, value in fields]
        lines[-1] = lines[-1].rstrip(",")
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def _export_latex(params: ReportExportInput, path: str, export_dir: str) -> str:
    if not path.endswith(".tex"):
        return json.dumps({"error": "LaTeX export path must end with .tex"}, indent=2)

    claims: dict[str, dict] = {}
    if params.claims_path:
        claims_abs = os.path.abspath(params.claims_path)
        ok, err = _validate_path(claims_abs, [export_dir])
        if not ok:
            return json.dumps({"error": f"claims_path not allowed: {err}",
                               "allowed": [export_dir]}, indent=2)
        claims, err = load_claims(claims_abs)
        if err:
            return json.dumps({"error": err}, indent=2)

    pack_status = "not_applicable"
    if params.claims_path:
        manifest = load_manifest(Path(claims_abs).parent / "manifest.json")
        pack_status = str(manifest.get("pack_status") or "unknown")
        if pack_status != "complete" and not params.allow_degraded:
            non_citable = [{"claim_id": c["claim_id"], "reason": c.get("reason", "")}
                           for c in claims.values() if c.get("citable") is not True]
            return json.dumps({"error": "pack is not complete", "pack_status": pack_status,
                               "non_citable": non_citable,
                               "hint": "pass allow_degraded=true to render anyway"}, indent=2)

    errors: list[dict] = []
    resolved = 0
    body: list[str] = []
    for section in params.docx_sections:
        heading, count = _resolve_text(section.heading, claims, errors, "heading")
        resolved += count
        paragraphs = []
        for paragraph in section.paragraphs:
            rendered, count = _resolve_text(paragraph, claims, errors, section.heading)
            resolved += count
            paragraphs.append(rendered)
        bullets = []
        for bullet in section.bullets:
            rendered, count = _resolve_text(bullet, claims, errors, section.heading)
            resolved += count
            bullets.append(rendered)

        if section.heading.strip().lower() == "abstract":
            body.append("\\begin{abstract}")
            body.append("\n\n".join(paragraphs))
            body.append("\\end{abstract}")
            continue
        body.append(f"\\section{{{heading}}}")
        body.extend(paragraphs)
        if bullets:
            body.append("\\begin{itemize}")
            body.extend(f"\\item {bullet}" for bullet in bullets)
            body.append("\\end{itemize}")

    if errors:
        return json.dumps({"error": "claim check failed", "errors": errors}, indent=2)

    lines = [
        "% Generated by blue_team_mcp. Compile outside the server; no shell-escape.",
        f"% pack_status: {pack_status}; allow_degraded: {str(params.allow_degraded).lower()}",
        "\\documentclass[sigconf]{acmart}",
        "\\usepackage{booktabs}",
        "\\usepackage{graphicx}",
        "\\usepackage{amsmath}",
        "\\settopmatter{printacmref=false}",
        "\\pagestyle{plain}",
        "\\begin{document}",
        f"\\title{{{_tex_escape(params.title)}}}",
        "\\author{Anonymous}",
        "\\affiliation{%",
        "  \\institution{Replace with your institution}",
        "}",
        "\\maketitle",
        *body,
    ]
    if params.bib_entries:
        lines += ["\\bibliographystyle{ACM-Reference-Format}",
                  f"\\bibliography{{{Path(path).stem}}}"]
    lines.append("\\end{document}")

    bib_path = str(Path(path).with_suffix(".bib"))
    try:
        if params.bib_entries:
            Path(bib_path).write_text(_render_bib(params.bib_entries), encoding="utf-8")
        else:
            Path(bib_path).unlink(missing_ok=True)
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        return json.dumps({"error": f"LaTeX export write failed: {exc}"}, indent=2)

    return json.dumps({"status": "created", "format": "latex", "path": path,
                       "bib_path": bib_path if params.bib_entries else None,
                       "sections": len(params.docx_sections),
                       "claims_resolved": resolved,
                       "pack_status": pack_status,
                       "allow_degraded": params.allow_degraded}, indent=2)


@mcp.tool(name="blueteam_export_report",
          annotations={"readOnlyHint": False, "destructiveHint": True,
                       "idempotentHint": True, "openWorldHint": False})
async def blueteam_export_report(params: ReportExportInput) -> str:
    """Generate a SOC report deliverable (.docx / .xlsx / .pptx) via officecli,
    or a LaTeX manuscript (.tex + .bib) with no officecli dependency.

    Converts structured findings from MCP analysis tools into an Office document
    written through the officecli named-pipe resident. Supports:
      - docx: narrative incident report (sections -> headings/paragraphs/bullets)
      - xlsx: IOC / blocklist / compliance tables (sheets -> headers + rows)
      - pptx: executive briefing (slides -> title + bullets + speaker notes)
      - latex: ACM sigconf manuscript. A ``{{C-001}}`` token resolves to the
        claim's display value only when that claim is `citable`; unknown or
        non-citable claims fail the render and name the reason.

    **Requires**: officecli binary for docx/xlsx/pptx only. LaTeX export writes
    files and never compiles them.

    The path must sit under `BLUETEAM_EXPORT_DIR` (default
    `/var/log/blue-team-mcp/exports`); a path outside it is refused with
    `Path not allowed`.

    **Worked Examples**

    1. *DOCX incident report*:
       ``blueteam_export_report(format="docx", path="/var/log/blue-team-mcp/exports/incident.docx",
         title="Zimbra Brute Force", docx_sections=[{"heading":"Summary","paragraphs":["IP 117.247.110.24 ..."],"bullets":[]}])``

    2. *XLSX blocklist table*:
       ``blueteam_export_report(format="xlsx", path="/var/log/blue-team-mcp/exports/blocklist.xlsx",
         xlsx_sheets=[{"name":"Blocked","headers":["IP","Score"],"rows":[["1.2.3.4","80"]]}])``

    3. *PPTX executive briefing*:
       ``blueteam_export_report(format="pptx", path="/var/log/blue-team-mcp/exports/briefing.pptx",
         pptx_slides=[{"title":"Top Threats","bullets":["Brute force: 1,200 events"],"notes":"Escalate"}]])``

    4. *LaTeX manuscript with claim resolution*:
       ``blueteam_export_report(format="latex", path="/var/log/blue-team-mcp/exports/paper.tex",
         claims_path="/var/log/blue-team-mcp/exports/paper/draft-01/claims.json",
         docx_sections=[{"heading":"Results","paragraphs":["The server exposes {{C-001}} tools."]}])``
    """
    _audit_log("blueteam_export_report", {"format": params.format, "path": params.path})
    export_dir = default_report_dir()
    path = os.path.abspath(params.path)
    ok, err = _validate_path(path, [export_dir])
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}", "allowed": [export_dir]}, indent=2)
    target_dir = os.path.dirname(path)
    try:
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
    except OSError as e:
        return json.dumps({"error": f"Export directory not writable: {target_dir} ({e})",
                           "allowed": [export_dir]}, indent=2)

    if params.format == "latex":
        return await asyncio.to_thread(_export_latex, params, path, export_dir)

    if not OFFICECLI_AVAILABLE:
        return json.dumps({"error": "officecli-sdk not installed. Run: pip install officecli-sdk"}, indent=2)

    try:
        with officecli.create(path, "--force") as doc:
            if params.format == "docx":
                if params.docx_sections:
                    for sec in params.docx_sections:
                        doc.send({"command": "add", "path": "/body",
                                  "type": "paragraph",
                                  "props": {"text": sec.heading, "bold": "true",
                                             "style": "Heading1", "size": "16pt",
                                             "spaceAfter": "8pt"}})
                        for p in sec.paragraphs:
                            doc.send({"command": "add", "path": "/body",
                                      "type": "paragraph", "props": {"text": p}})
                        for b in sec.bullets:
                            doc.send({"command": "add", "path": "/body",
                                      "type": "paragraph",
                                      "props": {"text": f"• {b}"}})
                else:
                    doc.send({"command": "add", "path": "/body",
                              "type": "paragraph", "props": {"text": params.title, "bold": "true"}})

            elif params.format == "xlsx":
                if params.xlsx_sheets:
                    for sheet in params.xlsx_sheets:
                        sheet_name = sheet.name[:31]
                        for ci, h in enumerate(sheet.headers):
                            cell = f"/{sheet_name}/{_excel_col(ci)}1"
                            doc.send({"command": "set", "path": cell,
                                      "props": {"text": h, "bold": "true"}})
                        for ri, row in enumerate(sheet.rows, start=2):
                            for ci, val in enumerate(row):
                                cell = f"/{sheet_name}/{_excel_col(ci)}{ri}"
                                doc.send({"command": "set", "path": cell,
                                          "props": {"text": str(val)}})

            elif params.format == "pptx":
                if params.pptx_slides:
                    for i, slide in enumerate(params.pptx_slides, start=1):
                        doc.send({"command": "add", "path": "/",
                                  "type": "slide",
                                  "props": {"layout": "blank", "background": "FFFFFF"}})
                        # Title at top (explicit geometry required on blank layout)
                        doc.send({"command": "add", "path": f"/slide[{i}]",
                                  "type": "shape",
                                  "props": {"text": slide.title, "bold": "true",
                                             "x": "1.5cm", "y": "1.2cm",
                                             "width": "30cm", "height": "2cm"}})
                        # Bullets stacked below title, each on its own line
                        for bi, b in enumerate(slide.bullets):
                            doc.send({"command": "add", "path": f"/slide[{i}]",
                                      "type": "shape",
                                      "props": {"text": b,
                                                 "x": "1.5cm", "y": f"{3.8 + bi * 1.1}cm",
                                                 "width": "30cm", "height": "1cm"}})
                        if slide.notes:
                            doc.send({"command": "add", "path": f"/slide[{i}]",
                                      "type": "notes", "props": {"text": slide.notes}})
                else:
                    doc.send({"command": "add", "path": "/",
                              "type": "slide", "props": {"layout": "title"}})

            doc.send({"command": "save"})

        size = os.path.getsize(path)
        return json.dumps({"status": "created", "format": params.format,
                           "path": path, "size_bytes": size,
                           "size_kb": round(size / 1024, 1)}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"officecli export failed: {e}"}, indent=2)
