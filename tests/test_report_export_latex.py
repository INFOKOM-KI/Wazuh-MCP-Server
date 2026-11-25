#!/usr/bin/env python3
"""LaTeX export: claim resolution, citable gate, escaping, and write scope.

The renderer is the last gate before a manuscript leaves the server, so the tests
cover the two ways it can leak: a non-citable claim resolved as a value, and
untrusted text interpreted as a LaTeX command.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core.config import config
from mcp_server.tools.report_export import ReportExportInput, blueteam_export_report

CLAIMS = [
    {"claim_id": "C-001", "display": "168", "value": 168, "n": 168,
     "citable": True, "reason": ""},
    {"claim_id": "C-005", "display": "0", "value": 0, "n": 0,
     "citable": False, "reason": "n<5: below the evidence floor"},
]


def _root() -> Path:
    root = Path(config.operational.export_dir) / "latex-test"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _claims_file() -> str:
    path = _root() / "claims.json"
    path.write_text(json.dumps(CLAIMS), encoding="utf-8")
    (_root() / "manifest.json").write_text(
        json.dumps({"pack_status": "complete"}), encoding="utf-8")
    return str(path)


def _degrade_manifest() -> None:
    (_root() / "manifest.json").write_text(
        json.dumps({"pack_status": "degraded"}), encoding="utf-8")


_UNSET = object()


def _run(**overrides) -> dict:
    claims_path = overrides.pop("claims_path", _UNSET)
    if claims_path is _UNSET:
        claims_path = _claims_file()
    params = ReportExportInput(
        format="latex",
        path=overrides.pop("path", str(_root() / "paper.tex")),
        title="Test Paper",
        docx_sections=overrides.pop("sections", [
            {"heading": "Results", "paragraphs": ["The server exposes {{C-001}} tools."]}],
        ),
        claims_path=claims_path,
        allow_degraded=overrides.pop("allow_degraded", False),
        **overrides,
    )
    return json.loads(asyncio.run(blueteam_export_report(params)))


def test_citable_claim_resolves():
    out = _run()
    assert out["status"] == "created"
    tex = Path(out["path"]).read_text(encoding="utf-8")
    assert "The server exposes 168 tools." in tex
    assert "\\documentclass[sigconf]{acmart}" in tex
    assert out["claims_resolved"] == 1


def test_degraded_pack_is_refused_without_the_flag():
    claims = _claims_file()
    _degrade_manifest()
    target = _root() / "degraded.tex"
    target.unlink(missing_ok=True)
    out = _run(path=str(target), claims_path=claims)
    assert out["error"] == "pack is not complete"
    assert out["pack_status"] == "degraded"
    assert out["non_citable"][0]["claim_id"] == "C-005"
    assert not target.exists()


def test_allow_degraded_renders_and_records_the_flag():
    claims = _claims_file()
    _degrade_manifest()
    target = _root() / "allowed.tex"
    out = _run(path=str(target), claims_path=claims, allow_degraded=True)
    assert out["status"] == "created"
    assert out["pack_status"] == "degraded"
    assert out["allow_degraded"] is True
    assert "% pack_status: degraded; allow_degraded: true" in Path(target).read_text()


def test_non_citable_claim_fails_and_writes_nothing():
    target = _root() / "blocked.tex"
    target.unlink(missing_ok=True)
    out = _run(path=str(target), sections=[
        {"heading": "Results", "paragraphs": ["Zero cases seen: {{C-005}}."]}])
    assert out["error"] == "claim check failed"
    assert out["errors"][0]["claim_id"] == "C-005"
    assert out["errors"][0]["reason"] == "n<5: below the evidence floor"
    assert not target.exists()


def test_unknown_claim_fails():
    out = _run(sections=[
        {"heading": "Results", "paragraphs": ["Unknown {{C-999}}."]}])
    assert out["error"] == "claim check failed"
    assert out["errors"][0]["reason"] == "unknown claim id"


def test_token_without_manifest_fails():
    out = _run(claims_path=None)
    assert out["error"] == "claim check failed"
    assert out["errors"][0]["reason"] == "unknown claim id"


def test_latex_injection_is_escaped():
    out = _run(sections=[
        {"heading": "Results \\input{/etc/passwd}",
         "paragraphs": ["Paste \\input{/etc/passwd} and 100% of $x$ & #1 _2."]}])
    tex = Path(out["path"]).read_text(encoding="utf-8")
    assert "\\input{" not in tex
    assert "\\textbackslash{}input\\{/etc/passwd\\}" in tex
    assert "100\\%" in tex


def test_tex_extension_is_required():
    out = _run(path=str(_root() / "paper.md"))
    assert "must end with .tex" in out["error"]


def test_claims_path_outside_export_dir_is_refused():
    outside = Path("/etc/claims.json")
    out = _run(claims_path=str(outside))
    assert "claims_path not allowed" in out["error"]


def test_bibliography_is_written_beside_the_manuscript():
    out = _run(bib_entries=[{
        "key": "song2026paperorchestra",
        "title": "PaperOrchestra: A Multi-Agent Framework",
        "authors": "Song, Yiwen and Song, Yale",
        "year": "2026",
        "venue": "arXiv",
        "doi": "",
    }])
    bib = Path(out["bib_path"]).read_text(encoding="utf-8")
    assert "@inproceedings{song2026paperorchestra," in bib
    tex = Path(out["path"]).read_text(encoding="utf-8")
    assert "\\bibliography{paper}" in tex


def test_abstract_uses_the_abstract_environment():
    out = _run(sections=[{"heading": "Abstract", "paragraphs": ["Short abstract."]}])
    tex = Path(out["path"]).read_text(encoding="utf-8")
    assert "\\begin{abstract}" in tex
    assert "\\section{Abstract}" not in tex
