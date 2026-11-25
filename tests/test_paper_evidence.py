#!/usr/bin/env python3
"""Evidence pack: hashing, k-suppression, determinism, and write scope.

The pack is the reproducibility backbone of the paper pipeline, so the tests
target the four ways it can lie: a manifest hash that does not match the bytes,
a small cell that leaks a count, case text that reaches disk, and a content hash
that changes between runs on identical inputs.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import paper_evidence

METRICS = {
    "tool_calls": {"blueteam_case_list": 2, "blueteam_metrics": 3},
    "pipeline": {"tools": {"blueteam_case_list": 5}, "duration_ms_total": {"blueteam_case_list": 62.5}},
    "redaction_gate_failures": 0,
    "rate_limit_hits": 0,
}

ALERTS = {
    "available": True, "window_minutes": 1440, "total": 120,
    "severity": [{"level": 3, "count": 108}, {"level": 12, "count": 12}],
    "high_severity_count": 12,
    "top_rules": [{"rule_id": "5710", "count": 48}],
    "top_rule_share": 40.0, "truncated": False, "partial": False,
    "index_pattern": "wazuh-alerts-*", "filter": "rule.level exists",
    "per_entity_claims": False, "canonical_srcip_field": "data.srcip",
}

SECRET = "SECRET-CASE-TEXT"

CASES = [{
    "case_id": "case_1",
    "created_at": "2026-01-01T00:00:00+00:00",
    "title": SECRET,
    "notes": SECRET,
    "srcips": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
    "verdicts": [
        {"srcip": "10.0.0.1", "verdict": "suspicious"},
        {"srcip": "10.0.0.2", "verdict": "suspicious"},
        {"srcip": "10.0.0.3", "verdict": "suspicious"},
    ],
}] + [{
    "case_id": f"case_t{i}",
    "created_at": f"2026-02-0{i + 1}T00:00:00+00:00",
    "title": SECRET,
    "notes": SECRET,
    "verdicts": [{"srcip": f"192.0.2.{i}", "verdict": "true_positive"}],
} for i in range(5)]


def _tool(name: str, module: str, read_only: bool = True):
    return types.SimpleNamespace(
        name=name,
        description=f"{name} description",
        fn=types.SimpleNamespace(__module__=f"mcp_server.tools.{module}"),
        annotations={"readOnlyHint": read_only, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
    )


TOOLS = {
    "blueteam_case_list": _tool("blueteam_case_list", "case"),
    "blueteam_metrics": _tool("blueteam_metrics", "metrics"),
    "blueteam_case_get": _tool("blueteam_case_get", "case", read_only=False),
    "blueteam_case_create": _tool("blueteam_case_create", "case", read_only=False),
    "blueteam_case_add_iocs": _tool("blueteam_case_add_iocs", "case", read_only=False),
}


def _build(tmp_path: Path, run_id: str = "run-1", *,
           cases: list[dict] | None = None, metrics: dict | None = None,
           alerts: dict | None = None) -> dict:
    return paper_evidence.build_evidence_pack(
        str(tmp_path / "pack"), run_id,
        tools=TOOLS, metrics_snapshot=metrics or METRICS,
        cases=CASES if cases is None else cases,
        evaluations=[{"name": "pytest", "command": "pytest -q", "passed": 410,
                      "total": 412, "duration_s": 63.2}],
        repo_root=Path.cwd(),
        alerts=ALERTS if alerts is None else alerts,
        gating={"read_only": False, "disabled_categories": [], "disabled_tools": []},
    )


def test_manifest_hashes_match_the_bytes_on_disk(tmp_path):
    manifest = _build(tmp_path)
    pack = tmp_path / "pack"
    assert manifest["k_anonymity"] == 5
    assert manifest["min_evidence_n"] == 5
    assert {f["path"] for f in manifest["files"]} == {
        "tool_inventory.json", "metrics.json", "cases.json", "evaluations.json",
        "claims.json", "alerts.json", "figures/tool_modules.csv",
    }
    for entry in manifest["files"]:
        data = (pack / entry["path"]).read_bytes()
        assert entry["bytes"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert json.loads((pack / "manifest.json").read_text())["content_hash"] == manifest["content_hash"]
    assert manifest["claims"] == {"total": 11, "citable": 11}
    assert manifest["pack_status"] == "complete"
    assert manifest["alerts"] == {"available": True, "window_minutes": 1440,
                                  "error_kind": "", "index_pattern": "wazuh-alerts-*",
                                  "filter": "rule.level exists",
                                  "per_entity_claims": False,
                                  "canonical_srcip_field": "data.srcip"}
    assert manifest["gating"] == {"read_only": False, "disabled_categories": [],
                                  "disabled_tools": []}


def test_small_entity_cells_are_suppressed(tmp_path):
    _build(tmp_path)
    cases = json.loads((tmp_path / "pack" / "cases.json").read_text())
    rows = {row["verdict"]: row for row in cases["by_verdict"]}
    assert rows["suspicious"]["distinct_srcips"] == "<5"
    assert rows["suspicious"]["suppressed"] is True
    assert rows["true_positive"]["distinct_srcips"] == 5
    assert "suppressed" not in rows["true_positive"]


def test_case_text_and_ips_never_reach_disk(tmp_path):
    _build(tmp_path)
    body = "\n".join(p.read_text(encoding="utf-8")
                     for p in (tmp_path / "pack").rglob("*") if p.is_file())
    assert SECRET not in body
    assert "10.0.0." not in body
    assert "192.0.2." not in body


def test_content_hash_is_stable_across_runs(tmp_path):
    first = _build(tmp_path / "a")
    second = _build(tmp_path / "b")
    assert first["content_hash"] == second["content_hash"]


def test_alert_claims_display_the_window(tmp_path):
    _build(tmp_path)
    claims = {c["claim_id"]: c for c in
              json.loads((tmp_path / "pack" / "claims.json").read_text())}
    assert claims["C-009"]["display"] == "120 alerts (24h window)"
    assert claims["C-009"]["window_minutes"] == 1440
    assert claims["C-010"]["display"] == "12 alerts (24h window)"
    assert claims["C-011"]["display"] == "40.0% (24h window)"
    assert "wazuh-alerts-*" in claims["C-009"]["derivation"]
    assert claims["C-009"]["derivation"].endswith("where rule.level exists")


def test_rerun_does_not_adopt_a_stray_file(tmp_path):
    _build(tmp_path)
    (tmp_path / "pack" / "notes.txt").write_text("stray")
    manifest = _build(tmp_path)
    assert "notes.txt" not in {entry["path"] for entry in manifest["files"]}


def test_degenerate_claims_stay_but_are_not_citable(tmp_path):
    _build(tmp_path, cases=[], alerts={
        "available": False, "window_minutes": 0, "error_kind": "unreachable",
    }, metrics={
        "tool_calls": {}, "pipeline": {"tools": {}, "duration_ms_total": {}},
        "redaction_gate_failures": 0, "rate_limit_hits": 0,
    })
    claims = {c["claim_id"]: c for c in
              json.loads((tmp_path / "pack" / "claims.json").read_text())}
    assert set(claims) == {f"C-{i:03d}" for i in range(1, 12)}
    for cid in ("C-001", "C-002", "C-003", "C-004"):
        assert claims[cid]["citable"] is True
    for cid in ("C-005", "C-006", "C-007", "C-008"):
        assert claims[cid]["citable"] is False
        assert claims[cid]["n"] == 0
        assert claims[cid]["reason"] == "n<5: below the evidence floor"
    for cid in ("C-009", "C-010", "C-011"):
        assert claims[cid]["citable"] is False
        assert claims[cid]["reason"] == "indexer unavailable: unreachable"
    manifest = json.loads((tmp_path / "pack" / "manifest.json").read_text())
    assert manifest["claims"] == {"total": 11, "citable": 4}
    assert manifest["pack_status"] == "degraded"
    assert manifest["alerts"]["error_kind"] == "unreachable"
    alerts = json.loads((tmp_path / "pack" / "alerts.json").read_text())
    assert "error" not in alerts and "error_kind" not in alerts


def test_case_claim_needs_the_evidence_floor(tmp_path):
    _build(tmp_path, cases=CASES[:4])
    claims = {c["claim_id"]: c for c in
              json.loads((tmp_path / "pack" / "claims.json").read_text())}
    assert claims["C-005"]["citable"] is False
    assert claims["C-005"]["n"] == 4
    assert claims["C-005"]["reason"] == "n<5: below the evidence floor"


def test_every_claim_records_n_and_one_citation_rule(tmp_path):
    _build(tmp_path)
    for claim in json.loads((tmp_path / "pack" / "claims.json").read_text()):
        assert isinstance(claim["n"], int)
        assert claim["n_kind"] in {"population", "sample"}
        assert claim["n_kind"] == ("population" if claim["claim_id"] <= "C-004" else "sample")
        assert claim["artifact_sha256"]
        assert claim["citable"] == (claim["n"] >= 5)
        if not claim["citable"]:
            assert claim["reason"] == "n<5: below the evidence floor"


def test_evaluation_passed_cannot_exceed_total():
    from mcp_server.tools.paper import EvaluationRecord
    with pytest.raises(ValidationError):
        EvaluationRecord(name="pytest", passed=5, total=4)


def test_write_outside_export_dir_is_refused():
    from mcp_server.tools.paper import PaperEvidenceInput, blueteam_paper_evidence_pack
    out = asyncio.run(blueteam_paper_evidence_pack(
        PaperEvidenceInput(output_dir="/etc/paper-evidence", run_id="blocked")))
    payload = json.loads(out)
    assert "Path not allowed" in payload["error"]


def test_path_traversal_is_refused():
    from mcp_server.tools.paper import PaperEvidenceInput, blueteam_paper_evidence_pack
    out = asyncio.run(blueteam_paper_evidence_pack(
        PaperEvidenceInput(output_dir="/tmp/../../etc/paper-evidence", run_id="blocked")))
    assert "Path" in json.loads(out)["error"]


def test_no_paper_orchestra_credentials_in_the_server():
    root = Path(__file__).resolve().parents[1] / "mcp_server"
    forbidden = ("SEMANTIC_SCHOLAR_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                 "VERTEX_AI_PROJECT", "VERTEX_AI_LOCATION", "SMTP_PASSWORD")
    hits = {name: str(path) for name in forbidden for path in root.rglob("*.py")
            if name in path.read_text(encoding="utf-8", errors="ignore")}
    assert not hits, f"PaperOrchestra credential reference in the server: {hits}"
