#!/usr/bin/env python3
"""Draft claim checker: citable gate, number tracing, ten seeded fakes."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core.config import config
from mcp_server.core.paper_evidence import check_draft
from mcp_server.tools.paper import ClaimCheckInput, blueteam_paper_claim_check

CLAIMS = {
    "C-001": {"claim_id": "C-001", "display": "168", "value": 168, "n": 168,
              "n_kind": "population", "citable": True, "reason": ""},
    "C-005": {"claim_id": "C-005", "display": "0", "value": 0, "n": 0,
              "n_kind": "sample", "citable": False,
              "reason": "n<5: below the evidence floor"},
    "C-009": {"claim_id": "C-009", "display": "120 alerts (24h window)", "value": 120,
              "n": 120, "n_kind": "sample", "citable": True, "reason": ""},
}

FAKES = ["999", "4242", "77.7", "3.14", "90210", "555", "17", "64.8", "1234", "6.28"]


def test_citable_claims_and_their_numbers_pass():
    out = check_draft("The server exposes {{C-001}} tools, or {{C-009}}.", CLAIMS, "complete")
    assert out["ok"] is True
    assert out["claims_resolved"] == 2
    assert out["unsupported_numbers"] == []


def test_non_citable_claim_fails_with_the_normalized_reason():
    out = check_draft("Only {{C-005}} cases.", CLAIMS, "degraded")
    assert out["ok"] is False
    assert out["errors"] == [{"claim_id": "C-005",
                              "reason": "n<5: below the evidence floor"}]


def test_unknown_claim_fails():
    out = check_draft("{{C-999}}", CLAIMS, "complete")
    assert out["errors"][0]["reason"] == "unknown claim id"


def test_ten_seeded_fakes_are_all_flagged():
    draft = " ".join(f"claim {number}" for number in FAKES)
    out = check_draft(draft, CLAIMS, "complete")
    flagged = {row["number"] for row in out["unsupported_numbers"]}
    assert flagged == set(FAKES)
    assert out["ok"] is False


@pytest.mark.parametrize("sentence,fake", [
    ("Table 5 shows 8888 alerts.", "8888"),
    ("Section 2.3 says 8888 alerts.", "8888"),
    ("Eq. 4 gives 8888 alerts.", "8888"),
    ("Observed CVE-2021-44228 in 8888 alerts.", "8888"),
    ("Observed T1071.001 in 8888 alerts.", "8888"),
    ("Observed CWE-79 in 8888 alerts.", "8888"),
    ("Observed rule 100017 in 8888 alerts.", "8888"),
    ("Observed rule.id 100017 in 8888 alerts.", "8888"),
    ("Observed SHA-256 in 8888 alerts.", "8888"),
    ("Observed TLS 1.3 in 8888 alerts.", "8888"),
    ("Observed TLS 1.2/1.3 in 8888 alerts.", "8888"),
    ("Observed IPv4/IPv6 in 8888 alerts.", "8888"),
    ("Observed IPv4 in 8888 alerts.", "8888"),
    ("Observed AES-256 in 8888 alerts.", "8888"),
    ("Observed RSA-2048 in 8888 alerts.", "8888"),
    ("Observed FIPS 140-2 in 8888 alerts.", "8888"),
    ("Observed HTTP/2 in 8888 alerts.", "8888"),
])
def test_identifier_is_skipped_but_the_data_number_is_flagged(sentence, fake):
    out = check_draft(sentence, CLAIMS, "complete")
    assert [row["number"] for row in out["unsupported_numbers"]] == [fake]


def test_structural_refs_and_years_are_ignored():
    out = check_draft("Section 3, Table 4, Figure 5, Equation 6, published in 2024.",
                      CLAIMS, "complete")
    assert out["unsupported_numbers"] == []
    assert out["ok"] is True


def _write_pack() -> str:
    root = Path(config.operational.export_dir) / "paper" / "check-01"
    root.mkdir(parents=True, exist_ok=True)
    (root / "claims.json").write_text(json.dumps(list(CLAIMS.values())), encoding="utf-8")
    (root / "manifest.json").write_text(json.dumps({"pack_status": "complete"}),
                                       encoding="utf-8")
    return str(root / "claims.json")


def test_tool_returns_json_verdict():
    claims_path = _write_pack()
    out = asyncio.run(blueteam_paper_claim_check(ClaimCheckInput(
        draft="The server exposes {{C-001}} tools.",
        claims_path=claims_path, response_format="json")))
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["claims_resolved"] == 1


def test_tool_refuses_a_path_outside_the_export_dir():
    out = asyncio.run(blueteam_paper_claim_check(ClaimCheckInput(
        draft="text", claims_path="/etc/claims.json")))
    assert "claims_path not allowed" in json.loads(out)["error"]
