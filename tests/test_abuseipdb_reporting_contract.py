#!/usr/bin/env python3
"""Contract tests for prompt-triggered AbuseIPDB reporting.

These guard the instructions the LLM reads. They do not simulate an LLM; they
fail when the skill or the scheduled prompts drift back to "preview everything"
or start treating analysis/check requests as reporting authorization.
"""
from __future__ import annotations

import os
import pathlib

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer.invalid")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools.abuseipdb import AbuseIPDBReportInput  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL = ROOT / "resource" / "skill" / "soc-analysis.md"
PROMPTS = ROOT / "resource" / "your_prompthings"


def test_skill_distinguishes_reporting_from_analysis_and_check():
    text = SKILL.read_text(encoding="utf-8")
    for phrase in (
        "Check IP reputation",
        "Analyze Wazuh alerts",
        "Preview AbuseIPDB reports",
        "Analyze and report malicious IPs",
        "Routine SOC analysis, scheduled report, or background monitoring",
    ):
        assert phrase in text, f"skill lost its reporting-intent row: {phrase}"
    assert "authorization for this one operation" in text
    assert "without asking for a second per-IP confirmation" in text
    assert "Authorization does not carry over" in text
    assert "prompt-level authorization" in text
    assert "not server-side verification" in text
    assert "Never call this tool from a scheduled or read-only report" in text


def test_tool_schema_defaults_are_preview_and_unconfirmed():
    fields = AbuseIPDBReportInput.model_fields
    assert fields["dry_run"].default is True
    assert fields["confirm"].default is False
    assert "current user prompt" in fields["dry_run"].description
    assert "current user prompt" in fields["confirm"].description


def test_scheduled_prompts_never_authorize_reporting():
    files = sorted(PROMPTS.glob("*.md"))
    assert len(files) == 12
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "blueteam_abuseipdb_report" in text, path.name
        assert ("Do not call `blueteam_abuseipdb_report`" in text
                or "Jangan panggil `blueteam_abuseipdb_report`" in text), path.name
        assert ("never that request" in text
                or "bukan permintaan tersebut" in text), path.name
        assert ("must not have the `threatintel:report` scope" in text
                or "tidak boleh memiliki scope `threatintel:report`" in text), path.name
        assert "dry_run=false" not in text, f"{path.name} must not instruct a live report"
        assert "confirm=true" not in text, f"{path.name} must not instruct a live report"
