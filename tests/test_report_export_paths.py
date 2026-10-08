#!/usr/bin/env python3
"""Regression tests for the export-directory write scope.

The workflow/playbook report default used to be /tmp, which blueteam_export_report
refuses because the write scope is BLUETEAM_EXPORT_DIR only, so every default run
degraded the report step. The default now resolves from config and the tool creates
the directory itself, returning a typed error when it cannot.
"""
from __future__ import annotations

import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def test_default_report_dir_is_the_configured_export_dir():
    from mcp_server.core.config import config
    from mcp_server.tools.report_export import default_report_dir
    assert default_report_dir() == config.operational.export_dir


def test_workflow_and_playbook_inputs_default_to_the_export_dir():
    from mcp_server.tools.report_export import default_report_dir
    from mcp_server.tools.investigation_workflow import InvestigationWorkflowInput
    from mcp_server.tools.playbook_runner import PlaybookRunInput
    assert InvestigationWorkflowInput(srcip="8.8.8.8").report_dir == default_report_dir()
    assert PlaybookRunInput(srcip="8.8.8.8").report_dir == default_report_dir()


def test_report_step_writes_inside_the_export_dir_by_default(monkeypatch):
    import asyncio, json
    from mcp_server.tools import report_export
    from mcp_server.agents import investigation_graph as ig

    captured: dict = {}

    async def fake_export(params):
        captured["path"] = params.path
        return json.dumps({"path": params.path})

    monkeypatch.setattr(report_export, "blueteam_export_report", fake_export)
    state = asyncio.run(ig.report_step({"generate_report": True, "steps": ["extract: ok"]}))
    export_dir = report_export.default_report_dir()
    assert captured["path"].startswith(export_dir)
    assert state["report_path"].startswith(export_dir)


def test_export_report_refuses_path_outside_export_dir(monkeypatch):
    import asyncio, json
    from mcp_server.tools import report_export

    monkeypatch.setattr(report_export, "OFFICECLI_AVAILABLE", True)
    out = json.loads(asyncio.run(report_export.blueteam_export_report(
        report_export.ReportExportInput(format="docx", path="/tmp/outside.docx"))))
    assert "Path not allowed" in out["error"]
    assert out["allowed"] == [report_export.default_report_dir()]


def test_export_report_reports_unwritable_dir_as_typed_error(monkeypatch, tmp_path):
    import asyncio, json
    from mcp_server.tools import report_export

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    monkeypatch.setattr(report_export, "OFFICECLI_AVAILABLE", True)
    monkeypatch.setattr(report_export, "default_report_dir", lambda: str(blocked))
    out = json.loads(asyncio.run(report_export.blueteam_export_report(
        report_export.ReportExportInput(format="docx", path=str(blocked / "r.docx")))))
    assert "Export directory not writable" in out["error"]


class _CapturingGraph:
    """Records the initial state the entry point built, then reports it as the
    final state so the caller's result assembly still runs."""

    def __init__(self, captured: dict) -> None:
        self._captured = captured

    async def ainvoke(self, state, config=None):
        self._captured["state"] = state
        return dict(state)


def test_run_investigation_resolves_default_report_dir(monkeypatch):
    import asyncio
    from mcp_server.agents import investigation_graph as ig
    from mcp_server.tools.report_export import default_report_dir

    captured: dict = {}
    monkeypatch.setattr(ig, "_investigation_graph", _CapturingGraph(captured))
    monkeypatch.setattr(ig, "_DB_PATH", None)

    asyncio.run(ig.run_investigation(srcip="8.8.8.8"))
    assert captured["state"]["report_dir"] == default_report_dir()

    asyncio.run(ig.run_investigation(srcip="8.8.8.8", report_dir="/explicit"))
    assert captured["state"]["report_dir"] == "/explicit"


def test_run_playbook_resolves_default_report_dir(monkeypatch):
    import asyncio
    from mcp_server.agents import playbook_graph as pg
    from mcp_server.tools.report_export import default_report_dir

    captured: dict = {}

    async def no_rule_index():
        return None

    monkeypatch.setattr(pg, "_playbook_graph", _CapturingGraph(captured))
    monkeypatch.setattr(pg, "_DB_PATH", None)
    monkeypatch.setattr(pg, "_try_load_live_rule_index", no_rule_index)

    asyncio.run(pg.run_playbook(srcip="8.8.8.8"))
    assert captured["state"]["report_dir"] == default_report_dir()

    asyncio.run(pg.run_playbook(srcip="8.8.8.8", report_dir="/explicit"))
    assert captured["state"]["report_dir"] == "/explicit"
