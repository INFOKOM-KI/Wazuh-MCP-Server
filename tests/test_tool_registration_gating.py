#!/usr/bin/env python3
"""Registration matrix for WAZUH_DISABLED_TOOLS, category, and read-only gating.

Each case runs in a fresh interpreter because the FastMCP registry and the
configuration singleton are populated at import time. No network is used.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

# The repository conftest imports mcp_server before this module runs; seed the
# mandatory Indexer values so the autouse fixture can import it.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer.invalid")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECK = "blueteam_abuseipdb_check"
REPORT = "blueteam_abuseipdb_report"
FAIL2BAN_UNBAN = "blueteam_fail2ban_unban"
FAIL2BAN_STATUS = "blueteam_fail2ban_status"

_SCRIPT = """
import json
from mcp_server.tools import register_all_tools
from mcp_server import mcp
register_all_tools()
print("RESULT:" + json.dumps(sorted(mcp._tool_manager._tools)))
"""


def _registered(extra_env: dict[str, str]) -> list[str]:
    env = os.environ.copy()
    for key in ("WAZUH_DISABLED_TOOLS", "WAZUH_DISABLED_CATEGORIES",
                "WAZUH_READ_ONLY", "BLUETEAM_ABUSEIPDB_REPORTING_ENABLED",
                "MCP_API_KEY", "MCP_API_KEY_SCOPES"):
        env.pop(key, None)
    env.update({
        "PYTHONPATH": str(ROOT),
        "WAZUH_INDEXER_URL": "https://indexer.invalid",
        "WAZUH_INDEXER_PASSWORD": "test-indexer-pass",
        "BLUETEAM_RERANK_ENABLED": "false",
        "BLUETEAM_ABUSEIPDB_REPORTING_ENABLED": "false",
    })
    env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-c", _SCRIPT], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT:")), None)
    assert line is not None, proc.stdout[-2000:]
    return json.loads(line.split("RESULT:", 1)[1])


def test_baseline_registers_both_abuseipdb_tools():
    names = _registered({})
    assert CHECK in names and REPORT in names
    assert len(names) == 166


def test_disabled_report_keeps_check_registered():
    names = _registered({"WAZUH_DISABLED_TOOLS": REPORT})
    assert CHECK in names
    assert REPORT not in names
    assert len(names) == 165


def test_disabled_check_keeps_report_registered():
    names = _registered({"WAZUH_DISABLED_TOOLS": CHECK})
    assert REPORT in names
    assert CHECK not in names
    assert len(names) == 165


def test_disabled_names_are_case_insensitive_and_trimmed():
    names = _registered({"WAZUH_DISABLED_TOOLS": "  Blueteam_AbuseIPDB_Report  "})
    assert CHECK in names
    assert REPORT not in names
    assert len(names) == 165


def test_disabling_both_abuseipdb_tools_leaves_other_tools_alone():
    names = _registered({"WAZUH_DISABLED_TOOLS": f"{CHECK},{REPORT}"})
    assert CHECK not in names and REPORT not in names
    assert FAIL2BAN_UNBAN in names
    assert len(names) == 164


def test_disabled_tool_does_not_remove_its_siblings():
    names = _registered({"WAZUH_DISABLED_TOOLS": f"{REPORT},{FAIL2BAN_UNBAN}"})
    assert CHECK in names and REPORT not in names
    assert FAIL2BAN_UNBAN not in names
    assert FAIL2BAN_STATUS in names
    assert len(names) == 164


def test_category_gating_still_skips_the_whole_abuseipdb_module():
    names = _registered({"WAZUH_DISABLED_CATEGORIES": "abuseipdb"})
    assert CHECK not in names and REPORT not in names
    assert FAIL2BAN_UNBAN in names
    assert len(names) == 164


def test_read_only_still_skips_the_abuseipdb_module():
    names = _registered({"WAZUH_READ_ONLY": "true"})
    assert CHECK not in names and REPORT not in names
    assert len(names) == 138


def test_read_only_plus_disabled_report_is_still_both_absent():
    names = _registered({"WAZUH_READ_ONLY": "true", "WAZUH_DISABLED_TOOLS": REPORT})
    assert CHECK not in names and REPORT not in names
    assert len(names) == 138


def test_reporting_flag_false_does_not_change_registration():
    names = _registered({
        "WAZUH_DISABLED_TOOLS": REPORT,
        "BLUETEAM_ABUSEIPDB_REPORTING_ENABLED": "false",
    })
    assert CHECK in names and REPORT not in names
    assert len(names) == 165
