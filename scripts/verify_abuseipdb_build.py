"""Print which AbuseIPDB build this interpreter loads and whether it accepts a batch comment.

Run on the host that serves the MCP tool, inside the same environment as the server:

    python3 scripts/verify_abuseipdb_build.py

Exit 0 means the loaded code accepts one comment for several srcips.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # run from a checkout, uninstalled

OLD_RULE = "comment/timestamp require exactly one explicit srcip"


def main() -> int:
    from mcp_server.tools import abuseipdb

    path = inspect.getfile(abuseipdb)
    source = inspect.getsource(abuseipdb)
    print(f"module      : {path}")
    print(f"interpreter : {sys.executable}")
    print(f"cwd         : {os.getcwd()}")
    print(f"git HEAD    : {_git_head(path)}")
    print(f"old rule    : {'PRESENT (pre-fix)' if OLD_RULE in source else 'absent (fixed)'}")

    try:
        model = abuseipdb.AbuseIPDBReportInput(
            srcips=["8.8.8.8", "8.8.4.4"], comment="batch comment probe")
    except ValidationError as exc:
        print(f"batch probe : FAIL -> {exc}")
        return 1
    print(f"batch probe : PASS -> {len(model.srcips)} srcips accepted")
    return 0


def _git_head(module_path: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", os.path.dirname(module_path), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
