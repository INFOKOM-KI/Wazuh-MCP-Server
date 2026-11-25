#!/usr/bin/env python3
"""Path-validation regressions for blueteam_read_web_log.

Both explicit and predefined paths must pass BLUETEAM_ALLOWED_PATHS. These tests
use temporary directories and a fake _tail_file; no host log or sensitive file
is read.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer.invalid")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import mcp_server.core.subprocess as sp
import mcp_server.tools.host_forensics as hf
from mcp_server.tools.host_forensics import WebLogInput, blueteam_read_web_log


def _run(coro):
    return asyncio.run(coro)


def _allow(monkeypatch, *paths):
    monkeypatch.setattr(hf, "ALLOWED_PATH_PREFIXES", [str(p) for p in paths])


@pytest.fixture
def tree(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "access.log").write_text("inside line\n", encoding="utf-8")
    (outside / "secret.log").write_text("SENTINEL-OUTSIDE\n", encoding="utf-8")
    return allowed, outside


def test_explicit_path_outside_allowlist_rejected(monkeypatch, tree):
    allowed, outside = tree
    _allow(monkeypatch, allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file", lambda *a, **k: calls.append(a) or "no")
    out = _run(blueteam_read_web_log(WebLogInput(
        path=str(outside / "secret.log"), lines=5)))
    result = json.loads(out)
    assert "Path not allowed" in result["error"]
    assert "SENTINEL-OUTSIDE" not in out
    assert not calls


def test_explicit_path_inside_allowlist_read(monkeypatch, tree):
    allowed, _ = tree
    _allow(monkeypatch, allowed)
    calls = []

    def fake_tail(path, lines):
        calls.append((path, lines))
        return "inside line\n"

    monkeypatch.setattr(hf, "_tail_file", fake_tail)
    out = _run(blueteam_read_web_log(WebLogInput(
        path=str(allowed / "access.log"), lines=5)))
    assert calls == [(str((allowed / "access.log").resolve()), 5)]
    assert "inside line" in out


def test_relative_path_is_resolved_before_tail(monkeypatch, tree):
    allowed, _ = tree
    _allow(monkeypatch, allowed)
    monkeypatch.chdir(allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file",
                        lambda path, lines: calls.append(path) or "relative line")
    out = _run(blueteam_read_web_log(WebLogInput(path="access.log", lines=5)))
    assert calls == [str((allowed / "access.log").resolve())]
    assert "relative line" in out


def test_path_traversal_rejected(monkeypatch, tree):
    allowed, outside = tree
    _allow(monkeypatch, allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file", lambda *a, **k: calls.append(a) or "no")
    out = _run(blueteam_read_web_log(WebLogInput(
        path=str(allowed / ".." / "outside" / "secret.log"), lines=5)))
    result = json.loads(out)
    assert "Path not allowed" in result["error"]
    assert "Path traversal" in result["error"]
    assert not calls


def test_symlink_escape_rejected(monkeypatch, tree):
    allowed, outside = tree
    link = allowed / "link.log"
    try:
        link.symlink_to(outside / "secret.log")
    except OSError:
        pytest.skip("symlink creation is not permitted on this filesystem")
    _allow(monkeypatch, allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file", lambda *a, **k: calls.append(a) or "no")
    out = _run(blueteam_read_web_log(WebLogInput(path=str(link), lines=5)))
    result = json.loads(out)
    assert "Path not allowed" in result["error"]
    assert "SENTINEL-OUTSIDE" not in out
    assert not calls


def test_symlink_inside_allowlist_allowed(monkeypatch, tree):
    allowed, _ = tree
    link = allowed / "inside-link.log"
    try:
        link.symlink_to(allowed / "access.log")
    except OSError:
        pytest.skip("symlink creation is not permitted on this filesystem")
    _allow(monkeypatch, allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file",
                        lambda path, lines: calls.append(path) or "inside line")
    out = _run(blueteam_read_web_log(WebLogInput(path=str(link), lines=5)))
    assert calls == [str((allowed / "access.log").resolve())]
    assert "inside line" in out


def test_prefix_boundary_rejected(monkeypatch, tmp_path):
    log_dir = tmp_path / "log"
    log_other = tmp_path / "log-other"
    log_dir.mkdir()
    log_other.mkdir()
    (log_other / "secret.log").write_text("SENTINEL-OUTSIDE\n", encoding="utf-8")
    _allow(monkeypatch, log_dir)
    calls = []
    monkeypatch.setattr(hf, "_tail_file", lambda *a, **k: calls.append(a) or "no")
    out = _run(blueteam_read_web_log(WebLogInput(
        path=str(log_other / "secret.log"), lines=5)))
    result = json.loads(out)
    assert "Path not allowed" in result["error"]
    assert not calls


def test_tail_uses_option_terminator(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, timeout=sp.TIMEOUT):
        captured["cmd"] = cmd
        return {"stdout": "ok", "stderr": "", "returncode": 0}

    monkeypatch.setattr(sp, "_run", fake_run)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "-n").write_text("line\n", encoding="utf-8")
    assert sp._tail_file("-n", 5) == "ok"
    assert captured["cmd"] == ["tail", "-n", "5", "--", "-n"]


def test_default_log_type_allowed_when_var_is_allowed(monkeypatch):
    monkeypatch.setattr(hf, "ALLOWED_PATH_PREFIXES", ["/var/log"])
    calls = []
    monkeypatch.setattr(hf, "_tail_file",
                        lambda path, lines: calls.append((path, lines)) or "default line")
    out = _run(blueteam_read_web_log(WebLogInput(
        server="nginx", log_type="access", lines=5)))
    assert calls == [("/var/log/nginx/access.log", 5)]
    assert "default line" in out


def test_default_log_type_rejected_when_allowlist_is_narrowed(monkeypatch, tree):
    allowed, _ = tree
    _allow(monkeypatch, allowed)
    calls = []
    monkeypatch.setattr(hf, "_tail_file",
                        lambda *a, **k: calls.append(a) or "no")
    out = _run(blueteam_read_web_log(WebLogInput(
        server="nginx", log_type="access", lines=5)))
    result = json.loads(out)
    assert "Path not allowed" in result["error"]
    assert "default line" not in out
    assert not calls
