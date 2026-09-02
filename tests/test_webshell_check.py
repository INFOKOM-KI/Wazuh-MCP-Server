#!/usr/bin/env python3
"""Tests for webshell_check.py signature scanner"""
from __future__ import annotations


def test_scan_body_detects_b374k():
    from mcp_server.tools.webshell_check import _scan_body, _verdict
    body = "<html>b374k shell v2.8</html>"
    matches = _scan_body(body)
    assert len(matches) >= 1
    assert any("b374k" in m["family"] for m in matches)


def test_scan_body_detects_eval_base64():
    from mcp_server.tools.webshell_check import _scan_body, _verdict
    body = "<?php eval(base64_decode('cGhwaW5mbygpOw==')); ?>"
    matches = _scan_body(body)
    assert len(matches) >= 1
    assert any("Obfuscated" in m["family"] for m in matches)


def test_scan_body_detects_system_call():
    from mcp_server.tools.webshell_check import _scan_body
    body = "<?php system('id'); ?>"
    matches = _scan_body(body)
    assert len(matches) >= 1
    assert any("system()" in m["family"] for m in matches)


def test_clean_body_returns_empty():
    from mcp_server.tools.webshell_check import _scan_body, _verdict
    body = "<html><body>TangerangKota</body></html>"
    matches = _scan_body(body)
    assert matches == []


def test_verdict_confirmed():
    from mcp_server.tools.webshell_check import _verdict
    assert _verdict([
        {"weight": "high", "family": "b374k"},
        {"weight": "high", "family": "eval+base64"},
    ]) == "CONFIRMED"
    # Single high-weight match with login page -> suspicious, not login_page.
    assert _verdict([
        {"weight": "high", "family": "b374k"},
    ]) == "SUSPICIOUS"


def test_verdict_suspicious():
    from mcp_server.tools.webshell_check import _verdict
    assert _verdict([
        {"weight": "medium", "family": "system()"},
        {"weight": "medium", "family": "exec()"},
    ]) == "SUSPICIOUS"


def test_verdict_login_page():
    from mcp_server.tools.webshell_check import _verdict
    assert _verdict([
        {"weight": "high", "family": "b374k login page", "is_login_page": True},
    ]) == "LOGIN_PAGE"


def test_login_context_extraction():
    from mcp_server.tools.webshell_check import _extract_login_context
    body = """<html><head><title>b374k mini shell v3.2 :: Login</title></head>
    <body><h1>b374k</h1>
    <form method="post" action="">
    <input type="password" name="pass" placeholder="Password">
    <input type="submit" value="Login">
    </form></body></html>"""
    ctx = _extract_login_context(body)
    assert "b374k" in ctx
    assert "password" in ctx.lower()
    assert "TITLE:" in ctx
    assert "FORMS" in ctx


def test_verdict_clean():
    from mcp_server.tools.webshell_check import _verdict
    assert _verdict([]) == "CLEAN"


def test_url_validation_rejects_private_ip():
    from mcp_server.tools.webshell_check import WebshellCheckInput
    from pydantic import ValidationError
    try:
        WebshellCheckInput(url="http://10.0.0.1/shell.php")
        assert False, "Should have raised"
    except ValidationError:
        pass


def test_url_validation_rejects_hostname_resolving_private(monkeypatch):
    from mcp_server.tools import webshell_check
    from mcp_server.tools.webshell_check import WebshellCheckInput
    from pydantic import ValidationError
    monkeypatch.setattr(webshell_check, "_host_pins", lambda h, allowed: ([], "non-public"))
    try:
        WebshellCheckInput(url="http://evil.example.com/shell.php")
        assert False, "Should have raised"
    except ValidationError:
        pass


def test_pinned_curl_args_uses_resolve(monkeypatch):
    from mcp_server.tools import webshell_check
    from mcp_server.tools.webshell_check import _pinned_curl_args
    monkeypatch.setattr(webshell_check, "_host_pins", lambda h, allowed: (["1.2.3.4"], None))
    args, err = _pinned_curl_args("https://example.com/shell.php")
    assert err is None
    assert args == ["--resolve", "example.com:443:1.2.3.4"]


def test_redirect_target_revalidated(monkeypatch):
    """A redirect to a private host must be rejected, not curled (curl -L gap)."""
    import asyncio
    from mcp_server.tools import webshell_check
    from mcp_server.tools.webshell_check import WebshellCheckInput, blueteam_check_webshell

    calls = []

    async def fake_run(cmd, timeout=0):
        calls.append(cmd)
        return {"stdout": "HTTP_STATUS:302\nCONTENT_TYPE:text/html\nSIZE:0\nREDIRECT:http://127.0.0.1/x\n",
                "stderr": "", "returncode": 0}

    def fake_host_pins(host, allowed):
        return ([], "non-public") if host == "127.0.0.1" else (["1.2.3.4"], None)

    monkeypatch.setattr(webshell_check, "_run_async", fake_run)
    monkeypatch.setattr(webshell_check, "_host_pins", fake_host_pins)

    params = WebshellCheckInput(url="http://public.example/shell.php")
    out = asyncio.run(blueteam_check_webshell(params))
    assert len(calls) == 1, "redirect to private host must not be followed"
    assert "blocked" in out.lower()
    # The single allowed request must have been IP-pinned, not left to curl DNS.
    assert "--resolve" in calls[0]


def test_url_validation_accepts_public_domain():
    from mcp_server.tools.webshell_check import WebshellCheckInput
    ws = WebshellCheckInput(url="https://csirt.tangerangkota.go.id/asu.php")
    assert ws.url == "https://csirt.tangerangkota.go.id/asu.php"


if __name__ == "__main__":
    import sys, traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
