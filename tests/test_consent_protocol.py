"""Protocol-level tests for the VirusTotal consent elicitation.

These use the installed MCP Python SDK and a real stdio / streamable-HTTP
server process. The elicitation callback is simulated: it proves the protocol
path, not that a human saw the prompt.
"""
from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

import anyio
from mcp import types

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_USER", "test")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test")
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "tests" / "support" / "consent_protocol_server.py"


def _env(port: int = 0) -> dict[str, str]:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "WAZUH_INDEXER_URL": "https://127.0.0.1:9200",
        "WAZUH_INDEXER_USER": "test",
        "WAZUH_INDEXER_PASSWORD": "test",
        "WAZUH_MANAGER_URL": "",
    }
    if port:
        env["CONSENT_TEST_PORT"] = str(port)
    return env


def _approval(action: str = "accept", approve: bool = True) -> types.ElicitResult:
    if action == "accept":
        return types.ElicitResult(action="accept", content={"approve": approve})
    return types.ElicitResult(action=action)


async def _stdio_call(*, version: str | None = None, callback=None,
                      count: int = 1) -> tuple[str, list[dict], list[str]]:
    old_version = types.LATEST_PROTOCOL_VERSION
    if version is not None:
        types.LATEST_PROTOCOL_VERSION = version
    prompts: list[str] = []
    results: list[dict] = []
    try:
        async def handler(ctx, params):
            prompts.append(params.message)
            return await callback(ctx, params)

        async with stdio_client(StdioServerParameters(
                command=os.sys.executable, args=[str(SERVER)], env=_env(),
                cwd=str(ROOT))) as (read, write):
            async with ClientSession(
                    read, write,
                    elicitation_callback=handler if callback else None) as session:
                initialized = await session.initialize()
                for _ in range(count):
                    result = await session.call_tool(
                        "consent_probe", {"ip": "8.8.8.8"})
                    results.append(result.structuredContent)
                return initialized.protocolVersion, results, prompts
    finally:
        types.LATEST_PROTOCOL_VERSION = old_version


def test_legacy_2025_06_18_approval() -> None:
    async def approve(ctx, params):
        return _approval()

    version, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-06-18", callback=approve))
    assert version == "2025-06-18"
    assert results == [{"approved": True, "token_valid": True}]
    assert len(prompts) == 1
    assert "8.8.8.8" in prompts[0]
    assert "community" in prompts[0]


def test_legacy_2025_03_26_has_no_elicitation_and_fails_closed() -> None:
    async def approve(ctx, params):
        return _approval()

    version, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-03-26", callback=approve))
    assert version == "2025-03-26"
    assert results == [{"approved": False, "token_valid": False}]
    assert prompts == []


def test_decline_then_retry_approval_is_not_reused() -> None:
    actions = iter(("decline", "accept"))

    async def decide(ctx, params):
        action = next(actions)
        return _approval(action)

    version, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-06-18", callback=decide, count=2))
    assert version == "2025-06-18"
    assert results == [
        {"approved": False, "token_valid": False},
        {"approved": True, "token_valid": True},
    ]
    assert len(prompts) == 2


def test_cancel_does_not_issue_a_token() -> None:
    async def cancel(ctx, params):
        return _approval("cancel")

    _, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-06-18", callback=cancel))
    assert results == [{"approved": False, "token_valid": False}]
    assert len(prompts) == 1


def test_client_without_elicitation_capability_fails_closed() -> None:
    _, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-06-18", callback=None))
    assert results == [{"approved": False, "token_valid": False}]
    assert prompts == []


def test_2026_client_negotiates_down_to_2025_legacy_elicit() -> None:
    async def approve(ctx, params):
        return _approval()

    version, results, prompts = anyio.run(
        lambda: _stdio_call(version="2026-07-28", callback=approve))
    assert version == "2025-11-25"
    assert results == [{"approved": True, "token_valid": True}]
    assert len(prompts) == 1


def test_http_consent_decline_then_approval() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    process = subprocess.Popen(
        [os.sys.executable, str(SERVER), "--http"],
        env=_env(port), cwd=str(ROOT), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    actions = iter(("decline", "accept"))

    async def scenario():
        prompts: list[str] = []

        async def decide(ctx, params):
            prompts.append(params.message)
            return _approval(next(actions))

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                await anyio.sleep(0.05)
        else:
            raise AssertionError("HTTP consent test server did not start")
        async with streamable_http_client(
                f"http://127.0.0.1:{port}/mcp") as (read, write, _):
            async with ClientSession(read, write,
                                     elicitation_callback=decide) as session:
                initialized = await session.initialize()
                first = await session.call_tool(
                    "consent_probe", {"ip": "8.8.8.8"})
                second = await session.call_tool(
                    "consent_probe", {"ip": "8.8.8.8"})
                return initialized.protocolVersion, first, second, prompts

    try:
        version, first, second, prompts = anyio.run(scenario)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    assert version == "2025-11-25"
    assert first.structuredContent == {"approved": False, "token_valid": False}
    assert second.structuredContent == {"approved": True, "token_valid": True}
    assert len(prompts) == 2


def test_negotiated_2026_gate_fails_closed(monkeypatch) -> None:
    from types import SimpleNamespace

    from mcp_server.threat_intel import virustotal_consent as consent

    class FakeContext:
        async def elicit(self, message, schema):
            raise AssertionError("2026-native elicitation must not be attempted")

        request_context = SimpleNamespace(
            session=SimpleNamespace(
                client_params=SimpleNamespace(protocolVersion="2026-07-28")))

    monkeypatch.setattr(consent, "LATEST_PROTOCOL_VERSION", "2026-07-28")
    approved = anyio.run(
        consent.request_ioc_sharing, FakeContext(), "consent?")
    assert approved is False


def test_2026_client_negotiates_down_and_declines() -> None:
    async def decline(ctx, params):
        return _approval("decline")

    version, results, prompts = anyio.run(
        lambda: _stdio_call(version="2026-07-28", callback=decline))
    assert version == "2025-11-25"
    assert results == [{"approved": False, "token_valid": False}]
    assert len(prompts) == 1


def test_malformed_approval_is_treated_as_refusal() -> None:
    async def malformed(ctx, params):
        return types.ElicitResult(action="accept", content={"approve": "yes"})

    _, results, prompts = anyio.run(
        lambda: _stdio_call(version="2025-06-18", callback=malformed))
    assert results == [{"approved": False, "token_valid": False}]
    assert len(prompts) == 1
