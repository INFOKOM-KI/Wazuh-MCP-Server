"""Consent refusal reasons: one branch per cause, no HTTP, no quota.

Offline only. The fake contexts below mirror the attributes the real FastMCP
Context exposes on the path `request_ioc_sharing_detailed` reads.
"""
from __future__ import annotations

import anyio
import pytest
from types import SimpleNamespace

from mcp_server.threat_intel import virustotal_consent as consent


class _Session:
    def __init__(self, version="2025-06-18", elicitation=True):
        self.client_params = SimpleNamespace(protocolVersion=version)
        self._elicitation = elicitation

    def check_client_capability(self, capability):
        return self._elicitation


class _Ctx:
    def __init__(self, *, version="2025-06-18", elicitation=True,
                 action="accept", approve=True, raises=None):
        self.request_context = SimpleNamespace(session=_Session(version, elicitation))
        self.action = action
        self.approve = approve
        self.raises = raises
        self.calls = 0

    async def elicit(self, message, schema):
        self.calls += 1
        if self.raises:
            raise self.raises
        return SimpleNamespace(action=self.action,
                               data=SimpleNamespace(approve=self.approve))


class _NoParams:
    def __init__(self):
        self.client_params = None


def _ask(ctx):
    return anyio.run(consent.request_ioc_sharing_detailed, ctx, "consent?")


def test_context_missing():
    decision = _ask(None)
    assert decision.approved is False and decision.reason == "context_missing"
    assert bool(decision) is False


def test_session_without_client_params_is_context_missing():
    ctx = SimpleNamespace(request_context=SimpleNamespace(session=_NoParams()))
    assert _ask(ctx).reason == "context_missing"


def test_approved():
    ctx = _Ctx()
    decision = _ask(ctx)
    assert decision.approved is True and decision.reason == "approved"
    assert ctx.calls == 1


def test_missing_elicitation_capability():
    decision = _ask(_Ctx(elicitation=False))
    assert decision.reason == "elicitation_capability_missing"


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26"])
def test_unsupported_protocol(version):
    decision = _ask(_Ctx(version=version))
    assert decision.reason == "unsupported_protocol"
    assert decision.detail == f"requested={version}"


def test_older_revision_is_never_prompted():
    ctx = _Ctx(version="2025-03-26")
    assert _ask(ctx).approved is False
    assert ctx.calls == 0


def test_user_declines():
    assert _ask(_Ctx(action="decline")).reason == "user_declined"


def test_user_cancels():
    assert _ask(_Ctx(action="cancel")).reason == "user_cancelled"


def test_accepted_form_without_the_box_ticked_is_not_a_decline():
    decision = _ask(_Ctx(approve=False))
    assert decision.reason == "approval_not_given"
    assert decision.detail == "approve=false"


@pytest.mark.parametrize("approve", ["yes", 1, None])
def test_invalid_approval_payload(approve):
    decision = _ask(_Ctx(approve=approve))
    assert decision.approved is False
    assert decision.reason == "invalid_approval_response"


def test_elicitation_exception():
    decision = _ask(_Ctx(raises=RuntimeError("no prompt here")))
    assert decision.reason == "elicitation_error"
    assert decision.detail == "RuntimeError"


def test_boolean_wrapper_matches_the_detailed_result():
    assert anyio.run(consent.request_ioc_sharing, _Ctx(), "consent?") is True
    assert anyio.run(consent.request_ioc_sharing, _Ctx(approve=False), "x") is False


def test_client_action_cannot_forge_a_log_line():
    decision = _ask(_Ctx(action="accept\nforged entry"))
    assert decision.reason == "invalid_approval_response"
    assert "\n" not in decision.detail


def test_reason_does_not_leak_the_prompt_text(monkeypatch):
    seen = []
    monkeypatch.setattr(consent.logger, "info",
                        lambda msg, *args: seen.append((msg % args) if args else msg))
    _ask(_Ctx(action="decline"))
    assert all("consent?" not in line for line in seen)
    assert any("user_declined" in line for line in seen)
