"""Opt-in auto-init creates the quota state from the operator's env policy.

No network: the transport is mocked and only the local state file is exercised.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from mcp_server.threat_intel import virustotal as vt


class _Response:
    status_code = 200

    def json(self):
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                    "harmless": 60, "undetected": 10,
                                    "timeout": 0},
            "reputation": 0}}}


def _wire(monkeypatch, tmp_path, autoinit):
    state = tmp_path / "vt.db"

    async def fake_api_call(*args, **kwargs):
        return _Response()

    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(state))
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 5)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET_HOURS", 8.0)
    monkeypatch.setattr(vt, "VIRUSTOTAL_RATE_PER_MINUTE", 4)
    monkeypatch.setattr(vt, "VIRUSTOTAL_DAILY_LIMIT", 500)
    monkeypatch.setattr(vt, "VIRUSTOTAL_AUTOINIT", autoinit)
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "_api_call", fake_api_call)
    vt.reset_state()
    return state


def test_autoinit_creates_the_state_on_the_first_request(monkeypatch, tmp_path):
    state = _wire(monkeypatch, tmp_path, autoinit=True)
    token = vt.issue_consent("ip_addresses", "1.1.1.1")

    result = asyncio.run(vt.lookup("ip_addresses", "1.1.1.1", consent_token=token))

    assert result["malicious"] == 0
    assert state.exists()
    assert oct(state.stat().st_mode & 0o777) == "0o600"
    assert vt._get_quota().state()["spent"] == 1


def test_autoinit_off_still_fails_closed(monkeypatch, tmp_path):
    state = _wire(monkeypatch, tmp_path, autoinit=False)
    token = vt.issue_consent("ip_addresses", "1.1.1.1")

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "1.1.1.1", consent_token=token))

    assert err.value.kind == "state_missing"
    assert str(state) in err.value.message
    assert not state.exists()


def test_autoinit_never_runs_with_a_zero_budget(monkeypatch):
    from mcp_server.core.config import Config

    monkeypatch.setenv("BLUETEAM_VIRUSTOTAL_AUTOINIT", "true")
    monkeypatch.setenv("BLUETEAM_VIRUSTOTAL_BUDGET", "0")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

    with pytest.raises(Exception) as err:
        Config.from_env().validate()
    assert "AUTOINIT" in str(err.value)


def test_failed_autoinit_is_a_provider_error_not_a_crash(monkeypatch, tmp_path):
    from mcp_server.threat_intel import virustotal_quota as quota_mod

    _wire(monkeypatch, tmp_path, autoinit=True)
    token = vt.issue_consent("ip_addresses", "1.1.1.1")

    def broken_init(self):
        raise quota_mod.VirusTotalQuotaError(
            "VirusTotal quota state directory is unavailable",
            "storage_unavailable")

    monkeypatch.setattr(quota_mod.VirusTotalQuota, "auto_initialize", broken_init)

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "1.1.1.1", consent_token=token))
    assert err.value.kind == "storage_unavailable"


def _quota(tmp_path, **over):
    from mcp_server.threat_intel.virustotal_quota import VirusTotalQuota

    opts = dict(budget=5, hours=8.0, rate_per_minute=4, daily_limit=500)
    opts.update(over)
    return VirusTotalQuota(str(tmp_path / "vt.db"), **opts)


def test_deleted_state_is_not_recreated_after_a_budget_existed(tmp_path):
    from mcp_server.threat_intel.virustotal_quota import VirusTotalQuotaError

    quota = _quota(tmp_path)
    quota.initialize(1000.0)
    os.unlink(tmp_path / "vt.db")

    with pytest.raises(VirusTotalQuotaError) as err:
        quota.auto_initialize(2000.0)
    assert err.value.kind == "state_missing"
    assert "refusing to create a new budget" in err.value.message
    assert not (tmp_path / "vt.db").exists()


def test_deleted_state_after_partial_spend_still_refuses(tmp_path):
    quota = _quota(tmp_path)
    quota.initialize(1000.0)
    reservation = quota.reserve(1001.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    assert quota.state(1002.0)["spent"] == 1
    os.unlink(tmp_path / "vt.db")

    with pytest.raises(Exception) as err:
        quota.auto_initialize(2000.0)
    assert "refusing to create a new budget" in str(err.value)


def test_repeated_auto_initialize_keeps_accounting(tmp_path):
    quota = _quota(tmp_path)
    quota.auto_initialize(1000.0)
    reservation = quota.reserve(1001.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    quota.auto_initialize(1002.0)
    assert quota.state(1003.0)["spent"] == 1


def test_concurrent_auto_initialize_creates_one_budget(tmp_path):
    import threading

    quota = _quota(tmp_path)
    errors, barrier = [], threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=5)
            quota.auto_initialize(1000.0)
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert quota.state(1001.0)["budget"] == 5
    assert (tmp_path / "vt.db").exists()


def test_restart_keeps_spend(tmp_path):
    first = _quota(tmp_path)
    first.auto_initialize(1000.0)
    reservation = first.reserve(1001.0)
    first.finalize(reservation.reservation_id, consumed=True)

    second = _quota(tmp_path)
    assert second.state(1002.0)["spent"] == 1


def test_expired_window_is_not_rearmed_by_autoinit(tmp_path):
    from mcp_server.threat_intel.virustotal_quota import VirusTotalQuotaError

    quota = _quota(tmp_path)
    quota.auto_initialize(1000.0)
    with pytest.raises(VirusTotalQuotaError) as err:
        quota.reserve(1000.0 + 9 * 3600)
    assert err.value.kind == "arm_expired"
    quota.auto_initialize(1000.0 + 9 * 3600)
    with pytest.raises(VirusTotalQuotaError) as again:
        quota.reserve(1000.0 + 9 * 3600)
    assert again.value.kind == "arm_expired"


def test_corrupt_state_is_never_reinitialized(tmp_path):
    path = tmp_path / "vt.db"
    path.write_bytes(b"not a database")
    quota = _quota(tmp_path)
    with pytest.raises(Exception) as err:
        quota.reserve(1000.0)
    assert getattr(err.value, "kind", "") in {"state_corrupt", "storage_unavailable"}
    assert path.read_bytes() == b"not a database"


def test_missing_marker_on_an_existing_state_is_adopted(tmp_path):
    quota = _quota(tmp_path)
    quota.auto_initialize(1000.0)
    reservation = quota.reserve(1001.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    os.unlink(str(tmp_path / "vt.db") + ".initialized")

    quota.auto_initialize(1002.0)
    assert (tmp_path / "vt.db.initialized").exists()
    assert quota.state(1003.0)["spent"] == 1


def test_manual_init_requires_force_after_deletion(tmp_path):
    quota = _quota(tmp_path)
    quota.initialize(1000.0)
    os.unlink(tmp_path / "vt.db")

    with pytest.raises(Exception) as err:
        quota.initialize(1001.0)
    assert "force-recreate" in str(err.value)

    quota.initialize(1002.0, force=True)
    assert quota.state(1003.0)["spent"] == 0


def test_audit_failure_does_not_block_a_valid_request(monkeypatch, tmp_path):
    import mcp_server.core.audit as audit

    _wire(monkeypatch, tmp_path, autoinit=True)

    def broken(*args, **kwargs):
        raise RuntimeError("audit sink down")

    monkeypatch.setattr(audit, "_audit_log", broken)
    token = vt.issue_consent("ip_addresses", "1.1.1.1")
    result = asyncio.run(vt.lookup("ip_addresses", "1.1.1.1", consent_token=token))
    assert result["malicious"] == 0


def test_autoinit_audit_payload_names_only_the_state(monkeypatch, tmp_path):
    import mcp_server.core.audit as audit

    _wire(monkeypatch, tmp_path, autoinit=True)
    seen = []
    monkeypatch.setattr(audit, "_audit_log",
                        lambda name, payload, *a, **k: seen.append((name, payload)))
    token = vt.issue_consent("ip_addresses", "1.1.1.1")
    asyncio.run(vt.lookup("ip_addresses", "1.1.1.1", consent_token=token))
    assert seen == [("virustotal_quota_autoinit",
                     {"state": str(tmp_path / "vt.db")})]


def test_no_consent_means_no_initialization_and_no_request(monkeypatch, tmp_path):
    sent = []

    async def forbidden(*args, **kwargs):
        sent.append(1)
        raise AssertionError("transport must not run")

    _wire(monkeypatch, tmp_path, autoinit=True)
    monkeypatch.setattr(vt, "_api_call", forbidden)

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "1.1.1.1"))
    assert err.value.kind == "consent_required"
    assert not (tmp_path / "vt.db").exists()
    assert sent == []
