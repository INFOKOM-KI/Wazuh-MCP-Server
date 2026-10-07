#!/usr/bin/env python3
"""
Tests for mcp_server/core/redact.py - 6-layer PII redaction pipeline.
IMPORTANT: Module-level constants are read at import time from os.environ.
Set env vars BEFORE importing.  Some tests monkey-patch module attrs for
raw/forensic policy tests that need runtime toggles.
"""
from __future__ import annotations

import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")
os.environ.setdefault("BLUETEAM_OWNED_DOMAINS", "")
os.environ.setdefault("BLUETEAM_ALLOW_FORENSIC_BYPASS", "false")
os.environ.setdefault("BLUETEAM_FORENSIC_TOKEN", "")

import pytest
from unittest.mock import patch

import mcp_server.core.redact as _redact_mod
from mcp_server.core.redact import (
    _redact_alert_data,
    _strip_credentials,
    _is_owned_domain,
    _resolve_policy,
    _is_hostname_candidate,
    _mask_domain,
)


class TestCredentialStripping:

    def test_strips_bearer_in_log_text(self):
        """Bearer token in full log-line format is stripped."""
        result = _strip_credentials("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def")
        assert "REDACTED" in result
        assert "eyJhbGci" not in result

    def test_strips_api_key_in_log_text(self):
        result = _strip_credentials("x-api-key: sk-abc123def456")
        assert "API_KEY_REDACTED" in result

    def test_strips_jwt_token(self):
        result = _strip_credentials("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx")
        assert "JWT_REDACTED" in result

    def test_strips_password_param(self):
        result = _strip_credentials("password=supersecret123")
        assert "PASSWORD_REDACTED" in result
        assert "supersecret123" not in result

    def test_preserves_non_credential_text(self):
        text = "srcip=8.8.8.8 user=admin action=login"
        result = _strip_credentials(text)
        assert "8.8.8.8" in result
        assert "admin" in result

    def test_recursive_list_strip(self):
        data = ["safe", "Authorization: Bearer xyz", {"key": "password=secret"}]
        result = _strip_credentials(data)
        assert result[0] == "safe"
        assert "REDACTED" in result[1]
        assert "PASSWORD_REDACTED" in result[2]["key"]


class TestEmailRedaction:

    def test_full_policy_masks_emails(self):
        data = "Contact admin@example.com"
        result = _redact_alert_data(data, policy="full")
        assert "admin@example.com" not in result


class TestIPMasking:

    def test_masks_rfc1918_ips(self):
        data = "srcip=192.168.1.100 dstip=10.0.0.5"
        result = _redact_alert_data(data, policy="full")
        assert "192.168.1.100" not in result
        assert "10.0.0.5" not in result

    def test_preserves_public_ips(self):
        data = "srcip=8.8.8.8 dstip=1.1.1.1"
        result = _redact_alert_data(data, policy="full")
        assert "8.8.8.8" in result
        assert "1.1.1.1" in result

    def test_masks_loopback(self):
        data = "error from 127.0.0.1: connection refused"
        result = _redact_alert_data(data, policy="full")
        assert "127.0.0.1" not in result

    def test_public_ips_always_preserved(self):
        data = "attacker_ip=45.33.32.156"
        result = _redact_alert_data(data, policy="full")
        assert "45.33.32.156" in result


class TestDomainMasking:

    def test_masks_third_level_subdomain(self):
        """_mask_domain masks subdomains of 3+ parts (e.g. admin.example.com)."""
        assert _mask_domain("admin.example.com") != "admin.example.com"
        assert "example.com" in _mask_domain("admin.example.com")  # TLD visible

    def test_preserves_two_part_domain(self):
        """2-part domains (evil.cn) are NOT masked; only subdomains are."""
        assert _mask_domain("evil.cn") == "evil.cn"

    def test_full_policy_masks_subdomain_in_text(self):
        data = "curl http://admin.internal.corp/shell.sh"
        result = _redact_alert_data(data, policy="full")
        # admin.internal.corp is 3-part -> should be masked
        assert "admin.internal.corp" not in result


class TestPolicyResolution:

    def test_defaults_to_env(self):
        assert _resolve_policy(False, None, None) == "full"

    def test_bypass_flag_overrides(self):
        assert _resolve_policy(True, None, None) == "raw"

    def test_explicit_policy_wins(self):
        assert _resolve_policy(False, None, "protect_victim") == "protect_victim"

    def test_invalid_policy_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            _resolve_policy(False, None, "bogus")


class TestHostnameCandidate:

    def test_rejects_alpha_only(self):
        assert _is_hostname_candidate("web") is False

    def test_accepts_with_digit(self):
        assert _is_hostname_candidate("db1") is True

    def test_accepts_with_hyphen(self):
        assert _is_hostname_candidate("web-01") is True

    def test_rejects_numeric_only(self):
        """A terms agg on rule.id returns digits; masking them hides every top-rule table."""
        assert _is_hostname_candidate("31151") is False
        assert _is_hostname_candidate("3302") is False


def test_numeric_bucket_keys_survive_protect_victim():
    """Only hostname-shaped keys are masked, not rule ids standing in the same position."""
    data = {"aggregations": {"by_rule": {"buckets": [
        {"key": "31151", "doc_count": 124223},
        {"key": "web-01", "doc_count": 3},
    ]}}}
    result = _redact_alert_data(data, policy="protect_victim")
    keys = [b["key"] for b in result["aggregations"]["by_rule"]["buckets"]]
    assert keys[0] == "31151"
    assert keys[1] != "web-01"


class TestRawPolicyGate:

    def test_raw_policy_strips_credentials(self):
        """Raw policy strips credentials, preserves everything else."""
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", True):
            data = "Authorization: Bearer abc123 user=admin ip=192.168.1.1"
            result = _redact_alert_data(data, policy="raw")
            assert "REDACTED" in result
            assert "admin" in result
            assert "192.168.1.1" in result

    def test_raw_rejected_when_disabled(self):
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", False):
            with pytest.raises(ValueError, match="BLUETEAM_ALLOW_FORENSIC_BYPASS"):
                _redact_alert_data("test", policy="raw")


class TestOwnedDomainDetection:

    def test_exact_match(self):
        with patch.object(_redact_mod, "_OWNED_DOMAINS", {"tangerangkota.go.id"}):
            assert _is_owned_domain("tangerangkota.go.id") is True

    def test_subdomain_match(self):
        with patch.object(_redact_mod, "_OWNED_DOMAINS", {"tangerangkota.go.id"}):
            assert _is_owned_domain("mail.tangerangkota.go.id") is True

    def test_unrelated_not_owned(self):
        with patch.object(_redact_mod, "_OWNED_DOMAINS", {"tangerangkota.go.id"}):
            assert _is_owned_domain("evil.cn") is False


def _nested(path: str, value):
    node = value
    for part in reversed(path.split(".")):
        node = {part: node}
    return node


def _dig(doc, path: str):
    node = doc
    for part in path.split("."):
        node = node[part]
    return node


IDENTITY_PATHS = (
    "data.win.eventdata.subjectUserName",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserSid",
    "data.win.eventdata.targetUserSid",
    "data.win.system.userID",
    "data.win.system.securityUserID",
    "data.audit.acct",
    "data.audit.uid",
    "data.audit.euid",
    "data.aws.userIdentity.userName",
    "data.aws.userIdentity.accountId",
    "data.office365.UserId",
    "data.office365.Actor.ID",
    "data.ms-graph.userPrincipalName",
    "data.ms-graph.userId",
    "data.ms-graph.actor.userPrincipalName",
    "data.ms-graph.actor.userId",
    "syscheck.audit.user.name",
    "syscheck.uid_before",
    "syscheck.uname_before",
    "data.process.euser",
    "data.process.ruser",
    "data.process.suser",
    "data.srcuser",
    "data.dstuser",
)


class TestIdentityPathMasking:

    @pytest.mark.parametrize("policy", ["full", "protect_victim"])
    def test_identity_paths_masked_under_both_policies(self, policy):
        for path in IDENTITY_PATHS:
            out = _redact_alert_data(_nested(path, "jdoe.smith"), policy=policy)
            value = _dig(out, path)
            assert value != "jdoe.smith", f"{path} under {policy}"
            assert "***" in value, f"{path} under {policy}"

    def test_sid_values_are_masked(self):
        doc = _nested("data.win.eventdata.subjectUserSid", "S-1-5-21-111-222-333-1001")
        out = _redact_alert_data(doc, policy="full")
        value = _dig(out, "data.win.eventdata.subjectUserSid")
        assert "S-1-5-21" not in value
        assert "[h:" in value

    def test_identity_masking_disabled_by_env_flag(self):
        doc = _nested("data.win.eventdata.subjectUserName", "jdoe")
        with patch.object(_redact_mod, "BLUETEAM_REDACT_IDENTITIES", False):
            out = _redact_alert_data(doc, policy="full")
        assert _dig(out, "data.win.eventdata.subjectUserName") == "jdoe"

    def test_credential_protection_survives_identity_flag_off(self):
        doc = _nested("data.aws.requestParameters.masterUserPassword", "hunter2")
        with patch.object(_redact_mod, "BLUETEAM_REDACT_IDENTITIES", False):
            out = _redact_alert_data(doc, policy="full")
        assert _dig(out, "data.aws.requestParameters.masterUserPassword") == "<CREDENTIAL_REDACTED>"

    def test_non_identity_fields_preserved(self):
        doc = {"rule": {"id": "5710", "description": "sshd: attempted login"},
               "data": {"process": {"name": "nginx", "state": "running"},
                        "win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing"}}}}
        out = _redact_alert_data(doc, policy="full")
        assert out["rule"]["id"] == "5710"
        assert out["rule"]["description"] == "sshd: attempted login"
        assert out["data"]["process"]["name"] == "nginx"
        assert out["data"]["process"]["state"] == "running"
        assert out["data"]["win"]["system"]["providerName"] == "Microsoft-Windows-Security-Auditing"


class TestCredentialKeyLayer:

    def test_master_user_password_is_masked(self):
        out = _redact_alert_data(_nested("data.aws.requestParameters.masterUserPassword", "hunter2"),
                                 policy="full")
        assert _dig(out, "data.aws.requestParameters.masterUserPassword") == "<CREDENTIAL_REDACTED>"

    def test_secret_bearing_paths_are_masked(self):
        paths = ("data.aws.requestParameters.masterUsername",
                 "data.ms-graph.activationLockBypassCode",
                 "data.ms-graph.deviceHealthAttestationState.attestationIdentityKey")
        for path in paths:
            out = _redact_alert_data(_nested(path, "secret-value"), policy="full")
            assert _dig(out, path) == "<CREDENTIAL_REDACTED>", path

    def test_asia_temporary_key_is_stripped(self):
        key = "ASIAABCDEFGHIJKLMNOP"
        assert key not in _strip_credentials(f"access_key={key}")
        assert "CLOUD_API_KEY_REDACTED" in _strip_credentials(key)

    def test_credential_layer_mandatory_under_raw(self):
        doc = _nested("data.aws.requestParameters.masterUserPassword", "hunter2")
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", True):
            out = _redact_alert_data(doc, policy="raw")
        assert _dig(out, "data.aws.requestParameters.masterUserPassword") == "<CREDENTIAL_REDACTED>"

    def test_identity_not_masked_under_raw(self):
        doc = _nested("data.win.eventdata.subjectUserName", "jdoe")
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", True):
            out = _redact_alert_data(doc, policy="raw")
        assert _dig(out, "data.win.eventdata.subjectUserName") == "jdoe"

    def test_key_like_allowlisted_fields_preserved(self):
        doc = {"data": {"audit": {"key": "audit-wazuh"},
                        "win": {"eventdata": {"keyName": "HKLM\\Run"},
                                "system": {"keywords": ["Audit", "Security"]}}}}
        for policy in ("full", "protect_victim"):
            out = _redact_alert_data(doc, policy=policy)
            assert out["data"]["audit"]["key"] == "audit-wazuh", policy
            assert out["data"]["win"]["eventdata"]["keyName"] == "HKLM\\Run", policy
            assert out["data"]["win"]["system"]["keywords"] == ["Audit", "Security"], policy
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", True):
            raw = _redact_alert_data(doc, policy="raw")
        assert raw["data"]["audit"]["key"] == "audit-wazuh"
        assert raw["data"]["win"]["eventdata"]["keyName"] == "HKLM\\Run"


def test_memo_key_includes_identity_setting():
    """A flip of BLUETEAM_REDACT_IDENTITIES must not reuse memoized output."""
    _redact_mod._REDACT_MEMO.clear()
    probe = "memo isolation probe string"
    try:
        with patch.object(_redact_mod, "BLUETEAM_REDACT_IDENTITIES", True):
            _redact_alert_data(probe, policy="full")
        with patch.object(_redact_mod, "BLUETEAM_REDACT_IDENTITIES", False):
            _redact_alert_data(probe, policy="full")
        keys = [k for k in _redact_mod._REDACT_MEMO if k[0] == probe]
        assert {k[-1] for k in keys} == {True, False}
    finally:
        _redact_mod._REDACT_MEMO.clear()


class TestNoLengthTruncation:
    """The redaction layer never shortens a field, only masks content."""

    LONG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51")

    def test_long_full_log_returned_in_full(self):
        log = "alert context segment " * 20
        out = _redact_alert_data({"full_log": log}, policy="full")
        assert out["full_log"] == log

    def test_long_user_agent_returned_in_full(self):
        out = _redact_alert_data({"data": {"user_agent": self.LONG_UA}}, policy="full")
        assert out["data"]["user_agent"] == self.LONG_UA

    def test_long_field_with_ua_keyword_not_truncated(self):
        value = "curl request detail " * 20
        out = _redact_alert_data({"data": {"extra_data": value}}, policy="full")
        assert out["data"]["extra_data"] == value

    def test_sensitive_path_inside_full_log_still_masked(self):
        log = "cmd: cat /var/www/html/wp-content/plugins/shell.php && echo suffix-marker-xyz"
        out = _redact_alert_data({"full_log": log}, policy="full")
        assert "/var/www/html/wp-content/plugins/shell.php" not in out["full_log"]
        assert "[h:" in out["full_log"]
        assert "suffix-marker-xyz" in out["full_log"]

    def test_credential_redaction_unaffected(self):
        doc = _nested("data.aws.requestParameters.masterUserPassword", "hunter2")
        assert _dig(_redact_alert_data(doc, policy="full"),
                    "data.aws.requestParameters.masterUserPassword") == "<CREDENTIAL_REDACTED>"
        assert "supersecret123" not in _strip_credentials("password=supersecret123")
        with patch.object(_redact_mod, "BLUETEAM_ALLOW_FORENSIC_BYPASS", True):
            raw = _redact_alert_data(doc, policy="raw")
        assert _dig(raw, "data.aws.requestParameters.masterUserPassword") == "<CREDENTIAL_REDACTED>"

    def test_memo_does_not_reintroduce_truncation(self):
        _redact_mod._REDACT_MEMO.clear()
        value = self.LONG_UA
        try:
            first = _redact_alert_data(value, policy="full")
            second = _redact_alert_data(value, policy="full")
            assert first == value and second == value
            assert any(k[0] == value for k in _redact_mod._REDACT_MEMO)
        finally:
            _redact_mod._REDACT_MEMO.clear()


CREDENTIAL_LEAVES = [
    "data.aws.requestParameters.masterUserPassword",
    "data.aws.requestParameters.masterUsername",
    "data.aws.requestParameters.accessKeyId",
    "data.aws.userIdentity.accessKeyId",
    "data.aws.resource.accessKeyDetails.accessKeyId",
    "data.aws.resource.accessKeyDetails.principalId",
    "data.ms-graph.activationLockBypassCode",
    "data.ms-graph.deviceHealthAttestationState.attestationIdentityKey",
    "data.pwd",
]


@pytest.mark.parametrize("path", CREDENTIAL_LEAVES)
def test_all_nine_credential_leaves_are_masked(path):
    """All nine credential-classified leaves keep mandatory protection."""
    secret = "AKIAEXAMPLEVALUE1234"
    out = _redact_alert_data(_nested(path, secret), policy="full")
    value = _dig(out, path)
    assert value != secret, path
    assert secret not in value, path
