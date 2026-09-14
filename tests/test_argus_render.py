#!/usr/bin/env python3
"""Tests for the provider agnostic Argus response renderer."""
from __future__ import annotations
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from datetime import datetime, timedelta, timezone
from mcp_server.tools.alert_enrichment import _format_argus_markdown

# Trimmed from a real /lookup-jobs response. The comment carries a victim mailbox and
# an internal IP on purpose: neither may reach the rendered output.
SAMPLE = {
    "results": {
        "abuseipdb": {
            "success": True,
            "results": {
                "ipAddress": "107.150.96.242",
                "abuseConfidenceScore": 100,
                "countryCode": "US",
                "isp": "UCLOUD",
                "hostnames": [],
                "totalReports": 3,
                "reports": [
                    {
                        "reportedAt": "2026-09-14T02:15:32+00:00",
                        "comment": "mail-honeypot: SASL LOGIN authentication failed for user@example.org "
                                   "from 172.16.0.182 rhost=107.150.96.242 " + "x" * 400,
                        "categories": [18],
                        "reporterCountryCode": "ID",
                    },
                    {
                        "reportedAt": "2026-09-13T01:00:46+00:00",
                        "comment": "Repeated unauthorized access attempts.",
                        "categories": [14, 15, 18],
                        "reporterCountryCode": "DE",
                    },
                    {
                        "reportedAt": "2026-09-11T16:02:07+00:00",
                        "comment": "Seen attempting a bruteforce against SMTP services",
                        "categories": [18],
                        "reporterCountryCode": "GB",
                    },
                ],
            },
        },
        "argus_reports": {
            "success": True,
            "results": {"scores": 0, "total_reports": 0, "unique_reporters": 0, "reports": []},
        },
    }
}


def test_renders_every_provider_without_hardcoded_names():
    out = _format_argus_markdown(SAMPLE, "107.150.96.242")
    assert out.startswith("# Argus - 107.150.96.242")
    assert "## abuseipdb - success" in out
    assert "## argus_reports - success" in out
    assert "- **abuseConfidenceScore**: 100" in out
    assert "- **scores**: 0" in out
    assert "- **hostnames**: (empty)" in out


def test_summarises_report_objects():
    out = _format_argus_markdown(SAMPLE, "107.150.96.242")
    assert "- **reports**: 3 items" in out
    assert "categories: 18 (3), 14 (1), 15 (1)" in out     # multi-value list flattened
    assert "reporterCountryCode: ID (1), DE (1)" in out
    assert "reportedAt: newest 2026-09-14T02:15:32+00:00, oldest 2026-09-11T16:02:07+00:00" in out
    assert "3 text value(s), not expanded" in out


def test_free_text_never_reaches_the_output():
    """Honeypot comments hold victim emails and internal IPs. They are counted, not printed."""
    out = _format_argus_markdown(SAMPLE, "107.150.96.242")
    assert "user@example.org" not in out
    assert "172.16.0.182" not in out
    assert "SASL LOGIN" not in out


def test_adapts_to_a_changed_shape():
    """Renamed provider, renamed field, new provider, extra nesting: all render."""
    mutated = {
        "results": {
            "ip_reputation": {"success": True, "results": {"confidence": 87, "extra": {"asn": "AS123"}}},
            "shodan": {"success": False, "results": {}},
        }
    }
    out = _format_argus_markdown(mutated, "8.8.8.8")
    assert "## ip_reputation - success" in out
    assert "- **confidence**: 87" in out
    assert "- **extra.asn**: AS123" in out          # unknown nesting, no code change
    assert "## shodan - failed" in out
    assert "- (no data)" in out


def test_handles_empty_or_unexpected_envelopes():
    assert "(no results in response)" in _format_argus_markdown({}, "1.2.3.4")
    assert "(no results in response)" in _format_argus_markdown(None, "1.2.3.4")
    # No "results" envelope: render the flat payload instead of inventing providers.
    assert "- **score**: 5" in _format_argus_markdown({"score": 5}, "1.2.3.4")
    assert "- **results**: (empty)" in _format_argus_markdown({"results": {}}, "1.2.3.4")


def _full_sample(reports: int = 58) -> dict:
    """A payload with the size and field mixture of a real /lookup-jobs response:
    58 reports, multi-KB honeypot comments holding victim mailboxes and internal IPs.
    """
    long_log = ("Sep  9 16:04:45 sonne dovecot: auth: passwd-file(emporium@floppy.org,"
                "107.150.96.242): unknown user\n" + "x" * 3000)
    short = [
        "Repeated unauthorized access attempts.",
        "Seen attempting a bruteforce against SMTP services",
        "$f2bV_matches",
        "",
        "Suspicious activity ip=172.16.0.182 oip=107.150.96.242",
        "auth: Info: passwd-file(noc-as@ops.inixp.io,107.150.96.242): Password mismatch",
    ]
    cats = [[18]] * 30 + [[14, 15, 18]] * 12 + [[11, 18]] * 7 + [[15, 21]] * 4 + [[14]] * 2 \
        + [[18, 21], [18, 22], [11, 15, 18, 20], [15, 18, 20]]
    codes = ["ID", "DE", "GB", "NL", "US", "DK", "TH", "JP", "CA", "IL", "AU"]
    base = datetime(2026, 9, 14, 2, 15, 32, tzinfo=timezone.utc)
    return {"results": {
        "abuseipdb": {"success": True, "results": {
            "ipAddress": "107.150.96.242", "isPublic": True, "ipVersion": 4,
            "isWhitelisted": False, "abuseConfidenceScore": 100, "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit", "isp": "UCLOUD",
            "domain": "ucloud.cn", "hostnames": [], "isTor": False,
            "countryName": "United States of America", "totalReports": reports,
            "numDistinctUsers": 34, "lastReportedAt": "2026-09-14T02:15:32+00:00",
            "reports": [{
                "reportedAt": (base - timedelta(hours=7 * i)).isoformat(),
                "comment": long_log if i % 5 == 0 else short[i % len(short)],
                "categories": cats[i % len(cats)],
                "reporterId": 20000 + (i % 9) * 4000,
                "reporterCountryCode": codes[i % len(codes)],
                "reporterCountryName": "United States of America" if i % 11 == 4 else "Indonesia",
            } for i in range(reports)],
        }},
        "argus_reports": {"success": True, "results": {
            "scores": 0, "total_reports": 0, "unique_reporters": 0, "reports": []}},
    }}


def test_full_payload_renders_compact_and_pii_free():
    sample = _full_sample()
    out = _format_argus_markdown(sample, "107.150.96.242")
    raw = json.dumps(sample)
    assert len(out) < 2000 and len(raw) / len(out) > 20   # 50 KB payload, 1 KB answer
    assert "- **reports**: 58 items" in out
    assert "categories: 18 (52), 15 (17), 14 (14)" in out
    assert "reportedAt: newest 2026-09-14T02:15:32+00:00" in out
    for field in ("ipAddress", "isPublic", "ipVersion", "isWhitelisted", "abuseConfidenceScore",
                  "countryCode", "usageType", "isp", "domain", "isTor", "countryName",
                  "totalReports", "numDistinctUsers", "lastReportedAt"):
        assert f"- **{field}**: " in out, field
    for leaked in ("emporium@floppy.org", "172.16.0.182", "noc-as@ops.inixp.io", "dovecot"):
        assert leaked not in out


def test_tool_output_masks_pii_hidden_in_any_field():
    """A prose scalar the renderer prints still passes through the redaction boundary."""
    import asyncio
    import mcp_server.tools.alert_enrichment as ae

    payload = {"results": {"vendor_x": {"success": True, "results": {
        "notes": "escalate to csirt@tangerangkota.go.id from 172.16.9.28",
        "score": 7,
        "reports": [{"comment": "user@example.org hit us", "categories": [18]}],
    }}}}

    class _Resp:
        content = b"{}"

        def json(self):
            return payload

    async def _run():
        async def fake_api_call(method, url, **kw):
            return _Resp()

        real_call, real_limiter = ae._api_call, ae._argus_limiter
        ae._api_call, ae._argus_limiter = fake_api_call, asyncio.Semaphore(1)
        os.environ["ARGUS_API_KEY"] = "test-key"
        try:
            return await ae.argus_ip_lookup(ae.ArgusIpLookupInput(ip="107.150.96.242"))
        finally:
            ae._api_call, ae._argus_limiter = real_call, real_limiter
            os.environ.pop("ARGUS_API_KEY", None)

    out = asyncio.run(_run())
    assert "## vendor_x - success" in out and "- **score**: 7" in out
    assert "csirt@tangerangkota.go.id" not in out
    assert "172.16.9.28" not in out
    assert "user@example.org" not in out


if __name__ == "__main__":
    tests = [f for f in sorted(globals()) if f.startswith("test_")]
    for t in tests:
        globals()[t]()
        print(f"PASS {t}")
    print(f"\n{len(tests)}/{len(tests)} passed")
