#!/usr/bin/env python3
"""Batch VirusTotal for public source IPs observed in Wazuh alerts.

Every test mocks the VirusTotal HTTP boundary and the Indexer aggregation.
No live VirusTotal or Wazuh request is made.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from types import SimpleNamespace

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from pydantic import ValidationError

from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.threat_intel import virustotal as vt
from mcp_server.tools import alert_enrichment as ae
from mcp_server.tools import threat_intel_aggregate as agg


def _run(coro):
    return asyncio.run(coro)


def _report(malicious=0, suspicious=0, harmless=60, undetected=10,
            complete=True, cached=False):
    stats = {"malicious": malicious, "suspicious": suspicious,
             "harmless": harmless, "undetected": undetected, "timeout": 0}
    total = sum(stats.values())
    return {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless,
        "undetected": undetected, "timeout": 0,
        "stats_complete": complete,
        "missing_stats": [] if complete else ["timeout"],
        "analysis_stats": stats,
        "total_engines": total if complete else None,
        "detection_percent": (int(malicious / total * 100) if complete and total
                              else None),
        "any_detection": malicious > 0,
        "community_reputation": 3,
        "as_owner": "Example Networks",
        "asn": 64500,
        "network": "8.8.8.0/24",
        "country": "US",
        "total_votes": {"harmless": 1, "malicious": 0},
        "tags": ["scanner"],
        "last_analysis_date": 1_700_000_000,
        "http_status": 200,
        "cached": cached,
        "retrieved_at": "2026-11-12T00:00:00+00:00",
        "cache_age_seconds": 0,
        "cache_ttl_seconds": 3600,
        "cache_expired": False,
    }


@pytest.fixture(autouse=True)
def _vt_state(monkeypatch, tmp_path):
    vt.reset_state()
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "VIRUSTOTAL_CACHE_TTL", 3600)
    monkeypatch.setattr(vt, "VIRUSTOTAL_DAILY_LIMIT", 500)
    monkeypatch.setattr(vt, "VIRUSTOTAL_RATE_PER_MINUTE", 4)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 50)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET_HOURS", 8.0)
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "virustotal.db"))
    monkeypatch.setattr(vt, "VIRUSTOTAL_ALLOWED_HOSTS", "www.virustotal.com")
    monkeypatch.setattr(vt, "VIRUSTOTAL_MAX_RESPONSE_BYTES", 2_000_000)
    vt._get_quota().initialize()
    yield
    vt.reset_state()


def _consent(monkeypatch, approved=True, reason="approved"):
    seen: list[str] = []

    async def fake(ctx, message):
        seen.append(message)
        return SimpleNamespace(approved=approved, reason=reason)

    monkeypatch.setattr(ae, "request_ioc_sharing_detailed", fake)
    return seen


def _tool(ips, *, max_ips=None, approve=True, ctx=None, fmt="json"):
    params = ae.VirusTotalAlertIpsInput(
        ips=ips, acknowledge_ioc_sharing=True, response_format=fmt,
        **({"max_ips": max_ips} if max_ips is not None else {}))
    return _run(ae.blueteam_virustotal_alert_ips(
        params, ctx=ctx or SimpleNamespace()))


# The shared verdict helper


@pytest.mark.parametrize("payload,expected", [
    (_report(malicious=1), ("medium", True, "malicious")),
    (_report(malicious=70), ("high", True, "malicious")),
    (_report(suspicious=2), ("medium", None, "suspicious")),
    (_report(), ("none", False, "no_detections")),
    (_report(malicious=3, complete=False), (None, None, "inconclusive")),
])
def test_classify_report_is_the_single_verdict_definition(payload, expected):
    assert vt.classify_report(payload) == expected


@pytest.mark.parametrize("malicious,complete", [(1, True), (40, True), (0, True),
                                                (3, False)])
def test_classify_report_matches_the_aggregate_provider(monkeypatch, malicious,
                                                        complete):
    payload = _report(malicious=malicious, complete=complete)

    async def fake_lookup(kind, indicator, consent_token=None):
        return payload

    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "lookup", fake_lookup)
    result = _run(agg._virustotal_provider("8.8.8.8", "IPv4", "token"))
    risk, is_malicious, verdict = vt.classify_report(payload)
    assert (result.risk_level, result.is_malicious,
            result.detail["vt_verdict"]) == (risk, is_malicious, verdict)


# Explicit input path


def test_explicit_ips_use_one_prompt_and_one_token_per_ip(monkeypatch):
    seen = _consent(monkeypatch)
    calls: list[tuple[str, str, str]] = []

    async def fake_lookup(kind, indicator, consent_token=None):
        vt.consume_consent(consent_token, kind, indicator)
        calls.append((kind, indicator, consent_token))
        if indicator == "8.8.8.8":
            return _report(malicious=2)
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(["8.8.8.8", "1.1.1.1"]))

    assert len(seen) == 1
    assert "8.8.8.8" in seen[0] and "1.1.1.1" in seen[0]
    assert calls == [("ip_addresses", "8.8.8.8", calls[0][2]),
                     ("ip_addresses", "1.1.1.1", calls[1][2])]
    assert calls[0][2] != calls[1][2]
    assert [row["status"] for row in output["results"]] == ["malicious", "no_detections"]
    assert output["selected"] == 2 and output["queried"] == 2
    assert output["truncated"] == 0 and output["skipped"] == 0


def test_consent_refusal_sends_nothing_and_spends_no_quota(monkeypatch):
    seen = _consent(monkeypatch, approved=False, reason="user_declined")

    async def forbidden(kind, indicator, consent_token=None):
        pytest.fail("transport must not run after a consent refusal")

    monkeypatch.setattr(vt, "lookup", forbidden)
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8", "1.1.1.1"])

    assert "consent_required" in str(err.value)
    assert "[reason=user_declined]" in str(err.value)
    assert len(seen) == 1
    assert vt._get_quota().state()["spent"] == 0


def test_missing_api_key_skips_the_prompt(monkeypatch):
    seen = _consent(monkeypatch)
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "")
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "not_configured" in str(err.value)
    assert seen == []


def test_invalid_base_url_skips_the_prompt(monkeypatch):
    seen = _consent(monkeypatch)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BASE_URL", "http://127.0.0.1:8080/api/v3")
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "not_configured" in str(err.value)
    assert seen == []


def test_missing_quota_state_skips_the_prompt(monkeypatch, tmp_path):
    seen = _consent(monkeypatch)
    vt.reset_state()
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "absent.db"))
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "state_missing" in str(err.value)
    assert seen == []


def test_closed_budget_skips_the_prompt(monkeypatch):
    seen = _consent(monkeypatch)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 0)
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "budget_closed" in str(err.value)
    assert seen == []


def test_cooldown_skips_the_prompt(monkeypatch):
    seen = _consent(monkeypatch)
    vt._get_quota().set_cooldown(60)
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "cooldown" in str(err.value)
    assert seen == []


def test_spent_budget_skips_the_prompt(monkeypatch, tmp_path):
    seen = _consent(monkeypatch)
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 1)
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "small.db"))
    vt.reset_state()

    async def forbidden(kind, indicator, consent_token=None):
        pytest.fail("transport must not run when the budget is spent")

    monkeypatch.setattr(vt, "lookup", forbidden)
    quota = vt._get_quota()
    quota.initialize()
    reservation = quota.reserve()
    quota.finalize(reservation.reservation_id, consumed=True)
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "budget_exhausted" in str(err.value)
    assert seen == []


def test_daily_limit_skips_the_prompt(monkeypatch, tmp_path):
    seen = _consent(monkeypatch)
    monkeypatch.setattr(vt, "VIRUSTOTAL_DAILY_LIMIT", 1)
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "daily.db"))
    vt.reset_state()
    quota = vt._get_quota()
    quota.initialize()
    reservation = quota.reserve()
    quota.finalize(reservation.reservation_id, consumed=True)
    with pytest.raises(ThreatIntelError) as err:
        _tool(["8.8.8.8"])
    assert "daily_exhausted" in str(err.value)
    assert seen == []


def test_explicit_input_normalizes_and_skips_before_the_limit(monkeypatch):
    _consent(monkeypatch)
    calls: list[str] = []

    async def fake_lookup(kind, indicator, consent_token=None):
        calls.append(indicator)
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(
        ["10.0.0.5", "100.64.0.1", "127.0.0.1", "::ffff:10.0.0.1", "nope",
         "8.8.8.8", "::ffff:8.8.8.8"],
        max_ips=5))

    assert calls == ["8.8.8.8"]
    assert output["candidates"] == 7
    assert output["skipped"] == 5
    assert output["duplicates"] == 1
    assert output["eligible"] == 1
    assert output["selected"] == 1
    reasons = {item["reason"] for item in output["skipped_indicators"]}
    assert reasons == {"non_public", "invalid"}


def test_duplicates_are_removed_before_the_limit(monkeypatch):
    _consent(monkeypatch)
    calls: list[str] = []

    async def fake_lookup(kind, indicator, consent_token=None):
        calls.append(indicator)
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(
        ["8.8.8.8", "8.8.8.8", "1.1.1.1", "1.1.1.1"], max_ips=1))

    assert calls == ["8.8.8.8"]
    assert output["candidates"] == 4
    assert output["duplicates"] == 2
    assert output["eligible"] == 2
    assert output["selected"] == 1
    assert output["truncated"] == 1
    assert output["truncated_indicators"] == ["1.1.1.1"]
    assert (output["candidates"] == output["duplicates"] + output["skipped"]
            + output["eligible"])


def test_truncation_counts_eligible_unique_public_ips(monkeypatch):
    _consent(monkeypatch)

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4", "5.5.5.5", "6.6.6.6"]
    output = json.loads(_tool(ips, max_ips=2))

    assert output["eligible"] == 6
    assert output["selected"] == 2
    assert output["truncated"] == 4
    assert len(output["truncated_indicators"]) == 4
    assert output["selected"] == output["queried"] + output["not_attempted"]


def test_more_than_fifteen_explicit_ips_is_rejected():
    with pytest.raises(ValidationError):
        ae.VirusTotalAlertIpsInput(ips=[f"8.8.8.{i}" for i in range(1, 17)],
                                   acknowledge_ioc_sharing=True)


def test_global_blocker_marks_the_rest_not_attempted(monkeypatch):
    _consent(monkeypatch)
    calls: list[str] = []

    async def fake_lookup(kind, indicator, consent_token=None):
        calls.append(indicator)
        if indicator == "1.1.1.1":
            raise vt.VirusTotalError("bad key", "auth_error", http_status=401)
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4"]))

    assert calls == ["8.8.8.8", "1.1.1.1"]
    assert [row["status"] for row in output["results"]] == [
        "no_detections", "not_checked", "not_attempted", "not_attempted"]
    assert output["queried"] == 2
    assert output["not_attempted"] == 2
    assert output["results"][2]["error_kind"] == "auth_error"
    assert output["results"][3]["error_kind"] == "auth_error"


def test_per_indicator_failure_does_not_stop_the_batch(monkeypatch):
    _consent(monkeypatch)
    calls: list[str] = []

    async def fake_lookup(kind, indicator, consent_token=None):
        calls.append(indicator)
        if indicator == "8.8.8.8":
            raise vt.VirusTotalError("no report", "not_found", http_status=404)
        return _report(malicious=1)

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(["8.8.8.8", "1.1.1.1"]))

    assert calls == ["8.8.8.8", "1.1.1.1"]
    assert [row["status"] for row in output["results"]] == ["not_checked", "malicious"]
    assert output["results"][0]["error_kind"] == "not_found"
    assert output["not_attempted"] == 0


def test_incomplete_stats_stay_inconclusive(monkeypatch):
    _consent(monkeypatch)

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report(malicious=3, complete=False)

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(["8.8.8.8"]))

    row = output["results"][0]
    assert row["status"] == "inconclusive"
    assert row["is_malicious"] is None
    assert row["detections"] == "3/? (incomplete)"


def test_markdown_states_the_candidate_caveat(monkeypatch):
    _consent(monkeypatch)

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = _tool(["8.8.8.8"], fmt="markdown")
    assert "investigation candidate" in output
    assert "not proof the IP is benign" in output
    assert "| IP | Alerts | Max level |" in output


# Consent token properties used by the batch


def test_consent_token_is_bound_to_one_indicator():
    token = vt.issue_consent("ip_addresses", "8.8.8.8")
    with pytest.raises(vt.VirusTotalError) as err:
        vt.consume_consent(token, "ip_addresses", "1.1.1.1")
    assert err.value.kind == "consent_required"
    # A mismatch consumes the token as well, so it cannot be retried.
    with pytest.raises(vt.VirusTotalError):
        vt.consume_consent(token, "ip_addresses", "8.8.8.8")


def test_consent_token_cannot_be_reused():
    token = vt.issue_consent("ip_addresses", "8.8.8.8")
    vt.consume_consent(token, "ip_addresses", "8.8.8.8")
    with pytest.raises(vt.VirusTotalError) as err:
        vt.consume_consent(token, "ip_addresses", "8.8.8.8")
    assert err.value.kind == "consent_required"


def test_consent_token_expires():
    token = vt.issue_consent("ip_addresses", "8.8.8.8", ttl=0.0)
    time.sleep(0.01)
    with pytest.raises(vt.VirusTotalError) as err:
        vt.consume_consent(token, "ip_addresses", "8.8.8.8")
    assert err.value.kind == "consent_required"


# Harvest path


def _harvest_buckets():
    return {"aggregations": {"srcips": {
        "buckets": [
            {"key": "10.0.0.5", "doc_count": 9, "max_level": {"value": 15}},
            {"key": "8.8.8.8", "doc_count": 5, "max_level": {"value": 12}},
            {"key": "1.1.1.1", "doc_count": 2, "max_level": {"value": 8}},
        ],
        "sum_other_doc_count": 0,
        "doc_count_error_upper_bound": 0,
    }}, "_shards": {"failed": 0, "successful": 1, "total": 1}}


def test_harvest_queries_the_level_and_time_window(monkeypatch):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)
    posted: list[dict] = []

    async def fake_caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.srcip.keyword": "keyword"}

    async def fake_post(body, index_pattern=None):
        posted.append(body)
        return _harvest_buckets()

    async def fake_exact(query, candidates, index_pattern=None):
        return {"10.0.0.5": 9, "8.8.8.8": 5, "1.1.1.1": 2}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)
    monkeypatch.setattr(indexer, "_exact_srcip_counts", fake_exact)

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    params = ae.VirusTotalAlertIpsInput(
        since="24h", min_level=9, max_ips=2, acknowledge_ioc_sharing=True,
        response_format="json")
    output = json.loads(_run(ae.blueteam_virustotal_alert_ips(
        params, ctx=SimpleNamespace())))

    assert posted
    text = json.dumps(posted[0])
    assert "rule.level" in text and "\"gte\": 9" in text
    assert "@timestamp" in text and "strict_date_optional_time" in text
    # 10.0.0.5 is private and never reaches the lookup.
    assert [row["indicator"] for row in output["results"]] == ["8.8.8.8", "1.1.1.1"]
    assert output["source"] == "alerts"
    assert output["skipped"] == 1
    assert output["results"][0]["alerts"] == 5


def test_empty_harvest_sends_nothing(monkeypatch):
    from mcp_server.wazuh import indexer
    seen = _consent(monkeypatch)

    async def fake_caps(fields, index_pattern=None):
        return {"data.srcip": "keyword"}

    async def fake_post(body, index_pattern=None):
        return {"aggregations": {"srcips": {
            "buckets": [], "sum_other_doc_count": 0,
            "doc_count_error_upper_bound": 0}},
            "_shards": {"failed": 0, "successful": 1, "total": 1}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)

    params = ae.VirusTotalAlertIpsInput(acknowledge_ioc_sharing=True)
    output = _run(ae.blueteam_virustotal_alert_ips(params, ctx=SimpleNamespace()))
    assert "nothing was sent to virustotal" in output.lower()
    assert seen == []


def test_harvest_failure_is_not_reported_as_no_matches(monkeypatch):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)

    async def fake_caps(fields, index_pattern=None):
        return {}

    async def fake_post(body, index_pattern=None):
        return {"error": "index_not_found_exception"}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)

    params = ae.VirusTotalAlertIpsInput(acknowledge_ioc_sharing=True)
    with pytest.raises(ThreatIntelError) as err:
        _run(ae.blueteam_virustotal_alert_ips(params, ctx=SimpleNamespace()))
    assert "harvest failed" in str(err.value)
    assert "index_not_found_exception" in str(err.value)


def test_partial_harvest_is_flagged(monkeypatch):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)

    async def fake_census(query, aggs, index_pattern=None):
        return ({"srcips": {"buckets": [
            {"key": "8.8.8.8", "doc_count": 5, "max_level": {"value": 12}}]}},
            {"bucket_limit": 200,
             "paths": [{"field": "data.srcip", "returned": 1, "limit": 200,
                        "complete": False, "reasons": ["shard_failures"]}],
             "complete": False, "reasons": ["shard_failures"]},
            ["one source-IP path failed"])

    async def fake_exact(query, candidates, index_pattern=None):
        return {"8.8.8.8": 5}

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(indexer, "_srcip_census_merged", fake_census)
    monkeypatch.setattr(indexer, "_exact_srcip_counts", fake_exact)
    monkeypatch.setattr(vt, "lookup", fake_lookup)

    params = ae.VirusTotalAlertIpsInput(acknowledge_ioc_sharing=True,
                                        response_format="json")
    output = json.loads(_run(ae.blueteam_virustotal_alert_ips(
        params, ctx=SimpleNamespace())))
    assert output["harvest_partial"] is True
    assert output["census_complete"] is False
    assert output["unseen_candidates"] is True
    assert output["census_reasons"] == ["shard_failures"]
    assert output["results"][0]["indicator"] == "8.8.8.8"



# Census completeness


def _ip(index: int) -> str:
    return f"11.0.{index // 250}.{index % 250 + 1}"


def _buckets(count: int, start: int = 0) -> list[dict]:
    return [{"key": _ip(i), "doc_count": 1, "max_level": {"value": 8}}
            for i in range(start, start + count)]


def _census_raw(buckets, *, sum_other=0, error_bound=0, failed=0,
                timed_out=False, terminated_early=False, include_meta=True,
                include_sum_other=True, include_error_bound=True, partial=False):
    agg = {"buckets": buckets}
    if include_meta:
        if include_sum_other:
            agg["sum_other_doc_count"] = sum_other
        if include_error_bound:
            agg["doc_count_error_upper_bound"] = error_bound
    raw = {"aggregations": {"srcips": agg},
           "_shards": {"failed": failed,
                       "successful": 0 if failed else 1, "total": 1},
           "timed_out": timed_out,
           "terminated_early": terminated_early}
    if partial:
        raw["_partial"] = True
    return raw


def _census_harvest(monkeypatch, response, *, bucket_limit=200, max_ips=1,
                    caps=None, fmt="json", exact=None):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)

    async def fake_caps(fields, index_pattern=None):
        return caps if caps is not None else {"data.srcip": "keyword"}

    async def fake_post(body, index_pattern=None):
        return response(body) if callable(response) else response

    async def fake_exact(query, candidates, index_pattern=None):
        if exact is not None:
            return exact(candidates)
        return {str(ip): 1 for ip in candidates}

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)
    monkeypatch.setattr(indexer, "_exact_srcip_counts", fake_exact)
    monkeypatch.setattr(vt, "lookup", fake_lookup)
    params = ae.VirusTotalAlertIpsInput(
        bucket_limit=bucket_limit, max_ips=max_ips,
        acknowledge_ioc_sharing=True, response_format=fmt)
    result = _run(ae.blueteam_virustotal_alert_ips(params, ctx=SimpleNamespace()))
    return json.loads(result) if fmt == "json" else result


def test_census_complete_below_the_limit(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(49)),
                             bucket_limit=50)
    assert output["census_complete"] is True
    assert output["unseen_candidates"] is False
    assert output["census_reasons"] == []
    assert output["candidates"] == 49


def test_census_is_conservatively_incomplete_at_the_limit(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(50)),
                             bucket_limit=50)
    assert output["census_complete"] is False
    assert output["unseen_candidates"] is True
    assert "bucket_limit_reached" in output["census_reasons"]
    assert output["counts_exact"] is True


def test_census_incomplete_when_more_docs_exist(monkeypatch):
    output = _census_harvest(
        monkeypatch, _census_raw(_buckets(50), sum_other=25), bucket_limit=50)
    assert output["census_complete"] is False
    assert "bucket_limit_reached" in output["census_reasons"]
    assert "other_docs_omitted" in output["census_reasons"]


def test_merged_paths_above_the_limit_can_still_be_complete(monkeypatch):
    def by_field(body):
        field = body["aggs"]["srcips"]["terms"]["field"]
        if field == "data.srcip":
            return _census_raw(_buckets(120))
        return _census_raw(_buckets(110, start=120))

    output = _census_harvest(
        monkeypatch, by_field, bucket_limit=200,
        caps={"data.srcip": "keyword", "data.srcip.keyword": "keyword"})
    assert output["candidates"] == 230
    assert output["census_complete"] is True
    assert len(output["census_paths"]) == 2
    assert all(item["complete"] for item in output["census_paths"])


def test_one_path_at_its_limit_makes_the_census_incomplete(monkeypatch):
    def by_field(body):
        field = body["aggs"]["srcips"]["terms"]["field"]
        if field == "data.srcip":
            return _census_raw(_buckets(200))
        return _census_raw(_buckets(10, start=200))

    output = _census_harvest(
        monkeypatch, by_field, bucket_limit=200,
        caps={"data.srcip": "keyword", "data.srcip.keyword": "keyword"})
    assert output["census_complete"] is False
    assert output["census_paths"][0]["complete"] is False
    assert output["census_paths"][1]["complete"] is True


def test_sum_other_docs_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(10), sum_other=3))
    assert output["census_complete"] is False
    assert output["census_reasons"] == ["other_docs_omitted"]


def test_doc_count_error_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(10), error_bound=2))
    assert output["census_complete"] is False
    assert output["census_reasons"] == ["doc_count_error"]


@pytest.mark.parametrize("error_bound,include,expected", [
    (-1, True, ["doc_count_error_unknown"]),
    (-2, True, ["metadata_invalid"]),
    (None, True, ["metadata_missing"]),
    ("0", True, ["metadata_invalid"]),
    (True, True, ["metadata_invalid"]),
    (0.0, True, ["metadata_invalid"]),
    (0, True, []),
    (3, True, ["doc_count_error"]),
    (0, False, ["metadata_missing"]),
])
def test_error_bound_classification(monkeypatch, error_bound, include, expected):
    output = _census_harvest(
        monkeypatch,
        _census_raw(_buckets(10), error_bound=error_bound,
                    include_error_bound=include),
        bucket_limit=200)
    assert output["census_complete"] is (not expected)
    assert output["census_reasons"] == expected
    assert output["census_paths"][0]["reasons"] == expected


@pytest.mark.parametrize("sum_other,include,expected", [
    (-1, True, ["metadata_invalid"]),
    (None, True, ["metadata_missing"]),
    ("0", True, ["metadata_invalid"]),
    (True, True, ["metadata_invalid"]),
    (1.5, True, ["metadata_invalid"]),
    (0, True, []),
    (2, True, ["other_docs_omitted"]),
    (0, False, ["metadata_missing"]),
])
def test_sum_other_classification(monkeypatch, sum_other, include, expected):
    output = _census_harvest(
        monkeypatch,
        _census_raw(_buckets(10), sum_other=sum_other,
                    include_sum_other=include),
        bucket_limit=200)
    assert output["census_complete"] is (not expected)
    assert output["census_reasons"] == expected
    assert output["census_paths"][0]["reasons"] == expected


@pytest.mark.parametrize("sum_other,error_bound,expected", [
    (None, -1, ["doc_count_error_unknown", "metadata_missing"]),
    ("0", -1, ["doc_count_error_unknown", "metadata_invalid"]),
    (-1, -1, ["doc_count_error_unknown", "metadata_invalid"]),
])
def test_metadata_reasons_are_independent(monkeypatch, sum_other, error_bound,
                                          expected):
    output = _census_harvest(
        monkeypatch,
        _census_raw(_buckets(10), sum_other=sum_other, error_bound=error_bound),
        bucket_limit=200)
    assert output["census_complete"] is False
    assert output["census_reasons"] == expected


@pytest.mark.parametrize("error_bound,token", [
    (-1, "doc_count_error_unknown"),
    (-2, "metadata_invalid"),
])
def test_markdown_names_the_error_bound_status(monkeypatch, error_bound, token):
    output = _census_harvest(
        monkeypatch, _census_raw(_buckets(10), error_bound=error_bound),
        fmt="markdown")
    assert f"Census: incomplete ({token})" in output
    assert "Additional candidates may exist" in output


def test_failed_shards_mark_the_census_incomplete(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(10), failed=1))
    assert output["census_complete"] is False
    assert "shard_failures" in output["census_reasons"]


def test_partial_response_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(10), partial=True))
    assert output["census_complete"] is False
    assert "shard_failures" in output["census_reasons"]


def test_timeout_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(10), timed_out=True))
    assert output["census_complete"] is False
    assert "timed_out" in output["census_reasons"]


def test_early_termination_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(
        monkeypatch, _census_raw(_buckets(10), terminated_early=True))
    assert output["census_complete"] is False
    assert "terminated_early" in output["census_reasons"]


def test_missing_metadata_marks_the_census_incomplete(monkeypatch):
    output = _census_harvest(
        monkeypatch, _census_raw(_buckets(10), include_meta=False))
    assert output["census_complete"] is False
    assert "metadata_missing" in output["census_reasons"]


def test_truncated_and_unseen_are_different_counts(monkeypatch):
    complete = _census_harvest(monkeypatch, _census_raw(_buckets(49)),
                               bucket_limit=50, max_ips=1)
    assert complete["census_complete"] is True
    assert complete["unseen_candidates"] is False
    assert complete["truncated"] == 48

    incomplete = _census_harvest(monkeypatch, _census_raw(_buckets(50)),
                                 bucket_limit=50, max_ips=1)
    assert incomplete["census_complete"] is False
    assert incomplete["unseen_candidates"] is True
    assert incomplete["truncated"] == 49


def test_markdown_names_an_incomplete_census(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(50)),
                             bucket_limit=50, fmt="markdown")
    assert "Census: incomplete at bucket_limit=50" in output
    assert "At least 50 eligible candidate(s) were observed" in output
    assert "Additional candidates may exist" in output
    assert "Increase bucket_limit or narrow the time window" in output


def test_markdown_reports_a_complete_census(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(49)),
                             bucket_limit=50, fmt="markdown")
    assert "Census: complete across 1 mapped source-IP path(s)." in output
    assert "Counts: exact for every observed bucket." in output
    assert "Additional candidates may exist" not in output


def test_explicit_ips_have_no_census(monkeypatch):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)

    async def forbidden(*args, **kwargs):
        pytest.fail("the Indexer must not be called for an explicit list")

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", forbidden)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", forbidden)
    monkeypatch.setattr(vt, "lookup", fake_lookup)
    output = json.loads(_tool(["8.8.8.8"]))
    assert output["census_complete"] is None
    assert output["unseen_candidates"] is None
    assert output["bucket_limit"] is None
    assert output["census_paths"] == []
    assert output["correction_limit"] is None
    assert output["counts_exact"] is None



def test_one_path_error_marks_the_census_incomplete(monkeypatch):
    def by_field(body):
        field = body["aggs"]["srcips"]["terms"]["field"]
        if field == "data.srcip":
            return _census_raw(_buckets(5))
        return {"error": "path failed"}

    output = _census_harvest(
        monkeypatch, by_field, bucket_limit=200,
        caps={"data.srcip": "keyword", "data.srcip.keyword": "keyword"})
    assert output["candidates"] == 5
    assert output["census_complete"] is False
    assert "path_error" in output["census_reasons"]
    assert output["harvest_partial"] is True


def test_empty_incomplete_census_is_not_reported_as_no_matches(monkeypatch):
    output = _census_harvest(
        monkeypatch, _census_raw([], include_meta=False), fmt="markdown")
    assert "No public source IP matched" not in output
    assert "additional candidates may exist" in output.lower()
    assert "Counts: no observed buckets; no count correction required." in output
    assert "Increase bucket_limit or narrow the time window" in output


def test_empty_complete_census_is_reported_as_no_matches(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw([]), fmt="markdown")
    assert "No public source IP matched the alert window." in output
    assert "Census: complete across 1 mapped source-IP path(s)." in output
    assert "Counts: no observed buckets; no count correction required." in output



def test_default_top_fifteen_selection_is_unchanged(monkeypatch):
    items = [{"key": _ip(i), "doc_count": 100 - i, "max_level": {"value": 10}}
             for i in range(20)]
    counts = {_ip(i): 100 - i for i in range(20)}
    output = _census_harvest(
        monkeypatch, _census_raw(items), bucket_limit=200, max_ips=15,
        exact=lambda candidates: {ip: counts[ip] for ip in candidates})
    assert output["candidates"] == 20
    assert output["selected"] == 15
    assert output["truncated"] == 5
    assert [row["indicator"] for row in output["results"]] == [
        _ip(i) for i in range(15)]
    assert [row["alerts"] for row in output["results"]] == [
        100 - i for i in range(15)]
    assert output["counts_exact"] is True
    assert output["correction_limit"] == 200


# Correction boundary


def test_counts_exact_at_200_buckets_keeps_an_incomplete_census(monkeypatch):
    output = _census_harvest(monkeypatch, _census_raw(_buckets(200)),
                             bucket_limit=200, max_ips=1)
    assert output["counts_exact"] is True
    assert output["correction_limit"] == 200
    assert output["census_complete"] is False


def test_counts_bounded_above_200_buckets(monkeypatch):
    response = _census_raw(_buckets(201))
    js = _census_harvest(monkeypatch, response, bucket_limit=201, max_ips=1)
    md = _census_harvest(monkeypatch, response, bucket_limit=201, max_ips=1,
                         fmt="markdown")
    assert js["counts_exact"] is False
    assert js["correction_limit"] == 200
    assert "Counts: exact for up to 200 observed buckets" in md
    assert "Any ranking involving uncorrected buckets is approximate." in md


def test_correction_failure_sets_counts_exact_false(monkeypatch):
    def boom(candidates):
        raise RuntimeError("exact count failed")

    js = _census_harvest(monkeypatch, _census_raw(_buckets(10)),
                         bucket_limit=200, max_ips=1, exact=boom)
    md = _census_harvest(monkeypatch, _census_raw(_buckets(10)),
                         bucket_limit=200, max_ips=1, exact=boom, fmt="markdown")
    assert js["counts_exact"] is False
    assert js["harvest_partial"] is True
    assert "Counts: exact counts unavailable" in md


def test_partial_correction_keeps_the_merged_count(monkeypatch):
    items = [{"key": f"11.0.0.{i}", "doc_count": 11 - i,
              "max_level": {"value": 8}} for i in range(1, 6)]

    def partial(candidates):
        return {ip: 1 for ip in candidates[:-1]}

    output = _census_harvest(monkeypatch, _census_raw(items),
                             bucket_limit=200, max_ips=1, exact=partial)
    assert output["counts_exact"] is False
    assert output["results"][0]["indicator"] == "11.0.0.5"
    assert output["results"][0]["alerts"] == 6


def test_exact_count_error_keeps_the_merged_count(monkeypatch):
    from mcp_server.wazuh import indexer
    _consent(monkeypatch)

    async def fake_caps(fields, index_pattern=None):
        return {"data.srcip": "keyword"}

    async def fake_post(body, index_pattern=None):
        return _census_raw([
            {"key": "8.8.8.8", "doc_count": 5, "max_level": {"value": 8}}])

    async def fake_msearch(bodies, index_pattern=None):
        return [{"error": "exact count failed"} for _ in bodies]

    async def fake_lookup(kind, indicator, consent_token=None):
        return _report()

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", fake_msearch)
    monkeypatch.setattr(vt, "lookup", fake_lookup)
    params = ae.VirusTotalAlertIpsInput(
        max_ips=1, acknowledge_ioc_sharing=True, response_format="json")
    output = json.loads(_run(ae.blueteam_virustotal_alert_ips(
        params, ctx=SimpleNamespace())))
    assert output["counts_exact"] is False
    assert output["results"][0]["alerts"] == 5


def test_counts_markdown_variants():
    from mcp_server.tools.alert_enrichment import _vt_counts_markdown

    assert _vt_counts_markdown(None) == []
    assert _vt_counts_markdown(
        {"limit": 200, "observed": 0, "corrected": 0, "counts_exact": True}) == [
        "Counts: no observed buckets; no count correction required."]
    assert _vt_counts_markdown(
        {"limit": 200, "observed": 2, "corrected": 2, "counts_exact": True}) == [
        "Counts: exact for every observed bucket."]
    assert _vt_counts_markdown(
        {"limit": 200, "observed": 201, "corrected": 200,
         "counts_exact": False}) == [
        "Counts: exact for up to 200 observed buckets; later counts are merged "
        "lower bounds. Any ranking involving uncorrected buckets is approximate."]
    assert _vt_counts_markdown(
        {"limit": 200, "observed": 5, "corrected": 4, "counts_exact": False}) == [
        "Counts: exact for 4 of 5 observed buckets; the rest are merged lower "
        "bounds. Any ranking involving uncorrected buckets is approximate."]
    assert _vt_counts_markdown(
        {"limit": 200, "observed": 5, "corrected": 0, "counts_exact": False}) == [
        "Counts: exact counts unavailable; all observed bucket counts are merged "
        "lower bounds. Any ranking is approximate."]


def test_zero_observed_counts_are_exact(monkeypatch):
    js = _census_harvest(monkeypatch, _census_raw([]), fmt="json")
    assert js["candidates"] == 0
    assert js["counts_exact"] is True
    assert js["correction_limit"] == 200
    md = _census_harvest(monkeypatch, _census_raw([]), fmt="markdown")
    assert "Counts: no observed buckets; no count correction required." in md


def test_bucket_limit_defaults_and_bounds():
    assert ae.VirusTotalAlertIpsInput().bucket_limit == 200
    assert ae.VirusTotalAlertIpsInput(bucket_limit=15).bucket_limit == 15
    assert ae.VirusTotalAlertIpsInput(bucket_limit=1000).bucket_limit == 1000
    with pytest.raises(ValidationError):
        ae.VirusTotalAlertIpsInput(bucket_limit=14)
    with pytest.raises(ValidationError):
        ae.VirusTotalAlertIpsInput(bucket_limit=1001)


# Registration


def test_tool_is_registered_read_only_and_not_idempotent():
    from mcp.server.fastmcp.utilities.context_injection import find_context_parameter
    from mcp_server import mcp

    tool = mcp._tool_manager._tools["blueteam_virustotal_alert_ips"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.idempotentHint is False
    assert tool.annotations.openWorldHint is True
    target = getattr(ae.blueteam_virustotal_alert_ips, "__wrapped__",
                     ae.blueteam_virustotal_alert_ips)
    assert find_context_parameter(target) == "ctx"
