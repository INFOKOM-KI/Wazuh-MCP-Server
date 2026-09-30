#!/usr/bin/env python3
"""
Tests for core/netcalc.py and tools/subnetting.py.
The math is pure stdlib, so ``_usable_hosts`` and ``_host_range`` are
cross-checked against ``ipaddress.hosts()`` the hand-rolled /31, /127 and
host-route rules are exactly where a silent off-by-one would ship.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import ipaddress
import json
import pytest
from pydantic import ValidationError
from mcp_server.core.netcalc import (
    HARD_MAX_RESULTS,
    REJECT_REASON,
    _host_range,
    _usable_hosts,
    merge_networks,
    split_network,
)
from mcp_server.tools.subnetting import SubnetCalcInput, _render_markdown, blueteam_subnet_calc

_run = asyncio.run
_body = blueteam_subnet_calc.__wrapped__


def test_split_slash24_into_slash28():
    result = split_network("192.168.0.0/24", 28)
    assert result["status"] == "ok"
    assert result["total_subnets"] == 16
    assert result["returned"] == 16
    assert result["truncated"] is False
    assert result["addresses_per_subnet"] == 16
    assert result["usable_hosts_per_subnet"] == 14
    assert result["subnets"][0]["cidr"] == "192.168.0.0/28"
    assert result["subnets"][1]["cidr"] == "192.168.0.16/28"
    assert result["subnets"][-1]["cidr"] == "192.168.0.240/28"
    assert result["subnets"][0]["broadcast"] == "192.168.0.15"


def test_split_truncates_and_reports_the_true_total():
    result = split_network("10.0.0.0/16", 24, max_results=4)
    assert result["total_subnets"] == 256
    assert result["returned"] == 4
    assert result["truncated"] is True


def test_split_default_prefix_is_flagged_as_a_guess():
    result = split_network("192.168.0.0/24")
    assert result["new_prefix"] == 25
    assert result["new_prefix_source"] == "default"
    assert split_network("192.168.0.0/24", 28)["new_prefix_source"] == "explicit"


def test_split_reports_normalized_host_bits():
    result = split_network("192.168.0.7/28", 30)
    assert result["input"] == "192.168.0.0/28"
    assert result["input_normalized_from"] == "192.168.0.7/28"
    assert split_network("192.168.0.0/24", 28)["input_normalized_from"] is None


def test_split_bare_ip_becomes_a_host_route():
    result = split_network("10.0.0.5", 31)
    assert result["status"] == "error"
    assert "not longer" in result["error"]


@pytest.mark.parametrize("prefix,message", [
    (24, "not longer"),
    (16, "not longer"),
    (33, "1..32"),
    (0, "1..32"),
])
def test_split_rejects_impossible_prefixes(prefix, message):
    result = split_network("192.168.0.0/24", prefix)
    assert result["status"] == "error"
    assert message in result["error"]


def test_split_rejects_unparseable_input():
    result = split_network("not-an-ip/24", 28)
    assert result["status"] == "error"
    assert result["error"] == REJECT_REASON
    assert "not-an-ip" not in str(result)


def test_split_slash31_keeps_both_addresses_usable():
    result = split_network("10.0.0.0/30", 31)
    assert result["usable_hosts_per_subnet"] == 2
    first = result["subnets"][0]
    assert first["network"] == "10.0.0.0"
    assert first["first_host"] == "10.0.0.0"
    assert first["last_host"] == "10.0.0.1"


def test_split_ipv6_has_no_broadcast_column():
    result = split_network("2001:db8::/124", 126)
    assert result["family"] == "IPv6"
    assert result["total_subnets"] == 4
    assert "broadcast" not in result["subnets"][0]
    assert result["subnets"][0]["netmask"] == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"


def test_split_caps_rows_at_the_hard_limit():
    result = split_network("0.0.0.0/0", 24, max_results=10_000)
    assert result["max_results"] == HARD_MAX_RESULTS
    assert result["returned"] == HARD_MAX_RESULTS


@pytest.mark.parametrize("cidr", [
    "192.168.0.0/24", "10.0.0.0/30", "10.0.0.0/31", "10.0.0.5/32",
    "2001:db8::/126", "2001:db8::/127", "2001:db8::/128",
])
def test_usable_hosts_matches_stdlib(cidr):
    net = ipaddress.ip_network(cidr)
    assert _usable_hosts(net) == len(list(net.hosts()))


@pytest.mark.parametrize("cidr", [
    "192.168.0.0/28", "10.0.0.0/31", "10.0.0.5/32",
    "2001:db8::/126", "2001:db8::/127", "2001:db8::/128",
])
def test_host_range_matches_stdlib(cidr):
    net = ipaddress.ip_network(cidr)
    hosts = list(net.hosts())
    assert _host_range(net) == (str(hosts[0]), str(hosts[-1]))


def test_merge_collapses_sixteen_slash28_into_one_slash24():
    blocks = [f"192.168.0.{i * 16}/28" for i in range(16)]
    result = merge_networks(blocks)
    assert result["status"] == "ok"
    assert result["total_cidrs"] == 1
    assert result["cidrs"][0]["cidr"] == "192.168.0.0/24"
    assert result["covered_addresses"] == 256
    assert result["overlap_removed"] == 0


def test_merge_drops_duplicate_coverage():
    result = merge_networks(["10.0.0.0/24", "10.0.0.0/24", "10.0.0.128/25"])
    assert result["total_cidrs"] == 1
    assert result["input_addresses"] == 640
    assert result["covered_addresses"] == 256
    assert result["overlap_removed"] == 384


def test_merge_bare_ips_become_host_routes():
    result = merge_networks(["10.0.0.1", "10.0.0.2"])
    assert [row["cidr"] for row in result["cidrs"]] == ["10.0.0.1/32", "10.0.0.2/32"]


def test_merge_rejects_mixed_families():
    result = merge_networks(["10.0.0.0/24", "2001:db8::/32"])
    assert result["status"] == "error"
    assert result["families"] == ["IPv4", "IPv6"]


def test_merge_lists_invalid_values_and_keeps_the_rest():
    result = merge_networks(["10.0.0.0/24", "garbage", "10.0.0.128/25"])
    assert result["status"] == "ok"
    assert result["valid_count"] == 2
    assert result["total_cidrs"] == 1
    assert result["invalid"] == [{"index": 1, "reason": REJECT_REASON}]


def test_merge_all_invalid_is_an_error():
    result = merge_networks(["garbage", "also-garbage"])
    assert result["status"] == "error"
    assert len(result["invalid"]) == 2


def test_merge_empty_input_is_an_error():
    assert merge_networks([])["status"] == "error"


def test_merge_truncates_long_result_sets():
    blocks = [f"10.0.{i * 2}.0/24" for i in range(10)]
    result = merge_networks(blocks, max_results=3)
    assert result["total_cidrs"] == 10
    assert result["returned"] == 3
    assert result["truncated"] is True


def test_merge_ipv6_only():
    result = merge_networks(["2001:db8::/126", "2001:db8::4/126"])
    assert result["family"] == "IPv6"
    assert [row["cidr"] for row in result["cidrs"]] == ["2001:db8::/125"]


def test_split_requires_cidr():
    with pytest.raises(ValidationError):
        SubnetCalcInput(operation="split")


def test_merge_requires_ips():
    with pytest.raises(ValidationError):
        SubnetCalcInput(operation="merge")
    with pytest.raises(ValidationError):
        SubnetCalcInput(operation="merge", ips=[])


def test_input_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        SubnetCalcInput(cidr="10.0.0.0/24", prefix=28, cidrs="typo")


def test_input_rejects_out_of_range_prefix_and_max_results():
    with pytest.raises(ValidationError):
        SubnetCalcInput(cidr="10.0.0.0/24", prefix=129)
    with pytest.raises(ValidationError):
        SubnetCalcInput(cidr="10.0.0.0/24", max_results=HARD_MAX_RESULTS + 1)


def test_input_rejects_oversized_entry():
    with pytest.raises(ValidationError):
        SubnetCalcInput(operation="merge", ips=["10.0.0.1" * 20])


def test_tool_returns_internal_topology_unmasked():
    """The tool is redact=False on purpose: a masked CIDR is not an answer."""
    payload = json.loads(_run(_body(SubnetCalcInput(
        operation="split", cidr="10.0.0.0/24", prefix=28, response_format="json"))))
    assert payload["subnets"][0]["cidr"] == "10.0.0.0/28"
    assert payload["subnets"][0]["broadcast"] == "10.0.0.15"
    assert "subnet_masked" not in payload
    text = _run(_body(SubnetCalcInput(cidr="10.0.0.0/24", prefix=28)))
    assert "10.0.0.0/28" in text
    assert "***" not in text


def test_rejected_input_is_never_echoed():
    """Output is unmasked, so a pasted credential must not ride back out inside
    the failure text - Layer 1 never gets a chance to strip it."""
    secret = "http://user:pass@10.0.0.0/24"
    payload = json.loads(_run(_body(SubnetCalcInput(cidr=secret, prefix=28,
                                                    response_format="json"))))
    assert payload["status"] == "error"
    blob = json.dumps(payload)
    assert "pass" not in blob and "user" not in blob and secret not in blob
    assert "pass" not in _run(_body(SubnetCalcInput(cidr=secret, prefix=28)))


def test_merge_reports_invalid_values_by_position_only():
    payload = json.loads(_run(_body(SubnetCalcInput(
        operation="merge", ips=["10.0.0.0/24", "http://u:p@10.0.0.1/24", "10.0.0.128/25"],
        response_format="json"))))
    assert payload["invalid"] == [{"index": 1, "reason": REJECT_REASON}]
    assert payload["total_cidrs"] == 1


def test_reject_reason_exists_for_every_bad_shape():
    for bad in ("10.0.0.0/33", "nonsense", "10.0.0.256/24", "http://u:p@10.0.0.1/24"):
        result = split_network(bad, 28)
        assert result["error"] == REJECT_REASON
        assert bad not in str(result)


def test_tool_markdown_contains_the_subnet_table():
    text = _run(_body(SubnetCalcInput(cidr="192.168.0.0/24", prefix=28)))
    assert "# 🧮 Subnet Split" in text
    assert "| 0 | `192.168.0.0/28` |" in text
    assert "**Subnets**: 16 total, 16 returned" in text


def test_tool_reports_a_split_error_as_markdown():
    text = _run(_body(SubnetCalcInput(cidr="192.168.0.0/24", prefix=24)))
    assert "Subnet calculation failed" in text
    assert "not longer" in text


def test_tool_merge_markdown_lists_invalid_positions():
    text = _run(_body(SubnetCalcInput(
        operation="merge", ips=["10.0.0.0/24", "junk", "10.0.0.128/25"])))
    assert "**Covering set**: 1 CIDR(s) covering 256 addresses" in text
    assert "input[1]" in text
    assert "junk" not in text


def test_render_markdown_ignores_unknown_operations_gracefully():
    assert _render_markdown({"status": "error", "error": "boom"}).startswith(
        "# Subnet calculation failed")
