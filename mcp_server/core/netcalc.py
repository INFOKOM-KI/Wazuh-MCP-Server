#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Network arithmetic for blueteam_subnet_calc: split one block into equal
sub-blocks, or merge a list of IPs/blocks into the smallest covering CIDR set.
Pure stdlib (ipaddress, itertools) with no I/O, no pydantic and no network. The
tool wrapper owns the schema; this module owns the math, so the arithmetic is
testable without the MCP bootstrap. Nothing here calls the Indexer, the Manager
or any provider, so no SSRF/RFC1918 guard applies.

A rejected value is never echoed back. The tool returns its output unmasked (a
masked CIDR is not an answer), so an invalid input such as
``http://user:pass@10.0.0.1/24`` would otherwise reach the LLM with no credential
layer in front of it. Failures report a position and ``REJECT_REASON`` instead.
"""
from __future__ import annotations
import ipaddress
import itertools

DEFAULT_MAX_RESULTS = 64
HARD_MAX_RESULTS = 256

# One fixed reason for every rejected value. The ipaddress exception message
# embeds the input, and this tool returns unmasked output, so a pasted credential
# must not be able to ride back out inside an error string.
REJECT_REASON = "not a valid IPv4 or IPv6 address or CIDR"


def _parse(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a CIDR or a bare IP. A bare IP becomes a host route (/32 or /128).
    Host bits in the input are masked rather than rejected callers report that
    drift so the analyst sees their input move."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty address")
    if "/" not in text:
        text = f"{text}/{ipaddress.ip_address(text).max_prefixlen}"
    return ipaddress.ip_network(text, strict=False)


def _cap(max_results: int) -> int:
    """Clamp the row cap. Pydantic bounds it at the edge; this keeps the core
    safe when called directly."""
    return max(1, min(int(max_results), HARD_MAX_RESULTS))


def _usable_hosts(net) -> int:
    """Assignable addresses. /31 and /127 give 2 (RFC 3021, RFC 6164) and a host
    route gives 1; longer prefixes lose the network and broadcast addresses
    (IPv4) or the subnet router anycast address (IPv6, RFC 4291)."""
    max_prefix = net.max_prefixlen
    if net.prefixlen == max_prefix:
        return 1
    if net.prefixlen == max_prefix - 1:
        return 2
    return net.num_addresses - 2 if net.version == 4 else net.num_addresses - 1


def _host_range(net) -> tuple[str, str]:
    """First and last assignable address. IPv6 has no broadcast address, so its
    last address stays usable and broadcast_address is the range end."""
    short = net.prefixlen >= net.max_prefixlen - 1
    first = net.network_address if short else net.network_address + 1
    last = net.broadcast_address - 1 if net.version == 4 and not short else net.broadcast_address
    return str(first), str(last)


def _describe(net) -> dict:
    first, last = _host_range(net)
    row = {
        "cidr": str(net),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "network": str(net.network_address),
        "num_addresses": net.num_addresses,
        "usable_hosts": _usable_hosts(net),
        "first_host": first,
        "last_host": last,
    }
    if net.version == 4:
        row["broadcast"] = str(net.broadcast_address)
    return row


def split_network(cidr: str, new_prefix: int | None = None,
                  max_results: int = DEFAULT_MAX_RESULTS) -> dict:
    """Split one CIDR block into equal sub-blocks at ``new_prefix``.
    ``new_prefix`` defaults to input prefix + 1 and is reported as
    ``new_prefix_source: "default"``, so a caller can never mistake a guessed
    prefix for a requested one. Returns at most ``max_results`` rows and sets
    ``truncated`` when the block holds more.
    """
    try:
        net = _parse(cidr)
    except ValueError:
        return {"status": "error", "operation": "split",
                "error": REJECT_REASON}

    cap = _cap(max_results)
    max_prefix = net.max_prefixlen
    prefix_source = "explicit"
    if new_prefix is None:
        new_prefix = net.prefixlen + 1
        prefix_source = "default"
    if not 1 <= new_prefix <= max_prefix:
        return {"status": "error", "operation": "split", "input": str(net),
                "error": f"prefix must be 1..{max_prefix}, got {new_prefix}"}
    if new_prefix <= net.prefixlen:
        return {"status": "error", "operation": "split", "input": str(net),
                "error": f"/{new_prefix} is not longer than the input /{net.prefixlen}; "
                         f"a split needs a longer prefix"}

    total = 1 << (new_prefix - net.prefixlen)
    # subnets() gained count= only in Python 3.13; islice keeps 3.12 correct.
    emitted = list(itertools.islice(net.subnets(new_prefix=new_prefix), cap))
    return {
        "status": "ok",
        "operation": "split",
        "input": str(net),
        "input_normalized_from": cidr.strip() if cidr.strip() != str(net) else None,
        "family": f"IPv{net.version}",
        "new_prefix": new_prefix,
        "new_prefix_source": prefix_source,
        "total_subnets": total,
        "returned": len(emitted),
        "truncated": total > cap,
        "max_results": cap,
        "addresses_per_subnet": emitted[0].num_addresses,
        "usable_hosts_per_subnet": _usable_hosts(emitted[0]),
        "subnets": [_describe(net) for net in emitted],
    }


def merge_networks(values: list[str], max_results: int = DEFAULT_MAX_RESULTS) -> dict:
    """Merge IPs and blocks into the smallest covering CIDR set, dropping overlap.
    Unparseable values are listed under ``invalid`` by position and reason, and the
    valid ones are still merged: a partial answer that names the failures beats a
    total refusal when the caller pasted a blocklist with one bad row. Mixed
    IPv4/IPv6 input is an error ``collapse_addresses`` cannot span families.
    """
    cap = _cap(max_results)
    if not values:
        return {"status": "error", "operation": "merge",
                "error": "no values supplied"}

    nets = []
    invalid: list[dict] = []
    families: set[int] = set()
    for index, value in enumerate(values):
        try:
            net = _parse(value)
        except ValueError:
            invalid.append({"index": index, "reason": REJECT_REASON})
            continue
        nets.append(net)
        families.add(net.version)

    if not nets:
        return {"status": "error", "operation": "merge",
                "error": "no value parsed as an IP or CIDR",
                "invalid": invalid[:cap]}
    if len(families) > 1:
        return {"status": "error", "operation": "merge",
                "error": "cannot merge IPv4 and IPv6 in one call; split the input by family",
                "families": sorted(f"IPv{v}" for v in families)}

    merged = list(ipaddress.collapse_addresses(nets))
    shown = merged[:cap]
    input_addresses = sum(net.num_addresses for net in nets)
    covered = sum(net.num_addresses for net in merged)
    return {
        "status": "ok",
        "operation": "merge",
        "family": f"IPv{families.pop()}",
        "input_count": len(values),
        "valid_count": len(nets),
        "invalid": invalid[:cap],
        "total_cidrs": len(merged),
        "returned": len(shown),
        "truncated": len(merged) > cap,
        "max_results": cap,
        "input_addresses": input_addresses,
        "covered_addresses": covered,
        "overlap_removed": input_addresses - covered,
        "cidrs": [
            {"cidr": str(net), "netmask": str(net.netmask), "network": str(net.network_address),
             "num_addresses": net.num_addresses}
            for net in shown
        ],
    }
