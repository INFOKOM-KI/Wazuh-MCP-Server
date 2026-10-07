#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Offline network arithmetic: split a CIDR block into equal sub-blocks, or merge
an IP/block list into the smallest covering CIDR set.
Answers "what does this block look like as /28s" and "what is the smallest
ruleset that covers these 400 hosts". No Wazuh API, no threat-intel provider, no
filesystem: the result is computed locally from the input.

Redaction: ``@blueteam_tool(redact=False)`` is deliberate. Layer 3 rewrites RFC1918
network and broadcast addresses (``10.0.0.0/24`` -> ``10.***.***.0/24``), which
destroys the answer, and the only pipeline escape is policy ``raw`` hard-gated
behind BLUETEAM_ALLOW_FORENSIC_BYPASS, so it would turn a default deployment into
a hard error. Same trap documented for ``misp.py`` and ``sigma_rules.py``.

Compensating controls:
  * The tool reads nothing. No Indexer, Manager, filesystem or store call, so it
    can only return addresses the caller supplied.
  * Every value it emits is parsed by ``ipaddress`` first. A value that fails
    validation is never echoed (see ``netcalc.REJECT_REASON``), so a pasted
    credential cannot ride back out inside an error message.
  * The audit log is unaffected: ``_audit_log`` runs params and the result
    preview through ``_redact_alert_data`` regardless of this flag.

NOTE: no ``from __future__ import annotations``; PEP 563 defers evaluation and
breaks @blueteam_tool type resolution.
"""
import json
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from mcp_server.core.netcalc import (
    DEFAULT_MAX_RESULTS,
    HARD_MAX_RESULTS,
    merge_networks,
    split_network,
)
from mcp_server.core.tool_decorator import blueteam_tool

_MAX_VALUE_LEN = 64


class SubnetCalcInput(BaseModel):
    """Input model for blueteam_subnet_calc."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    operation: Literal["split", "merge"] = Field(
        default="split",
        description="'split' divides one cidr into equal sub-blocks; 'merge' collapses ips "
                    "into the smallest covering CIDR set.")
    cidr: Optional[str] = Field(
        default=None, max_length=_MAX_VALUE_LEN,
        description="Block to split, e.g. '192.168.0.0/24'. Bare IPs are accepted as host routes. "
                    "Required for operation='split'.")
    prefix: Optional[int] = Field(
        default=None, ge=1, le=128,
        description="Subnet prefix for operation='split'. Must be longer than the input prefix. "
                    "Defaults to input prefix + 1 and the response marks that as a default.")
    ips: Optional[list[str]] = Field(
        default=None, max_length=1000,
        description="IPs and/or CIDRs to merge. Required for operation='merge'. Mixed IPv4 and "
                    "IPv6 in one call is rejected.")
    max_results: int = Field(
        default=DEFAULT_MAX_RESULTS, ge=1, le=HARD_MAX_RESULTS,
        description=f"Maximum rows returned (hard cap {HARD_MAX_RESULTS}). The response sets "
                    f"'truncated: true' when the true count is higher.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("ips")
    @classmethod
    def _check_item_length(cls, v):
        if v is None:
            return v
        for item in v:
            if len(item) > _MAX_VALUE_LEN:
                raise ValueError(f"entry too long (max {_MAX_VALUE_LEN} chars)")
        return v

    @model_validator(mode="after")
    def _require_operation_field(self):
        if self.operation == "split" and not self.cidr:
            raise ValueError("operation='split' requires 'cidr'")
        if self.operation == "merge" and not self.ips:
            raise ValueError("operation='merge' requires a non-empty 'ips' list")
        return self


def _render_markdown(payload: dict) -> str:
    """Render a netcalc result. Split and merge payloads share the error shape,
    so a failed calculation stays readable instead of dumping raw JSON."""
    if payload.get("status") != "ok":
        return f"# Subnet calculation failed\n\n**Error**: {payload.get('error')}"

    if payload["operation"] == "split":
        lines = [f"# 🧮 Subnet Split - `{payload['input']}` -> /{payload['new_prefix']}", "",
                 f"**Subnets**: {payload['total_subnets']:,} total, {payload['returned']:,} returned"
                 + (" (truncated - raise `max_results`)" if payload["truncated"] else ""),
                 f"**Per subnet**: {payload['addresses_per_subnet']:,} addresses, "
                 f"{payload['usable_hosts_per_subnet']:,} usable hosts"]
        if payload.get("input_normalized_from"):
            lines.append(f"**Input masked to network**: `{payload['input_normalized_from']}` → "
                         f"`{payload['input']}` (host bits were set, not rejected)")
        if payload.get("new_prefix_source") == "default":
            lines.append(f"**Prefix defaulted** to /{payload['new_prefix']} (input + 1) - pass "
                         f"`prefix` to choose it explicitly")
        lines += ["",
                  "| # | CIDR | Netmask | Network | Broadcast | Usable | First host | Last host |",
                  "|---|---|---|---|---|---|---|---|"]
        for index, row in enumerate(payload["subnets"]):
            lines.append(f"| {index} | `{row['cidr']}` | {row['netmask']} | {row['network']} "
                         f"| {row.get('broadcast', '—')} | {row['usable_hosts']:,} "
                         f"| {row['first_host']} | {row['last_host']} |")
        lines += ["", "_A /31 or /127 reports 2 usable hosts and a host route reports 1 "
                      "(RFC 3021 / RFC 6164); IPv6 has no broadcast column._"]
        return "\n".join(lines)

    lines = ["# 🧮 CIDR Merge", "",
             f"**Input**: {payload['input_count']:,} value(s), {payload['family']}",
             f"**Covering set**: {payload['total_cidrs']:,} CIDR(s) covering "
             f"{payload['covered_addresses']:,} addresses"]
    if payload["overlap_removed"]:
        lines.append(f"**Overlap/adjacency removed**: {payload['overlap_removed']:,} addresses no "
                     f"longer need their own rule")
    if payload["truncated"]:
        lines.append(f"**Truncated**: showing {payload['returned']:,} of {payload['total_cidrs']:,} "
                     f"- raise `max_results`")
    if payload["invalid"]:
        lines += ["", f"**Unparsed values ({len(payload['invalid'])})** — dropped from the merge, "
                      f"by position in the input list:"]
        lines += [f"- input[{item['index']}] — {item['reason']}" for item in payload["invalid"]]
    lines += ["", "| # | CIDR | Netmask | Addresses |", "|---|---|---|---|"]
    for index, row in enumerate(payload["cidrs"]):
        lines.append(f"| {index} | `{row['cidr']}` | {row['netmask']} | {row['num_addresses']:,} |")
    lines += ["", "_Deploy this list as block/exclusion rules instead of N host rules; feed it "
                  "back through `operation=\"split\"` to enumerate._"]
    return "\n".join(lines)


@blueteam_tool(
    name="blueteam_subnet_calc",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    # Output stays unmasked: a masked CIDR is not an answer. See module docstring.
    redact=False,
)
async def blueteam_subnet_calc(params: SubnetCalcInput) -> str:
    """Split or merge CIDR blocks offline (no API, no network, deterministic).
    Use this to turn attacker/scanner source blocks into enumerable subnets, or
    to collapse a host blocklist into the smallest firewall rule set. Both
    operations are computed from the input alone: nothing is looked up, so an
    unchanged input always yields the same output.

    Args:
        params.operation: 'split' (default) or 'merge'.
        params.cidr: Block to split. Bare IP becomes a host route.
        params.prefix: Subnet prefix, must be longer than the input prefix.
        Omitted -> input prefix + 1, reported as a default in the response.
        params.ips: IPs/CIDRs to merge (1-1000). One family per call.
        params.max_results: Row cap, 1-256 (default 64).
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json, unmasked. Split: total/returned subnet counts,
        per-subnet netmask, network, broadcast, usable hosts, first/last host.
        Merge: covering CIDR list, address totals, overlap removed, and any
        unparsed input positions under ``invalid``. Failures return
        ``status: "error"`` with a reason, never a partial result presented as
        complete.

    Private addresses come back exact - that is the point of the tool. A rejected
    value is never echoed back, and the audit log still applies the full
    redaction pipeline.

    Worked Examples:
        1. /24 into /28s -> ``blueteam_subnet_calc(cidr="192.168.0.0/24", prefix=28)``
        2. Collapse a scanner blocklist -> ``blueteam_subnet_calc(operation="merge",
           ips=["203.0.113.5", "203.0.113.6", "203.0.113.0/25"])``
        3. IPv6 without a prefix guess -> ``blueteam_subnet_calc(cidr="2001:db8::/120",
           prefix=126, response_format="json")``

    Permissions: none. Reads no Indexer, Manager, filesystem or store data.
    Rate limits: none. Local arithmetic. Output is capped by ``max_results``
    rather than by an upstream quota.
    """
    if params.operation == "split":
        payload = split_network(params.cidr, params.prefix, params.max_results)
    else:
        payload = merge_networks(params.ips or [], params.max_results)

    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _render_markdown(payload)
