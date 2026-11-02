#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Audit the cve.now technology map against the groups a deployment actually emits.

``mcp_server/threat_intel/cve_now_tech_map.json`` decides when
``blueteam_cve_now_attack_correlate`` may call an alert technology-based correlation.
It was seeded from ruleset files, not from live telemetry, so this script reports what
the Indexer really contains and leaves the decision to the operator. It never edits the
map and never proposes a mapping it cannot show evidence for.

Read-only by construction:
  * one ``POST {index}/_search`` with ``size: 0`` - no documents are returned, only
    bucket counts and a two-hit sample of ``rule.id``;
  * a ``GET {index}/_field_caps`` probe before the search;
  * the request body is checked against a write-key denylist before it is sent, so a
    future edit that adds ``script``, ``pipeline`` or an update clause fails loudly;
  * no credentials are printed; only the indexer host is shown.

Usage:
    export WAZUH_INDEXER_URL="https://<indexer>:9200"
    export WAZUH_INDEXER_USER="admin"                  # optional, default admin
    export WAZUH_INDEXER_PASSWORD="<from your vault>"  # never echo this
    export WAZUH_INDEXER_VERIFY_SSL="true"             # set false only for a lab CA

    # request shape only, no network, no credentials needed
    python scripts/cve_now_tech_map_audit.py --dry-run --json

    # the audit
    python scripts/cve_now_tech_map_audit.py --days 7
    python scripts/cve_now_tech_map_audit.py --days 30 --json > audit.json

Exit codes: 0 = report produced, 1 = Indexer error or unusable response, 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Running `python scripts/<this file>` puts `scripts/` on sys.path, not the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEFAULT_INDEX = "wazuh-alerts-*"
DEFAULT_DAYS = 7
DEFAULT_GROUPS = 300

# rule.groups is the audit subject; decoder and location are where the log came from.
EVIDENCE_FIELDS = ("decoder.name", "location")

# Keys that would turn the search into a write or a server-side execution.
WRITE_KEYS = frozenset({
    "script", "script_fields", "runtime_mappings", "pipeline", "_update", "_delete",
    "_bulk", "upsert", "doc", "dest", "conflicts", "max_docs", "refresh",
})

FORBIDDEN_ENDPOINT_PARTS = ("_update", "_delete", "_bulk", "_doc", "_close", "_open")


def build_body(days: int, field: str, groups: int, *,
               decoders: bool = True, locations: bool = True,
               samples: bool = True) -> dict:
    """Aggregation over ``field`` with per-bucket evidence sub-aggregations."""
    sub: dict = {}
    if decoders:
        sub["decoders"] = {"terms": {"field": "decoder.name", "size": 5}}
    if locations:
        sub["locations"] = {"terms": {"field": "location", "size": 5}}
    if samples:
        # rule.id only: descriptions can carry usernames or paths.
        sub["samples"] = {"top_hits": {"size": 2, "_source": ["rule.id"]}}

    groups_agg: dict = {"terms": {"field": field, "size": groups}}
    if sub:
        groups_agg["aggs"] = sub

    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {"groups": groups_agg},
    }


def write_keys_in(body, path: str = "") -> list[str]:
    """Return every write/execute key found anywhere in a request body."""
    found: list[str] = []
    if isinstance(body, dict):
        for key, value in body.items():
            here = f"{path}.{key}" if path else str(key)
            if key in WRITE_KEYS:
                found.append(here)
            found.extend(write_keys_in(value, here))
    elif isinstance(body, list):
        for index, value in enumerate(body):
            found.extend(write_keys_in(value, f"{path}[{index}]"))
    return found


def assert_read_only(body: dict, index_pattern: str) -> None:
    """Refuse to send a body that could write or execute on the cluster."""
    bad_keys = write_keys_in(body)
    if bad_keys:
        raise SystemExit(f"refusing to send: write/execute key(s) present: {bad_keys}")
    lowered = index_pattern.lower()
    bad_path = [part for part in FORBIDDEN_ENDPOINT_PARTS if part in lowered]
    if bad_path:
        raise SystemExit(f"refusing to send: index pattern carries {bad_path}")
    if body.get("size") != 0:
        raise SystemExit("refusing to send: size must stay 0, the audit reads no documents")


def indexer_label(url: str) -> str:
    """Scheme, host and port only. A credential embedded in the URL never prints."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if not parts.hostname:
        return "(unparsable WAZUH_INDEXER_URL)"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme or 'https'}://{parts.hostname}{port}"


def name_slugs(token: str, tech_slugs) -> list[str]:
    """Slugs that appear as a whole segment of the group token itself.

    ``mysql_login_fail`` -> ``mysql``; ``php2shell`` -> nothing, because ``php2shell``
    is not ``php``. This is naming evidence for a human to review, never an automatic
    mapping: a rule named after a product can still be a generic web-attack rule.
    """
    parts = re.split(r"[^a-z0-9.]+", str(token).lower())
    return sorted({part for part in parts if part in tech_slugs})


def event_source_slugs(decoders: list[str], locations: list[str], tech_slugs) -> list[str]:
    """Slugs a decoder name or a path segment equals exactly.

    This is log-source evidence, not group meaning: ``web_attack`` on
    ``/var/log/nginx/access.log`` proves nginx wrote the log, not that the rule is
    about the nginx product. Reported in its own bucket so it is never mistaken for
    a reason to map the group.
    """
    hits = set()
    for name in decoders:
        slug = name.strip().lower().replace(" ", "-")
        if slug in tech_slugs:
            hits.add(slug)
    for location in locations:
        for part in Path(location).parts:
            slug = part.strip().lower()
            if slug in tech_slugs:
                hits.add(slug)
    return sorted(hits)


def _bucket_values(bucket: dict, name: str) -> list[str]:
    return [row.get("key") for row in ((bucket.get(name) or {}).get("buckets") or [])
            if row.get("key")]


def classify(buckets: list[dict], group_map: dict[str, str], tech_slugs) -> dict:
    """Split observed groups into mapped, reviewable, log-source-only, and unrelated."""
    confirmed, needs_review, source_only, no_signal = [], [], [], []
    for bucket in buckets:
        token = bucket.get("key")
        decoders = _bucket_values(bucket, "decoders")
        locations = _bucket_values(bucket, "locations")
        samples = [hit.get("_source", {}).get("rule.id")
                   for hit in (((bucket.get("samples") or {}).get("hits") or {}).get("hits") or [])]
        row = {
            "group": token,
            "docs": bucket.get("doc_count"),
            "decoders": decoders,
            "locations": locations,
            "rule_ids": [rule_id for rule_id in samples if rule_id],
        }
        slug = group_map.get(str(token).lower())
        if slug:
            confirmed.append({**row, "slug": slug})
            continue
        row["name_suggests"] = name_slugs(token, tech_slugs)
        row["event_source_suggests"] = event_source_slugs(decoders, locations, tech_slugs)
        if row["name_suggests"]:
            needs_review.append(row)
        elif row["event_source_suggests"]:
            source_only.append(row)
        else:
            no_signal.append(row)
    observed = {str(row["group"]).lower() for row in confirmed}
    stale = [token for token in group_map if token not in observed]
    return {"confirmed": confirmed, "in_map_not_observed": stale,
            "unmapped_needs_review": needs_review,
            "unmapped_log_source_only": source_only,
            "unmapped_no_signal": no_signal}


def render_text(report: dict) -> str:
    lines = [f"cve.now technology map audit - read-only over {report['indexer']}",
             f"index {report['index']} | window last {report['days']}d | field {report['field']}",
             f"observed groups {report['observed_groups']} | mapped tokens {len(report['map']['groups'])}"
             f" of {report['map']['slugs']} slugs", ""]

    if report.get("partial"):
        lines.append("WARNING: _partial - some shards rejected the query, counts are a subset.")
        lines.append("")
    if report.get("fields_verified"):
        missing = report.get("fields_missing") or []
        lines.append(f"field_caps: {report['fields_verified']} verified"
                     + (f", missing: {missing} (sub-aggregation dropped)" if missing else ""))
        lines.append("")

    def section(title: str, rows: list[dict], formatter) -> None:
        lines.append(f"{title} ({len(rows)})")
        if not rows:
            lines.append("  (none)")
        for row in rows[:40]:
            lines.append(formatter(row))
        if len(rows) > 40:
            lines.append(f"  ... {len(rows) - 40} more in --json output")
        lines.append("")

    section("MAPPED AND OBSERVED", report["confirmed"],
            lambda r: f"  {r['group']:<28} {r['docs']:>8} docs -> {r['slug']}"
                      f"   decoders={r['decoders']} locations={r['locations']}")
    section("IN MAP BUT NOT OBSERVED", [{"group": t} for t in report["in_map_not_observed"]],
            lambda r: f"  {r['group']}")
    section("UNMAPPED, THE GROUP NAME NAMES A TECHNOLOGY (review by hand)",
            report["unmapped_needs_review"],
            lambda r: f"  {r['group']:<28} {r['docs']:>8} docs   name suggests={r['name_suggests']}"
                      f"   decoders={r['decoders']} locations={r['locations']}")
    section("UNMAPPED, LOG SOURCE ONLY (never map a group from this)",
            report["unmapped_log_source_only"],
            lambda r: f"  {r['group']:<28} {r['docs']:>8} docs   written by={r['event_source_suggests']}"
                      f"   decoders={r['decoders']} locations={r['locations']}")
    section("UNMAPPED, NO TECHNOLOGY SIGNAL (leave unmapped)",
            report["unmapped_no_signal"],
            lambda r: f"  {r['group']:<28} {r['docs']:>8} docs   decoders={r['decoders']}"
                      f" locations={r['locations']}")

    lines.append("No mapping was changed by this run. A mapping is added only when the evidence")
    lines.append("above names the technology itself, never because a group name resembles one.")
    return "\n".join(lines)


async def run_audit(args) -> int:
    from mcp_server.threat_intel.cve_now import TECH_SLUGS, _GROUP_MAP
    from mcp_server.wazuh.indexer import _wazuh_indexer_field_caps, _wazuh_indexer_post

    caps = await _wazuh_indexer_field_caps([args.field, *EVIDENCE_FIELDS], args.index)
    verified = bool(caps)
    if verified and args.field not in caps:
        # An empty bucket list would read as "no groups", when the field is simply absent.
        print(f"{args.field} is not mapped in {args.index} - check --index/--field. "
              "The audit needs that field to say anything at all.", file=sys.stderr)
        return 1
    missing = [name for name in EVIDENCE_FIELDS if verified and name not in caps]
    body = build_body(args.days, args.field, args.max_groups,
                      decoders=not (verified and "decoder.name" in missing),
                      locations=not (verified and "location" in missing))
    assert_read_only(body, args.index)

    response = await _wazuh_indexer_post(body, args.index)
    if response.get("error"):
        print(f"Indexer error: {response['error']}", file=sys.stderr)
        return 1
    buckets = ((response.get("aggregations") or {}).get("groups") or {}).get("buckets") or []
    if not buckets:
        print("No rule.groups values in the window. Widen --days.", file=sys.stderr)
        return 1

    map_path = Path(__file__).resolve().parent.parent / "mcp_server" / "threat_intel" / "cve_now_tech_map.json"
    map_doc = json.loads(map_path.read_text(encoding="utf-8"))
    report = {
        "indexer": indexer_label(os.environ.get("WAZUH_INDEXER_URL", "")),
        "index": args.index,
        "days": args.days,
        "field": args.field,
        "observed_groups": len(buckets),
        "partial": bool(response.get("_partial")),
        "fields_verified": len(caps) if verified else 0,
        "fields_missing": missing,
        "map": {"groups": _GROUP_MAP, "slugs": len(TECH_SLUGS),
                "verified_on": (map_doc.get("_meta") or {}).get("verified_on")},
        **classify(buckets, _GROUP_MAP, TECH_SLUGS),
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render_text(report))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--index", default=DEFAULT_INDEX)
    parser.add_argument("--field", default="rule.groups")
    parser.add_argument("--max-groups", type=int, default=DEFAULT_GROUPS)
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the request body and exit; no network, no credentials")
    args = parser.parse_args()

    if args.dry_run:
        body = build_body(args.days, args.field, args.max_groups)
        assert_read_only(body, args.index)
        print(json.dumps({"dry_run": True, "method": "POST",
                          "endpoint": f"{{indexer}}/{args.index}/_search",
                          "read_only": True, "body": body}, indent=2))
        return 0

    missing = [name for name in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_PASSWORD")
               if not os.environ.get(name)]
    if missing:
        print(f"missing environment variable(s): {', '.join(missing)}", file=sys.stderr)
        return 2

    import asyncio
    return asyncio.run(run_audit(args))


if __name__ == "__main__":
    sys.exit(main())
