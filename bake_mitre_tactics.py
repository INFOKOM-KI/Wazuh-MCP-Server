#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
The ATT&CK tactic metadata into mcp_server/label/mitre_tactics_generated.py.
The generated module is imported at runtime so the labeler never parses the ~40-53 MB
STIX bundle and never fetches anything: the bundle is a build input, not a dependency.

Usage:
    python3 bake_mitre_tactics.py                                  # reads $BLUETEAM_STIX_CACHE
    python3 bake_mitre_tactics.py --bundle /path/to/enterprise-attack.json
    python3 bake_mitre_tactics.py --fetch                          # download, then bake
    python3 bake_mitre_tactics.py --check                          # drift report, writes nothing

The vocabulary is a UNION: STIX supplies 15 x-mitre-tactic objects, while this
deployment's ruleset still emits "Defense Evasion", which ATT&CK v18 split into
Stealth + Defense Impairment. Baking STIX alone would drop that name and the
criteria guard would raise at import, taking the whole tool registry down.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
OUT = REPO / "mcp_server" / "label" / "mitre_tactics_generated.py"
DEFAULT_BUNDLE = "/var/log/blue-team-mcp/mitre_enterprise_attack.json"
DEFAULT_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
               "refs/heads/master/enterprise-attack/enterprise-attack.json")
MAX_BYTES = int(os.environ.get("BLUETEAM_STIX_MAX_MB", "100")) * 1024 * 1024
EXTERNAL_ID = re.compile(r"^TA\d{4}$")


def extract_tactics(bundle: dict) -> list[dict]:
    """x-mitre-tactic objects -> sorted [{shortname, name, external_id, description}].
    A tactic with no external_id or shortname is skipped rather than emitted with a
    placeholder: an unidentified entry would silently join the label vocabulary.
    """
    out: list[dict] = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "x-mitre-tactic":
            continue
        shortname = (obj.get("x_mitre_shortname") or "").strip()
        name = (obj.get("name") or "").strip()
        external = ""
        for ref in obj.get("external_references") or []:
            if isinstance(ref, dict) and EXTERNAL_ID.match(str(ref.get("external_id") or "")):
                external = str(ref["external_id"])
                break
        if not (shortname and name and external):
            continue
        out.append({"shortname": shortname, "name": name, "external_id": external,
                    "description": " ".join((obj.get("description") or "").split())})
    return sorted(out, key=lambda t: t["external_id"])


def attack_version(bundle: dict) -> str:
    for obj in bundle.get("objects", []):
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version") or obj.get("name") or "unknown")
    return "unknown"


def vocabulary_drift(upstream: set[str], expected: set[str],
                     legacy: set[str]) -> tuple[list[str], list[str]]:
    """Local copy, deliberately: importing mcp_server.label.criteria here would import
    the stale generated module and its guard would raise before this script could
    regenerate it. constants.mitre_vocabulary_drift holds the runtime implementation."""
    return (sorted(expected - upstream - legacy), sorted(upstream - expected))


def render(tactics: list[dict], source: str, sha: str, version: str) -> str:
    rows = "\n".join(
        f"{json.dumps(t['shortname'])}: {{"
        f"\"name\": {json.dumps(t['name'])}, "
        f"\"external_id\": {json.dumps(t['external_id'])}, "
        f"\"description\": {json.dumps(t['description'])}}},"
        for t in tactics
    )
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        '#!/usr/bin/env python3\n'
        '"""\n'
        "© NAuliajati - TangerangKota-CSIRT\n"
        "GENERATED FILE do not edit. Produced by bake_mitre_tactics.py.\n\n"
        f"Source      : {source}\n"
        f"Source sha256: {sha}\n"
        f"ATT&CK      : {version}\n"
        f"Tactics     : {len(tactics)} x-mitre-tactic objects\n"
        f"Generated   : {stamp}\n\n"
        "Runtime imports this module instead of parsing the STIX bundle, so the labeler\n"
        "does no I/O and no network. Regenerate after an ATT&CK release, or when\n"
        "constants.MITRE_TACTIC_TO_CATEGORY gains a tactic:\n"
        "python3 bake_mitre_tactics.py --bundle /var/log/blue-team-mcp/"
        "mitre_enterprise_attack.json\n\n"
        "Descriptions are provenance for humans; the classifier prompt lives in\n"
        "criteria.py, which keeps its own one-line phrases per tactic.\n"
        '"""\n'
        f"SOURCE = {json.dumps(source)}\n"
        f"SOURCE_SHA256 = {json.dumps(sha)}\n"
        f"ATTACK_VERSION = {json.dumps(version)}\n\n"
        "TACTICS: dict[str, dict[str, str]] = {\n"
        f"{rows}\n"
        "}\n"
    )


def _strip_stamp(text: str) -> str:
    """Drop the generation timestamp before comparing, so a re-run with an unchanged
    bundle reports 'already current' instead of rewriting one line of churn."""
    return re.sub(r"^Generated   : .*$", "Generated   : <stamp>", text, flags=re.M)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2])
    parser.add_argument("--bundle", default=os.environ.get("BLUETEAM_STIX_CACHE", DEFAULT_BUNDLE),
                        help=f"local STIX 2.1 bundle (default: {DEFAULT_BUNDLE})")
    parser.add_argument("--url", default=os.environ.get("MITRE_ATTACK_STIX", DEFAULT_URL))
    parser.add_argument("--fetch", action="store_true",
                        help="download --url first, then bake from it")
    parser.add_argument("--check", action="store_true",
                        help="report drift without writing the generated module")
    args = parser.parse_args()

    raw: bytes
    if args.fetch:
        url = args.url
        if not url.startswith("https://"):
            print(f"refusing non-https source: {url}", file=sys.stderr)
            return 2
        print(f"fetching {url}")
        with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "blue-team-mcp/1.0"}),
                timeout=60) as resp:
            raw = resp.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            print(f"bundle exceeds {MAX_BYTES} bytes; raise BLUETEAM_STIX_MAX_MB", file=sys.stderr)
            return 2
        Path(args.bundle).parent.mkdir(parents=True, exist_ok=True)
        Path(args.bundle).write_bytes(raw)
        print(f"cached {len(raw)} bytes to {args.bundle}")
    else:
        path = Path(args.bundle)
        if not path.is_file():
            print(f"STIX bundle not found: {path}\n"
                  f"Populate it with any of:\n"
                  f"  - the existing loader: any blueteam_stix_* tool call, which caches to\n"
                  f"    $BLUETEAM_STIX_CACHE ({DEFAULT_BUNDLE})\n"
                  f"  - this script: --fetch\n"
                  f"  - --bundle pointing at a copy you already have", file=sys.stderr)
            return 2
        raw = path.read_bytes()

    bundle = json.loads(raw.decode("utf-8"))
    tactics = extract_tactics(bundle)
    if len(tactics) < 10:
        print(f"only {len(tactics)} tactics extracted - bundle looks wrong, refusing to write",
              file=sys.stderr)
        return 1

    sys.path.insert(0, str(REPO))
    for key, value in (("WAZUH_INDEXER_URL", "https://127.0.0.1:9200"),
                       ("WAZUH_INDEXER_PASSWORD", "unused")):
        os.environ.setdefault(key, value)
    from mcp_server.core.constants import LEGACY_MITRE_TACTICS, MITRE_TACTIC_TO_CATEGORY

    upstream = {t["name"] for t in tactics}
    expected = set(MITRE_TACTIC_TO_CATEGORY)
    missing, extra = vocabulary_drift(upstream, expected, set(LEGACY_MITRE_TACTICS))
    for name in missing:
        print(f"MISSING: {name} is scored by this deployment but absent from the bundle",
              file=sys.stderr)
    for name in extra:
        print(f"note: {name} ships upstream but is not scored here (cannot be labelled)")

    content = render(tactics, args.bundle if not args.fetch else args.url,
                     hashlib.sha256(raw).hexdigest(), attack_version(bundle))
    if args.check:
        print(f"drift: {len(missing)} missing, {len(extra)} extra; nothing written (--check)")
        return 1 if missing else 0

    previous = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
    if _strip_stamp(previous) == _strip_stamp(content):
        print(f"{OUT.name} already current: {len(tactics)} tactics, ATT&CK "
              f"{attack_version(bundle)}")
        return 1 if missing else 0
    OUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)}: {len(tactics)} tactics, "
          f"ATT&CK {attack_version(bundle)}, sha256 {hashlib.sha256(raw).hexdigest()[:12]}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
