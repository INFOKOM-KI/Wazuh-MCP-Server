#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for the STIX 2.1 bundle producer: egress exclusion rules,
deterministic UUIDv5 ids, bundle shape, and the fixed-point redaction gate.
The exclusion tests are the security boundary: a regression that lets an RFC1918
address, an owned domain, an internal hostname, or an email into a bundle is a
data leak, not a formatting bug.
"""
from __future__ import annotations
import asyncio
import json
import os
import tempfile

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
os.environ.setdefault("BLUETEAM_RERANK_ENABLED", "false")
os.environ.setdefault("BLUETEAM_EXPORT_DIR", tempfile.mkdtemp(prefix="stix-export-test-"))
os.environ.setdefault("BLUETEAM_OWNED_DOMAINS", "tangerangkota.go.id")
os.environ.setdefault("BLUETEAM_STIX_IDENTITY_NAME", "TangerangKota CSIRT")
os.environ.setdefault("BLUETEAM_STIX_EGRESS_ENABLED", "true")

import pytest

try:
    import stix2
    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

from mcp_server.core.redact import _redact_alert_data, get_owned_domains, set_owned_domains
from mcp_server.core.stix_objects import TLP_MARKING_DEFINITIONS, load_markings_file, stix_id
from mcp_server.tools.stix_export import (StixExportInput, _build_bundle, blueteam_stix_export,
                                          classify_indicator, pattern_for)


@pytest.fixture(autouse=True)
def _owned_domains_configured():
    """redact.py reads BLUETEAM_OWNED_DOMAINS into module state when it is first
    imported, so the setdefault above loses to whichever test module imported it
    first (test_redact sets the same var empty). set_owned_domains is the runtime API
    for exactly this and does not depend on import order.
    """
    before = get_owned_domains()
    set_owned_domains("tangerangkota.go.id")
    yield
    set_owned_domains(",".join(sorted(before)))

PUBLIC = [
    "45.61.136.7",
    "23.94.5.201",
    "2001:4860:4860::8888",
    "evil-c2.example.com",
    "http://evil.example.com/payload.exe",
    "https://c2.bad.example.org:8443/a",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
]

NOT_SHAREABLE = [
    "10.0.0.5", "192.168.1.10", "172.16.5.4", "172.31.9.9", "127.0.0.1",
    "169.254.10.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "203.0.113.10", "192.0.2.5", "198.18.0.1", "100.64.0.1",
    "::1", "fe80::1", "::ffff:10.0.0.1",
    "soc.tangerangkota.go.id", "mail.tangerangkota.go.id", "host.local",
    "web.internal", "WEBSERVER01", "not a valid ioc!",
    "http://10.0.0.5/x", "http://u:p@evil.example.com/", "ftp://evil.example.com/x",
    "file:///etc/passwd", "not-a-hash", "analyst@example.com",
]


@pytest.mark.parametrize("value", PUBLIC)
def test_public_indicators_are_shareable(value):
    kind, reason = classify_indicator(value)
    assert kind, f"{value} should be shareable but was dropped: {reason}"


@pytest.mark.parametrize("value", NOT_SHAREABLE)
def test_internal_and_invalid_indicators_are_dropped(value):
    kind, reason = classify_indicator(value)
    assert kind == "", f"{value} must never leave the perimeter (classified as {kind})"
    assert reason


def test_pattern_shapes_match_stix_2_1():
    assert pattern_for("ipv4-addr", "45.61.136.7") == "[ipv4-addr:value = '45.61.136.7']"
    assert pattern_for("domain-name", "Evil-C2.Example.com") == "[domain-name:value = 'evil-c2.example.com']"
    assert pattern_for("url", "http://e.example.com/A") == "[url:value = 'http://e.example.com/A']"
    assert pattern_for("file", "D41D8CD98F00B204E9800998ECF8427E") == \
        "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"
    assert pattern_for("url", "http://e.example.com/a'b") == "[url:value = 'http://e.example.com/a\\'b']"


def test_indicator_ids_are_deterministic_and_distinct():
    assert stix_id("indicator", "[ipv4-addr:value = '45.61.136.7']") == \
        stix_id("indicator", "[ipv4-addr:value = '45.61.136.7']")
    assert stix_id("indicator", "a") != stix_id("indicator", "b")
    assert stix_id("indicator", "a") != stix_id("report", "a")
    assert stix_id("indicator", "a").startswith("indicator--")


def _bundle_for(values, **meta_overrides):
    rows = [{"kind": classify_indicator(v)[0], "value": v, "reference": ""}
            for v in values if classify_indicator(v)[0]]
    meta = {
        "identity": {"type": "identity", "spec_version": "2.1",
                     "id": stix_id("identity", "TangerangKota CSIRT"),
                     "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
                     "name": "TangerangKota CSIRT", "identity_class": "organization"},
        "tlp": "AMBER", "report_name": "Test bundle", "description": "",
        "created": "2026-01-01T00:00:00.000Z", "sources": ["crowdsec"],
        "confidence": 70, "techniques": {}, "extra_markings": [],
    }
    meta.update(meta_overrides)
    return _build_bundle(rows=rows, meta=meta)


def test_bundle_is_conformant_and_self_contained():
    bundle = _bundle_for(PUBLIC)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    ids = set()
    for obj in bundle["objects"]:
        assert obj["spec_version"] == "2.1", obj
        assert obj["type"] and obj["id"] and obj["created"], obj
        ids.add(obj["id"])
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report["object_refs"], "report must reference its indicators"
    assert set(report["object_refs"]) <= ids, "dangling object_refs"
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["pattern_type"] == "stix" and indicator["pattern_version"] == "2.1"
    assert indicator["valid_from"] and indicator["created_by_ref"]
    assert indicator["object_marking_refs"] == [TLP_MARKING_DEFINITIONS["AMBER"]["id"]]
    assert indicator["confidence"] == 70
    assert TLP_MARKING_DEFINITIONS["AMBER"]["id"] == \
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def test_relationships_link_only_supplied_techniques():
    bundle = _bundle_for(["45.61.136.7"],
                         techniques={"T1071.001": "attack-pattern--abc"})
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "indicates"
    assert rels[0]["target_ref"] == "attack-pattern--abc"
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert rels[0]["source_ref"] == ind["id"]
    assert rels[0]["id"] == stix_id("relationship", f"indicates:{ind['id']}:attack-pattern--abc")


def test_bundle_survives_the_redaction_fixed_point():
    payload = json.dumps(_bundle_for(PUBLIC + NOT_SHAREABLE), sort_keys=True)
    assert "10.0.0.5" not in payload and "tangerangkota.go.id" not in payload
    assert _redact_alert_data(payload, policy="protect_victim") == payload


def test_export_writes_a_bundle_and_excludes_internal_values():
    out_dir = os.environ["BLUETEAM_EXPORT_DIR"]
    target = os.path.join(out_dir, "stix", "test-export.json")
    result = json.loads(asyncio.run(blueteam_stix_export(StixExportInput(
        indicators=PUBLIC + NOT_SHAREABLE,
        report_name="Egress test",
        tlp="AMBER",
        response_format="json",
        include_bundle=True,
        path=target,
    ))))
    assert result["status"] == "written", result
    assert result["indicators"] == len(PUBLIC)
    assert result["dropped"], "dropped values must be reported per reason"
    written = open(target, encoding="utf-8").read()
    for secret in ("10.0.0.5", "192.168.1.10", "tangerangkota.go.id", "WEBSERVER01",
                   "analyst@example.com", "not a valid ioc"):
        assert secret not in written, f"{secret} leaked into the bundle"
    assert json.loads(written)["type"] == "bundle"
    assert result["bundle"] == json.loads(written)


def test_export_refuses_before_config_or_identity():
    saved = os.environ.pop("BLUETEAM_STIX_EGRESS_ENABLED", None)
    try:
        err = json.loads(asyncio.run(blueteam_stix_export(
            StixExportInput(indicators=["45.61.136.7"], response_format="json"))))
        assert "disabled" in err["error"]
        os.environ["BLUETEAM_STIX_EGRESS_ENABLED"] = "true"
        os.environ.pop("BLUETEAM_STIX_IDENTITY_NAME", None)
        err = json.loads(asyncio.run(blueteam_stix_export(
            StixExportInput(indicators=["45.61.136.7"], response_format="json"))))
        assert "BLUETEAM_STIX_IDENTITY_NAME" in err["error"]
    finally:
        os.environ["BLUETEAM_STIX_EGRESS_ENABLED"] = "true"
        os.environ["BLUETEAM_STIX_IDENTITY_NAME"] = "TangerangKota CSIRT"


def test_export_refuses_when_no_shareable_values_remain():
    result = json.loads(asyncio.run(blueteam_stix_export(StixExportInput(
        indicators=["10.0.0.5", "soc.tangerangkota.go.id", "a@b.example.com"],
        response_format="json"))))
    assert "No shareable indicators" in result["error"]
    assert result["dropped"]


def test_location_path_in_description_trips_the_fixed_point_gate():
    """The gate must catch what the allowlist cannot see: free-text context."""
    result = json.loads(asyncio.run(blueteam_stix_export(StixExportInput(
        indicators=["45.61.136.7"],
        description="seen in /var/log/auth.log on the Zimbra host",
        response_format="json"))))
    assert "Egress refused" in result["error"], result


def test_export_never_masks_values_into_the_bundle():
    """Exclusions are drops, never '*' masks - a masked IOC is a wrong IOC."""
    payload = json.dumps(_bundle_for(PUBLIC + NOT_SHAREABLE), sort_keys=True)
    assert "*" not in payload, "no masked placeholder may reach a shared bundle"


@pytest.mark.skipif(not HAS_STIX2, reason="stix2 not installed")
def test_bundle_parses_with_the_reference_stix2_library():
    """Cross-validation against an independent STIX 2.1 implementation.
    The attack-pattern id must be a real ``<type>--<UUID>``: the spec rejects a
    short-form placeholder, and stix2 validates ids on parse."""
    technique_id = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
    bundle = _bundle_for(["45.61.136.7", "evil-c2.example.com", "http://evil.example.com/a",
                          "d41d8cd98f00b204e9800998ecf8427e"],
                         techniques={"T1071.001": technique_id})
    bundle["objects"].append({
        "type": "attack-pattern", "spec_version": "2.1", "id": technique_id,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "Test technique",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1071.001"}],
    })
    # allow_custom=False: every object and property must be one the spec defines. A
    # stray custom property would pass in lenient mode and be dropped by the peer.
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    assert parsed["type"] == "bundle"
    assert len(parsed["objects"]) == len(bundle["objects"])


# Markings file: TLP 1.0 and TLP 2.0 shapes
TLP_2_0_AMBER_STRICT = {
    "type": "marking-definition", "spec_version": "2.1",
    "id": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "created": "2022-10-01T00:00:00.000Z", "name": "TLP:AMBER+STRICT",
    "extensions": {
        "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
            "extension_type": "property-extension", "tlp_2_0": "amber+strict"}},
}


def _write_markings(tmp_path, payload):
    path = tmp_path / "markings.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_markings_file_accepts_tlp_2_0_extension_form(tmp_path):
    """TLP 2.0 carries the value in `extensions`, not a top-level `definition`.
    The validator used to reject the exact form the module docstring names."""
    bundle = {"type": "bundle", "id": "bundle--d6e3c0b4-f916-4d15-a01f-e3761c5f48ac",
              "objects": [TLP_2_0_AMBER_STRICT]}
    objects, err = load_markings_file(_write_markings(tmp_path, bundle))
    assert err == ""
    assert objects[0]["name"] == "TLP:AMBER+STRICT"
    extension = objects[0]["extensions"]["extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"]
    assert extension["tlp_2_0"] == "amber+strict"


def test_markings_file_still_accepts_tlp_1_0_definition(tmp_path):
    objects, err = load_markings_file(_write_markings(tmp_path, TLP_MARKING_DEFINITIONS["AMBER"]))
    assert err == ""
    assert objects[0]["definition"] == {"tlp": "amber"}


def test_markings_file_accepts_list_and_single_object(tmp_path):
    for payload in ([TLP_2_0_AMBER_STRICT], TLP_2_0_AMBER_STRICT):
        objects, err = load_markings_file(_write_markings(tmp_path, payload))
        assert err == ""
        assert len(objects) == 1


@pytest.mark.parametrize("entry,needle", [
    ({"type": "marking-definition", "id": "marking-definition--x", "extensions": {"a": 1}}, "name"),
    ({"type": "marking-definition", "id": "marking-definition--x", "name": "n"}, "definition or extensions"),
    ({"type": "identity", "id": "identity--x", "name": "n", "definition": {}}, "expected 'marking-definition'"),
    ({"type": "marking-definition", "id": "marking-x", "name": "n", "definition": {}}, "malformed id"),
    ("not an object", "non-object"),
])
def test_markings_file_rejects_invalid_entries(tmp_path, entry, needle):
    objects, err = load_markings_file(_write_markings(tmp_path, [entry, TLP_2_0_AMBER_STRICT]))
    assert objects == []
    assert needle in err


def test_markings_file_rejects_invalid_json_and_unreadable_path(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    objects, err = load_markings_file(str(empty))
    assert objects == []
    assert "not valid JSON" in err
    objects, err = load_markings_file(str(tmp_path / "missing.json"))
    assert objects == []
    assert "unreadable" in err


def test_markings_file_size_cap(tmp_path):
    path = tmp_path / "big.json"
    path.write_text("[]" + " " * (1024 * 1024), encoding="utf-8")
    objects, err = load_markings_file(str(path))
    assert objects == []
    assert "exceeds" in err


def test_markings_file_unset_is_not_an_error(monkeypatch):
    monkeypatch.delenv("BLUETEAM_STIX_MARKINGS_FILE", raising=False)
    assert load_markings_file() == ([], "")


def test_export_includes_tlp_2_0_extra_marking(tmp_path, monkeypatch):
    bundle = {"type": "bundle", "id": "bundle--d6e3c0b4-f916-4d15-a01f-e3761c5f48ac",
              "objects": [TLP_2_0_AMBER_STRICT]}
    monkeypatch.setenv("BLUETEAM_STIX_MARKINGS_FILE", _write_markings(tmp_path, bundle))
    result = json.loads(asyncio.run(blueteam_stix_export(StixExportInput(
        indicators=["45.61.136.7"], include_bundle=True, response_format="json"))))
    assert "error" not in result, result
    names = [obj.get("name") for obj in result["bundle"]["objects"]
             if obj.get("type") == "marking-definition"]
    assert "TLP:AMBER+STRICT" in names
