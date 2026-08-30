#!/usr/bin/env python3
"""Self-checks for the dependency-scan parsers and severity extraction.
Run:  WAZUH_INDEXER_URL=http://127.0.0.1:9200 WAZUH_INDEXER_PASSWORD=x \
      python -m pytest tests/test_dependency_scan.py -q
The OSV network fan-out (scan_dependencies_bulk) is exercised live during
development; these tests cover the deterministic pure logic only.
"""
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "http://127.0.0.1:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "x")

from mcp_server.threat_intel.dependency_scan import (  # noqa: E402
    _extract_severity,
    parse_dependency_list,
)


def test_requirements_txt():
    out = parse_dependency_list("requests==2.28.0\n# comment\nflask>=2.0\nbare\n")
    assert out == [
        {"name": "requests", "ecosystem": "PyPI", "version": "2.28.0"},
        {"name": "flask", "ecosystem": "PyPI", "version": "2.0"},
        {"name": "bare", "ecosystem": "PyPI", "version": ""},
    ]


def test_package_json():
    out = parse_dependency_list(
        '{"dependencies":{"lodash":"4.17.15"},"devDependencies":{"jest":"^29.0.0"}}'
    )
    assert out == [
        {"name": "lodash", "ecosystem": "npm", "version": "4.17.15"},
        {"name": "jest", "ecosystem": "npm", "version": "29.0.0"},
    ]


def test_pom_xml_namespace_and_property_ref():
    xml = (
        '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<dependencies>"
        "<dependency><groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1.2.3</version></dependency>"
        "<dependency><groupId>g2</groupId><artifactId>a2</artifactId>"
        "<version>${project.version}</version></dependency>"
        "</dependencies></project>"
    )
    out = parse_dependency_list(xml)
    assert out == [
        {"name": "g:a", "ecosystem": "Maven", "version": "1.2.3"},
        {"name": "g2:a2", "ecosystem": "Maven", "version": ""},
    ]


def test_generic_lines_and_unparseable():
    assert parse_dependency_list("requests:PyPI:2.28.0\nlodash:npm:4.17.15") == [
        {"name": "requests", "ecosystem": "PyPI", "version": "2.28.0"},
        {"name": "lodash", "ecosystem": "npm", "version": "4.17.15"},
    ]
    assert parse_dependency_list("") == []
    assert parse_dependency_list("just prose with no structure") == []


def test_severity_extraction():
    label = {"database_specific": {"severity": "CRITICAL"}}
    numeric = {"severity": [{"type": "CVSS_V3", "score": 9.8}]}
    vector = {"severity": [{"type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    none = {}
    assert _extract_severity(label) == "CRITICAL"
    assert _extract_severity(numeric) == "CRITICAL"
    assert _extract_severity(vector) == "CRITICAL"
    assert _extract_severity(none) == "UNKNOWN"
