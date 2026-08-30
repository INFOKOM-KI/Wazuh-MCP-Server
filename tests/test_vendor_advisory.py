#!/usr/bin/env python3
"""Self-checks for the vendor-advisory parsers (pure logic, no network).
Run:  WAZUH_INDEXER_URL=http://127.0.0.1:9200 WAZUH_INDEXER_PASSWORD=x \
      python -m pytest tests/test_vendor_advisory.py -q
"""
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "http://127.0.0.1:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "x")

from mcp_server.threat_intel.vendor_advisory import (  # noqa: E402
    _parse_msrc,
    _parse_redhat,
    _parse_ubuntu,
    _strip_html,
)


def test_strip_html():
    assert _strip_html("<p>Foo &nbsp;bar</p>") == "Foo bar"


def test_parse_msrc_entry():
    out = _parse_msrc([{
        "cveTitle": "Apache Log4j Remote Code Execution Vulnerability",
        "tag": "Apache Log4j2",
        "exploited": "Yes",
        "publiclyDisclosed": "Yes",
        "releaseDate": "2021-12-16T08:00:00Z",
        "description": "<p>Certain versions are vulnerable.</p>",
        "mitreUrl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
    }])
    assert out["title"].startswith("Apache Log4j")
    assert out["exploited"] == "Yes"
    assert out["description"] == "Certain versions are vulnerable."


def test_parse_msrc_empty():
    assert _parse_msrc([]) == {}


def test_parse_redhat():
    data = {
        "threat_severity": "Critical",
        "cvss3": {"cvss3_base_score": "9.8",
                  "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L"},
        "cwe": "CWE-20",
        "bugzilla": {"url": "https://bugzilla.redhat.com/2030932",
                     "description": "log4j-core RCE"},
        "affected_release": [{
            "advisory": "RHSA-2021:5137", "package": "openshift-logging/foo",
            "product_name": "OpenShift Logging 5.0", "release_date": "2021-12-14",
            "cpe": "cpe:/a:redhat:logging:5.0",
        }],
        "package_state": [{
            "package_name": "log4j-core", "product_name": "A-MQ Clients 2",
            "fix_state": "Not affected", "cpe": "cpe:/a:redhat:a_mq_clients:2",
        }],
    }
    out = _parse_redhat(data)
    assert out["severity"] == "Critical"
    assert out["cvss3_score"] == "9.8"
    assert out["advisories"][0]["advisory"] == "RHSA-2021:5137"
    assert out["package_states"][0]["state"] == "Not affected"


def test_parse_redhat_empty():
    assert _parse_redhat({"threat_severity": "", "affected_release": [],
                          "package_state": []}) == {}


def test_parse_ubuntu():
    data = {
        "priority": "high", "status": "active", "cvss3": 10.0,
        "description": "Apache Log4j2 RCE",
        "notices": [{"id": "USN-5192-1", "title": "Apache Log4j 2 vulnerability",
                     "summary": "crash or run programs", "published": "2021-12-14"}],
        "packages": [{
            "name": "apache-log4j2",
            "statuses": [{"release_codename": "focal", "status": "released",
                          "description": "2.15.0-0.20.04.1"}],
        }],
        "references": ["https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/Log4Shell"],
    }
    out = _parse_ubuntu(data)
    assert out["priority"] == "high"
    assert out["cvss3"] == 10.0
    assert out["notices"][0]["id"] == "USN-5192-1"
    assert out["packages"][0]["statuses"][0]["status"] == "released"


def test_parse_ubuntu_empty():
    assert _parse_ubuntu({}) == {}
