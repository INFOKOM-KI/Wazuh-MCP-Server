#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Label vocabulary for blueteam_incident_label: the 16 MITRE ATT&CK tactics the 3-Sum
engine already scores, plus the wording each backend needs.

The vocabulary is imported from ``constants.MITRE_TACTIC_TO_CATEGORY``, never
retyped: a local copy would drift from the correlation engine the moment a tactic
is added there, and a label the engine cannot map to a category is a dead end.

Both backends read this one table. Laya consumes ``criteria`` as the choice
descriptions; the ONNX prototype backend embeds ``prototypes`` as class anchors.
Editing a phrase changes ``version()``, which is stamped into every response and
audit row, so labels produced under different wording are never compared as equal.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Tuple

from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY

CRITERIA_VERSION = "v1"

QUESTION = "Which MITRE ATT&CK tactic phase does `body` most likely belong to?"

TACTICS: Tuple[str, ...] = tuple(sorted(MITRE_TACTIC_TO_CATEGORY))

# The criteria text is written for a model choosing between 16 phases, so it says
# what the phase means in an alert stream, not what ATT&CK says in the abstract.
_TABLE: Dict[str, Dict[str, Any]] = {
    "Reconnaissance": {
        "criteria": "scanning, probing or enumeration of hosts and services",
        "prototypes": (
            "port scan and service enumeration against multiple hosts",
            "web directory brute forcing and vulnerability probing",
        ),
    },
    "Resource Development": {
        "criteria": "adversary infrastructure preparation and staging",
        "prototypes": (
            "domain or infrastructure registration that precedes a campaign",
            "malware hosting and staging infrastructure referenced by an alert",
        ),
    },
    "Initial Access": {
        "criteria": "the first foothold on a host or account",
        "prototypes": (
            "successful exploit of an exposed service or a web shell upload",
            "external login with valid credentials or a phishing payload executed",
        ),
    },
    "Execution": {
        "criteria": "command, script or process execution on a host",
        "prototypes": (
            "command and script interpreter execution on a host",
            "a process launched from a temporary directory or a script engine",
        ),
    },
    "Persistence": {
        "criteria": "maintaining access across reboots or restarts",
        "prototypes": (
            "a service, scheduled task or run key installed to survive a reboot",
            "a new local account or cron entry created for later access",
        ),
    },
    "Privilege Escalation": {
        "criteria": "gaining higher privileges on a host or account",
        "prototypes": (
            "local privilege gain through sudo, setuid or a vulnerable driver",
            "an account added to an administrative group",
        ),
    },
    "Defense Evasion": {
        "criteria": "hiding activity or avoiding detection",
        "prototypes": (
            "log clearing, obfuscated command line or indicator removal",
            "a binary renamed or a timestamp modified to avoid a signature",
        ),
    },
    "Stealth": {
        "criteria": "low-profile tradecraft that blends with normal activity",
        "prototypes": (
            "a living-off-the-land binary used instead of a custom tool",
            "activity throttled to stay below alerting volume thresholds",
        ),
    },
    "Defense Impairment": {
        "criteria": "disabling or degrading security controls",
        "prototypes": (
            "an endpoint agent, antivirus or audit service stopped or disabled",
            "a firewall or security policy rule removed to allow traffic",
        ),
    },
    "Credential Access": {
        "criteria": "stealing or guessing credentials",
        "prototypes": (
            "password brute force or spraying against an authentication service",
            "credential dumping from memory or a stored credential file",
        ),
    },
    "Discovery": {
        "criteria": "post-access enumeration inside the environment",
        "prototypes": (
            "internal network, host or account enumeration after access",
            "directory service or share enumeration from an internal host",
        ),
    },
    "Lateral Movement": {
        "criteria": "moving from one host to another inside the network",
        "prototypes": (
            "remote service execution such as PsExec, WMI or SMB from an internal host",
            "an internal RDP or SSH session to a host not normally reached",
        ),
    },
    "Collection": {
        "criteria": "gathering and staging data of interest",
        "prototypes": (
            "bulk file archiving or a mailbox export before transfer",
            "screen capture or clipboard harvesting on a workstation",
        ),
    },
    "Command and Control": {
        "criteria": "communication with external attacker-controlled infrastructure",
        "prototypes": (
            "a periodic beacon to an external address on a fixed interval",
            "a reverse shell, DNS tunnel or known C2 framework callback",
        ),
    },
    "Exfiltration": {
        "criteria": "transferring data out of the network",
        "prototypes": (
            "outbound transfer of a staged archive to an external destination",
            "unusual upload volume to a file sharing or cloud storage service",
        ),
    },
    "Impact": {
        "criteria": "damage, disruption or destruction of systems or data",
        "prototypes": (
            "mass encryption or deletion of files consistent with ransomware",
            "a disruptive action that takes a service or host offline",
        ),
    },
}


def _assert_vocabulary() -> None:
    """Fail at import, not at the first call: a tactic added to constants.py and not
    to this table would otherwise surface as a label with no prototypes, and the
    prototype backend would silently rank a class it cannot describe."""
    missing = sorted(set(TACTICS) - set(_TABLE))
    extra = sorted(set(_TABLE) - set(TACTICS))
    if missing or extra:
        raise RuntimeError(
            f"criteria.py is out of sync with MITRE_TACTIC_TO_CATEGORY "
            f"(missing: {missing or 'none'}; unknown: {extra or 'none'})"
        )


_assert_vocabulary()


def criteria_map() -> Dict[str, str]:
    """Tactic -> one-line description, in the shape Laya's ``choice`` expects."""
    return {tactic: str(_TABLE[tactic]["criteria"]) for tactic in TACTICS}


def prototypes() -> List[Tuple[str, str]]:
    """``(tactic, phrase)`` pairs in a stable order, for the prototype backend.
    Order is part of the contract: the score vector is aligned to these rows."""
    rows: List[Tuple[str, str]] = []
    for tactic in TACTICS:
        for phrase in _TABLE[tactic]["prototypes"]:
            rows.append((tactic, str(phrase)))
    return rows


def _hash() -> str:
    canonical = json.dumps(
        {"v": CRITERIA_VERSION, "q": QUESTION,
         "t": {t: list(_TABLE[t]["prototypes"]) for t in TACTICS},
         "c": criteria_map()},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]


VERSION = f"{CRITERIA_VERSION}:{_hash()}"


def version() -> str:
    """Criteria revision stamped into every response and audit row."""
    return VERSION
