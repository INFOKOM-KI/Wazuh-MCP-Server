#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
SSVC (Stakeholder-Specific Vulnerability Categorization) - the CISA "Deployer"
decision tree, ported from the cve-mcp-server (scoring_version=2, plan 2.5).
A qualitative, gated alternative to the numeric ``score_cve`` composite score.
Instead of summing weighted contributions into a 0-100 number, it walks the
published CISA Deployer decision table and emits an action band
(``Act`` / ``Attend`` / ``Track*`` / ``Track``) with an explainable rationale.
The four SSVC decision points are derived from the signals already produced by
this repo's CVE enrichment (``blueteam_cve_score`` inputs):

* Exploitation     - KEV membership (active), EPSS >= 0.90 (active), a public
                     PoC or EPSS >= 0.10 (poc), else none.
* Automatable      - open exposure AND real exploitation evidence -> yes.
* Technical Impact - CVSS >= 9.0 -> total, else partial (severity proxy).
* Mission & WB     - CVSS >= 9.0 high, >= 7.0 medium, else low (severity proxy).

Unknown System Exposure defaults to ``open`` per CISA guidance (conservative).
References: CISA SSVC Guide v2.0.3; CERT/CC SSVC CISA-Coordinator model
(https://github.com/CERTCC/SSVC).
"""
from __future__ import annotations

# Canonical CISA "Deployer" decision table (36 branches).
# Key: (exploitation, automatable, technical_impact)
# Value: 3-tuple of outcomes for mission_wellbeing in (low, medium, high).
_DECISION_TABLE: dict[tuple[str, str, str], tuple[str, str, str]] = {
    ("none", "no", "partial"): ("Track", "Track", "Track"),
    ("none", "no", "total"): ("Track", "Track", "Track*"),
    ("none", "yes", "partial"): ("Track", "Track", "Attend"),
    ("none", "yes", "total"): ("Track", "Track", "Attend"),
    ("poc", "no", "partial"): ("Track", "Track", "Track*"),
    ("poc", "no", "total"): ("Track", "Track*", "Attend"),
    ("poc", "yes", "partial"): ("Track", "Track", "Attend"),
    ("poc", "yes", "total"): ("Track", "Track*", "Attend"),
    ("active", "no", "partial"): ("Track", "Track", "Attend"),
    ("active", "no", "total"): ("Track", "Attend", "Act"),
    ("active", "yes", "partial"): ("Attend", "Attend", "Act"),
    ("active", "yes", "total"): ("Attend", "Act", "Act"),
}

_OUTCOME_PRIORITY: dict[str, int] = {
    "Track": 0, "Track*": 1, "Attend": 2, "Act": 3,
}

_ACTION_GUIDANCE: dict[str, str] = {
    "Track": (
        "No action required at this time; remediate within standard update "
        "timelines and reassess if new information emerges."
    ),
    "Track*": (
        "Monitor closely for change; the vulnerability has characteristics that "
        "may warrant reassessment, but remediate within standard update timelines."
    ),
    "Attend": (
        "Requires attention from supervisory staff; remediate sooner than "
        "standard update timelines and consider mitigations or notification."
    ),
    "Act": (
        "Requires immediate attention from supervisory and leadership staff; "
        "remediate as soon as possible (patch, isolate, or mitigate)."
    ),
}

# PoC confidence labels indicating a public/weaponized exploit. Mirrors the
# labels produced by this repo's search_poc() and risk_scorer.score_cve.
_POC_LABELS_WEAPONIZED: frozenset[str] = frozenset({
    "WEAPONIZED", "PUBLIC_EXPLOIT_REMOTE", "PUBLIC_EXPLOIT",
    "PUBLIC_POC_HIGH_QUALITY", "PUBLIC_POC_LOW_QUALITY",
    "PUBLIC", "POC", "PROOF_OF_CONCEPT",
})

_EXPOSURE_VALUES: frozenset[str] = frozenset({"small", "controlled", "open"})


def _classify_exploitation(*, in_kev: bool, epss_probability: float,
                           poc_confidence: str) -> str:
    if in_kev:
        return "active"
    label = (poc_confidence or "NONE").strip().upper()
    if epss_probability >= 0.90:
        return "active"
    if label in _POC_LABELS_WEAPONIZED and label != "NONE":
        return "poc"
    if epss_probability >= 0.10:
        return "poc"
    return "none"


def _normalize_exposure(exposure: str) -> str:
    value = (exposure or "").strip().lower()
    return value if value in _EXPOSURE_VALUES else "open"


def _classify_automatable(*, exposure: str, exploitation: str,
                          epss_probability: float) -> str:
    if exposure != "open":
        return "no"
    if exploitation in ("active", "poc"):
        return "yes"
    if epss_probability >= 0.10:
        return "yes"
    return "no"


def _classify_technical_impact(cvss_score: float) -> str:
    return "total" if cvss_score >= 9.0 else "partial"


def _classify_mission_wellbeing(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "high"
    if cvss_score >= 7.0:
        return "medium"
    return "low"


def ssvc_decision(
    *,
    in_kev: bool,
    epss_probability: float,
    poc_confidence: str,
    cvss_score: float,
    exposure: str = "open",
) -> dict:
    """Walk the CISA Deployer SSVC tree and return an action band.
    Returns ``{"scoring_version", "exploitation", "exposure", "decision",
    "action", "rationale"}`` where ``decision`` records every derived SSVC
    decision point and the outcome, ``action`` is one of Act/Attend/Track*/Track,
    and ``rationale`` explains the path taken. Inputs are defensively coerced
    (clamped to valid ranges); unknown exposure defaults to ``open``.
    """
    try:
        epss_probability = float(epss_probability)
    except (TypeError, ValueError):
        epss_probability = 0.0
    epss_probability = max(0.0, min(1.0, epss_probability))

    try:
        cvss_score = float(cvss_score)
    except (TypeError, ValueError):
        cvss_score = 0.0
    cvss_score = max(0.0, min(10.0, cvss_score))

    in_kev = bool(in_kev)

    exploitation = _classify_exploitation(
        in_kev=in_kev, epss_probability=epss_probability,
        poc_confidence=poc_confidence,
    )
    exposure_norm = _normalize_exposure(exposure)
    automatable = _classify_automatable(
        exposure=exposure_norm, exploitation=exploitation,
        epss_probability=epss_probability,
    )
    technical_impact = _classify_technical_impact(cvss_score)
    mission_wellbeing = _classify_mission_wellbeing(cvss_score)

    outcomes = _DECISION_TABLE[(exploitation, automatable, technical_impact)]
    mw_index = {"low": 0, "medium": 1, "high": 2}[mission_wellbeing]
    action = outcomes[mw_index]

    exploitation_reason = {
        "active": (
            "in the CISA KEV catalogue (active exploitation)" if in_kev
            else "very high EPSS probability (active exploitation pressure)"
        ),
        "poc": "a public/weaponized exploit or credible EPSS probability exists",
        "none": "no public proof-of-concept and no observed exploitation",
    }[exploitation]

    rationale = (
        f"SSVC Deployer decision: Exploitation={exploitation} "
        f"({exploitation_reason}); System Exposure={exposure_norm}; "
        f"Automatable={automatable}; Technical Impact={technical_impact} "
        f"(CVSS {cvss_score:g} severity proxy); Mission & Well-being="
        f"{mission_wellbeing} (CVSS {cvss_score:g} severity proxy). "
        f"This path resolves to '{action}': {_ACTION_GUIDANCE[action]}"
    )

    return {
        "scoring_version": "2.0",
        "exploitation": exploitation,
        "exposure": exposure_norm,
        "decision": {
            "exploitation": exploitation,
            "automatable": automatable,
            "technical_impact": technical_impact,
            "mission_wellbeing": mission_wellbeing,
            "exposure": exposure_norm,
            "outcome": action,
            "outcome_priority": _OUTCOME_PRIORITY[action],
        },
        "action": action,
        "rationale": rationale,
    }
