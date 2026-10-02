#!/usr/bin/env python3
"""
Contract and regression tests for ``mcp_server.correlation.source_core``.
Imports happen inside helpers, so a renamed or missing module fails each test
with an explicit contract message instead of a collection error.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import inspect
import pytest

DAY = 86400.0

def _core():
    try:
        import mcp_server.correlation.source_core as mod
    except ImportError as exc:
        pytest.fail(f"contract missing: mcp_server.correlation.source_core ({exc})")
    return mod


def _row(ip, ts, tactic="Reconnaissance", country=None):
    return {"source_ip": ip, "observed_at": ts, "tactic": tactic, "country": country}


def _entry(value, ts, country=None, tactics=None):
    return {"value": value, "observed_at": ts, "country": country,
            "tactics": list(tactics or [])}


def test_classify_public_ipv4():
    core = _core()
    result = core.classify_source("8.8.8.8")
    assert result["valid"] is True
    assert result["version"] == 4
    assert result["is_internal"] is False
    assert result["netblock"] == "8.8.8.0/24"
    assert result["normalized"] == "8.8.8.8"


def test_classify_public_ipv6_uses_64():
    core = _core()
    result = core.classify_source("2606:4700:4700::1111")
    assert result["valid"] is True
    assert result["version"] == 6
    assert result["is_internal"] is False
    assert result["netblock"] == "2606:4700:4700::/64"


def test_classify_prefix_overrides():
    core = _core()
    assert core.classify_source("8.8.8.8", v4_prefix=16)["netblock"] == "8.8.0.0/16"
    assert core.classify_source("2606:4700:4700::1111",
                                v6_prefix=48)["netblock"] == "2606:4700:4700::/48"


@pytest.mark.parametrize("value", ["not-an-ip", "", "999.1.1.1", "8.8.8", None])
def test_classify_malformed(value):
    core = _core()
    result = core.classify_source(value)
    assert result["valid"] is False
    assert result["netblock"] is None
    assert result["reason"]


@pytest.mark.parametrize("value", ["10.0.0.1", "127.0.0.1", "169.254.1.1",
                                   "224.0.0.1", "100.64.0.1", "::1", "fc00::1"])
def test_classify_internal(value):
    core = _core()
    result = core.classify_source(value)
    assert result["valid"] is True
    assert result["is_internal"] is True


def test_classify_strips_whitespace():
    core = _core()
    assert core.classify_source(" 8.8.8.8 ")["normalized"] == "8.8.8.8"


def test_timeline_collapses_consecutive_and_tiebreaks():
    core = _core()
    rows = [_row("8.8.8.8", 10.0), _row("8.8.8.8", 11.0),
            _row("1.1.1.1", 12.0), _row("8.8.8.8", 12.0)]
    timeline = core.build_timeline(rows)
    assert [entry["value"] for entry in timeline] == ["8.8.8.8", "1.1.1.1", "8.8.8.8"]


def test_timeline_cutoff_is_exclusive():
    core = _core()
    rows = [_row("8.8.8.8", 9.0), _row("1.1.1.1", 10.0), _row("8.8.8.8", 11.0)]
    timeline = core.build_timeline(rows, cutoff_ts=10.0)
    assert [entry["value"] for entry in timeline] == ["8.8.8.8"]


def test_timeline_carries_tactics_and_country():
    core = _core()
    rows = [_row("8.8.8.8", 9.0, "Reconnaissance", "United States"),
            _row("8.8.8.8", 10.0, "Execution", "United States")]
    entry = core.build_timeline(rows)[0]
    assert entry["country"] == "United States"
    assert set(entry["tactics"]) == {"Reconnaissance", "Execution"}
    assert entry["observed_at"] == 9.0


def test_country_timeline_dedupes_and_skips_unknown():
    core = _core()
    rows = [_row("8.8.8.8", 9.0, country="A"), _row("1.1.1.1", 10.0, country=None),
            _row("8.8.8.8", 11.0, country="A"), _row("8.8.8.8", 12.0, country="B")]
    timeline = core.build_country_timeline(rows)
    assert [entry["value"] for entry in timeline] == ["A", "B"]


def test_recency_weight_is_exponential_half_life():
    core = _core()
    assert core.recency_weight(0.0, 14.0) == pytest.approx(1.0)
    assert core.recency_weight(14 * DAY, 14.0) == pytest.approx(0.5, abs=1e-9)
    assert core.recency_weight(28 * DAY, 14.0) == pytest.approx(0.25, abs=1e-9)


def test_weighted_transitions_recency_and_counts():
    core = _core()
    timeline = [_entry("A", 0.0), _entry("B", 14 * DAY), _entry("A", 21 * DAY)]
    transitions = core.weighted_transitions(timeline, half_life_days=14.0,
                                            cutoff_ts=28 * DAY)
    assert transitions["A"]["B"]["weight"] == pytest.approx(0.5, abs=1e-9)
    assert transitions["A"]["B"]["count"] == 1
    assert transitions["B"]["A"]["weight"] == pytest.approx(2 ** -0.5, abs=1e-9)


def test_transition_probability_laplace_and_support():
    core = _core()
    transitions = {"A": {"B": {"weight": 3.0, "count": 2},
                         "C": {"weight": 1.0, "count": 1}}}
    known = core.transition_probability(transitions, "A", "B", alpha=0.5)
    assert known["probability"] == pytest.approx(3.5 / 5.0)
    assert known["support"] == 2
    assert known["row_total_weight"] == pytest.approx(4.0)
    unseen = core.transition_probability(transitions, "A", "D", alpha=0.5)
    assert unseen["probability"] == pytest.approx(0.5 / 5.0)
    assert unseen["support"] == 0


def test_transition_probability_unknown_previous_is_none():
    core = _core()
    result = core.transition_probability({}, "A", "B")
    assert result["probability"] is None
    assert result["support"] == 0


def test_component_context_cosine():
    core = _core()
    assert core.component_context({"Reconnaissance": 1.0},
                                  ["Reconnaissance"]) == pytest.approx(1.0)
    assert core.component_context({"Reconnaissance": 1.0},
                                  ["Execution"]) == pytest.approx(0.0)
    assert core.component_context({"Reconnaissance": 0.5, "Execution": 0.5},
                                  ["Reconnaissance"]) == pytest.approx(0.7071, abs=1e-4)
    assert core.component_context({"Reconnaissance": 0.5, "Execution": 0.5},
                                  ["Reconnaissance", "Execution"]) == pytest.approx(1.0, abs=1e-4)


def test_component_recurrence():
    core = _core()
    assert core.component_recurrence([0.0, DAY, 2 * DAY, 3 * DAY]) == pytest.approx(1.0)
    irregular = core.component_recurrence([0.0, DAY, 5 * DAY])
    assert 0.0 < irregular < 1.0
    assert core.component_recurrence([0.0, DAY]) == 0.0


def test_normalize_max():
    core = _core()
    assert core.normalize_max({"a": 2.0, "b": 1.0, "c": 0.0}) == {
        "a": 1.0, "b": 0.5, "c": 0.0}
    assert core.normalize_max({"a": 0.0, "b": 0.0}) == {"a": 0.0, "b": 0.0}


def test_score_sequence_is_deterministic_and_ordered():
    core = _core()
    entries = [_entry("A", 0.0), _entry("B", DAY), _entry("A", 2 * DAY)]
    first = core.score_sequence(entries, [], 3 * DAY)
    second = core.score_sequence(entries, [], 3 * DAY)
    assert first == second
    scores = [candidate["model_score"] for candidate in first["candidates"]]
    assert scores == sorted(scores, reverse=True)


def test_score_sequence_ignores_future_entries():
    core = _core()
    entries = [_entry("A", 0.0), _entry("B", DAY), _entry("Z", 10 * DAY)]
    result = core.score_sequence(entries, [], 2 * DAY)
    values = {candidate["value"] for candidate in result["candidates"]}
    assert "Z" not in values
    assert result["previous_value"] == "B"
    assert result["vocabulary_size"] == 2


def test_score_sequence_tie_break_is_value_ascending():
    core = _core()
    entries = [_entry("B", 0.0), _entry("A", DAY)]
    result = core.score_sequence(entries, [], 2 * DAY, weights={})
    assert [candidate["value"] for candidate in result["candidates"]] == ["A", "B"]


def test_score_sequence_max_candidates():
    core = _core()
    entries = [_entry(f"10.0.{index // 256}.{index % 256}", index * 60)
               for index in range(30)]
    result = core.score_sequence(entries, [], 30 * 60.0, max_candidates=5)
    assert len(result["candidates"]) == 5


def test_score_sequence_low_support_uses_frequency_fallback():
    core = _core()
    entries = [_entry("A", 0.0), _entry("B", DAY), _entry("A", 2 * DAY),
               _entry("C", 3 * DAY)]
    result = core.score_sequence(entries, [], 4 * DAY, min_transitions=3,
                                 weights={"transition": 1.0, "recency": 1.0})
    for candidate in result["candidates"]:
        assert candidate["score_kind"] == "fallback_frequency"
        assert candidate["components"]["transition"] == 0.0
    assert result["candidates"][0]["model_score"] == pytest.approx(1.0)


def test_score_sequence_context_weight_selects_tactic_match():
    core = _core()
    entries = [_entry("A", 0.0, tactics=["Reconnaissance"]),
               _entry("B", DAY, tactics=["Impact"])]
    result = core.score_sequence(entries, ["Reconnaissance"], 2 * DAY,
                                 weights={"context": 1.0})
    assert result["candidates"][0]["value"] == "A"


def test_score_sequence_candidate_evidence_fields():
    core = _core()
    entries = [_entry("A", 0.0, country="US"),
               _entry("B", DAY, country="DE"), _entry("A", 2 * DAY, country="US")]
    candidate = {item["value"]: item for item in
                 core.score_sequence(entries, [], 3 * DAY)["candidates"]}["A"]
    assert candidate["occurrence_count"] == 2
    assert candidate["first_seen"] == 0.0
    assert candidate["last_seen"] == 2 * DAY
    assert candidate["country"] == "US"
    assert candidate["rank"] == 1


def test_score_sequence_never_labels_sources_malicious():
    core = _core()
    entries = [_entry("8.8.8.8", 0.0), _entry("1.1.1.1", DAY)]
    result = core.score_sequence(entries, [], 2 * DAY)
    forbidden = {"malicious", "attacker", "threat", "is_attacker", "attribution"}
    for candidate in result["candidates"]:
        assert not (forbidden & set(candidate))


def test_transition_storage_is_bounded_by_transitions_not_vocabulary():
    core = _core()
    timeline = [_entry(f"10.0.{index // 256}.{index % 256}", index * 60.0)
                for index in range(300)]
    transitions = core.weighted_transitions(timeline, half_life_days=14.0,
                                            cutoff_ts=300 * 60.0)
    entry_count = sum(len(row) for row in transitions.values())
    assert entry_count == 299
    assert entry_count < 300 ** 2
    result = core.score_sequence(timeline, [], 300 * 60.0, max_candidates=10,
                                 min_transitions=1)
    assert result["transition_entries"] == 299
    assert len(result["candidates"]) <= 10


def test_top_k_and_reciprocal_rank_helpers():
    core = _core()
    candidates = ["A", "B", "C"]
    assert core.top_k_hit(candidates, "A", 1) is True
    assert core.top_k_hit(candidates, "C", 5) is True
    assert core.top_k_hit(candidates, "Z", 5) is False
    assert core.reciprocal_rank(candidates, "A") == pytest.approx(1.0)
    assert core.reciprocal_rank(candidates, "B") == pytest.approx(0.5)
    assert core.reciprocal_rank(candidates, "Z") == pytest.approx(0.0)


def test_evaluate_rolling_signature_has_no_random_split():
    core = _core()
    names = set(inspect.signature(core.evaluate_rolling).parameters)
    assert not {name for name in names if "seed" in name or "shuffle" in name
                or "random" in name}
