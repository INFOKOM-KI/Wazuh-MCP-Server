#!/usr/bin/env python3
"""
Tests for mcp_server/correlation/forecast_core.py tactic-sequence estimators.
Pure computation: no Indexer, no store, no hmmlearn required. The HMM fit test
tolerates both worlds (library present or absent); the prediction math is
exercised with hand-built parameters so a deployment without hmmlearn still
serves a model trained elsewhere.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.correlation.forecast_core import (
    TACTIC_ORDER,
    TAXONOMY_VERSION,
    VOLUME_KIND,
    build_sequences,
    fit_categorical_hmm,
    fit_markov_chain,
    fit_poisson_hmm,
    normalize_tactics,
    poisson_logpmf,
    predict_next_hmm,
    predict_next_markov,
    predict_volume,
    sequence_logprob,
    validate_model,
)

SEQUENCES = [
    ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    ["Reconnaissance", "Initial Access", "Persistence", "Command and Control"],
    ["Discovery", "Lateral Movement", "Exfiltration"],
    ["Discovery", "Lateral Movement", "Exfiltration"],
    ["Discovery", "Credential Access", "Lateral Movement", "Exfiltration"],
]


def _model():
    fit = fit_markov_chain(SEQUENCES, alpha=1.0, min_sequences=5, min_transitions=10)
    assert fit["status"] == "ok"
    return fit


def test_normalize_tactics_accepts_strings_lists_and_drops_unknowns():
    assert normalize_tactics("command and control") == ["Command and Control"]
    assert normalize_tactics(["Impact", "not-a-tactic", "Impact"]) == ["Impact"]
    assert normalize_tactics(None) == []


def test_build_sequences_sorts_dedups_and_counts_drops():
    rows = [
        {"entity_key": "A", "tactic": "Discovery", "observed_at": 2},
        {"entity_key": "A", "tactic": "Discovery", "observed_at": 3},
        {"entity_key": "A", "tactic": "Command and Control", "observed_at": 4},
        {"entity_key": "A", "tactic": ["Lateral Movement", "Exfiltration"], "observed_at": 5},
        {"entity_key": "B", "tactic": "Impact", "observed_at": 1},
        {"entity_key": "", "tactic": "Impact", "observed_at": 1},
        {"entity_key": "C", "tactic": "not-a-tactic", "observed_at": 1},
    ]
    built = build_sequences(rows)
    assert built["sequences"] == [
        ["Discovery", "Command and Control", "Lateral Movement", "Exfiltration"]]
    assert built["entities"] == 2
    assert built["dropped_unknown"] == 1
    assert built["dropped_no_entity"] == 1
    assert built["dropped_short"] == 1


def test_fit_reports_insufficient_instead_of_empty():
    fit = fit_markov_chain([["Discovery", "Impact"]], min_sequences=5, min_transitions=20)
    assert fit["status"] == "insufficient_data"
    assert "minimum" in fit["reason"]


def test_fit_laplace_smooths_unseen_transitions_and_rows_sum_to_one():
    fit = _model()
    assert abs(sum(fit["startprob"]) - 1) <= 1e-3
    for row in fit["transmat"]:
        assert abs(sum(row) - 1) <= 1e-3
    reconnaissance = TACTIC_ORDER.index("Reconnaissance")
    discovery = TACTIC_ORDER.index("Discovery")
    assert fit["counts"][reconnaissance][discovery] == 0
    assert fit["transmat"][reconnaissance][discovery] > 0


def test_predict_markov_tops_the_observed_transition():
    fit = _model()
    result = predict_next_markov(fit, ["Reconnaissance"], top_k=3, min_support=2)
    assert result["status"] == "ok"
    assert result["current_tactic"] == "Reconnaissance"
    assert result["predictions"][0]["tactic"] == "Initial Access"
    assert result["support"] == 3
    assert result["low_support"] is False
    assert result["escalation_probability"] > 0


def test_predict_markov_unseen_tactic_falls_back_to_uniform():
    fit = _model()
    result = predict_next_markov(fit, ["not-a-tactic"], top_k=3, min_support=3)
    assert result["uniform_fallback"] is True
    assert result["current_tactic"] is None
    assert result["predictions"][0]["probability"] == round(1 / len(TACTIC_ORDER), 6)


def test_predict_markov_flags_low_support_row():
    fit = _model()
    result = predict_next_markov(fit, ["Discovery"], top_k=2, min_support=5)
    assert result["low_support"] is True
    assert result["predictions"][0]["tactic"] == "Lateral Movement"


def test_sequence_logprob_ranks_a_known_chain_above_a_reversed_one():
    fit = _model()
    known = sequence_logprob(fit, ["Reconnaissance", "Initial Access", "Execution"])
    reversed_chain = sequence_logprob(
        fit, ["Execution", "Initial Access", "Reconnaissance"])
    assert known["status"] == "ok"
    assert known["mean_logprob"] > reversed_chain["mean_logprob"]


def test_sequence_logprob_needs_two_known_tactics():
    fit = _model()
    assert sequence_logprob(fit, ["Discovery"])["status"] == "insufficient_data"


def test_fit_rejects_unknown_tactic_in_corpus():
    with pytest.raises(ValueError):
        fit_markov_chain([["not-a-tactic", "Impact"]] * 5, min_sequences=2, min_transitions=1)


def _hand_hmm_model():
    size = len(TACTIC_ORDER)
    spread = 0.1 / (size - 1)
    emission = []
    for primary in ("Reconnaissance", "Command and Control"):
        row = [spread] * size
        row[TACTIC_ORDER.index(primary)] = 0.9
        emission.append(row)
    return {
        "model_id": "hand", "kind": "hmm", "taxonomy_version": TAXONOMY_VERSION,
        "tactics": list(TACTIC_ORDER), "startprob": [1.0, 0.0],
        "transmat": [[0.2, 0.8], [0.1, 0.9]], "emissionprob": emission,
        "n_sequences": 10, "n_transitions": 40, "created_at": 0.0, "params": {},
    }


def test_validate_model_accepts_hand_built_hmm():
    validate_model(_hand_hmm_model())


def test_validate_model_refuses_shifted_vocabulary():
    model = _hand_hmm_model()
    model["tactics"] = list(reversed(TACTIC_ORDER))
    with pytest.raises(ValueError):
        validate_model(model)


def test_validate_model_refuses_a_row_that_does_not_sum_to_one():
    model = _hand_hmm_model()
    model["transmat"] = [[0.8, 0.8], [0.1, 0.9]]
    with pytest.raises(ValueError):
        validate_model(model)


def test_predict_hmm_follows_the_hidden_transition_and_emission():
    result = predict_next_hmm(_hand_hmm_model(), ["Reconnaissance"], top_k=2)
    assert result["status"] == "ok"
    assert result["predictions"][0]["tactic"] == "Command and Control"
    # start [1,0] -> next state [0.2, 0.8]; state 1 emits Command and Control at 0.9,
    # plus state 0's uniform spread: 0.8*0.9 + 0.2*(0.1/15) ~= 0.7213.
    assert result["predictions"][0]["probability"] == pytest.approx(0.7213, abs=1e-3)
    assert result["escalation_probability"] >= 0.72


def test_predict_hmm_without_a_known_tactic_is_uniform():
    result = predict_next_hmm(_hand_hmm_model(), ["not-a-tactic"], top_k=1)
    assert result["uniform_fallback"] is True


def test_fit_categorical_hmm_reports_unavailable_or_fits():
    result = fit_categorical_hmm(SEQUENCES, n_components=2, min_sequences=5)
    if result["status"] == "unavailable":
        assert "hmmlearn" in result["reason"]
    else:
        assert result["status"] == "ok"
        assert len(result["transmat"]) == 2
        assert len(result["emissionprob"][0]) == len(TACTIC_ORDER)


def _volume_series():
    return [2, 3, 1, 4, 2] * 10 + [20, 25, 18, 22, 24] * 10


def _hand_volume_model():
    return {
        "model_id": "vol", "kind": VOLUME_KIND, "taxonomy_version": TAXONOMY_VERSION,
        "tactics": list(TACTIC_ORDER), "startprob": [1.0, 0.0],
        "transmat": [[0.9, 0.1], [0.1, 0.9]], "lambdas": [1.0, 10.0],
        "emissionprob": None, "row_support": None,
        "n_sequences": 100, "n_transitions": 0, "created_at": 0.0, "params": {},
    }


def test_poisson_logpmf_matches_the_hand_value():
    assert poisson_logpmf(2, 3) == pytest.approx(-1.4959, abs=1e-4)


def test_fit_poisson_reports_insufficient_on_thin_series():
    result = fit_poisson_hmm([1, 2, 3], min_buckets=48)
    assert result["status"] == "insufficient_data"
    assert "buckets" in result["reason"]


def test_fit_poisson_rejects_all_zero_and_constant_series():
    assert fit_poisson_hmm([0] * 60, min_buckets=48)["status"] == "insufficient_data"
    assert fit_poisson_hmm([5] * 60, min_buckets=48)["status"] == "insufficient_data"


def test_fit_poisson_hmm_reports_unavailable_or_fits():
    result = fit_poisson_hmm(_volume_series(), n_components=2, min_buckets=48)
    if result["status"] == "unavailable":
        assert "hmmlearn" in result["reason"]
    else:
        assert result["status"] == "ok"
        assert result["kind"] == VOLUME_KIND
        assert len(result["lambdas"]) == 2
        assert min(result["lambdas"]) > 0


def test_validate_model_accepts_a_volume_model():
    validate_model(_hand_volume_model())


def test_validate_model_refuses_bad_lambdas():
    model = _hand_volume_model()
    model["lambdas"] = [0.0, 10.0]
    with pytest.raises(ValueError):
        validate_model(model)
    model["lambdas"] = [1.0]
    with pytest.raises(ValueError):
        validate_model(model)


def test_predict_volume_rolls_the_regime_chain():
    result = predict_volume(_hand_volume_model(), [], horizon_buckets=2)
    assert result["status"] == "ok"
    assert result["expected_counts"] == [1.9, 2.62]
    assert result["peak_probability"] == pytest.approx(0.19, abs=1e-3)
    assert result["peak_states"] == [1]
    assert result["expected_total"] == pytest.approx(4.52, abs=1e-2)


def test_predict_volume_context_shifts_the_posterior():
    model = _hand_volume_model()
    # A deterministic prior would give state 1 zero mass and the filter could
    # never move there; a real EM fit never starts that sharp.
    model["startprob"] = [0.5, 0.5]
    burst = predict_volume(model, [25, 25], horizon_buckets=1)
    calm = predict_volume(model, [0, 0], horizon_buckets=1)
    assert burst["expected_counts"][0] > 5.0
    assert calm["expected_counts"][0] < burst["expected_counts"][0]
    assert burst["posterior_fallback"] is False


def test_predict_volume_flags_a_collapsed_posterior():
    # startprob [1, 0] and an observation only state 1 can emit: the posterior
    # collapses to zero, so the prior is used and the fallback is flagged.
    result = predict_volume(_hand_volume_model(), [25, 25], horizon_buckets=1)
    assert result["posterior_fallback"] is True
    assert result["expected_counts"] == [1.9]


def test_predict_volume_refuses_degenerate_lambdas():
    model = _hand_volume_model()
    model["lambdas"] = [5.0, 5.0]
    assert predict_volume(model, [], 24)["status"] == "unavailable"
