#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tactic sequence forecasting primitives for blueteam_tactic_forecast.
Two estimators over the same observation format (entity, tactic, timestamp):
``markov``
    First-order transition table with Laplace smoothing and per-row support
    counts. Cheap, interpretable, the default.
``hmm``
    A ``CategoricalHMM`` from the optional ``hmmlearn`` package, where the
    hidden states are campaign phases and emissions are observed tactics. It
    is only worth its extra data requirement when the observed tactic is a
    noisy proxy for an underlying phase; fit both and compare held-out
    mean log-likelihood before trusting it.

Fitted parameters are plain JSON-serialisable lists because
``core/forecast_store.py`` persists them and the predict path is pure
arithmetic. A deployment can therefore serve predictions without hmmlearn
installed, as long as training ran on a host that had it.
Every degraded path is a visible status instead of an exception:
``insufficient_data`` below the sample floor, ``unavailable`` when hmmlearn is
absent, uniform fallback for an unseen tactic or a zero-count row, and a
``low_support`` flag on a row too thin to trust. No probability is ever
fabricated for a tactic the corpus never produced.
"""
from __future__ import annotations
import hashlib
import logging
import math
from typing import Any, Optional
from mcp_server.core.constants import MITRE_TACTIC_WEIGHTS

logger = logging.getLogger("blue_team_mcp.forecast_core")

TACTIC_ORDER: tuple[str, ...] = tuple(sorted(MITRE_TACTIC_WEIGHTS))
TACTIC_INDEX: dict[str, int] = {tactic: index for index, tactic in enumerate(TACTIC_ORDER)}

# Stamped on every stored model. A taxonomy change that adds or renames a tactic
# shifts the matrix layout, and a model trained on the old vocabulary cannot
# score the new one, the same refusal cluster_store applies to FEATURE_VERSION.
TAXONOMY_VERSION = "v1:" + hashlib.sha256(
    "|".join(TACTIC_ORDER).encode("utf-8")).hexdigest()[:8]

# Tactics that turn access into damage: control, exfiltration, impact and
# lateral spread. The escalation probability is the mass these carry in the
# next step distribution.
ESCALATION_TACTICS: tuple[str, ...] = (
    "Command and Control", "Exfiltration", "Impact", "Lateral Movement",
)

# A row-normalised matrix read back from JSON cannot sum to exactly 1.0; the
# tolerance lives here so store and tests share one number.
PROB_SUM_TOLERANCE = 1e-3


def normalize_tactics(value: Any) -> list[str]:
    """Canonicalise one alert's ``rule.mitre.tactic`` into known tactic names.
    The field is a keyword array in some mappings and a plain string in others,
    so both shapes are accepted. Unknown names are dropped rather than coerced:
    a tactic outside the local vocabulary has no matrix column, and inventing a
    row for it would silently widen the taxonomy. Order is preserved and
    duplicates within one alert are collapsed, because co-occurring tactics are
    one kill-chain step, not a loop.
    """
    raw = value if isinstance(value, (list, tuple)) else [value]
    out: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if not text:
            continue
        name: Optional[str] = text if text in TACTIC_INDEX else None
        if name is None:
            lowered = text.lower()
            name = next((t for t in TACTIC_ORDER if t.lower() == lowered), None)
        if name is not None and name not in out:
            out.append(name)
    return out


def uniform_distribution() -> list[float]:
    """Flat fallback over the full vocabulary. Used where a real row is absent."""
    weight = 1.0 / len(TACTIC_ORDER)
    return [weight] * len(TACTIC_ORDER)


def build_sequences(observations: list[dict]) -> dict:
    """Fold observation rows into per-entity tactic sequences.
    Rows are ``{"entity_key", "tactic", "observed_at"}`` where ``tactic`` may be
    a string or a list. Sequences are ordered by timestamp, consecutive
    duplicates are collapsed (a rule firing three times is persistence, not a
    transition), and sequences shorter than two tactics are dropped, there is
    no transition to learn from them. Dropped rows are counted, never silently
    discarded.
    """
    grouped: dict[str, list[tuple[float, int, str]]] = {}
    dropped_unknown = 0
    dropped_no_entity = 0
    for row in observations:
        key = str(row.get("entity_key") or "").strip().lower()
        if not key:
            dropped_no_entity += 1
            continue
        tactics = normalize_tactics(row.get("tactic"))
        if not tactics:
            dropped_unknown += 1
            continue
        observed_at = float(row.get("observed_at") or 0.0)
        for offset, tactic in enumerate(tactics):
            grouped.setdefault(key, []).append((observed_at, offset, tactic))

    sequences: list[list[str]] = []
    dropped_short = 0
    for key in sorted(grouped):
        sequence: list[str] = []
        for _ts, _offset, tactic in sorted(grouped[key], key=lambda item: (item[0], item[1])):
            if not sequence or sequence[-1] != tactic:
                sequence.append(tactic)
        if len(sequence) >= 2:
            sequences.append(sequence)
        else:
            dropped_short += 1
    return {"sequences": sequences, "entities": len(grouped),
            "dropped_unknown": dropped_unknown, "dropped_no_entity": dropped_no_entity,
            "dropped_short": dropped_short}


def _insufficient(n_sequences: int, n_transitions: int,
                  min_sequences: int, min_transitions: int, noun: str = "sequences") -> dict:
    return {
        "status": "insufficient_data", "n_sequences": n_sequences,
        "n_transitions": n_transitions,
        "reason": (f"{n_sequences} {noun} / {n_transitions} transitions below the configured "
                   f"minimum ({min_sequences}/{min_transitions})"),
    }


def _top_k(probabilities: list[float], top_k: int) -> list[dict]:
    ranked = sorted(zip(TACTIC_ORDER, probabilities), key=lambda item: (-item[1], item[0]))
    return [{"tactic": tactic, "probability": round(prob, 6)} for tactic, prob in ranked[:top_k]]


def _escalation(probabilities: list[float]) -> float:
    return round(sum(p for tactic, p in zip(TACTIC_ORDER, probabilities)
                     if tactic in ESCALATION_TACTICS), 6)


def _uniform_prediction(reason: str, top_k: int, method: str) -> dict:
    probabilities = uniform_distribution()
    return {
        "status": "ok", "method": method, "current_tactic": None,
        "uniform_fallback": True, "reason": reason,
        "predictions": _top_k(probabilities, top_k),
        "escalation_probability": _escalation(probabilities),
    }


def fit_markov_chain(sequences: list[list[str]], alpha: float = 1.0,
                     min_sequences: int = 5, min_transitions: int = 20) -> dict:
    """Fit a Laplace-smoothed first-order transition matrix over tactic sequences.
    ``alpha`` is the add-constant prior: with 16 tactics, an unseen transition
    gets ``alpha / (row_total + alpha * 16)`` instead of zero. Zero probability
    would make an unseen-but-benign path score as infinitely anomalous and would
    poison the log-likelihood; smoothing keeps it merely unlikely.
    A zero-count row is set to the uniform distribution rather than divided by
    zero. ``row_support`` carries the raw transition count per tactic so a
    caller can report how thin a prediction is; the probability is never
    returned without that count available.
    """
    n_sequences = len(sequences)
    n_transitions = sum(max(0, len(sequence) - 1) for sequence in sequences)
    if n_sequences < min_sequences or n_transitions < min_transitions:
        return _insufficient(n_sequences, n_transitions, min_sequences, min_transitions)

    size = len(TACTIC_ORDER)
    counts = [[0] * size for _ in range(size)]
    start_counts = [0] * size
    for sequence in sequences:
        try:
            indexes = [TACTIC_INDEX[tactic] for tactic in sequence]
        except KeyError as exc:
            raise ValueError(f"unknown tactic {exc.args[0]!r} in corpus; normalize before fitting") from exc
        start_counts[indexes[0]] += 1
        for current, following in zip(indexes, indexes[1:]):
            counts[current][following] += 1

    transmat: list[list[float]] = []
    row_support: list[int] = []
    for row in counts:
        total = sum(row)
        row_support.append(total)
        if total == 0:
            transmat.append(uniform_distribution())
            continue
        denominator = total + alpha * size
        transmat.append([round((count + alpha) / denominator, 6) for count in row])

    start_total = sum(start_counts)
    start_denominator = start_total + alpha * size
    startprob = [round((count + alpha) / start_denominator, 6) for count in start_counts]
    return {
        "status": "ok", "kind": "markov", "tactics": list(TACTIC_ORDER),
        "taxonomy_version": TAXONOMY_VERSION, "alpha": float(alpha),
        "startprob": startprob, "transmat": transmat,
        "counts": counts, "row_support": row_support,
        "n_sequences": n_sequences, "n_transitions": n_transitions,
    }


def predict_next_markov(model: dict, sequence: list[str], top_k: int = 3,
                        min_support: int = 3) -> dict:
    """Distribution over the tactic after the last known tactic in ``sequence``.
    An empty or fully-unknown sequence returns the uniform distribution with
    ``uniform_fallback=true``: the caller asked for a prediction the corpus
    cannot anchor, and a guessed tactic would be worse than an explicit
    non-answer. A row with fewer than ``min_support`` observed transitions is
    still returned, flagged ``low_support``.
    """
    current: Optional[str] = None
    for raw in reversed(list(sequence or [])):
        known = normalize_tactics(raw)
        if known:
            current = known[0]
            break
    if current is None:
        return _uniform_prediction("the sequence carries no known tactic", top_k, "markov")

    index = TACTIC_INDEX[current]
    probabilities = list(model["transmat"][index])
    row_support = model.get("row_support") or [0] * len(TACTIC_ORDER)
    support = int(row_support[index])
    return {
        "status": "ok", "method": "markov", "current_tactic": current,
        "uniform_fallback": False, "support": support,
        "low_support": support < int(min_support),
        "predictions": _top_k(probabilities, top_k),
        "escalation_probability": _escalation(probabilities),
    }


def _forward_gamma(sequence: list[str], model: dict) -> Optional[list[float]]:
    """Scaled forward pass returning P(state_T | observed sequence).
    The per-step normalisation drops a constant that the final normalised
    posterior does not need; without it, long sequences underflow to zero in
    plain float arithmetic. ``None`` means the posterior collapsed, which the
    caller reports as a uniform fallback rather than dividing by zero.
    """
    emission = model.get("emissionprob")
    if not emission:
        return None
    n_states = len(model["startprob"])
    alpha = [float(value) for value in model["startprob"]]
    known = 0
    for raw in sequence:
        tactics = normalize_tactics(raw)
        if not tactics:
            continue
        known += 1
        column = TACTIC_INDEX[tactics[0]]
        alpha = [alpha[state] * float(emission[state][column]) for state in range(n_states)]
        total = sum(alpha)
        if total <= 1e-12:
            return None
        alpha = [value / total for value in alpha]
    return alpha if known else None


def predict_next_hmm(model: dict, sequence: list[str], top_k: int = 3) -> dict:
    """Next-tactic distribution from the filled-in HMM parameters.
    P(next tactic) = (gamma_T @ transmat) @ emission, where gamma_T is the
    forward posterior of the hidden phase after ``sequence``. Pure arithmetic:
    the stored matrices are enough, hmmlearn is needed only at training time.
    """
    gamma = _forward_gamma(list(sequence or []), model)
    if gamma is None:
        return _uniform_prediction(
            "stored HMM has no usable emission matrix for this sequence", top_k, "hmm")

    transmat = model["transmat"]
    emission = model["emissionprob"]
    n_states = len(model["startprob"])
    n_tactics = len(TACTIC_ORDER)
    next_state = [sum(gamma[state] * float(transmat[state][to]) for state in range(n_states))
                  for to in range(n_states)]
    next_tactic = [sum(next_state[state] * float(emission[state][column])
                       for state in range(n_states)) for column in range(n_tactics)]
    return {
        "status": "ok", "method": "hmm", "current_tactic": None,
        "uniform_fallback": False, "support": int(model.get("n_transitions") or 0),
        "low_support": False,
        "predictions": _top_k(next_tactic, top_k),
        "escalation_probability": _escalation(next_tactic),
    }


def sequence_logprob(model: dict, sequence: list[str]) -> dict:
    """Mean per-transition log likelihood of an observed chain under the model.
    A low mean is evidence the chain looks unlike the training corpus an
    advisory signal, not a verdict, because a genuinely new campaign is
    supposed to look unlikely. Smoothed probabilities guarantee the logarithm
    is defined for every pair.
    """
    indexes: list[int] = []
    for raw in sequence:
        known = normalize_tactics(raw)
        if known:
            indexes.append(TACTIC_INDEX[known[0]])
    if len(indexes) < 2:
        return {"status": "insufficient_data", "reason": "need at least two known tactics"}
    transmat = model["transmat"]
    total = 0.0
    steps = 0
    for current, following in zip(indexes, indexes[1:]):
        probability = float(transmat[current][following])
        total += math.log(max(probability, 1e-12))
        steps += 1
    return {"status": "ok", "steps": steps, "logprob": round(total, 6),
            "mean_logprob": round(total / steps, 6)}


def fit_categorical_hmm(sequences: list[list[str]], n_components: int = 4,
                        min_sequences: int = 15, seed: int = 42,
                        n_iter: int = 50) -> dict:
    """Train a CategoricalHMM (hidden campaign phase -> observed tactic).
    Import: hmmlearn is optional and the server must answer ``unavailable``
    rather than fail to start. A fit failure is reported as ``unavailable`` with
    the library's message, because a bad ``n_components`` for the corpus size is
    an operator-tunable condition, not a server fault.
    """
    if len(sequences) < min_sequences:
        return _insufficient(len(sequences), 0, min_sequences, 0, noun="sequences")
    try:
        from hmmlearn.hmm import CategoricalHMM
    except ImportError:
        return {"status": "unavailable",
                "reason": "hmmlearn is not installed; pip install hmmlearn "
                          "(setup.sh BLUETEAM_INSTALL_FORECAST=1)"}

    flat: list[int] = []
    lengths: list[int] = []
    try:
        for sequence in sequences:
            indexes = [TACTIC_INDEX[tactic] for tactic in sequence]
            flat.extend(indexes)
            lengths.append(len(indexes))
    except KeyError as exc:
        raise ValueError(f"unknown tactic {exc.args[0]!r} in corpus; normalize before fitting") from exc

    try:
        model = CategoricalHMM(n_components=int(n_components),
                               n_features=len(TACTIC_ORDER), n_iter=int(n_iter),
                               random_state=int(seed))
        model.fit([[index] for index in flat], lengths)
    except (ValueError, TypeError, RuntimeError) as exc:
        return {"status": "unavailable", "reason": f"hmmlearn fit failed: {exc}"}

    emissionprob = [[round(float(value), 6) for value in row] for row in model.emissionprob_]
    if len(emissionprob) != int(n_components) or len(emissionprob[0]) != len(TACTIC_ORDER):
        return {"status": "error",
                "reason": "hmmlearn returned an emission matrix that does not match the "
                          "local tactic vocabulary"}
    return {
        "status": "ok", "kind": "hmm", "tactics": list(TACTIC_ORDER),
        "taxonomy_version": TAXONOMY_VERSION,
        "startprob": [round(float(value), 6) for value in model.startprob_],
        "transmat": [[round(float(value), 6) for value in row] for row in model.transmat_],
        "emissionprob": emissionprob,
        "n_sequences": len(sequences), "n_transitions": len(flat) - len(sequences),
        "n_components": int(n_components), "seed": int(seed), "n_iter": int(n_iter),
    }


VOLUME_KIND = "poisson_hmm"

def poisson_logpmf(count: float, lam: float) -> float:
    """Log Poisson pmf. The count can arrive as a float from the store; the
    gamma function extends the factorial so no integer coercion is needed.
    A non-positive lambda is a malformed model and maps to zero probability."""
    if lam <= 0:
        return 0.0 if count == 0 else float("-inf")
    return -lam + count * math.log(lam) - math.lgamma(count + 1.0)


def fit_poisson_hmm(counts: list[int], n_components: int = 3, min_buckets: int = 48,
                    seed: int = 42, n_iter: int = 50) -> dict:
    """Fit a PoissonHMM over per-bucket alert counts.
    Counts are non-negative integers; a window with no alerts is a real zero
    bucket, not missing data, which is why the caller must query with
    ``min_doc_count: 0``. An all-zero or constant series has no regimes to
    identify and returns ``insufficient_data`` before hmmlearn is imported;
    thin coverage below ``min_buckets`` does the same. Import: a host
    without hmmlearn answers ``unavailable`` with the install hint.
    """
    if len(counts) < min_buckets:
        return _insufficient(len(counts), 0, min_buckets, 0, noun="buckets")
    if any(count < 0 for count in counts):
        raise ValueError("volume buckets must be non-negative counts")
    if max(counts) == 0:
        return {"status": "insufficient_data", "n_buckets": len(counts),
                "reason": "every bucket is zero; no regime can be identified"}
    if max(counts) - min(counts) == 0:
        return {"status": "insufficient_data", "n_buckets": len(counts),
                "reason": "the series is constant; Poisson regimes need variation"}
    if int(n_components) < 2 or int(n_components) >= len(counts):
        return _insufficient(len(counts), 0, max(int(n_components) + 1, min_buckets), 0,
                             noun="buckets")
    try:
        from hmmlearn.hmm import PoissonHMM
    except ImportError:
        return {"status": "unavailable",
                "reason": "hmmlearn is not installed; pip install hmmlearn "
                          "(setup.sh BLUETEAM_INSTALL_FORECAST=1)"}

    try:
        model = PoissonHMM(n_components=int(n_components), n_iter=int(n_iter),
                           random_state=int(seed))
        model.fit([[float(count)] for count in counts])
    except (ValueError, TypeError, RuntimeError, FloatingPointError) as exc:
        return {"status": "unavailable", "reason": f"hmmlearn PoissonHMM fit failed: {exc}"}

    lambdas = [round(float(row[0]), 6) for row in model.lambdas_]
    if len(lambdas) != int(n_components) or min(lambdas) <= 0:
        return {"status": "error",
                "reason": "hmmlearn returned a lambda vector that is not usable "
                          "(wrong length or non-positive mean)"}
    return {
        "status": "ok", "kind": VOLUME_KIND, "lambdas": lambdas,
        "startprob": [round(float(value), 6) for value in model.startprob_],
        "transmat": [[round(float(value), 6) for value in row] for row in model.transmat_],
        "n_buckets": len(counts), "n_components": int(n_components),
        "seed": int(seed), "n_iter": int(n_iter),
    }


def _volume_forward_last(counts: list, model: dict) -> Optional[list[float]]:
    """Filtered regime posterior after the observed context buckets.
    Scaled forward recursion with Poisson emissions in log space. ``None``
    means the posterior collapsed (an observation no state can plausibly
    emit); the caller falls back to the prior with a flag instead of dividing
    by zero.
    """
    lambdas = [float(value) for value in model["lambdas"]]
    size = len(lambdas)
    posterior = [float(value) for value in model["startprob"]]
    for count in counts:
        posterior = [posterior[state] * math.exp(poisson_logpmf(float(count), lambdas[state]))
                     for state in range(size)]
        total = sum(posterior)
        if total <= 1e-12:
            return None
        posterior = [value / total for value in posterior]
    return posterior


def _peak_probability(posterior: list[float], transmat: list[list[float]],
                      target_states: list[int], horizon: int) -> float:
    """Target state is active at least once in the next ``horizon`` steps.
    Computed over the sub-chain of non-target states: mass that leaves it is
    mass that has reached a peak, so one minus the surviving mass is the
    answer. Current target mass is excluded from the start, which makes the
    value 1.0 when the system is already in a peak (it continues to count as
    active). Exact for a first-order chain; no sampling.
    """
    size = len(posterior)
    target = set(target_states)
    safe = [0.0 if state in target else float(posterior[state]) for state in range(size)]
    for _ in range(int(horizon)):
        following = [0.0] * size
        for state in range(size):
            if safe[state] <= 0.0:
                continue
            for to in range(size):
                if to not in target:
                    following[to] += safe[state] * float(transmat[state][to])
        safe = following
    return round(1.0 - sum(safe), 6)


def predict_volume(model: dict, context_counts: list, horizon_buckets: int = 24) -> dict:
    """Regime-conditional volume forecast over the next ``horizon_buckets``.
    The state distribution after the observed context is rolled forward with
    the transition matrix; each step's expected count is the regime mixture
    mean ``sum_k P(state=k) * lambda_k``. ``peak_probability`` is the exact
    probability that a max-lambda state is active at least once in the
    horizon. A stored model whose lambdas do not separate returns
    ``unavailable`` rather than a forecast with a meaningless peak state.
    """
    lambdas = [float(value) for value in model.get("lambdas") or []]
    size = len(lambdas)
    if size < 2:
        return {"status": "unavailable", "reason": "stored model has no usable lambda vector"}
    if max(lambdas) - min(lambdas) <= 1e-9:
        return {"status": "unavailable",
                "reason": "stored model has no distinguishable regimes "
                          "(all lambda means are equal)"}
    posterior = _volume_forward_last(list(context_counts or []), model)
    posterior_fallback = posterior is None
    if posterior_fallback:
        posterior = [float(value) for value in model["startprob"]]

    transmat = []
    for row in model["transmat"]:
        total = sum(float(value) for value in row) or 1.0
        transmat.append([float(value) / total for value in row])
    state = list(posterior)
    expected_counts: list[float] = []
    for _ in range(int(horizon_buckets)):
        state = [sum(state[from_state] * transmat[from_state][to_state]
                     for from_state in range(size)) for to_state in range(size)]
        expected_counts.append(round(sum(state[state_index] * lambdas[state_index]
                                         for state_index in range(size)), 4))
    peak_states = [index for index, lam in enumerate(lambdas) if lam == max(lambdas)]
    return {
        "status": "ok", "method": VOLUME_KIND, "n_states": size,
        "lambdas": lambdas, "peak_states": peak_states,
        "context_buckets": len(context_counts or []),
        "posterior_fallback": posterior_fallback,
        "expected_counts": expected_counts,
        "expected_total": round(sum(expected_counts), 3),
        "mean_per_bucket": round(sum(expected_counts) / len(expected_counts), 3),
        "peak_probability": _peak_probability(posterior, transmat, peak_states, horizon_buckets),
        "final_state_distribution": [
            {"state": index, "probability": round(state[index], 6), "lambda": lambdas[index]}
            for index in range(size)],
    }


def validate_model(model: dict) -> None:
    """Refuse a stored model whose layout does not match this build.
    Raises ``ValueError`` with the exact mismatch. The store converts it to its
    own error type; nothing downstream should ever score against a matrix whose
    columns might mean different tactics, or a volume model whose lambda vector
    does not match its state count.
    """
    kind = model.get("kind")
    if kind not in ("markov", "hmm", VOLUME_KIND):
        raise ValueError(f"unknown model kind {kind!r}")
    if kind == VOLUME_KIND:
        lambdas = model.get("lambdas")
        if not isinstance(lambdas, list) or len(lambdas) < 2:
            raise ValueError("volume model is missing a usable lambda vector")
        if any(float(value) <= 0 for value in lambdas):
            raise ValueError("volume model carries a non-positive lambda")
    elif list(model.get("tactics") or []) != list(TACTIC_ORDER):
        raise ValueError("tactic vocabulary mismatch")

    size = len(TACTIC_ORDER)
    n_states = len(model["startprob"])
    if kind == VOLUME_KIND and len(model.get("lambdas") or []) != n_states:
        raise ValueError("lambda count does not match startprob")
    for name in ("startprob", "transmat"):
        if not isinstance(model.get(name), list) or not model[name]:
            raise ValueError(f"model is missing {name}")
    if len(model["transmat"]) != n_states:
        raise ValueError("transmat state count does not match startprob")
    if kind == "markov" and n_states != size:
        raise ValueError("a Markov chain needs one state per tactic")
    if abs(sum(float(v) for v in model["startprob"]) - 1.0) > PROB_SUM_TOLERANCE:
        raise ValueError("startprob does not sum to 1")
    for row in model["transmat"]:
        if len(row) != n_states or abs(sum(float(v) for v in row) - 1.0) > PROB_SUM_TOLERANCE:
            raise ValueError("transmat row does not sum to 1")
        if any(not 0.0 <= float(v) <= 1.0 for v in row):
            raise ValueError("transmat carries a probability outside [0, 1]")
    emission = model.get("emissionprob")
    if emission is not None:
        if len(emission) != n_states:
            raise ValueError("emissionprob state count does not match startprob")
        for row in emission:
            if len(row) != size or abs(sum(float(v) for v in row) - 1.0) > PROB_SUM_TOLERANCE:
                raise ValueError("emissionprob row does not sum to 1")
