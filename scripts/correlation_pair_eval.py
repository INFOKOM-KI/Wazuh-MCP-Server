#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Offline pair evaluation harness for same-incident correlation.

It validates versioned pair records and computes positive-class precision,
recall, and F1 with incident-grouped bootstrap intervals. Official metrics come
only from independently adjudicated labels. Weak-label and external-reference
rows are reported as named pilots. Missing or insufficient labels produce an
explicit ``not_evaluable`` result; no number is fabricated.

The shipped engines do not emit a pair-level same-incident prediction: Engine A
returns per-IP triggers and Engine B returns per-bucket anomalies. The evaluated
scorer here is therefore an explicitly named offline baseline, not the engine.
It predicts same-incident when the pair shares a subject and the two timestamps
sit within the operating window. Engine-derived IOC evidence stays out of it.

The pure extractor is loaded by path, so this evaluator never imports the
server package or its config bootstrap. It reads a JSONL file and prints a
report; it never touches a store.

Usage:
    python3 scripts/correlation_pair_eval.py --pairs pairs_eval.jsonl
    python3 scripts/correlation_pair_eval.py --pairs pairs_eval.jsonl --json
    python3 scripts/correlation_pair_eval.py --pairs pairs_eval.jsonl \
        --sweep-windows 600,3600,86400

Exit 0 = report produced (even ``not_evaluable``); exit 2 = input refused.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PAIR_FEATURES_PATH = ROOT / "mcp_server" / "correlation" / "pair_features.py"


def _load_pair_features():
    """Load the pure extractor by path.

    Importing the package would run the server config bootstrap, which raises
    without an Indexer URL. The extractor needs neither, so the offline
    evaluator loads the module directly and stays config-independent.
    """
    spec = importlib.util.spec_from_file_location("correlation_pair_features", PAIR_FEATURES_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"pair feature module not found at {PAIR_FEATURES_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pair_features = _load_pair_features()

PAIR_FEATURE_VERSION = pair_features.PAIR_FEATURE_VERSION
PAIR_SCHEMA_VERSION = pair_features.PAIR_SCHEMA_VERSION
ALERT_FIELDS = pair_features.ALERT_FIELDS
FEATURE_KEYS = pair_features.FEATURE_KEYS
RECORD_KEYS = pair_features.RECORD_KEYS

LABELS = ("same_incident", "unrelated", "insufficient_evidence",
          "related_behavior", "shared_ioc_only")
BINARY_LABELS = ("same_incident", "unrelated")
LABEL_SOURCES = ("adjudicated", "weak_case_link", "external_reference")
OFFICIAL_SOURCE = "adjudicated"
SPLITS = ("train", "validation", "test")
PILOT_NAMES = {"weak_case_link": "weak_label_pilot",
               "external_reference": "external_reference_agreement"}
LABEL_DERIVED_FEATURE_KEYS = ("same_case", "case_id", "case_link", "case_id_match")
DEFAULT_TIME_WINDOW_SECONDS = 3600
MIN_BOOTSTRAP_DEFINED = 50
BASELINE_VERSION = "v0"
OFFICIAL_ORIGINS = ("operator_declared_official",)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def load_records(path: Path) -> tuple[list[dict], list[tuple[int, str]]]:
    """JSONL rows plus ``(line number, reason)`` for every skipped line."""
    rows: list[dict] = []
    parse_issues: list[tuple[int, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                parse_issues.append((lineno, f"invalid JSON: {exc.msg}"))
                continue
            if not isinstance(row, dict):
                parse_issues.append((lineno, "record is not a JSON object"))
                continue
            rows.append(row)
    return rows, parse_issues


def _add_issue(issues: list[dict], check: str, row: int, pair_id_value: Any, detail: str) -> None:
    issues.append({"check": check, "row": row, "pair_id": pair_id_value, "detail": detail})


def validate_records(rows: list[dict]) -> list[dict]:
    """Every check that must pass before a metric may be computed."""
    issues: list[dict] = []
    seen_pairs: dict[str, str] = {}
    group_splits: dict[str, set[str]] = {}
    for index, row in enumerate(rows, 1):
        pair_key = _text(row.get("pair_id"))
        unknown = sorted(set(row) - set(RECORD_KEYS))
        if unknown:
            _add_issue(issues, "unknown_record_keys", index, pair_key, f"unknown keys {unknown}")
        missing = [key for key in RECORD_KEYS if key not in row]
        if missing:
            _add_issue(issues, "missing_record_keys", index, pair_key, f"missing keys {missing}")
        if row.get("schema_version") != PAIR_SCHEMA_VERSION:
            _add_issue(issues, "schema_version", index, pair_key,
                       f"expected {PAIR_SCHEMA_VERSION}, got {row.get('schema_version')!r}")
        if row.get("feature_version") != PAIR_FEATURE_VERSION:
            _add_issue(issues, "feature_version", index, pair_key,
                       f"expected {PAIR_FEATURE_VERSION}, got {row.get('feature_version')!r}")
        if row.get("label") not in LABELS:
            _add_issue(issues, "label_vocab", index, pair_key, f"unknown label {row.get('label')!r}")
        if row.get("label_source") not in LABEL_SOURCES:
            _add_issue(issues, "label_source_vocab", index, pair_key,
                       f"unknown label_source {row.get('label_source')!r}")
        if not _text(row.get("recorded_by")):
            _add_issue(issues, "provenance", index, pair_key, "recorded_by is required")
        if row.get("split") not in SPLITS:
            _add_issue(issues, "split_vocab", index, pair_key, f"unknown split {row.get('split')!r}")
        group = _text(row.get("group_id"))
        if not group:
            _add_issue(issues, "group_required", index, pair_key, "group_id is required")
        elif row.get("split") in SPLITS:
            group_splits.setdefault(group, set()).add(row.get("split"))

        parsed_alerts: dict[str, dict] = {}
        for side in ("alert_a", "alert_b"):
            alert = row.get(side)
            if not isinstance(alert, dict):
                _add_issue(issues, "alert_shape", index, pair_key, f"{side} is not an object")
                continue
            alert_unknown = sorted(set(alert) - set(ALERT_FIELDS))
            if alert_unknown:
                _add_issue(issues, "alert_keys", index, pair_key,
                           f"{side} has fields outside the schema: {alert_unknown}")
            if not _text(alert.get("alert_id")):
                _add_issue(issues, "alert_id", index, pair_key, f"{side} has no alert_id")
            else:
                parsed_alerts[side] = alert

        if len(parsed_alerts) == 2:
            left, right = parsed_alerts["alert_a"], parsed_alerts["alert_b"]
            if _text(left.get("alert_id")) == _text(right.get("alert_id")):
                _add_issue(issues, "alert_id", index, pair_key, "pair needs two distinct alert_ids")
            else:
                expected_pair = pair_features.pair_id(left, right)
                if pair_key != expected_pair:
                    _add_issue(issues, "pair_id", index, pair_key,
                               f"pair_id does not match the alert ids (expected {expected_pair})")
                _validate_features(issues, index, pair_key, row, left, right)

        if pair_key:
            previous = seen_pairs.get(pair_key)
            if previous is None:
                seen_pairs[pair_key] = str(row.get("label"))
            elif previous == str(row.get("label")):
                _add_issue(issues, "duplicate_pair", index, pair_key, "pair appears more than once")
            else:
                _add_issue(issues, "conflicting_adjudication", index, pair_key,
                           f"pair carries both {previous!r} and {row.get('label')!r}")
        else:
            _add_issue(issues, "pair_id", index, pair_key, "pair_id is required")

    for group, splits in sorted(group_splits.items()):
        if len(splits) > 1:
            _add_issue(issues, "group_split_leakage", 0, None,
                       f"group {group!r} appears in splits {sorted(splits)}")
    return issues


def _validate_features(issues: list[dict], index: int, pair_key: Any, row: dict,
                       left: dict, right: dict) -> None:
    features = row.get("features")
    if not isinstance(features, dict):
        _add_issue(issues, "feature_shape", index, pair_key, "features is not an object")
        return
    unknown = sorted(set(features) - set(FEATURE_KEYS))
    for key in unknown:
        if key in LABEL_DERIVED_FEATURE_KEYS:
            _add_issue(issues, "label_derived_feature", index, pair_key,
                       f"feature {key!r} derives from the label and cannot score pairs")
        else:
            _add_issue(issues, "unknown_feature_keys", index, pair_key, f"unknown feature {key!r}")
    missing = [key for key in FEATURE_KEYS if key not in features]
    if missing:
        _add_issue(issues, "missing_feature_keys", index, pair_key, f"missing features {missing}")
        return
    if unknown:
        return
    try:
        recomputed = pair_features.extract_pair_features(left, right)
    except ValueError as exc:
        _add_issue(issues, "feature_mismatch", index, pair_key, f"cannot recompute: {exc}")
        return
    if features != recomputed:
        _add_issue(issues, "feature_mismatch", index, pair_key,
                   "stored features differ from the shipped extractor output")


def baseline_predict(row: dict, window_seconds: float) -> bool | None:
    """Offline baseline prediction, or None when the pair is not scorable.

    None means the pair lacks a subject or a parseable timestamp, so the
    baseline declines to claim anything instead of defaulting to unrelated.
    """
    features = row.get("features")
    if not isinstance(features, dict):
        return None
    if features.get("same_subject") is False:
        return False
    if features.get("same_subject") is not True:
        return None
    delta = features.get("time_delta_seconds")
    if not isinstance(delta, (int, float)):
        return None
    return delta <= window_seconds


def score_pairs(rows: list[dict], window_seconds: float) -> tuple[list[tuple[bool, str]], int]:
    """``(predicted, label)`` pairs that the baseline could score, plus the skip count."""
    scored: list[tuple[bool, str]] = []
    unscorable = 0
    for row in rows:
        prediction = baseline_predict(row, window_seconds)
        if prediction is None:
            unscorable += 1
            continue
        scored.append((prediction, str(row.get("label"))))
    return scored, unscorable


def binary_metrics(scored: list[tuple[bool, str]]) -> dict[str, Any] | None:
    if not scored:
        return None
    true_positive = sum(1 for prediction, label in scored if prediction and label == "same_incident")
    false_positive = sum(1 for prediction, label in scored if prediction and label == "unrelated")
    false_negative = sum(1 for prediction, label in scored if not prediction and label == "same_incident")
    true_negative = sum(1 for prediction, label in scored if not prediction and label == "unrelated")
    precision = round(true_positive / (true_positive + false_positive), 4) if true_positive + false_positive else None
    recall = round(true_positive / (true_positive + false_negative), 4) if true_positive + false_negative else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = round(2 * precision * recall / (precision + recall), 4)
    return {"pairs": len(scored), "tp": true_positive, "fp": false_positive,
            "tn": true_negative, "fn": false_negative,
            "precision": precision, "recall": recall, "f1": f1}


def _percentile(series: list[float], quantile: float) -> float:
    index = min(int(quantile * (len(series) - 1) + 0.5), len(series) - 1)
    return series[index]


def grouped_bootstrap(rows: list[dict], window_seconds: float, n_boot: int,
                      seed: int) -> dict[str, Any]:
    """Percentile CI resampling incident groups, not pairs.

    Pairs inside one group share alerts and entities, so a pair-level resample
    would report an interval narrower than the data supports.
    """
    groups = sorted({group for group in (_text(row.get("group_id")) for row in rows) if group})
    result = {"available": False, "reason": None, "groups": len(groups),
              "resamples": n_boot, "defined": 0, "skipped": 0, "ci": None}
    if len(groups) < 2:
        result["reason"] = "fewer than 2 incident groups"
        return result
    by_group = {group: [row for row in rows if _text(row.get("group_id")) == group] for group in groups}
    rng = random.Random(seed)
    series: dict[str, list[float]] = {"f1": [], "precision": [], "recall": []}
    defined = 0
    skipped = 0
    for _ in range(n_boot):
        resampled: list[dict] = []
        for _pick in range(len(groups)):
            resampled.extend(by_group[rng.choice(groups)])
        scored, _unscorable = score_pairs(resampled, window_seconds)
        metrics = binary_metrics(scored)
        if metrics is None or any(metrics[key] is None for key in series):
            skipped += 1
            continue
        for key in series:
            series[key].append(float(metrics[key]))
        defined += 1
    result["defined"] = defined
    result["skipped"] = skipped
    if defined < MIN_BOOTSTRAP_DEFINED:
        result["reason"] = f"only {defined} defined bootstrap replicates (need {MIN_BOOTSTRAP_DEFINED})"
        return result
    ci: dict[str, dict[str, float]] = {}
    for key, values in series.items():
        values.sort()
        low, high = _percentile(values, 0.025), _percentile(values, 0.975)
        ci[key] = {"lo": round(low, 4), "hi": round(high, 4),
                   "half_width": round((high - low) / 2, 4)}
    result["available"] = True
    result["ci"] = ci
    return result


def evaluate_binary_cohort(rows: list[dict], *, window_seconds: float, min_positives: int,
                           min_negatives: int, min_groups: int, max_ci_half_width: float,
                           bootstrap_n: int, seed: int, pilot: bool) -> dict[str, Any]:
    rows = [row for row in rows if row.get("label") in BINARY_LABELS]
    positives = sum(1 for row in rows if row.get("label") == "same_incident")
    negatives = sum(1 for row in rows if row.get("label") == "unrelated")
    groups = len({group for group in (_text(row.get("group_id")) for row in rows) if group})
    scored, unscorable = score_pairs(rows, window_seconds)
    scorable_rows = [row for row in rows if baseline_predict(row, window_seconds) is not None]
    scorable_positives = sum(1 for row in scorable_rows if row.get("label") == "same_incident")
    scorable_negatives = sum(1 for row in scorable_rows if row.get("label") == "unrelated")
    scorable_groups = len({group for group in (_text(row.get("group_id")) for row in scorable_rows) if group})
    base: dict[str, Any] = {"pairs": len(rows), "positives": positives, "negatives": negatives,
                            "groups": groups, "scorable_positives": scorable_positives,
                            "scorable_negatives": scorable_negatives, "scorable_groups": scorable_groups,
                            "unscorable_pairs": unscorable, "window_seconds": window_seconds,
                            "pilot_only": pilot}
    reasons = []
    if scorable_positives < min_positives:
        reasons.append(f"scorable positives {scorable_positives} < minimum {min_positives}")
    if scorable_negatives < min_negatives:
        reasons.append(f"scorable negatives {scorable_negatives} < minimum {min_negatives}")
    if reasons:
        return {**base, "status": "not_evaluable", "reasons": reasons, "notes": [],
                "metrics": None, "ci": None}
    metrics = binary_metrics(scored)
    if metrics is None:
        return {**base, "status": "not_evaluable", "reasons": ["no scorable pairs"],
                "notes": [], "metrics": None, "ci": None}
    undefined = [key for key in ("precision", "recall", "f1") if metrics.get(key) is None]
    if undefined:
        return {**base, "status": "not_evaluable",
                "reasons": [f"undefined metrics {undefined}: a required denominator is empty"],
                "notes": [], "metrics": None, "ci": None}
    ci = grouped_bootstrap(scorable_rows, window_seconds, bootstrap_n, seed)
    status = "ok"
    notes: list[str] = []
    if unscorable:
        status = "inconclusive"
        notes.append(f"{unscorable} unscorable pair(s) excluded from metrics")
    if not pilot and scorable_groups < min_groups:
        status = "inconclusive"
        notes.append(f"scorable independent groups {scorable_groups} below the provisional "
                     f"planning target {min_groups}")
    if ci.get("available"):
        half_width = ci["ci"]["f1"]["half_width"]
        if half_width > max_ci_half_width:
            status = "inconclusive"
            notes.append(f"F1 CI half-width {half_width} above {max_ci_half_width}")
    else:
        notes.append(f"grouped bootstrap unavailable: {ci.get('reason')}")
        if not pilot:
            status = "inconclusive"
    return {**base, "status": status, "reasons": [], "notes": notes,
            "metrics": metrics, "ci": ci}


def _select_window(rows: list[dict], windows: list[int]) -> dict[str, Any] | None:
    """Rank candidate operating windows on validation: F1, then precision, then smaller."""
    best: dict[str, Any] | None = None
    for window in windows:
        scored, _unscorable = score_pairs(rows, window)
        metrics = binary_metrics(scored)
        if metrics is None or metrics["f1"] is None:
            continue
        key = (metrics["f1"], metrics["precision"] if metrics["precision"] is not None else -1.0, -window)
        if best is None or key > best["key"]:
            best = {"key": key, "window_seconds": window, "validation_metrics": metrics}
    return best


def _select_eval_rows(official_rows: list[dict], window_seconds: int,
                      sweep_windows: list[int] | None) -> tuple[list[dict], int, dict[str, Any]]:
    validation = [row for row in official_rows if row.get("split") == "validation"]
    test = [row for row in official_rows if row.get("split") == "test"]
    if sweep_windows and validation and test:
        selected = _select_window(validation, sweep_windows)
        if selected is not None:
            return test, selected["window_seconds"], {
                "status": "frozen_from_validation",
                "window_seconds": selected["window_seconds"],
                "validation_metrics": selected["validation_metrics"],
                "evaluated_split": "test",
            }
    if test:
        return test, window_seconds, {"status": "default_window", "window_seconds": window_seconds,
                                      "evaluated_split": "test"}
    return official_rows, window_seconds, {"status": "default_window", "window_seconds": window_seconds,
                                           "evaluated_split": "all_official"}


def _str_counts(values: list[Any]) -> dict[str, int]:
    counts = Counter(str(value) if value is not None else "missing" for value in values)
    return dict(sorted(counts.items()))


def run_evaluation(rows: list[dict], issues: list[dict], *, window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
                   sweep_windows: list[int] | None = None, min_positives: int = 5,
                   min_negatives: int = 5, min_groups: int = 30,
                   max_ci_half_width: float = 0.10, bootstrap_n: int = 2000,
                   seed: int = 7, dataset_origin: str = "unspecified") -> dict[str, Any]:
    groups = {group for group in (_text(row.get("group_id")) for row in rows) if group}
    baseline = {
        "name": "shared_subject_time_window",
        "version": BASELINE_VERSION,
        "provenance": "offline_deterministic_baseline",
        "engine_pair_prediction": False,
        "rule": "same_subject is True and time_delta_seconds <= window_seconds",
        "note": ("The shipped engines emit per-IP triggers and per-bucket anomalies, "
                 "not pair-level same-incident predictions. This baseline is not the "
                 "engine, and its metrics do not measure engine quality."),
    }
    if sweep_windows:
        baseline["sweep_windows"] = list(sweep_windows)
    payload: dict[str, Any] = {
        "tool": "correlation_pair_eval",
        "schema_version": PAIR_SCHEMA_VERSION,
        "feature_version": PAIR_FEATURE_VERSION,
        "dataset_origin": dataset_origin,
        "baseline": baseline,
        "counts": {
            "records": len(rows),
            "groups": len(groups),
            "by_label": _str_counts([row.get("label") for row in rows]),
            "by_source": _str_counts([row.get("label_source") for row in rows]),
            "by_split": _str_counts([row.get("split") for row in rows]),
        },
        "excluded_labels": {label: count for label, count in
                            _str_counts([row.get("label") for row in rows]).items()
                            if label not in BINARY_LABELS},
        "validation": {"status": "invalid" if issues else "ok",
                       "issue_count": len(issues), "issues": issues},
        "limitations": [
            "official metrics require adjudicated labels; weak-label and external-reference rows are pilots",
            "reviewer attribution (recorded_by) is a declared string; the application does not authenticate reviewers",
            "official_eligible and dataset_origin are declarations; neither authenticates the dataset",
            "pairs are a sampled candidate population unless the export covers every candidate",
            "the evaluated scorer is the offline baseline, not shipped Engine A/B/C",
            "engine-derived IOC features are excluded from the baseline; they may support a separate retrieval baseline",
        ],
    }
    if issues:
        blocked = {"status": "invalid_dataset", "reasons":
                   ["validation issues must be resolved before any metric is computed"],
                   "metrics": None, "ci": None, "pilot_only": False, "official_eligible": False}
        payload["official"] = blocked
        payload["pilots"] = {name: dict(blocked) for name in PILOT_NAMES.values()}
        return payload

    official_rows = [row for row in rows
                     if row.get("label_source") == OFFICIAL_SOURCE and row.get("label") in BINARY_LABELS]
    eval_rows, selected_window, threshold = _select_eval_rows(official_rows, window_seconds, sweep_windows)
    official = evaluate_binary_cohort(eval_rows, window_seconds=selected_window,
                                      min_positives=min_positives, min_negatives=min_negatives,
                                      min_groups=min_groups, max_ci_half_width=max_ci_half_width,
                                      bootstrap_n=bootstrap_n, seed=seed, pilot=False)
    official["threshold"] = threshold
    official["official_eligible"] = dataset_origin in OFFICIAL_ORIGINS
    if dataset_origin not in OFFICIAL_ORIGINS:
        payload["ineligible_reference"] = {
            "dataset_origin": dataset_origin,
            "status": official.get("status"),
            "metrics": official.get("metrics"),
            "ci": official.get("ci"),
            "notes": official.get("notes", []),
            "window_seconds": official.get("window_seconds"),
        }
        official["status"] = "not_evaluable"
        official["reasons"] = [f"dataset_origin={dataset_origin}: not an official performance result",
                               *official.get("reasons", [])]
        official["notes"] = []
        official["metrics"] = None
        official["ci"] = None
    payload["official"] = official

    pilots: dict[str, Any] = {}
    for source, pilot_name in PILOT_NAMES.items():
        pilot_rows = [row for row in rows
                      if row.get("label_source") == source and row.get("label") in BINARY_LABELS]
        pilot = evaluate_binary_cohort(pilot_rows, window_seconds=selected_window,
                                       min_positives=min_positives, min_negatives=min_negatives,
                                       min_groups=0, max_ci_half_width=max_ci_half_width,
                                       bootstrap_n=bootstrap_n, seed=seed, pilot=True)
        pilot["source"] = source
        pilot["ground_truth"] = "not_independent"
        pilots[pilot_name] = pilot
    payload["pilots"] = pilots
    return payload


def _format_metric(metrics: dict[str, Any] | None, key: str) -> str:
    if not metrics or metrics.get(key) is None:
        return "n/a"
    return f"{metrics[key]:.4f}"


def _ci_line(ci: dict[str, Any] | None, key: str) -> str:
    if not ci or not ci.get("available") or not ci.get("ci"):
        return "n/a"
    entry = ci["ci"][key]
    return f"[{entry['lo']:.4f}, {entry['hi']:.4f}]"


def render_markdown(payload: dict[str, Any]) -> str:
    counts = payload["counts"]
    lines = ["# Correlation pair evaluation", "",
             f"- Schema: `{payload['schema_version']}` / features `{payload['feature_version']}`",
             f"- Dataset origin: `{payload['dataset_origin']}`",
             f"- Records: {counts['records']} in {counts['groups']} incident groups",
             f"- Validation: {payload['validation']['status']} "
             f"({payload['validation']['issue_count']} issues)",
             f"- Evaluated scorer: `{payload['baseline']['name']}` {payload['baseline']['version']} "
             "(offline baseline, not the engine)", ""]
    section = payload["official"]
    lines += ["## Official", "",
              f"- Status: `{section.get('status')}`",
              f"- Official eligible: {section.get('official_eligible')}"]
    if section.get("threshold"):
        lines.append(f"- Threshold: window {section['threshold']['window_seconds']}s "
                     f"({section['threshold']['status']})")
    if section.get("reasons"):
        lines.append(f"- Reasons: {'; '.join(section['reasons'])}")
    if section.get("notes"):
        lines.append(f"- Notes: {'; '.join(section['notes'])}")
    lines += ["",
              "| metric | value | grouped 95% CI |",
              "|---|---|---|",
              f"| precision | {_format_metric(section.get('metrics'), 'precision')} "
              f"| {_ci_line(section.get('ci'), 'precision')} |",
              f"| recall | {_format_metric(section.get('metrics'), 'recall')} "
              f"| {_ci_line(section.get('ci'), 'recall')} |",
              f"| F1 | {_format_metric(section.get('metrics'), 'f1')} "
              f"| {_ci_line(section.get('ci'), 'f1')} |", ""]
    lines += ["## Pilots", ""]
    for name, section in payload["pilots"].items():
        lines.append(f"- `{name}`: status `{section.get('status')}`, "
                     f"F1 {_format_metric(section.get('metrics'), 'f1')}, "
                     f"pilot_only={section.get('pilot_only')}")
    lines += ["", "## Excluded labels", ""]
    if payload["excluded_labels"]:
        for label, count in payload["excluded_labels"].items():
            lines.append(f"- {label}: {count}")
    else:
        lines.append("- none")
    lines += ["", "## Limitations", ""]
    for item in payload["limitations"]:
        lines.append(f"- {item}")
    issues = payload["validation"]["issues"]
    if issues:
        lines += ["", "## Validation issues", ""]
        for issue in issues:
            lines.append(f"- `{issue['check']}` row {issue['row']}: {issue['detail']}")
    return "\n".join(lines) + "\n"


def _parse_windows(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    windows = sorted({int(part) for part in raw.split(",") if part.strip()})
    if not windows or any(window <= 0 for window in windows):
        raise ValueError("sweep windows must be positive integers")
    return windows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", required=True, help="JSONL file of versioned pair records")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_TIME_WINDOW_SECONDS,
                        help="operating window for the offline baseline")
    parser.add_argument("--sweep-windows", default=None,
                        help="comma-separated candidate windows selected on validation")
    parser.add_argument("--min-positives", type=int, default=5)
    parser.add_argument("--min-negatives", type=int, default=5)
    parser.add_argument("--min-groups", type=int, default=30,
                        help="provisional planning target; below it the status is inconclusive")
    parser.add_argument("--max-ci-half-width", type=float, default=0.10)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--dataset-origin",
                        choices=("unspecified", "operator_declared_official", "synthetic"),
                        default="unspecified",
                        help="declare the dataset origin; official metrics require operator_declared_official")
    parser.add_argument("--synthetic", action="store_true",
                        help="alias for --dataset-origin synthetic")
    args = parser.parse_args(argv)

    if args.window_seconds <= 0:
        print("refused: --window-seconds must be positive", file=sys.stderr)
        return 2
    if args.min_positives < 1 or args.min_negatives < 1:
        print("refused: --min-positives and --min-negatives must be >= 1", file=sys.stderr)
        return 2
    if args.synthetic and args.dataset_origin not in ("unspecified", "synthetic"):
        print(f"refused: --synthetic conflicts with --dataset-origin {args.dataset_origin}",
              file=sys.stderr)
        return 2
    dataset_origin = "synthetic" if args.synthetic else args.dataset_origin

    path = Path(args.pairs)
    if not path.is_file():
        print(f"refused: pairs file not found ({path})", file=sys.stderr)
        return 2
    try:
        rows, parse_issues = load_records(path)
    except OSError as exc:
        print(f"refused: cannot read {path} ({type(exc).__name__})", file=sys.stderr)
        return 2
    try:
        sweep_windows = _parse_windows(args.sweep_windows)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    issues = [{"check": "parse", "row": lineno, "pair_id": None, "detail": detail}
              for lineno, detail in parse_issues]
    issues.extend(validate_records(rows))
    payload = run_evaluation(rows, issues, window_seconds=args.window_seconds,
                             sweep_windows=sweep_windows, min_positives=args.min_positives,
                             min_negatives=args.min_negatives, min_groups=args.min_groups,
                             max_ci_half_width=args.max_ci_half_width,
                             bootstrap_n=args.bootstrap, seed=args.seed,
                             dataset_origin=dataset_origin)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_markdown(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
