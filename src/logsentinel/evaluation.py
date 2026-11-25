"""Evaluation harness: compare rule-based, ML-based, and hybrid detection
against ground-truth labels from the synthetic generator.

ML is trained on an independently-generated, purely-normal baseline and
scored against a separate test batch, rather than fitting and scoring the
same data. Fitting and scoring identical data would measure how the model
ranks the batch it already memorized, not how well it generalizes to new
traffic, which is not a meaningful evaluation of detection quality."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timezone

from logsentinel.detection.features import extract_features
from logsentinel.detection.ml import score_at_threshold, score_windows, train_model
from logsentinel.detection.rules import run_all_rules
from logsentinel.generator import LabeledLine, generate_normal_traffic, to_log_text
from logsentinel.parser import LogEntry, parse_lines


@dataclass(frozen=True)
class Metrics:
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int


_EMPTY_METRICS = Metrics(0.0, 0.0, 0.0, 0, 0, 0)


def _ips_with_label(lines: list[LabeledLine], label: str) -> set[str]:
    return {ll.ip for ll in lines if ll.label == label}


def _compute_metrics(flagged_ips: set[str], true_ips: set[str], all_ips: set[str]) -> Metrics:
    tp = len(flagged_ips & true_ips)
    fp = len(flagged_ips - true_ips)
    fn = len(true_ips - flagged_ips)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return Metrics(precision, recall, f1, tp, fp, fn)


def train_baseline(
    window_seconds: int = 60,
    normal_count: int = 200,
    seed: int = 1000,
    contamination: float | str = "auto",
):
    """Train an Isolation Forest on independently-generated, purely-normal
    traffic (a different seed than any test batch). This is the model later
    scored against real test batches, it never sees the data it's evaluated
    on, avoiding train/test leakage."""
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rng = random.Random(seed)
    normal_lines = generate_normal_traffic(normal_count, base_time, rng)
    entries, _ = parse_lines(to_log_text(normal_lines).splitlines())
    features = extract_features(entries, window_seconds=window_seconds)

    if not features:
        raise ValueError("baseline produced zero feature windows; increase normal_count")

    return train_model(features, contamination=contamination, seed=seed)


def evaluate_rules(entries: list[LogEntry], lines: list[LabeledLine]) -> dict[str, Metrics]:
    """Precision/recall/F1 for the rule-based detectors, per attack type."""
    if not entries:
        return {label: _EMPTY_METRICS for label in ("brute_force", "scan", "sqli")}

    alerts = run_all_rules(entries)
    all_ips = {e.ip for e in entries}

    results = {}
    for label in ("brute_force", "scan", "sqli"):
        flagged = {a.ip for a in alerts if a.rule == label}
        true_ips = _ips_with_label(lines, label)
        results[label] = _compute_metrics(flagged, true_ips, all_ips)
    return results


def evaluate_ml(
    entries: list[LogEntry],
    lines: list[LabeledLine],
    model,
    window_seconds: int = 60,
) -> Metrics:
    """Precision/recall/F1 for the ML detector, scoring `entries` against an
    already-trained `model` (see train_baseline) rather than training on
    `entries` itself."""
    if not entries:
        return _EMPTY_METRICS

    features = extract_features(entries, window_seconds=window_seconds)
    if not features:
        return _EMPTY_METRICS

    ml_alerts = score_windows(model, features)
    flagged_ips = {a.ip for a in ml_alerts}
    true_ips = {ll.ip for ll in lines if ll.label != "normal"}
    all_ips = {e.ip for e in entries}

    return _compute_metrics(flagged_ips, true_ips, all_ips)


def evaluate_hybrid(
    entries: list[LogEntry],
    lines: list[LabeledLine],
    model,
    window_seconds: int = 60,
) -> Metrics:
    """Precision/recall/F1 when an IP is flagged if EITHER rules OR the
    already-trained ML model flags it."""
    if not entries:
        return _EMPTY_METRICS

    rule_alerts = run_all_rules(entries)
    rule_ips = {a.ip for a in rule_alerts}

    features = extract_features(entries, window_seconds=window_seconds)
    ml_ips = {a.ip for a in score_windows(model, features)} if features else set()

    flagged_ips = rule_ips | ml_ips
    true_ips = {ll.ip for ll in lines if ll.label != "normal"}
    all_ips = {e.ip for e in entries}

    return _compute_metrics(flagged_ips, true_ips, all_ips)


def false_alert_rate_per_1000(
    model,
    benign_lines: list[LabeledLine],
    thresholds: list[float],
    window_seconds: int = 60,
) -> dict[float, float]:
    """For each decision_function threshold, report how many windows per
    1000 would be falsely flagged on a HELD-OUT benign dataset, independent
    from both the training baseline and whatever batch is being evaluated.
    This answers "how noisy is this model at different sensitivities?",
    separately from recall/precision against known attacks."""
    entries, _ = parse_lines(to_log_text(benign_lines).splitlines())
    features = extract_features(entries, window_seconds=window_seconds)
    if not features:
        return {t: 0.0 for t in thresholds}

    results = {}
    for t in thresholds:
        flagged = score_at_threshold(model, features, t)
        results[t] = (len(flagged) / len(features)) * 1000
    return results


def run_full_evaluation(
    lines: list[LabeledLine],
    window_seconds: int = 60,
    baseline_seed: int = 1000,
) -> dict:
    """Run rules, ML, and hybrid evaluation on the same test batch, training
    ML on an independent baseline rather than on this batch itself. Also
    reports parse coverage (how many lines parsed vs were malformed) so a
    batch with poor parse coverage doesn't silently produce misleading
    metrics."""
    entries, malformed = parse_lines(to_log_text(lines).splitlines())

    if not entries:
        empty_rules = {label: _EMPTY_METRICS for label in ("brute_force", "scan", "sqli")}
        return {
            "rules": empty_rules,
            "ml": _EMPTY_METRICS,
            "hybrid": _EMPTY_METRICS,
            "parsed_lines": 0,
            "malformed_lines": malformed,
        }

    model = train_baseline(window_seconds=window_seconds, seed=baseline_seed)

    return {
        "rules": evaluate_rules(entries, lines),
        "ml": evaluate_ml(entries, lines, model, window_seconds=window_seconds),
        "hybrid": evaluate_hybrid(entries, lines, model, window_seconds=window_seconds),
        "parsed_lines": len(entries),
        "malformed_lines": malformed,
    }
