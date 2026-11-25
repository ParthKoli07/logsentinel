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
from datetime import datetime, timedelta, timezone

from logsentinel.detection.features import extract_features
from logsentinel.detection.ml import score_at_threshold, score_windows, train_model
from logsentinel.detection.rules import run_all_rules
from logsentinel.generator import Incident, LabeledLine, generate_normal_traffic, to_log_text
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


def _baseline_traffic(seed: int, normal_count: int = 200) -> list[LabeledLine]:
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rng = random.Random(f"logsentinel-baseline-v1:{seed}")
    return generate_normal_traffic(normal_count, base_time, rng)


def train_baseline(
    window_seconds: int = 60,
    normal_count: int = 200,
    seed: int = 1000,
    contamination: float | str = "auto",
):
    normal_lines = _baseline_traffic(seed, normal_count)
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
            "rules_combined": _EMPTY_METRICS,
            "ml": _EMPTY_METRICS,
            "hybrid": _EMPTY_METRICS,
            "parsed_lines": 0,
            "malformed_lines": malformed,
        }

    model = train_baseline(window_seconds=window_seconds, seed=baseline_seed)

    return {
        "rules": evaluate_rules(entries, lines),
        "rules_combined": evaluate_rules_combined(entries, lines),
        "ml": evaluate_ml(entries, lines, model, window_seconds=window_seconds),
        "hybrid": evaluate_hybrid(entries, lines, model, window_seconds=window_seconds),
        "parsed_lines": len(entries),
        "malformed_lines": malformed,
    }

def evaluate_rules_combined(entries: list[LogEntry], lines: list[LabeledLine]) -> Metrics:
    """Treat all rule-based detectors as one system: did ANY rule flag this
    IP, versus did this IP actually perform ANY attack. This is the correct
    baseline to compare hybrid against, not the max of three separate
    per-type numbers, which overstates what rules-only actually achieves
    when a single IP could be missed by one rule but caught by another."""
    if not entries:
        return _EMPTY_METRICS

    alerts = run_all_rules(entries)
    flagged_ips = {a.ip for a in alerts}
    true_ips = {ll.ip for ll in lines if ll.label != "normal"}
    all_ips = {e.ip for e in entries}

    return _compute_metrics(flagged_ips, true_ips, all_ips)

def _alert_overlaps_incident(start: datetime, end: datetime, incident: Incident) -> bool:
    return start < incident.end and end > incident.start


def evaluate_incidents(
    entries: list[LogEntry],
    incidents: list[Incident],
    model,
    window_seconds: int = 60,
) -> dict[str, dict]:
    """For each ground-truth incident, check whether rules, ML, or hybrid
    flagged THIS incident specifically — matching by IP and overlapping
    time window — rather than crediting an IP for every incident it was
    ever part of."""
    rule_alerts = run_all_rules(entries)
    features = extract_features(entries, window_seconds=window_seconds)
    ml_alerts = score_windows(model, features) if features else []

    def _ml_span(a) -> tuple[datetime, datetime]:
        start = datetime.fromisoformat(a.window_start)
        return start, start + timedelta(seconds=window_seconds)

    def _caught_by_rules(incident: Incident) -> bool:
        return any(
            a.ip == incident.ip
            and a.window_start is not None
            and _alert_overlaps_incident(a.window_start, a.window_end, incident)
            for a in rule_alerts
        )

    def _caught_by_ml(incident: Incident) -> bool:
        return any(
            a.ip == incident.ip and _alert_overlaps_incident(*_ml_span(a), incident)
            for a in ml_alerts
        )

    results = {}
    for name, caught_fn in (
        ("rules_combined", _caught_by_rules),
        ("ml", _caught_by_ml),
        ("hybrid", lambda inc: _caught_by_rules(inc) or _caught_by_ml(inc)),
    ):
        total = len(incidents)
        caught = sum(1 for inc in incidents if caught_fn(inc))
        results[name] = {
            "incidents_total": total,
            "incidents_caught": caught,
            "incident_recall": (caught / total) if total else 0.0,
        }
    return results


def run_full_evaluation_with_incidents(
    lines: list[LabeledLine],
    incidents: list[Incident],
    window_seconds: int = 60,
    baseline_seed: int = 1000,
) -> dict:
    """run_full_evaluation plus incident-level recall."""
    results = run_full_evaluation(lines, window_seconds=window_seconds, baseline_seed=baseline_seed)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    if not entries or not incidents:
        results["incidents"] = {}
        return results

    model = train_baseline(window_seconds=window_seconds, seed=baseline_seed)
    results["incidents"] = evaluate_incidents(
        entries, incidents, model, window_seconds=window_seconds
    )
    return results
