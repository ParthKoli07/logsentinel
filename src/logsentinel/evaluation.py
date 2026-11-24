"""Evaluation harness: compare rule-based, ML-based, and hybrid detection
against ground-truth labels from the synthetic generator."""

from __future__ import annotations

from dataclasses import dataclass

from logsentinel.detection.features import extract_features
from logsentinel.detection.ml import score_windows, train_model
from logsentinel.detection.rules import run_all_rules
from logsentinel.generator import LabeledLine
from logsentinel.parser import LogEntry, parse_lines


@dataclass(frozen=True)
class Metrics:
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int


def _ips_with_label(lines: list[LabeledLine], label: str) -> set[str]:
    """IPs that ground truth says performed this attack type."""
    return {ll.ip for ll in lines if ll.label == label}


def _compute_metrics(flagged_ips: set[str], true_ips: set[str], all_ips: set[str]) -> Metrics:
    tp = len(flagged_ips & true_ips)
    fp = len(flagged_ips - true_ips)
    fn = len(true_ips - flagged_ips)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return Metrics(precision, recall, f1, tp, fp, fn)


def evaluate_rules(
    entries: list[LogEntry], lines: list[LabeledLine]
) -> dict[str, Metrics]:
    """Precision/recall/F1 for the rule-based detectors, per attack type."""
    alerts = run_all_rules(entries)
    all_ips = {e.ip for e in entries}

    results = {}
    for label, rule_name in [
        ("brute_force", "brute_force"),
        ("scan", "scan"),
        ("sqli", "sqli"),
    ]:
        flagged = {a.ip for a in alerts if a.rule == rule_name}
        true_ips = _ips_with_label(lines, label)
        results[label] = _compute_metrics(flagged, true_ips, all_ips)
    return results


def evaluate_ml(
    entries: list[LogEntry], lines: list[LabeledLine], contamination: float = 0.1
) -> Metrics:
    """Precision/recall/F1 for the ML detector against *any* attack (ML has
    no notion of attack type, only normal vs anomalous)."""
    features = extract_features(entries)
    model = train_model(features, contamination=contamination)
    ml_alerts = score_windows(model, features)

    flagged_ips = {a.ip for a in ml_alerts}
    true_ips = {ll.ip for ll in lines if ll.label != "normal"}
    all_ips = {e.ip for e in entries}

    return _compute_metrics(flagged_ips, true_ips, all_ips)


def evaluate_hybrid(
    entries: list[LogEntry], lines: list[LabeledLine], contamination: float = 0.1
) -> Metrics:
    """Precision/recall/F1 when an IP is flagged if EITHER rules OR ML flag it."""
    rule_alerts = run_all_rules(entries)
    rule_ips = {a.ip for a in rule_alerts}

    features = extract_features(entries)
    model = train_model(features, contamination=contamination)
    ml_alerts = score_windows(model, features)
    ml_ips = {a.ip for a in ml_alerts}

    flagged_ips = rule_ips | ml_ips
    true_ips = {ll.ip for ll in lines if ll.label != "normal"}
    all_ips = {e.ip for e in entries}

    return _compute_metrics(flagged_ips, true_ips, all_ips)


def run_full_evaluation(
    lines: list[LabeledLine],
) -> dict[str, dict[str, Metrics] | Metrics]:
    """Run rules, ML, and hybrid evaluation on the same dataset and return
    all results together, for a side-by-side comparison."""
    from logsentinel.generator import to_log_text

    entries, _ = parse_lines(to_log_text(lines).splitlines())

    return {
        "rules": evaluate_rules(entries, lines),
        "ml": evaluate_ml(entries, lines),
        "hybrid": evaluate_hybrid(entries, lines),
    }
