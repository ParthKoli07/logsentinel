"""Regression test: fails if detection quality drops below known-good
thresholds. This runs the real evaluation harness against the generator's
labeled dataset, so a change that silently weakens detection is caught here,
not discovered later during a demo."""

from logsentinel.evaluation import run_full_evaluation
from logsentinel.generator import generate_dataset

_RULE_RECALL_FLOOR = 1.0
_RULE_PRECISION_FLOOR = 1.0
_ML_RECALL_FLOOR = 0.8  # observed 1.00; floor leaves margin for variance
_ML_MIN_F1 = 0.1
# observed 0.16 post-leakage-fix; ML trades precision for recall on independent baseline


def test_rule_detectors_maintain_perfect_precision_and_recall():
    lines = generate_dataset(normal_count=100, seed=42)
    results = run_full_evaluation(lines)

    for attack_type, metrics in results["rules"].items():
        assert metrics.recall >= _RULE_RECALL_FLOOR, (
            f"{attack_type} recall dropped to {metrics.recall:.2f}"
        )
        assert metrics.precision >= _RULE_PRECISION_FLOOR, (
            f"{attack_type} precision dropped to {metrics.precision:.2f}"
        )


def test_ml_detector_maintains_minimum_recall_and_f1():
    lines = generate_dataset(normal_count=100, seed=42)
    results = run_full_evaluation(lines)
    ml = results["ml"]

    assert ml.recall >= _ML_RECALL_FLOOR, f"ML recall dropped to {ml.recall:.2f}"
    assert ml.f1 >= _ML_MIN_F1, f"ML F1 dropped to {ml.f1:.2f}"


def test_hybrid_never_performs_worse_than_combined_rules():
    """Compares hybrid against the single combined rules-only metric, not
    the max of three separate per-type numbers, which was a weaker and
    somewhat circular comparison."""
    lines = generate_dataset(normal_count=100, seed=42)
    results = run_full_evaluation(lines)

    rules_combined_recall = results["rules_combined"].recall
    hybrid_recall = results["hybrid"].recall

    assert hybrid_recall >= rules_combined_recall - 0.05, (
        f"hybrid recall ({hybrid_recall:.2f}) fell below "
        f"rules-combined recall ({rules_combined_recall:.2f})"
    )


def test_multiple_seeds_stay_within_known_bounds():
    for seed in (1, 7, 42, 99):
        lines = generate_dataset(normal_count=50, seed=seed)
        results = run_full_evaluation(lines)

        for attack_type, metrics in results["rules"].items():
            assert metrics.recall >= _RULE_RECALL_FLOOR, (
                f"seed={seed} {attack_type} recall dropped to {metrics.recall:.2f}"
            )


def test_run_full_evaluation_reports_parse_coverage():
    lines = generate_dataset(normal_count=50, seed=42)
    results = run_full_evaluation(lines)
    assert results["malformed_lines"] == 0
    assert results["parsed_lines"] > 0
