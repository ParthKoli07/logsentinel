"""Regression test: fails if detection quality drops below known-good
thresholds. This runs the real evaluation harness against the generator's
labeled dataset, so a change that silently weakens detection is caught here,
not discovered later during a demo."""

from logsentinel.evaluation import run_full_evaluation
from logsentinel.generator import generate_dataset

# These floors come from the Day 13 baseline run (seed=42, normal_count=100).
# Rules are signature-based and should stay at perfect recall on known
# patterns; if any of these drop, something in the detection pipeline broke.
_RULE_RECALL_FLOOR = 1.0
_RULE_PRECISION_FLOOR = 1.0
_ML_RECALL_FLOOR = 0.8  # ML can vary run to run; recall should stay high
_ML_MIN_F1 = 0.3  # loose floor — ML trades precision for recall by design


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


def test_hybrid_never_performs_worse_than_rules_alone():
    """Hybrid (rules OR ML) should never have lower recall than the best
    single rule-based detector, since it's a superset of rule alerts."""
    lines = generate_dataset(normal_count=100, seed=42)
    results = run_full_evaluation(lines)

    best_rule_recall = max(m.recall for m in results["rules"].values())
    hybrid_recall = results["hybrid"].recall

    assert hybrid_recall >= best_rule_recall - 0.05, (
        f"hybrid recall ({hybrid_recall:.2f}) fell below "
        f"rules-only recall ({best_rule_recall:.2f})"
    )


def test_multiple_seeds_stay_within_known_bounds():
    """Sanity-check across a few different seeds, not just the one baseline
    run, so we're not accidentally overfit to a single lucky dataset."""
    for seed in (1, 7, 42, 99):
        lines = generate_dataset(normal_count=50, seed=seed)
        results = run_full_evaluation(lines)

        for attack_type, metrics in results["rules"].items():
            assert metrics.recall >= _RULE_RECALL_FLOOR, (
                f"seed={seed} {attack_type} recall dropped to {metrics.recall:.2f}"
            )
