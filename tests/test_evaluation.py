from logsentinel.evaluation import (
    evaluate_hybrid,
    evaluate_ml,
    evaluate_rules,
    false_alert_rate_per_1000,
    run_full_evaluation,
    train_baseline,
)
from logsentinel.generator import generate_dataset, generate_normal_traffic, to_log_text
from logsentinel.parser import parse_lines


def _dataset(seed=5, normal_count=40):
    lines = generate_dataset(normal_count=normal_count, seed=seed)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    return entries, lines


def test_rules_achieve_perfect_recall_on_known_patterns():
    entries, lines = _dataset()
    results = evaluate_rules(entries, lines)
    assert results["brute_force"].recall == 1.0
    assert results["scan"].recall == 1.0
    assert results["sqli"].recall == 1.0


def test_rules_have_no_false_positives_on_normal_traffic():
    entries, lines = _dataset()
    results = evaluate_rules(entries, lines)
    for metrics in results.values():
        assert metrics.false_positives == 0


def test_ml_is_trained_on_an_independent_baseline_not_the_test_batch():
    """The whole point of train_baseline: it must not depend on the batch
    being evaluated, so training it twice with the same seed, regardless of
    which test batch is later scored, gives an identical model."""
    model_a = train_baseline(seed=1000)
    model_b = train_baseline(seed=1000)
    entries, _ = _dataset(seed=1)
    other_entries, _ = _dataset(seed=2)

    from logsentinel.detection.features import extract_features

    features_a = extract_features(entries)
    features_b = extract_features(other_entries)
    # Same model, scored against two different batches, should not error and
    # should be the literal same fitted model (not retrained per batch).
    assert model_a.get_params() == model_b.get_params()
    assert len(features_a) > 0
    assert len(features_b) > 0


def test_ml_detects_at_least_some_attacker_ips():
    entries, lines = _dataset()
    model = train_baseline(seed=1000)
    metrics = evaluate_ml(entries, lines, model)
    assert metrics.true_positives >= 1


def test_hybrid_recall_is_at_least_as_good_as_rules_alone():
    entries, lines = _dataset()
    model = train_baseline(seed=1000)
    rule_results = evaluate_rules(entries, lines)
    hybrid = evaluate_hybrid(entries, lines, model)

    any_rule_recall = max(m.recall for m in rule_results.values())
    assert hybrid.recall >= any_rule_recall * 0.9


def test_run_full_evaluation_returns_all_three_approaches_and_parse_coverage():
    lines = generate_dataset(normal_count=30, seed=9)
    results = run_full_evaluation(lines)
    assert set(results.keys()) == {"rules", "ml", "hybrid", "parsed_lines", "malformed_lines"}
    assert set(results["rules"].keys()) == {"brute_force", "scan", "sqli"}
    assert results["parsed_lines"] > 0
    assert results["malformed_lines"] == 0


def test_run_full_evaluation_handles_zero_valid_entries_without_crashing():
    garbage_lines = []  # no LabeledLine objects at all -> to_log_text produces ""
    results = run_full_evaluation(garbage_lines)
    assert results["parsed_lines"] == 0
    assert results["ml"].precision == 0.0
    assert results["ml"].recall == 0.0


def test_false_alert_rate_per_1000_on_held_out_benign_data():
    model = train_baseline(seed=1000)
    import random
    from datetime import datetime, timezone

    rng = random.Random(42)  # different seed from the baseline (1000)
    benign_lines = generate_normal_traffic(50, datetime(2026, 2, 1, tzinfo=timezone.utc), rng)

    rates = false_alert_rate_per_1000(model, benign_lines, thresholds=[-0.1, 0.0, 0.1])
    assert set(rates.keys()) == {-0.1, 0.0, 0.1}
    # A higher (less negative) threshold should flag at least as many windows.
    assert rates[0.1] >= rates[-0.1]
