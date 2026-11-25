from logsentinel.evaluation import (
    evaluate_hybrid,
    evaluate_ml,
    evaluate_rules,
    evaluate_rules_combined,
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


def test_baseline_seed_cannot_collide_with_a_plain_int_test_seed():
    """Even if a test fixture happens to use the exact same integer (1000)
    as the baseline's default seed, the baseline's composite-keyed RNG must
    produce DIFFERENT underlying traffic, not the same requests replayed
    with different timestamps."""
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_normal_traffic

    baseline_rng = random.Random("logsentinel-baseline-v1:1000")
    baseline_lines = generate_normal_traffic(
        50, datetime(2026, 1, 1, tzinfo=timezone.utc), baseline_rng
    )

    colliding_rng = random.Random(1000)  # a caller naively picking seed=1000
    test_lines = generate_normal_traffic(
        50, datetime(2026, 6, 1, tzinfo=timezone.utc), colliding_rng
    )

    # Compare the request line *content* ignoring the timestamp bracket,
    # since that's the part that would differ even in the leaky old scheme.
    def _strip_timestamp(line: str) -> str:
        return line.split("]", 1)[1] if "]" in line else line

    baseline_bodies = {_strip_timestamp(ll.line) for ll in baseline_lines}
    test_bodies = {_strip_timestamp(ll.line) for ll in test_lines}

    overlap = baseline_bodies & test_bodies
    assert len(overlap) < len(baseline_bodies) * 0.5, (
        "baseline traffic overlaps too heavily with a colliding plain-int "
        "seeded test fixture; composite seeding did not prevent reuse"
    )


def test_rules_combined_matches_or_exceeds_any_single_rule_type():
    entries, lines = _dataset()
    combined = evaluate_rules_combined(entries, lines)
    per_type = evaluate_rules(entries, lines)

    best_single_type_recall = max(m.recall for m in per_type.values())
    assert combined.recall >= best_single_type_recall


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
    assert set(results.keys()) == {
        "rules", "rules_combined", "ml", "hybrid", "parsed_lines", "malformed_lines"
    }
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
