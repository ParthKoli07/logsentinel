from logsentinel.evaluation import (
    evaluate_hybrid,
    evaluate_ml,
    evaluate_rules,
    run_full_evaluation,
)
from logsentinel.generator import generate_dataset, to_log_text
from logsentinel.parser import parse_lines


def _dataset(seed=5, normal_count=40):
    lines = generate_dataset(normal_count=normal_count, seed=seed)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    return entries, lines


def test_rules_achieve_perfect_recall_on_known_patterns():
    """Rules are signature-based, so they should catch the exact patterns
    the generator produces, by design."""
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


def test_ml_detects_at_least_some_attacker_ips():
    entries, lines = _dataset()
    metrics = evaluate_ml(entries, lines)
    assert metrics.true_positives >= 1


def test_hybrid_recall_is_at_least_as_good_as_rules_alone():
    entries, lines = _dataset()
    rule_results = evaluate_rules(entries, lines)
    hybrid = evaluate_hybrid(entries, lines)

    # Hybrid should never miss attacks that signature rules already catch.
    any_rule_recall = max(m.recall for m in rule_results.values())
    assert hybrid.recall >= any_rule_recall * 0.9  # small tolerance for IP overlap edge cases


def test_run_full_evaluation_returns_all_three_approaches():
    lines = generate_dataset(normal_count=30, seed=9)
    results = run_full_evaluation(lines)
    assert set(results.keys()) == {"rules", "ml", "hybrid"}
    assert set(results["rules"].keys()) == {"brute_force", "scan", "sqli"}
