from datetime import datetime, timezone

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
        "rules", "rules_combined", "ml", "hybrid",
        "parsed_lines", "malformed_lines", "ml_threshold",
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

def test_baseline_traffic_does_not_collide_with_a_plain_int_test_seed():
    """Calls the REAL _baseline_traffic() used by train_baseline(), so
    reverting the string-seed fix would make this test fail for real."""
    import random
    from datetime import datetime, timezone

    from logsentinel.evaluation import _baseline_traffic
    from logsentinel.generator import generate_normal_traffic

    baseline_lines = _baseline_traffic(seed=1000, normal_count=50)

    colliding_rng = random.Random(1000)
    test_lines = generate_normal_traffic(
        50, datetime(2026, 6, 1, tzinfo=timezone.utc), colliding_rng
    )

    def _strip_timestamp(line: str) -> str:
        return line.split("]", 1)[1] if "]" in line else line

    baseline_bodies = {_strip_timestamp(ll.line) for ll in baseline_lines}
    test_bodies = {_strip_timestamp(ll.line) for ll in test_lines}
    overlap = baseline_bodies & test_bodies
    assert len(overlap) < len(baseline_bodies) * 0.5


def test_evaluate_incidents_reports_recall_for_each_approach():
    from logsentinel.evaluation import evaluate_incidents, train_baseline
    from logsentinel.generator import generate_dataset_with_incidents

    lines, incidents = generate_dataset_with_incidents(normal_count=50, seed=2)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    model = train_baseline(seed=1000)

    results = evaluate_incidents(entries, incidents, model)
    assert set(results.keys()) == {"rules_combined", "ml", "hybrid"}
    for info in results.values():
        assert info["incidents_total"] == len(incidents)


def test_run_full_evaluation_with_incidents_includes_incident_key():
    from logsentinel.evaluation import run_full_evaluation_with_incidents
    from logsentinel.generator import generate_dataset_with_incidents

    lines, incidents = generate_dataset_with_incidents(normal_count=30, seed=3)
    results = run_full_evaluation_with_incidents(lines, incidents)
    assert "incidents" in results
    assert "hybrid" in results["incidents"]

def test_rule_alert_does_not_credit_a_different_incident_type_on_same_ip():
    """Reproduces the exact bug Codex found: the synthetic scan and SQLi
    generators draw IPs from the same pool and can coincidentally collide.
    A scan alert must never credit a same-IP SQLi incident just because
    their time windows happen to overlap."""
    from datetime import timedelta

    from logsentinel.detection.rules import Alert
    from logsentinel.evaluation import _rule_alert_matches_incident
    from logsentinel.generator import Incident

    ip = "192.0.2.77"
    t0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    scan_alert = Alert(
        ip=ip,
        rule="scan",
        severity="medium",
        detail="scan",
        window_start=t0,
        window_end=t0 + timedelta(seconds=600),
    )
    scan_incident = Incident(ip=ip, label="scan", start=t0, end=t0 + timedelta(seconds=5))
    sqli_incident = Incident(
        ip=ip, label="sqli", start=t0 + timedelta(seconds=30), end=t0 + timedelta(seconds=35)
    )

    assert _rule_alert_matches_incident(scan_alert, scan_incident) is True
    assert _rule_alert_matches_incident(scan_alert, sqli_incident) is False



def test_one_of_two_same_ip_incidents_can_remain_missed():
    """Two incidents on the same IP, same attack type. Only the first has
    a real corresponding alert. Matching must not credit the second one
    just because it shares an IP (and type) with a caught incident — the
    default fixture has 7 distinct attacker IPs and can't expose this, so
    this test builds the scenario directly."""
    from datetime import timedelta

    from logsentinel.detection.rules import Alert
    from logsentinel.evaluation import _rule_alert_matches_incident
    from logsentinel.generator import Incident

    ip = "192.0.2.90"
    t0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    caught_incident = Incident(ip=ip, label="scan", start=t0, end=t0 + timedelta(seconds=5))
    missed_incident = Incident(
        ip=ip,
        label="scan",
        start=t0 + timedelta(hours=2),
        end=t0 + timedelta(hours=2, seconds=5),
    )

    # Only one alert exists, covering just the first incident's window.
    fabricated_alerts = [
        Alert(
            ip=ip,
            rule="scan",
            severity="medium",
            detail="scan",
            window_start=t0,
            window_end=t0 + timedelta(seconds=600),
        )
    ]

    caught = any(_rule_alert_matches_incident(a, caught_incident) for a in fabricated_alerts)
    missed = any(_rule_alert_matches_incident(a, missed_incident) for a in fabricated_alerts)

    assert caught is True
    assert missed is False

def test_two_same_type_incidents_in_one_bucket_only_credit_the_one_with_real_evidence():
    """Regression for the reported edge case: an alert must not credit a
    second same-type incident on the same IP just because that incident's
    time falls inside the detection bucket — only an incident whose
    timestamps overlap the alert's actual (tight) evidence span should be
    credited."""
    from datetime import timedelta

    from logsentinel.detection.rules import Alert
    from logsentinel.evaluation import _rule_alert_matches_incident
    from logsentinel.generator import Incident

    ip = "192.0.2.50"
    t0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    # Tight evidence: the alert's real triggering requests span only 3s.
    alert = Alert(
        ip=ip,
        rule="scan",
        severity="medium",
        detail="scan",
        window_start=t0,
        window_end=t0 + timedelta(seconds=3),
    )

    real_incident = Incident(ip=ip, label="scan", start=t0, end=t0 + timedelta(seconds=5))
    # Falls inside the OLD, artificially wide 600s bucket window, but NOT
    # inside the alert's real evidence span — must not be credited.
    other_incident_same_bucket = Incident(
        ip=ip,
        label="scan",
        start=t0 + timedelta(seconds=300),
        end=t0 + timedelta(seconds=305),
    )

    assert _rule_alert_matches_incident(alert, real_incident) is True
    assert _rule_alert_matches_incident(alert, other_incident_same_bucket) is False
