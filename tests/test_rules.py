from logsentinel.detection.rules import (
    detect_brute_force,
    detect_scanning,
    detect_sqli,
    run_all_rules,
)
from logsentinel.generator import generate_dataset, to_log_text
from logsentinel.parser import parse_lines


def _parsed_dataset(seed: int = 1, normal_count: int = 30):
    lines = generate_dataset(normal_count=normal_count, seed=seed)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    return entries


def test_brute_force_detected_on_generated_dataset():
    entries = _parsed_dataset()
    alerts = detect_brute_force(entries)
    assert any(a.rule == "brute_force" for a in alerts)


def test_scan_detected_on_generated_dataset():
    entries = _parsed_dataset()
    alerts = detect_scanning(entries)
    assert any(a.rule == "scan" for a in alerts)


def test_sqli_detected_on_generated_dataset():
    entries = _parsed_dataset()
    alerts = detect_sqli(entries)
    assert any(a.rule == "sqli" for a in alerts)


def test_normal_traffic_alone_triggers_nothing():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_normal_traffic

    rng = random.Random(1)
    lines = generate_normal_traffic(50, datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    assert run_all_rules(entries) == []


def test_run_all_rules_combines_every_detector():
    entries = _parsed_dataset()
    alerts = run_all_rules(entries)
    rules_seen = {a.rule for a in alerts}
    assert rules_seen == {"brute_force", "scan", "sqli"}


def test_brute_force_below_threshold_is_not_flagged():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_brute_force

    rng = random.Random(2)
    lines = generate_brute_force(datetime(2026, 1, 1, tzinfo=timezone.utc), rng, attempts=3)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    assert detect_brute_force(entries, threshold=5) == []


def test_two_separated_brute_force_bursts_from_same_ip_yield_two_alerts():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_brute_force

    rng = random.Random(3)
    ip_lines_1 = generate_brute_force(datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc), rng)
    # Force the same IP for the second burst by reusing its generated IP.
    ip = ip_lines_1[0].ip
    rng2 = random.Random(3)
    ip_lines_2 = generate_brute_force(datetime(2026, 1, 1, 9, 30, tzinfo=timezone.utc), rng2)

    all_lines = ip_lines_1 + ip_lines_2
    entries, _ = parse_lines(to_log_text(all_lines).splitlines())
    alerts = detect_brute_force(entries, window_seconds=600)

    same_ip_alerts = [a for a in alerts if a.ip == ip]
    assert len(same_ip_alerts) == 2


def test_benign_login_failures_do_not_trigger_brute_force():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_benign_login_failures

    rng = random.Random(5)
    lines = generate_benign_login_failures(datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    assert detect_brute_force(entries) == []


def test_benign_traffic_burst_does_not_trigger_any_rule():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_benign_traffic_burst

    rng = random.Random(6)
    lines = generate_benign_traffic_burst(datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    assert run_all_rules(entries) == []
