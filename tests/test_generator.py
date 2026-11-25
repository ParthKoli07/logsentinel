from logsentinel.generator import (
    generate_brute_force,
    generate_dataset,
    generate_scan,
    generate_sqli,
    to_labels,
    to_log_text,
)
from logsentinel.parser import parse_lines


def test_dataset_is_deterministic_with_same_seed():
    a = generate_dataset(normal_count=20, seed=1)
    b = generate_dataset(normal_count=20, seed=1)
    assert [ll.line for ll in a] == [ll.line for ll in b]


def test_dataset_contains_all_label_types():
    lines = generate_dataset(normal_count=20, seed=1)
    labels = set(to_labels(lines))
    assert labels == {"normal", "brute_force", "scan", "sqli"}


def test_every_generated_line_is_parseable():
    lines = generate_dataset(normal_count=30, seed=7)
    text = to_log_text(lines)
    entries, malformed = parse_lines(text.splitlines())
    assert malformed == 0
    assert len(entries) == len(lines)


def test_brute_force_lines_share_one_ip():
    import random

    rng = random.Random(5)
    from datetime import datetime, timezone

    lines = generate_brute_force(datetime(2026, 1, 1, tzinfo=timezone.utc), rng, attempts=6)
    ips = {ll.ip for ll in lines}
    assert len(ips) == 1
    assert len(lines) == 6
    assert all(ll.label == "brute_force" for ll in lines)


def test_scan_hits_multiple_sensitive_paths():
    import random

    rng = random.Random(3)
    from datetime import datetime, timezone

    lines = generate_scan(datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    paths = [ll.line for ll in lines]
    assert any("/admin" in p for p in paths)
    assert any(".env" in p for p in paths)


def test_sqli_lines_contain_injection_pattern():
    import random

    rng = random.Random(9)
    from datetime import datetime, timezone

    lines = generate_sqli(datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    assert all("sqli" == ll.label for ll in lines)
    assert any("UNION" in ll.line or "OR 1=1" in ll.line or "DROP" in ll.line for ll in lines)

def test_dataset_with_incidents_returns_valid_time_spans():
    from logsentinel.generator import generate_dataset_with_incidents

    lines, incidents = generate_dataset_with_incidents(normal_count=30, seed=1)
    assert len(incidents) == 7  # 2 brute_force + 2 scan + 2 sqli + 1 mixed-activity scan
    for inc in incidents:
        assert inc.start < inc.end


def test_benign_login_failures_are_labeled_normal():
    import random
    from datetime import datetime, timezone

    from logsentinel.generator import generate_benign_login_failures

    rng = random.Random(1)
    lines = generate_benign_login_failures(datetime(2026, 1, 1, tzinfo=timezone.utc), rng)
    assert all(ll.label == "normal" for ll in lines)
    assert len(lines) == 2


def test_mixed_activity_ip_appears_in_both_normal_and_attack_lines():
    from logsentinel.generator import generate_dataset_with_incidents

    lines, incidents = generate_dataset_with_incidents(normal_count=30, seed=1)
    scan_incident_ips = {inc.ip for inc in incidents if inc.label == "scan"}
    # At least one scan IP should also have a "normal" line (the mixed case).
    assert any(
        any(ll.ip == ip and ll.label == "normal" for ll in lines) for ip in scan_incident_ips
    )
