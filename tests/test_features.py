from datetime import datetime, timezone

from logsentinel.detection.features import extract_features
from logsentinel.generator import generate_dataset, to_log_text
from logsentinel.parser import LogEntry, parse_lines


def _entry(ip, ts, status=200, path="/", agent="Mozilla/5.0", size=500):
    return LogEntry(
        ip=ip,
        user=None,
        timestamp=ts,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status=status,
        size=size,
        referrer=None,
        user_agent=agent,
    )


def test_single_ip_single_window_groups_correctly():
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    entries = [_entry("1.1.1.1", base), _entry("1.1.1.1", base.replace(second=30))]
    features = extract_features(entries, window_seconds=60)
    assert len(features) == 1
    assert features[0].request_count == 2
    assert features[0].ip == "1.1.1.1"


def test_different_ips_produce_separate_buckets():
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    entries = [_entry("1.1.1.1", base), _entry("2.2.2.2", base)]
    features = extract_features(entries, window_seconds=60)
    assert len(features) == 2
    assert {f.ip for f in features} == {"1.1.1.1", "2.2.2.2"}


def test_entries_outside_window_split_into_separate_buckets():
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    later = base.replace(minute=5)
    entries = [_entry("1.1.1.1", base), _entry("1.1.1.1", later)]
    features = extract_features(entries, window_seconds=60)
    assert len(features) == 2


def test_error_ratio_computed_correctly():
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    entries = [
        _entry("1.1.1.1", base, status=200),
        _entry("1.1.1.1", base, status=401),
        _entry("1.1.1.1", base, status=401),
        _entry("1.1.1.1", base, status=401),
    ]
    features = extract_features(entries, window_seconds=60)
    assert features[0].error_ratio == 0.75


def test_identical_user_agents_have_zero_entropy():
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    entries = [_entry("1.1.1.1", base, agent="same") for _ in range(5)]
    features = extract_features(entries, window_seconds=60)
    assert features[0].user_agent_entropy == 0.0


def test_brute_force_window_has_high_error_ratio_and_low_unique_paths():
    """Sanity check against real generated data: a brute-force burst should
    look very different from normal browsing in feature space."""
    lines = generate_dataset(normal_count=30, seed=3)
    entries, _ = parse_lines(to_log_text(lines).splitlines())
    features = extract_features(entries, window_seconds=60)

    brute_force_like = [f for f in features if f.error_ratio > 0.5 and f.unique_paths == 1]
    assert len(brute_force_like) >= 1
