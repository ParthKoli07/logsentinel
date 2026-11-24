from datetime import datetime, timezone

from logsentinel.detection.features import WindowFeatures
from logsentinel.detection.ml import score_windows, train_model


def _window(ip, request_count, error_ratio, unique_paths, entropy=0.5, avg_size=500.0):
    return WindowFeatures(
        ip=ip,
        window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        request_count=request_count,
        error_ratio=error_ratio,
        unique_paths=unique_paths,
        user_agent_entropy=entropy,
        avg_size=avg_size,
    )


def _normal_windows(count=50):
    return [_window(f"10.0.0.{i % 20}", 5, 0.05, 3) for i in range(count)]


def test_model_trains_without_error_on_normal_data():
    windows = _normal_windows()
    model = train_model(windows, contamination=0.1)
    assert model is not None


def test_obvious_anomaly_is_flagged_among_normal_data():
    windows = _normal_windows(50)
    anomaly = _window("198.51.100.7", request_count=200, error_ratio=0.95, unique_paths=1)
    all_windows = windows + [anomaly]

    model = train_model(all_windows, contamination=0.1)
    alerts = score_windows(model, all_windows)

    assert any(a.ip == "198.51.100.7" for a in alerts)


def test_score_windows_returns_empty_for_empty_input():
    windows = _normal_windows()
    model = train_model(windows)
    assert score_windows(model, []) == []


def test_alerts_sorted_by_most_anomalous_first():
    windows = _normal_windows(50)
    mild_anomaly = _window("1.1.1.1", 50, 0.3, 2)
    extreme_anomaly = _window("2.2.2.2", 500, 0.99, 1)
    all_windows = windows + [mild_anomaly, extreme_anomaly]

    model = train_model(all_windows, contamination=0.1)
    alerts = score_windows(model, all_windows)

    assert len(alerts) >= 1
    # Most anomalous (lowest score) should come first.
    scores = [a.anomaly_score for a in alerts]
    assert scores == sorted(scores)
