"""Isolation Forest anomaly detector trained on per-IP, per-window features."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from logsentinel.detection.features import WindowFeatures

_FEATURE_FIELDS = (
    "request_count",
    "error_ratio",
    "unique_paths",
    "user_agent_entropy",
    "avg_size",
)


@dataclass(frozen=True)
class MLAlert:
    ip: str
    window_start: str
    anomaly_score: float
    detail: str


def _to_matrix(features: list[WindowFeatures]) -> np.ndarray:
    return np.array([[getattr(f, name) for name in _FEATURE_FIELDS] for f in features])


def train_model(
    features: list[WindowFeatures], contamination: float | str = 0.1, seed: int = 42
) -> IsolationForest:
    if not features:
        raise ValueError("cannot train on zero feature windows")

    matrix = _to_matrix(features)
    model = IsolationForest(contamination=contamination, random_state=seed)
    model.fit(matrix)
    return model


def score_windows(model: IsolationForest, features: list[WindowFeatures]) -> list[MLAlert]:
    """Score each window and return alerts for the ones flagged as anomalous.

    IsolationForest.predict returns -1 for anomalies, 1 for normal points.
    decision_function returns a continuous score: lower means more anomalous.
    """
    if not features:
        return []

    matrix = _to_matrix(features)
    predictions = model.predict(matrix)
    scores = model.decision_function(matrix)

    alerts = []
    for feat, pred, score in zip(features, predictions, scores):
        if pred == -1:
            alerts.append(
                MLAlert(
                    ip=feat.ip,
                    window_start=feat.window_start.isoformat(),
                    anomaly_score=float(score),
                    detail=(
                        f"{feat.request_count} reqs, "
                        f"error_ratio={feat.error_ratio:.2f}, "
                        f"unique_paths={feat.unique_paths}"
                    ),
                )
            )
    alerts.sort(key=lambda a: a.anomaly_score)
    return alerts

def score_at_threshold(
    model: IsolationForest, features: list[WindowFeatures], threshold: float
) -> list[MLAlert]:
    """Score windows against an explicit decision_function threshold instead
    of the model's built-in contamination-based cutoff. Lower scores are more
    anomalous; a window is flagged when its score falls below `threshold`.
    Used to report false-alert rate at different operating points, rather
    than only the single cutoff `contamination` implies."""
    if not features:
        return []

    matrix = _to_matrix(features)
    scores = model.decision_function(matrix)

    alerts = []
    for feat, score in zip(features, scores):
        if score < threshold:
            alerts.append(
                MLAlert(
                    ip=feat.ip,
                    window_start=feat.window_start.isoformat(),
                    anomaly_score=float(score),
                    detail=(
                        f"{feat.request_count} reqs, "
                        f"error_ratio={feat.error_ratio:.2f}, "
                        f"unique_paths={feat.unique_paths}"
                    ),
                )
            )
    alerts.sort(key=lambda a: a.anomaly_score)
    return alerts
