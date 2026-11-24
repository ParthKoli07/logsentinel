"""Feature extraction: turn raw log entries into per-IP, per-window numeric features."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from logsentinel.parser import LogEntry


@dataclass
class WindowFeatures:
    ip: str
    window_start: datetime
    request_count: int
    error_ratio: float
    unique_paths: int
    user_agent_entropy: float
    avg_size: float

    def as_dict(self) -> dict[str, float | int | str]:
        return {
            "ip": self.ip,
            "window_start": self.window_start.isoformat(),
            "request_count": self.request_count,
            "error_ratio": self.error_ratio,
            "unique_paths": self.unique_paths,
            "user_agent_entropy": self.user_agent_entropy,
            "avg_size": self.avg_size,
        }


def _window_start(ts: datetime, window_seconds: int) -> datetime:
    epoch_seconds = int(ts.timestamp())
    bucket_start = epoch_seconds - (epoch_seconds % window_seconds)
    return datetime.fromtimestamp(bucket_start, tz=ts.tzinfo)


def _entropy(values: list[str]) -> float:
    """Shannon entropy of a list of strings. 0 if all identical, higher if varied."""
    if not values:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for v in values:
        counts[v] += 1
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


@dataclass
class _Bucket:
    entries: list[LogEntry] = field(default_factory=list)


def extract_features(entries: list[LogEntry], window_seconds: int = 60) -> list[WindowFeatures]:
    """Group entries by (ip, time window) and compute features for each group."""
    buckets: dict[tuple[str, datetime], _Bucket] = defaultdict(_Bucket)

    for e in entries:
        key = (e.ip, _window_start(e.timestamp, window_seconds))
        buckets[key].entries.append(e)

    results = []
    for (ip, window_start), bucket in buckets.items():
        group = bucket.entries
        total = len(group)
        error_count = sum(1 for e in group if e.status >= 400)
        unique_paths = len({e.path for e in group if e.path})
        agents = [e.user_agent for e in group if e.user_agent]
        avg_size = sum(e.size for e in group) / total if total else 0.0

        results.append(
            WindowFeatures(
                ip=ip,
                window_start=window_start,
                request_count=total,
                error_ratio=error_count / total if total else 0.0,
                unique_paths=unique_paths,
                user_agent_entropy=_entropy(agents),
                avg_size=avg_size,
            )
        )

    results.sort(key=lambda f: (f.window_start, f.ip))
    return results
