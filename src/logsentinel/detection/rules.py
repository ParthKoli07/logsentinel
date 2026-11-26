"""Rule-based detectors for brute force, scanning, and injection attempts."""

from __future__ import annotations

import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from logsentinel.parser import LogEntry

_SENSITIVE_PATHS = {
    "/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin", "/config.php"
}
_SQLI_MARKERS = ("union select", "or 1=1", "drop table", "--", "' or '")


@dataclass(frozen=True)
class Alert:
    ip: str
    rule: str
    severity: str
    detail: str
    window_start: datetime | None = None
    window_end: datetime | None = None


def detect_brute_force(
    entries: list[LogEntry], threshold: int = 5, window_seconds: int = 600
) -> list[Alert]:
    """Flag (ip, window) pairs with >= threshold failed logins. The alert's
    window_start/window_end reflect the actual timestamps of the triggering
    requests, not the full detection bucket, so a same-type incident that
    merely falls inside the same wide bucket (without contributing any
    evidence) is not wrongly credited."""
    buckets: dict[tuple[str, datetime], list[datetime]] = defaultdict(list)
    for e in entries:
        if e.status == 401 and e.path and "login" in e.path.lower():
            key = (e.ip, _window_start(e.timestamp, window_seconds))
            buckets[key].append(e.timestamp)

    alerts = []
    for (ip, _bucket), timestamps in buckets.items():
        if len(timestamps) >= threshold:
            alerts.append(
                Alert(
                    ip=ip,
                    rule="brute_force",
                    severity="high",
                    detail=f"{len(timestamps)} failed login attempts",
                    window_start=min(timestamps),
                    window_end=max(timestamps) + timedelta(seconds=1),
                )
            )
    return alerts


def detect_scanning(
    entries: list[LogEntry], threshold: int = 3, window_seconds: int = 600
) -> list[Alert]:
    """Flag (ip, window) pairs that hit several distinct sensitive paths.
    Same evidence-window tightening as detect_brute_force above."""
    paths_by_key: dict[tuple[str, datetime], set[str]] = defaultdict(set)
    timestamps_by_key: dict[tuple[str, datetime], list[datetime]] = defaultdict(list)

    for e in entries:
        if e.path and e.path in _SENSITIVE_PATHS:
            key = (e.ip, _window_start(e.timestamp, window_seconds))
            paths_by_key[key].add(e.path)
            timestamps_by_key[key].append(e.timestamp)

    alerts = []
    for key, paths in paths_by_key.items():
        if len(paths) >= threshold:
            ip, _bucket = key
            timestamps = timestamps_by_key[key]
            alerts.append(
                Alert(
                    ip=ip,
                    rule="scan",
                    severity="medium",
                    detail=f"probed {len(paths)} sensitive paths: {', '.join(sorted(paths))}",
                    window_start=min(timestamps),
                    window_end=max(timestamps) + timedelta(seconds=1),
                )
            )
    return alerts


def detect_sqli(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    for e in entries:
        if not e.path:
            continue
        lowered = urllib.parse.unquote(e.path).lower()
        if any(marker in lowered for marker in _SQLI_MARKERS):
            alerts.append(
                Alert(
                    ip=e.ip,
                    rule="sqli",
                    severity="high",
                    detail=f"suspicious query string in path: {e.path}",
                    window_start=e.timestamp,
                    window_end=e.timestamp + timedelta(seconds=5),
                )
            )
    return alerts


def run_all_rules(entries: list[LogEntry]) -> list[Alert]:
    """Run every rule-based detector and combine the results."""
    alerts: list[Alert] = []
    alerts += detect_brute_force(entries)
    alerts += detect_scanning(entries)
    alerts += detect_sqli(entries)
    return alerts

def _window_start(ts: datetime, window_seconds: int) -> datetime:
    epoch_seconds = int(ts.timestamp())
    bucket_start = epoch_seconds - (epoch_seconds % window_seconds)
    return datetime.fromtimestamp(bucket_start, tz=ts.tzinfo)
