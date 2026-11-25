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
    """Flag (ip, window) pairs with >= threshold failed logins. Windowing
    means two brute-force bursts from the same IP, separated in time,
    produce two separate alerts rather than being merged into one."""
    buckets: dict[tuple[str, datetime], int] = defaultdict(int)
    for e in entries:
        if e.status == 401 and e.path and "login" in e.path.lower():
            key = (e.ip, _window_start(e.timestamp, window_seconds))
            buckets[key] += 1

    alerts = []
    for (ip, window_start), count in buckets.items():
        if count >= threshold:
            alerts.append(
                Alert(
                    ip=ip,
                    rule="brute_force",
                    severity="high",
                    detail=f"{count} failed login attempts",
                    window_start=window_start,
                    window_end=window_start + timedelta(seconds=window_seconds),
                )
            )
    return alerts


def detect_scanning(
    entries: list[LogEntry], threshold: int = 3, window_seconds: int = 600
) -> list[Alert]:
    hits: dict[tuple[str, datetime], set[str]] = defaultdict(set)
    for e in entries:
        if e.path and e.path in _SENSITIVE_PATHS:
            key = (e.ip, _window_start(e.timestamp, window_seconds))
            hits[key].add(e.path)

    alerts = []
    for (ip, window_start), paths in hits.items():
        if len(paths) >= threshold:
            alerts.append(
                Alert(
                    ip=ip,
                    rule="scan",
                    severity="medium",
                    detail=f"probed {len(paths)} sensitive paths: {', '.join(sorted(paths))}",
                    window_start=window_start,
                    window_end=window_start + timedelta(seconds=window_seconds),
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
