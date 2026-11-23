"""Rule-based detectors for brute force, scanning, and injection attempts."""

from __future__ import annotations

import urllib.parse
from collections import defaultdict
from dataclasses import dataclass

from logsentinel.parser import LogEntry

_SENSITIVE_PATHS = {
    "/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin", "/config.php"
}
_SQLI_MARKERS = ("union select", "or 1=1", "drop table", "--", "' or '")


@dataclass(frozen=True)
class Alert:
    ip: str
    rule: str
    severity: str  # "low", "medium", "high"
    detail: str


def detect_brute_force(entries: list[LogEntry], threshold: int = 5) -> list[Alert]:
    """Flag IPs with >= threshold failed logins (401) to the same auth-like path."""
    failures: dict[str, int] = defaultdict(int)
    for e in entries:
        if e.status == 401 and e.path and "login" in e.path.lower():
            failures[e.ip] += 1

    return [
        Alert(
            ip=ip,
            rule="brute_force",
            severity="high",
            detail=f"{count} failed login attempts",
        )
        for ip, count in failures.items()
        if count >= threshold
    ]


def detect_scanning(entries: list[LogEntry], threshold: int = 3) -> list[Alert]:
    """Flag IPs that hit several distinct sensitive/reconnaissance paths."""
    hits: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        if e.path and e.path in _SENSITIVE_PATHS:
            hits[e.ip].add(e.path)

    return [
        Alert(
            ip=ip,
            rule="scan",
            severity="medium",
            detail=f"probed {len(paths)} sensitive paths: {', '.join(sorted(paths))}",
        )
        for ip, paths in hits.items()
        if len(paths) >= threshold
    ]


def detect_sqli(entries: list[LogEntry]) -> list[Alert]:
    """Flag requests whose path contains a known SQL-injection signature."""
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
