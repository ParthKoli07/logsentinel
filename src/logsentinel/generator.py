"""Synthetic access-log generator with ground-truth attack labels.

Produces realistic-looking combined-log-format lines mixed with labeled
attack patterns, for testing detectors and measuring precision/recall.
"""

from __future__ import annotations

import random
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

@dataclass(frozen=True)
class Incident:
    """A single ground-truth attack event with an explicit time span, so
    evaluation can check whether THIS incident was caught, not just
    whether the attacker's IP was ever flagged anywhere in the batch."""
    ip: str
    label: str
    start: datetime
    end: datetime

_NORMAL_PATHS = ["/", "/about", "/products", "/contact", "/blog", "/products/42"]
_NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]
_SCAN_PATHS = ["/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin", "/config.php"]
_SQLI_SUFFIXES = ["' OR 1=1--", "' UNION SELECT NULL--", "'; DROP TABLE users;--"]
_SCANNER_AGENTS = ["Nmap Scripting Engine", "sqlmap/1.7", "python-requests/2.31", "curl/8.4"]


@dataclass(frozen=True)
class LabeledLine:
    line: str
    label: str  # "normal", "brute_force", "scan", "sqli"
    ip: str


def _timestamp(base: datetime, offset_seconds: int) -> str:
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%d/%b/%Y:%H:%M:%S %z")


def _format_line(
    ip: str, ts: str, method: str, path: str, status: int, size: int, agent: str) -> str:
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def _random_ip(rng: random.Random, pool_prefix: str) -> str:
    return f"{pool_prefix}.{rng.randint(1, 254)}"


def generate_normal_traffic(
    count: int, base_time: datetime, rng: random.Random, fixed_ip: str | None = None
) -> list[LabeledLine]:
    lines = []
    for i in range(count):
        ip = fixed_ip or _random_ip(rng, "203.0.113")
        ts = _timestamp(base_time, i * rng.randint(1, 20))
        path = rng.choice(_NORMAL_PATHS)
        agent = rng.choice(_NORMAL_AGENTS)
        status = rng.choices([200, 200, 200, 304, 404], weights=[70, 10, 10, 5, 5])[0]
        size = rng.randint(200, 8000)
        line = _format_line(ip, ts, "GET", path, status, size, agent)
        lines.append(LabeledLine(line, "normal", ip))
    return lines


def generate_brute_force(
    base_time: datetime, rng: random.Random, attempts: int = 8
) -> list[LabeledLine]:
    ip = _random_ip(rng, "198.51.100")
    agent = "python-requests/2.31"
    lines = []
    for i in range(attempts):
        ts = _timestamp(base_time, i)  # rapid-fire: 1 second apart
        line = _format_line(ip, ts, "POST", "/login", 401, 128, agent)
        lines.append(LabeledLine(line, "brute_force", ip))
    return lines


def generate_scan(base_time: datetime, rng: random.Random) -> list[LabeledLine]:
    ip = _random_ip(rng, "192.0.2")
    agent = rng.choice(_SCANNER_AGENTS)
    lines = []
    for i, path in enumerate(_SCAN_PATHS):
        ts = _timestamp(base_time, i)
        line = _format_line(ip, ts, "GET", path, 404, 196, agent)
        lines.append(LabeledLine(line, "scan", ip))
    return lines


def generate_sqli(base_time: datetime, rng: random.Random) -> list[LabeledLine]:
    ip = _random_ip(rng, "192.0.2")
    agent = "sqlmap/1.7"
    lines = []
    for i, suffix in enumerate(_SQLI_SUFFIXES):
        ts = _timestamp(base_time, i)
        encoded_suffix = urllib.parse.quote(suffix, safe="")
        path = f"/products?id=1{encoded_suffix}"
        line = _format_line(ip, ts, "GET", path, 500, 512, agent)
        lines.append(LabeledLine(line, "sqli", ip))
    return lines


def generate_dataset(
    normal_count: int = 200,
    seed: int = 42,
    start_time: datetime | None = None,
) -> list[LabeledLine]:
    """Build a full labeled dataset: normal traffic plus one of each attack type,
    shuffled by time so a detector sees them interleaved, as in a real log."""
    rng = random.Random(seed)
    base_time = start_time or datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)

    all_lines: list[LabeledLine] = []
    all_lines += generate_normal_traffic(normal_count, base_time, rng)
    all_lines += generate_brute_force(base_time + timedelta(minutes=5), rng)
    all_lines += generate_scan(base_time + timedelta(minutes=10), rng)
    all_lines += generate_sqli(base_time + timedelta(minutes=15), rng)

    # Sort by the embedded timestamp so attacks are interleaved realistically.
    all_lines.sort(key=lambda ll: ll.line.split("[")[1].split("]")[0])
    return all_lines


def to_log_text(lines: list[LabeledLine]) -> str:
    return "\n".join(ll.line for ll in lines) + "\n"


def to_labels(lines: list[LabeledLine]) -> list[str]:
    return [ll.label for ll in lines]

def generate_benign_login_failures(
    base_time: datetime, rng: random.Random, attempts: int = 2
) -> list[LabeledLine]:
    """A user mistyping their password a couple of times. Below any
    sane brute-force threshold — a correct detector must NOT flag this."""
    ip = _random_ip(rng, "203.0.113")
    agent = rng.choice(_NORMAL_AGENTS)
    lines = []
    for i in range(attempts):
        ts = _timestamp(base_time, i * 10)
        line = _format_line(ip, ts, "POST", "/login", 401, 128, agent)
        lines.append(LabeledLine(line, "normal", ip))
    return lines


def generate_benign_traffic_burst(
    base_time: datetime, rng: random.Random, count: int = 30
) -> list[LabeledLine]:
    """A legitimate spike in traffic (e.g. a page going viral), not an
    attack. Tests whether rate-based detection over-triggers on volume
    alone rather than on the actual attack signature."""
    ip = _random_ip(rng, "203.0.113")
    agent = rng.choice(_NORMAL_AGENTS)
    lines = []
    for i in range(count):
        ts = _timestamp(base_time, i)
        path = rng.choice(_NORMAL_PATHS)
        line = _format_line(ip, ts, "GET", path, 200, rng.randint(500, 5000), agent)
        lines.append(LabeledLine(line, "normal", ip))
    return lines


def _parse_embedded_timestamp(line: str) -> datetime:
    raw = line.split("[", 1)[1].split("]", 1)[0]
    return datetime.strptime(raw, _TIME_FORMAT)


def _incident_from_lines(lines: list[LabeledLine], label: str) -> Incident:
    ip = lines[0].ip
    timestamps = [_parse_embedded_timestamp(ll.line) for ll in lines]
    return Incident(
        ip=ip, label=label, start=min(timestamps), end=max(timestamps) + timedelta(seconds=5)
    )


def generate_dataset_with_incidents(
    normal_count: int = 200,
    seed: int = 42,
    start_time: datetime | None = None,
) -> tuple[list[LabeledLine], list[Incident]]:
    """Like generate_dataset, but with multiple incidents per attack type,
    benign noise that resembles attacks but shouldn't be flagged, and one
    IP with both legitimate and malicious activity. Returns the full line
    list plus Incident ground-truth records with explicit time spans."""
    rng = random.Random(seed)
    base_time = start_time or datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)

    all_lines: list[LabeledLine] = []
    incidents: list[Incident] = []

    all_lines += generate_normal_traffic(normal_count, base_time, rng)

    for i in range(2):
        start = base_time + timedelta(minutes=5 + i * 20)
        bf_lines = generate_brute_force(start, rng, attempts=8)
        all_lines += bf_lines
        incidents.append(_incident_from_lines(bf_lines, "brute_force"))

    for i in range(2):
        start = base_time + timedelta(minutes=10 + i * 20)
        scan_lines = generate_scan(start, rng)
        all_lines += scan_lines
        incidents.append(_incident_from_lines(scan_lines, "scan"))

    for i in range(2):
        start = base_time + timedelta(minutes=15 + i * 20)
        sqli_lines = generate_sqli(start, rng)
        all_lines += sqli_lines
        incidents.append(_incident_from_lines(sqli_lines, "sqli"))

    all_lines += generate_benign_login_failures(base_time + timedelta(minutes=50), rng)
    all_lines += generate_benign_traffic_burst(base_time + timedelta(minutes=55), rng)

    mixed_scan = generate_scan(base_time + timedelta(minutes=60), rng)
    mixed_ip = mixed_scan[0].ip
    all_lines += generate_normal_traffic(
        10, base_time + timedelta(minutes=58), rng, fixed_ip=mixed_ip
    )
    all_lines += mixed_scan
    incidents.append(_incident_from_lines(mixed_scan, "scan"))

    all_lines.sort(key=lambda ll: ll.line.split("[")[1].split("]")[0])
    return all_lines, incidents
