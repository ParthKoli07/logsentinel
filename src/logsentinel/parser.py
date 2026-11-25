"""Parser for Apache/Nginx Combined Log Format lines."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

_LINE_RE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True)
class LogEntry:
    ip: str
    user: str | None
    timestamp: datetime
    method: str | None
    path: str | None
    protocol: str | None
    status: int
    size: int
    referrer: str | None
    user_agent: str | None


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def parse_line(line: str) -> LogEntry | None:
    """Parse one log line. Returns None if the line is malformed."""
    match = _LINE_RE.match(line.strip())
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match["time"], _TIME_FORMAT)
    except ValueError:
        return None

    parts = match["request"].split(" ")
    method = path = protocol = None
    if len(parts) >= 2:
        method, path = parts[0], parts[1]
        protocol = parts[2] if len(parts) > 2 else None

    try:
        size = 0 if match["size"] == "-" else int(match["size"])
        status = int(match["status"])
    except ValueError:
        return None

    return LogEntry(
        ip=match["ip"],
        user=_dash_to_none(match["user"]),
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        size=size,
        referrer=_dash_to_none(match["referrer"]),
        user_agent=_dash_to_none(match["agent"]),
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[LogEntry], int]:
    """Parse many lines. Returns (entries, number_of_malformed_lines)."""
    entries: list[LogEntry] = []
    malformed = 0
    for line in lines:
        if not line.strip():
            continue
        entry = parse_line(line)
        if entry is None:
            malformed += 1
        else:
            entries.append(entry)
    return entries, malformed


def iter_entries(lines: Iterable[str]) -> Iterator[LogEntry]:
    """Yield only the valid entries, silently skipping malformed lines."""
    for line in lines:
        entry = parse_line(line)
        if entry is not None:
            yield entry
