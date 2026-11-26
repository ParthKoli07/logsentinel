"""Reading and updating the single-row detection rule configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuleConfig:
    brute_force_threshold: int
    scan_threshold: int
    window_seconds: int


_DEFAULTS = RuleConfig(brute_force_threshold=5, scan_threshold=3, window_seconds=600)


def get_rule_config(client: Any) -> RuleConfig:
    """Fetch the current rule configuration. Falls back to defaults if the
    row is somehow missing, rather than crashing the app."""
    result = client.table("rule_config").select("*").eq("id", 1).execute()
    if not result.data:
        return _DEFAULTS
    row = result.data[0]
    return RuleConfig(
        brute_force_threshold=row["brute_force_threshold"],
        scan_threshold=row["scan_threshold"],
        window_seconds=row["window_seconds"],
    )


def update_rule_config(client: Any, config: RuleConfig, updated_by: str) -> None:
    """Persist a new rule configuration. Validates basic sanity before
    writing, since this directly controls detection sensitivity for
    everyone using the app."""
    if config.brute_force_threshold < 1:
        raise ValueError("brute_force_threshold must be at least 1")
    if config.scan_threshold < 1:
        raise ValueError("scan_threshold must be at least 1")
    if config.window_seconds < 10:
        raise ValueError("window_seconds must be at least 10")

    client.table("rule_config").update(
        {
            "brute_force_threshold": config.brute_force_threshold,
            "scan_threshold": config.scan_threshold,
            "window_seconds": config.window_seconds,
            "updated_by": updated_by,
        }
    ).eq("id", 1).execute()
