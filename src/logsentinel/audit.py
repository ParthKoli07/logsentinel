"""Append-only audit logging. Every meaningful action in the app writes
one row here: who did it, what it was, and when."""

from __future__ import annotations

from typing import Any

# Keep this list in sync with every call site that logs an action, so a
# typo in an action name doesn't silently create an unrecognized entry.
ACTIONS = (
    "upload_batch",
    "save_alerts",
    "update_alert_status",
    "update_rule_config",
)


def log_action(client: Any, actor: str, action: str, details: str = "") -> None:
    """Record one audit entry. Raises if the action isn't a known one,
    catching typos at the call site rather than silently logging garbage."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action!r}, must be one of {ACTIONS}")
    client.table("audit_log").insert(
        {"actor": actor, "action": action, "details": details}
    ).execute()


def list_audit_log(client: Any, limit: int = 100) -> list[dict]:
    """Fetch the most recent audit entries, newest first."""
    result = (
        client.table("audit_log")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data
