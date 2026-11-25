"""Persisting and retrieving detection alerts via Supabase."""

from __future__ import annotations

from typing import Any

from logsentinel.detection.rules import Alert

_VALID_STATUSES = ("open", "investigating", "resolved")


def save_alerts(
    client: Any,
    batch_id: str,
    alerts: list[Alert],
    created_by: str,
) -> int:
    """Insert a list of rule-based alerts tied to a log batch. Returns the
    number of alerts inserted."""
    if not alerts:
        return 0

    rows = [
        {
            "batch_id": batch_id,
            "ip": a.ip,
            "rule": a.rule,
            "severity": a.severity,
            "detail": a.detail,
            "created_by": created_by,
        }
        for a in alerts
    ]
    client.table("alerts").insert(rows).execute()
    return len(rows)


def list_alerts(client: Any, status: str | None = None) -> list[dict]:
    """Fetch alerts, newest first. Optionally filter by status."""
    query = client.table("alerts").select("*").order("created_at", desc=True)
    if status:
        query = query.eq("status", status)
    result = query.execute()
    return result.data


def update_alert_status(client: Any, alert_id: str, new_status: str) -> None:
    """Move an alert through open -> investigating -> resolved."""
    if new_status not in _VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status!r}, must be one of {_VALID_STATUSES}")
    client.table("alerts").update({"status": new_status}).eq("id", alert_id).execute()
