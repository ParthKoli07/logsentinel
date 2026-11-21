"""Persisting parsed log entries to Supabase."""

from __future__ import annotations

from typing import Any

from logsentinel.parser import LogEntry


def save_batch(
    client: Any,
    uploaded_by: str,
    filename: str,
    entries: list[LogEntry],
    malformed_lines: int,
) -> str:
    """Insert a log batch and its entries. Returns the new batch id."""
    batch_result = (
        client.table("log_batches")
        .insert(
            {
                "uploaded_by": uploaded_by,
                "filename": filename,
                "total_lines": len(entries),
                "malformed_lines": malformed_lines,
            }
        )
        .execute()
    )
    batch_id = batch_result.data[0]["id"]

    if entries:
        rows = [
            {
                "batch_id": batch_id,
                "ip": e.ip,
                "ts": e.timestamp.isoformat(),
                "method": e.method,
                "path": e.path,
                "status": e.status,
                "size": e.size,
                "user_agent": e.user_agent,
            }
            for e in entries
        ]
        client.table("log_entries").insert(rows).execute()

    return batch_id
