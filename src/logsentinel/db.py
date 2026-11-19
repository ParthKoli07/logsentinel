"""Supabase client wiring. All DB access for the app goes through here."""

from __future__ import annotations

from typing import Any


def get_client(url: str, anon_key: str) -> Any:
    """Create a Supabase client. Import is local so this module stays optional
    for code paths (and tests) that don't need a real connection."""
    from supabase import create_client

    return create_client(url, anon_key)


def check_connection(client: Any) -> tuple[bool, str]:
    """Run a trivial query to verify the client can reach Supabase.

    Returns (ok, message). A missing table still counts as a successful
    connection, since it proves the URL and key are valid and auth passed.
    """
    try:
        client.table("_connection_check").select("*").limit(1).execute()
        return True, "Connected."
    except Exception as exc:
        text = str(exc)
        if "does not exist" in text or "PGRST" in text:
            return True, "Connected (no tables yet)."
        return False, text
