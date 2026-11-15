"""Role resolution. Temporary email-based mapping; moves to the database later."""

from __future__ import annotations

from typing import Iterable

ROLES = ("viewer", "analyst", "admin")

_PERMISSIONS = {
    "viewer": {"view_dashboard"},
    "analyst": {"view_dashboard", "triage_alerts", "upload_logs"},
    "admin": {"view_dashboard", "triage_alerts", "upload_logs", "manage_rules", "manage_users"},
}


def get_role(
    email: str | None,
    admins: Iterable[str] = (),
    analysts: Iterable[str] = (),
) -> str:
    """Return the role for an email. Unknown or missing emails get 'viewer'."""
    if not email:
        return "viewer"
    normalized = email.strip().lower()
    if normalized in {a.strip().lower() for a in admins}:
        return "admin"
    if normalized in {a.strip().lower() for a in analysts}:
        return "analyst"
    return "viewer"


def can(role: str, action: str) -> bool:
    """Return True if the role is allowed to perform the action."""
    return action in _PERMISSIONS.get(role, set())
