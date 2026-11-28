"""Email/password account creation and authentication.

Passwords are hashed with Argon2 (never stored in plaintext), following
OWASP's current recommendation over bcrypt/scrypt for new systems.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class Account:
    email: str
    role: str


def _validate_signup(email: str, password: str) -> None:
    if not _EMAIL_RE.match(email):
        raise ValueError("invalid email address")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")


def create_account(client: Any, email: str, password: str) -> Account:
    """Create a new account with a hashed password. Raises ValueError on
    invalid input or if the email is already registered."""
    email = email.strip().lower()
    _validate_signup(email, password)

    existing = client.table("users").select("id").eq("email", email).execute()
    if existing.data:
        raise ValueError("an account with this email already exists")

    password_hash = _hasher.hash(password)
    client.table("users").insert(
        {"email": email, "password_hash": password_hash, "role": "viewer"}
    ).execute()
    return Account(email=email, role="viewer")


def authenticate(client: Any, email: str, password: str) -> Account | None:
    """Verify credentials. Returns the Account on success, None on failure.
    Never raises for wrong credentials, only for unexpected errors, so
    callers can show a generic "invalid email or password" message without
    leaking which part was wrong."""
    email = email.strip().lower()
    result = client.table("users").select("*").eq("email", email).execute()
    if not result.data:
        return None

    row = result.data[0]
    try:
        _hasher.verify(row["password_hash"], password)
    except VerifyMismatchError:
        return None

    return Account(email=row["email"], role=row["role"])
