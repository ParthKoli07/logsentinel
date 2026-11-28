from unittest.mock import MagicMock

import pytest

from logsentinel.accounts import authenticate, create_account


def _client_with_no_existing_user():
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
    return client


def test_create_account_succeeds_with_valid_input():
    client = _client_with_no_existing_user()
    account = create_account(client, "New.User@Example.com", "a-real-password")
    assert account.email == "new.user@example.com"
    assert account.role == "viewer"


def test_create_account_rejects_invalid_email():
    client = _client_with_no_existing_user()
    with pytest.raises(ValueError):
        create_account(client, "not-an-email", "a-real-password")


def test_create_account_rejects_short_password():
    client = _client_with_no_existing_user()
    with pytest.raises(ValueError):
        create_account(client, "user@example.com", "short")


def test_create_account_rejects_duplicate_email():
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"id": "existing-id"}
    ]
    with pytest.raises(ValueError):
        create_account(client, "user@example.com", "a-real-password")


def test_authenticate_succeeds_with_correct_password():
    from argon2 import PasswordHasher

    real_hash = PasswordHasher().hash("correct-password")
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"email": "user@example.com", "password_hash": real_hash, "role": "analyst"}
    ]
    account = authenticate(client, "user@example.com", "correct-password")
    assert account is not None
    assert account.role == "analyst"


def test_authenticate_fails_with_wrong_password():
    from argon2 import PasswordHasher

    real_hash = PasswordHasher().hash("correct-password")
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"email": "user@example.com", "password_hash": real_hash, "role": "analyst"}
    ]
    account = authenticate(client, "user@example.com", "wrong-password")
    assert account is None


def test_authenticate_fails_for_unknown_email():
    client = _client_with_no_existing_user()
    account = authenticate(client, "nobody@example.com", "whatever")
    assert account is None
