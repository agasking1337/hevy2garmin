"""Tests for the account and encrypted-secret foundation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hevy2garmin import db
from hevy2garmin.accounts import (
    authenticate_user,
    create_session,
    create_user,
    decrypt_secret,
    encrypt_secret,
    generate_encryption_key,
    get_session_user,
    get_user_secret,
    revoke_session,
    set_user_secret,
)
from hevy2garmin.db_sqlite import SQLiteDatabase


@pytest.fixture(autouse=True)
def account_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("H2G_ENCRYPTION_KEY", generate_encryption_key())
    monkeypatch.setattr(db, "_instance", SQLiteDatabase(tmp_path / "accounts.db"))
    monkeypatch.delenv("DATABASE_URL", raising=False)


def test_user_password_and_session_lifecycle() -> None:
    user_id = create_user("Test@Example.com", "correct horse battery staple")

    assert authenticate_user("test@example.com", "wrong password") is None
    assert authenticate_user("TEST@example.com", "correct horse battery staple") == user_id

    token = create_session(user_id)
    assert get_session_user(token) == user_id
    revoke_session(token)
    assert get_session_user(token) is None


def test_integration_secret_is_encrypted_at_rest() -> None:
    user_id = create_user("test@example.com", "correct horse battery staple")
    set_user_secret(user_id, "hevy_api_key", "hevy-private-key")

    connection = db.get_db()._get_conn()
    stored = connection.execute("SELECT ciphertext FROM user_secrets").fetchone()[0]
    connection.close()

    assert stored != "hevy-private-key"
    assert decrypt_secret(stored) == "hevy-private-key"
    assert get_user_secret(user_id, "hevy_api_key") == "hevy-private-key"


def test_encrypt_secret_requires_valid_deployment_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H2G_ENCRYPTION_KEY", "not-a-key")
    with pytest.raises(Exception):
        encrypt_secret("value")
