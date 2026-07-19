"""Database-backed accounts and encrypted integration credentials.

This module is deliberately separate from the legacy shared-dashboard auth.
The account feature is activated only after all operational data has been
partitioned by user, preventing an incomplete migration from exposing data.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from nacl import exceptions, pwhash, secret, utils

from hevy2garmin import db

SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
KEY_ENVIRONMENT_VARIABLE = "H2G_ENCRYPTION_KEY"


class AccountConfigurationError(RuntimeError):
    """Raised when a required account-security setting is absent or invalid."""


def _encryption_key() -> bytes:
    """Load the 32-byte database encryption key from the environment."""
    encoded = os.environ.get(KEY_ENVIRONMENT_VARIABLE, "")
    try:
        key = base64.urlsafe_b64decode(encoded.encode())
    except Exception as error:
        raise AccountConfigurationError(
            f"{KEY_ENVIRONMENT_VARIABLE} must be a URL-safe base64-encoded 32-byte key"
        ) from error
    if len(key) != secret.SecretBox.KEY_SIZE:
        raise AccountConfigurationError(
            f"{KEY_ENVIRONMENT_VARIABLE} must decode to {secret.SecretBox.KEY_SIZE} bytes"
        )
    return key


def generate_encryption_key() -> str:
    """Generate a deployment secret suitable for ``H2G_ENCRYPTION_KEY``."""
    return base64.urlsafe_b64encode(utils.random(secret.SecretBox.KEY_SIZE)).decode()


def encrypt_secret(value: str) -> str:
    """Encrypt a credential with authenticated XSalsa20-Poly1305 encryption."""
    encrypted = secret.SecretBox(_encryption_key()).encrypt(value.encode())
    return base64.urlsafe_b64encode(bytes(encrypted)).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a credential stored by :func:`encrypt_secret`."""
    try:
        encrypted = base64.urlsafe_b64decode(ciphertext.encode())
        return secret.SecretBox(_encryption_key()).decrypt(encrypted).decode()
    except (ValueError, TypeError, exceptions.CryptoError, UnicodeDecodeError) as error:
        raise AccountConfigurationError("Stored credential could not be decrypted") from error


def hash_password(password: str) -> str:
    """Hash an account password with Argon2id using PyNaCl's safe defaults."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    return pwhash.argon2id.str(password.encode()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify an Argon2id password hash without exposing comparison timing."""
    try:
        return pwhash.argon2id.verify(password_hash.encode(), password.encode())
    except exceptions.InvalidkeyError:
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def _connection() -> Iterator[tuple[object, bool]]:
    """Yield a database connection and whether it speaks PostgreSQL SQL."""
    database = db.get_db()
    connection = database._get_conn()
    postgres = bool(db.get_database_url())
    try:
        yield connection, postgres
        connection.commit()
    finally:
        if not postgres:
            connection.close()


def _placeholder(postgres: bool) -> str:
    return "%s" if postgres else "?"


def create_user(email: str, password: str) -> str:
    """Create an account and return its stable UUID string."""
    normalized_email = email.strip().lower()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("Enter a valid email address")
    user_id = str(uuid.uuid4())
    password_hash = hash_password(password)
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        cursor = connection.cursor()
        try:
            cursor.execute(
                f"INSERT INTO users (id, email, password_hash) VALUES ({placeholder}, {placeholder}, {placeholder})",
                (user_id, normalized_email, password_hash),
            )
        except Exception as error:
            if "unique" in str(error).lower() or "duplicate" in str(error).lower():
                raise ValueError("An account already exists for this email") from error
            raise
    return user_id


def authenticate_user(email: str, password: str) -> str | None:
    """Return the account ID for valid credentials, otherwise ``None``."""
    normalized_email = email.strip().lower()
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        cursor = connection.cursor()
        cursor.execute(
            f"SELECT id, password_hash FROM users WHERE email = {placeholder}",
            (normalized_email,),
        )
        row = cursor.fetchone()
        if not row or not verify_password(password, row["password_hash"] if postgres else row[1]):
            return None
        user_id = str(row["id"] if postgres else row[0])
        timestamp = "NOW()" if postgres else "datetime('now')"
        cursor.execute(
            f"UPDATE users SET last_login_at = {timestamp} WHERE id = {placeholder}",
            (user_id,),
        )
        return user_id


def create_session(user_id: str) -> str:
    """Persist a random, revocable session token and return its raw value."""
    token = secrets.token_urlsafe(32)
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)
        cursor = connection.cursor()
        cursor.execute(
            f"INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES ({placeholder}, {placeholder}, {placeholder})",
            (_token_hash(token), user_id, expires_at if postgres else int(time.time()) + SESSION_TTL_SECONDS),
        )
    return token


def get_session_user(token: str | None) -> str | None:
    """Resolve a valid account session token to its account ID."""
    if not token:
        return None
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        cursor = connection.cursor()
        expiry_check = "expires_at > NOW()" if postgres else "expires_at > ?"
        parameters: tuple[object, ...] = (_token_hash(token),) if postgres else (_token_hash(token), int(time.time()))
        cursor.execute(
            f"SELECT user_id FROM user_sessions WHERE token_hash = {placeholder} AND {expiry_check}",
            parameters,
        )
        row = cursor.fetchone()
        return str(row["user_id"] if postgres else row[0]) if row else None


def revoke_session(token: str | None) -> None:
    """Invalidate a session token immediately."""
    if not token:
        return
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        connection.cursor().execute(
            f"DELETE FROM user_sessions WHERE token_hash = {placeholder}", (_token_hash(token),)
        )


def set_user_secret(user_id: str, name: str, value: str) -> None:
    """Encrypt and upsert one integration credential for an account."""
    if not value:
        return
    if name not in {"hevy_api_key", "garmin_email", "garmin_password", "garmin_tokens"}:
        raise ValueError("Unsupported secret name")
    ciphertext = encrypt_secret(value)
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        cursor = connection.cursor()
        if postgres:
            cursor.execute(
                """INSERT INTO user_secrets (user_id, name, ciphertext) VALUES (%s, %s, %s)
                   ON CONFLICT (user_id, name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext,
                   key_version = 1, updated_at = NOW()""",
                (user_id, name, ciphertext),
            )
        else:
            cursor.execute(
                """INSERT INTO user_secrets (user_id, name, ciphertext) VALUES (?, ?, ?)
                   ON CONFLICT(user_id, name) DO UPDATE SET ciphertext = excluded.ciphertext,
                   key_version = 1, updated_at = datetime('now')""",
                (user_id, name, ciphertext),
            )


def get_user_secret(user_id: str, name: str) -> str | None:
    """Return one decrypted credential for an account, if present."""
    with _connection() as (connection, postgres):
        placeholder = _placeholder(postgres)
        cursor = connection.cursor()
        cursor.execute(
            f"SELECT ciphertext FROM user_secrets WHERE user_id = {placeholder} AND name = {placeholder}",
            (user_id, name),
        )
        row = cursor.fetchone()
        ciphertext = row["ciphertext"] if postgres and row else (row[0] if row else None)
    return decrypt_secret(ciphertext) if ciphertext else None
