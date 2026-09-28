"""AES-256-GCM at rest, with key versioning baked into the ciphertext.

One key format: a base64 string that decodes to exactly 32 bytes. Anything
else - hex, raw bytes, a short passphrase - is a misconfiguration and raises
immediately. We do not guess an encoding or derive a key from a weak input;
a silently-wrong key is worse than a loud crash on boot.

Ciphertext layout (all of it goes in one Text column, base64-encoded once
more for storage as ASCII):

    version(1 byte) || nonce(12 bytes) || AESGCM(nonce, plaintext) [tag included]

`version` selects which key decrypts it, so `GITHUB_ENCRYPTION_KEY` can be
rotated by setting the new value there and moving the old value to
`GITHUB_ENCRYPTION_KEY_PREVIOUS` (version 2 and version 1 respectively) -
existing rows keep decrypting with the old key until `rotate_secret()`
re-encrypts them under the new one.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import String, TypeDecorator

from app.config import settings

NONCE_LEN = 12
KEY_LEN = 32

CURRENT_VERSION = 2
PREVIOUS_VERSION = 1


class EncryptionError(RuntimeError):
    pass


def _decode_key(raw: str, *, label: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001 — any decode failure is the same story
        raise EncryptionError(
            f"{label} must be base64; refusing to guess another encoding"
        ) from exc
    if len(key) != KEY_LEN:
        raise EncryptionError(
            f"{label} must decode to exactly {KEY_LEN} bytes, got {len(key)}"
        )
    return key


def _keyring() -> dict[int, bytes]:
    if not settings.github_encryption_key:
        raise EncryptionError("GITHUB_ENCRYPTION_KEY is not set")
    keys = {CURRENT_VERSION: _decode_key(settings.github_encryption_key, label="GITHUB_ENCRYPTION_KEY")}
    if settings.github_encryption_key_previous:
        keys[PREVIOUS_VERSION] = _decode_key(
            settings.github_encryption_key_previous, label="GITHUB_ENCRYPTION_KEY_PREVIOUS"
        )
    return keys


def encrypt_secret(plaintext: str) -> str:
    """Encrypts with the current key version. Returns an opaque ASCII blob."""
    key = _keyring()[CURRENT_VERSION]
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = bytes([CURRENT_VERSION]) + nonce + ct
    return base64.b64encode(blob).decode("ascii")


def decrypt_secret(token: str) -> str:
    """Decrypts with whichever key version the token was written under."""
    try:
        blob = base64.b64decode(token, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise EncryptionError("ciphertext is not valid base64") from exc
    if len(blob) < 1 + NONCE_LEN:
        raise EncryptionError("ciphertext is too short")
    version, nonce, ct = blob[0], blob[1:1 + NONCE_LEN], blob[1 + NONCE_LEN:]
    keyring = _keyring()
    key = keyring.get(version)
    if key is None:
        raise EncryptionError(f"no key available for ciphertext version {version}")
    try:
        pt = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:  # noqa: BLE001 — tampered/garbage ciphertext, never a stack trace to the caller
        raise EncryptionError("decryption failed: wrong key or tampered ciphertext") from exc
    return pt.decode("utf-8")


def ciphertext_version(token: str) -> int:
    blob = base64.b64decode(token, validate=True)
    return blob[0]


class EncryptedString(TypeDecorator):
    """SQLAlchemy column type: transparent AES-256-GCM at the ORM boundary.
    The database only ever sees ciphertext."""
    impl = String(2048)
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return encrypt_secret(value)

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return decrypt_secret(value)
