"""The one door connectors use to persist and rotate a credential.

GitHub's OAuth token pair, a future connector's API key, a webhook secret -
whatever shape the credential takes, it goes through `store_secret` /
`read_secret` / `rotate_secret` / `delete_secret`. None of them touch a
database row directly; the caller still owns where the ciphertext lives
(an `EncryptedString` column, most of the time). This module's only job is
to be the single place that wraps the encryption primitives, so nobody ever
calls `encrypt_secret`/`decrypt_secret` from connector code directly.
"""
from __future__ import annotations

import logging

from app.core.secrets.encryption import (
    CURRENT_VERSION,
    ciphertext_version,
    decrypt_secret,
    encrypt_secret,
)

log = logging.getLogger(__name__)


def store_secret(plaintext: str) -> str:
    """Encrypts a credential for storage. Never logs the plaintext."""
    return encrypt_secret(plaintext)


def read_secret(ciphertext: str) -> str:
    """Decrypts a stored credential."""
    return decrypt_secret(ciphertext)


def rotate_secret(ciphertext: str) -> str:
    """Re-encrypts under the current key version. A no-op re-encrypt (still
    decrypt+encrypt, so a tampered blob is still caught) if it already is."""
    plaintext = decrypt_secret(ciphertext)
    rotated = encrypt_secret(plaintext)
    if ciphertext_version(ciphertext) != CURRENT_VERSION:
        log.info("rotated a secret from key version %d to %d", ciphertext_version(ciphertext), CURRENT_VERSION)
    return rotated


def delete_secret(ciphertext: str | None) -> None:
    """Marks a credential as gone. Callers still clear their own column/row -
    this is the audit hook every future connector's disconnect flow calls
    through, so secret lifecycle logging stays in one place."""
    if ciphertext is None:
        return
    log.info("secret invalidated (version %d)", ciphertext_version(ciphertext))
