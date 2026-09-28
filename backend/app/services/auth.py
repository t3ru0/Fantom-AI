"""Password hashing and JWT issuance/verification.

Three token types, distinguished by a `type` claim so an access token cannot
be replayed as a refresh token or vice versa: access (short-lived, sent on
every request), refresh (long-lived, exchanged for a new access token),
reset (one hour, single purpose — set a new password).

Logout revokes a token by its `jti`, recorded in `revoked_tokens` until it
would have expired anyway. Access tokens are short enough that revocation
mostly matters for the refresh token a client held.
"""
from __future__ import annotations

import secrets
import time
import uuid
from datetime import datetime, timezone

import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.models import RevokedToken

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS = "access"
REFRESH = "refresh"
RESET = "reset"
ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised for any invalid, expired, wrong-type, or revoked token."""


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_ctx.verify(password, password_hash)
    except ValueError:
        return False


def _issue(user_id: uuid.UUID, token_type: str, ttl_s: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": now + ttl_s,
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_access_token(user_id: uuid.UUID) -> str:
    return _issue(user_id, ACCESS, settings.jwt_access_ttl_min * 60)


def create_refresh_token(user_id: uuid.UUID) -> str:
    return _issue(user_id, REFRESH, settings.jwt_refresh_ttl_days * 86400)


def create_reset_token(user_id: uuid.UUID) -> str:
    return _issue(user_id, RESET, 3600)


def decode_token(token: str, expected_type: str, db: Session | None = None) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if payload.get("type") != expected_type:
        raise TokenError(f"expected a {expected_type} token")
    if db is not None and db.get(RevokedToken, payload["jti"]) is not None:
        raise TokenError("token has been revoked")
    return payload


def revoke(token: str, db: Session) -> None:
    """Best-effort: an already-expired or malformed token needs no revocation."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM],
                              options={"verify_exp": False})
    except jwt.PyJWTError:
        return
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    if db.get(RevokedToken, payload["jti"]) is None:
        db.add(RevokedToken(jti=payload["jti"], expires_at=exp))
        db.commit()
