"""Everything cryptographic that isn't token-at-rest encryption (that's
`app.core.secrets`): PKCE, signed OAuth state, webhook HMAC verification and
delivery replay detection.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.config import settings
from app.core.secrets import manager as secrets_manager
from app.models.github import GithubOAuthState, GithubWebhook, GithubWebhookDelivery

STATE_TTL_S = 600           # 10 minutes
SIG_HEADER = "x-hub-signature-256"
DELIVERY_HEADER = "x-github-delivery"
EVENT_HEADER = "x-github-event"
HOOK_ID_HEADER = "x-github-hook-id"
MAX_WEBHOOK_BODY_BYTES = 5 * 1024 * 1024      # GitHub caps deliveries at 25MB; we don't need to


class SecurityError(Exception):
    """Base for anything that must produce a 4xx, never a 5xx."""


class StateError(SecurityError):
    pass


class BadSignature(SecurityError):
    pass


class PayloadTooLarge(SecurityError):
    pass


class ReplayDetected(SecurityError):
    pass


# --------------------------------------------------------------------- PKCE --
def generate_pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) per RFC 7636, S256 method."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ------------------------------------------------------------- signed state --
def _state_secret() -> bytes:
    return settings.jwt_secret.encode("utf-8")


def _sign(payload_b64: str) -> str:
    return hmac.new(_state_secret(), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()


def create_oauth_state(db: Session, *, org_id: uuid.UUID, user_id: uuid.UUID, code_verifier: str) -> str:
    """Stores the PKCE verifier server-side and returns a signed, timestamped
    state token that carries only an opaque id - never the verifier itself."""
    sid = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    db.add(GithubOAuthState(
        sid=sid,
        code_verifier_encrypted=secrets_manager.store_secret(code_verifier),
        organization_id=org_id, user_id=user_id,
        expires_at=now + timedelta(seconds=STATE_TTL_S),
    ))
    db.flush()

    payload = json.dumps({"sid": sid, "ts": int(time.time())}, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{payload_b64}.{_sign(payload_b64)}"


@dataclass(slots=True)
class ResolvedState:
    sid: str
    org_id: uuid.UUID
    user_id: uuid.UUID
    code_verifier: str


def consume_oauth_state(db: Session, token: str) -> ResolvedState:
    """Verifies the signature and timestamp, then single-use-consumes the
    matching DB row. A stolen `token` alone verifies the signature fine, but
    still needs a live, unexpired, unconsumed DB row behind it - that row is
    deleted here, so a replayed callback (or a second use of the same link)
    fails on its second attempt."""
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        raise StateError("malformed state") from None
    if not hmac.compare_digest(_sign(payload_b64), sig):
        raise StateError("state signature mismatch")
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        sid, ts = payload["sid"], int(payload["ts"])
    except (ValueError, KeyError, TypeError):
        raise StateError("malformed state payload") from None
    if time.time() - ts > STATE_TTL_S:
        raise StateError("state expired")

    row = db.get(GithubOAuthState, sid)
    if row is None:
        raise StateError("state not found or already used")
    if row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(row)
        db.flush()
        raise StateError("state expired")

    resolved = ResolvedState(
        sid=row.sid, org_id=row.organization_id, user_id=row.user_id,
        code_verifier=secrets_manager.read_secret(row.code_verifier_encrypted),
    )
    db.delete(row)
    db.flush()
    return resolved


# --------------------------------------------------------------- webhooks ---
def webhook_callback_url() -> str:
    """The one URL every repository's webhook points at, derived from
    `GITHUB_REDIRECT_URI` (which already carries this deployment's public
    origin) rather than a second env var to keep in sync with it."""
    parts = urlsplit(settings.github_redirect_uri)
    origin = f"{parts.scheme}://{parts.netloc}"
    return f"{origin}/connectors/github/webhook"


def generate_webhook_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _hmac_matches(body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def check_content_length(content_length: int | None) -> None:
    """Rejected by size before the body is even read off the wire."""
    if content_length is not None and content_length > MAX_WEBHOOK_BODY_BYTES:
        raise PayloadTooLarge(f"payload of {content_length} bytes exceeds the {MAX_WEBHOOK_BODY_BYTES} byte limit")


def verify_delivery_signature(body: bytes, signature: str | None, webhook: GithubWebhook) -> None:
    """Constant-time check against the webhook's current secret, falling back
    to the previous one only inside its grace window. Raises BadSignature."""
    if not signature:
        raise BadSignature("missing signature header")
    if not signature.startswith("sha256="):
        raise BadSignature("unsupported signature algorithm")

    current = secrets_manager.read_secret(webhook.secret_encrypted)
    if _hmac_matches(body, signature, current):
        return

    if webhook.previous_secret_encrypted and webhook.previous_secret_expires_at:
        if webhook.previous_secret_expires_at.replace(tzinfo=timezone.utc) >= datetime.now(timezone.utc):
            previous = secrets_manager.read_secret(webhook.previous_secret_encrypted)
            if _hmac_matches(body, signature, previous):
                return

    raise BadSignature("signature mismatch")


def check_replay(db: Session, delivery_id: str) -> None:
    """Every delivery id is checked here before processing. A repeated id is a
    replay regardless of whether the signature verified - this call happens
    after signature verification, but its result is authoritative on its own."""
    if db.query(GithubWebhookDelivery).filter(GithubWebhookDelivery.delivery_id == delivery_id).first():
        raise ReplayDetected(f"delivery {delivery_id} was already processed")
