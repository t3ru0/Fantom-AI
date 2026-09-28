"""Webhook verification and event parsing.

Signature verification is the security boundary of this entire product. Anyone
on the internet can POST to the webhook URL; the HMAC is the only thing that
separates GitHub from an attacker who wants us to clone a repository of their
choosing. It is checked first, in constant time, before the body is parsed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

SIG_HEADER = "x-hub-signature-256"
EVENT_HEADER = "x-github-event"
DELIVERY_HEADER = "x-github-delivery"


class WebhookError(Exception):
    """Raised for anything that should produce a 4xx, never a 5xx."""


class BadSignature(WebhookError):
    pass


def verify(body: bytes, signature: str | None, secret: str) -> None:
    """Constant-time HMAC-SHA256 check. Raises BadSignature on any problem.

    Rejects a missing header rather than treating it as "unsigned but fine" —
    an unsigned delivery is exactly what an attacker would send.
    """
    if not secret:
        raise BadSignature("no webhook secret configured")
    if not signature:
        raise BadSignature("missing signature header")
    if not signature.startswith("sha256="):
        raise BadSignature("unsupported signature algorithm")

    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise BadSignature("signature mismatch")


def sign(body: bytes, secret: str) -> str:
    """Produce a signature. Used by the tests and by the local replay tool."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
@dataclass(slots=True)
class PushEvent:
    repo: str                      # owner/name
    repo_id: int | None
    installation_id: int | None
    ref: str                       # refs/heads/main
    branch: str
    before: str
    after: str
    pusher: str
    commit_message: str
    changed_files: list[str] = field(default_factory=list)
    is_delete: bool = False
    is_default_branch: bool = False
    private: bool = True

    @property
    def should_scan(self) -> bool:
        """Tag pushes, branch deletions and empty pushes are not inspections."""
        if self.is_delete:
            return False
        if not self.ref.startswith("refs/heads/"):
            return False
        return bool(self.after) and self.after != "0" * 40


def parse_push(payload: dict[str, Any]) -> PushEvent:
    repo = payload.get("repository") or {}
    ref = payload.get("ref") or ""
    after = payload.get("after") or ""

    changed: list[str] = []
    for c in payload.get("commits") or []:
        for key in ("added", "modified", "removed"):
            changed.extend(c.get(key) or [])
    # Preserve order, drop duplicates.
    seen: dict[str, None] = {}
    for path in changed:
        seen.setdefault(path, None)

    head = payload.get("head_commit") or {}
    return PushEvent(
        repo=repo.get("full_name") or "",
        repo_id=repo.get("id"),
        installation_id=(payload.get("installation") or {}).get("id"),
        ref=ref,
        branch=ref.removeprefix("refs/heads/"),
        before=payload.get("before") or "",
        after=after,
        pusher=(payload.get("pusher") or {}).get("name") or "",
        commit_message=(head.get("message") or "").splitlines()[0][:500] if head else "",
        changed_files=list(seen),
        is_delete=bool(payload.get("deleted")),
        is_default_branch=ref.removeprefix("refs/heads/") == (repo.get("default_branch") or ""),
        private=bool(repo.get("private", True)),
    )


@dataclass(slots=True)
class InstallationEvent:
    action: str                    # created | deleted | suspend | unsuspend
    installation_id: int
    account: str
    repos: list[str] = field(default_factory=list)


def parse_installation(payload: dict[str, Any]) -> InstallationEvent:
    inst = payload.get("installation") or {}
    account = (inst.get("account") or {}).get("login") or ""
    repos = [
        r.get("full_name") or ""
        for r in (payload.get("repositories") or payload.get("repositories_added") or [])
    ]
    return InstallationEvent(
        action=payload.get("action") or "",
        installation_id=inst.get("id") or 0,
        account=account,
        repos=[r for r in repos if r],
    )


def load(body: bytes) -> dict[str, Any]:
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise WebhookError(f"payload is not JSON: {exc}") from exc
