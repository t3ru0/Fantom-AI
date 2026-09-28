"""GitHub App authentication.

Three credentials, in order of scope:
  app JWT            — signed with the app private key, proves "I am this app"
  installation token — exchanged from the JWT, scoped to one installation,
                       expires in one hour, is never logged and never persisted
  nothing else       — we never ask a user for a personal access token

Permissions requested are read-only on contents and metadata. The app cannot
push, merge or change a repository, by construction.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import httpx

from app.config import settings

log = logging.getLogger(__name__)

API = "https://api.github.com"
ACCEPT = "application/vnd.github+json"
APIVER = "2022-11-28"


class GitHubAuthError(RuntimeError):
    pass


def _private_key() -> str:
    raw = settings.github_private_key or ""
    if not raw:
        raise GitHubAuthError("GITHUB_PRIVATE_KEY is not set")
    # .env cannot hold real newlines, so the PEM is stored with literal \n
    return raw.replace("\\n", "\n").strip()


def app_jwt(ttl_s: int = 540) -> str:
    """RS256 JWT for the app itself. GitHub allows at most 10 minutes."""
    try:
        import jwt  # PyJWT
    except ImportError as exc:                     # pragma: no cover
        raise GitHubAuthError("PyJWT is required: pip install 'pyjwt[crypto]'") from exc
    if not settings.github_app_id:
        raise GitHubAuthError("GITHUB_APP_ID is not set")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + ttl_s, "iss": settings.github_app_id}
    return jwt.encode(payload, _private_key(), algorithm="RS256")


@dataclass(slots=True)
class Token:
    value: str
    expires_at: float

    @property
    def fresh(self) -> bool:
        return time.time() < self.expires_at - 120     # refresh two minutes early


_cache: dict[int, Token] = {}
_lock = threading.Lock()


def installation_token(installation_id: int) -> str:
    """Short-lived token for one installation. Cached in memory only."""
    with _lock:
        tok = _cache.get(installation_id)
        if tok and tok.fresh:
            return tok.value

    headers = {
        "Authorization": f"Bearer {app_jwt()}",
        "Accept": ACCEPT,
        "X-GitHub-Api-Version": APIVER,
    }
    url = f"{API}/app/installations/{installation_id}/access_tokens"
    with httpx.Client(timeout=20) as client:
        r = client.post(url, headers=headers)
    if r.status_code != 201:
        raise GitHubAuthError(f"token exchange failed: {r.status_code} {r.text[:200]}")

    data = r.json()
    # expires_at is ISO-8601; treat it as one hour and refresh early regardless.
    tok = Token(value=data["token"], expires_at=time.time() + 3600)
    with _lock:
        _cache[installation_id] = tok
    log.info("issued installation token for %s (never logged)", installation_id)
    return tok.value


def client_for(installation_id: int | None) -> httpx.Client:
    """An httpx client carrying the right credential, or none for public repos."""
    headers = {"Accept": ACCEPT, "X-GitHub-Api-Version": APIVER,
               "User-Agent": "fantom/0.1"}
    if installation_id:
        headers["Authorization"] = f"Bearer {installation_token(installation_id)}"
    return httpx.Client(base_url=API, headers=headers, timeout=25)


def repo_meta(repo: str, installation_id: int | None = None) -> dict:
    """Repository metadata. Works unauthenticated for public repositories."""
    with client_for(installation_id) as c:
        r = c.get(f"/repos/{repo}")
    if r.status_code == 404:
        raise GitHubAuthError(f"{repo} not found, or the app is not installed on it")
    if r.status_code >= 400:
        raise GitHubAuthError(f"GitHub said {r.status_code}: {r.text[:200]}")
    d = r.json()
    return {
        "id": d.get("id"),
        "full_name": d.get("full_name"),
        "private": d.get("private"),
        "default_branch": d.get("default_branch"),
        "size_kb": d.get("size"),
        "language": d.get("language"),
        "archived": d.get("archived"),
        "pushed_at": d.get("pushed_at"),
    }
