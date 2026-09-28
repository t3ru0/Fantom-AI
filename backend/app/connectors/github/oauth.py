"""GitHub authentication, behind a strategy interface.

Two credentials the GitHub connector can authenticate installations with:

  OAuthAppStrategy              — Authorization Code + PKCE, user-to-server
                                   tokens. Implemented, this is what Connector
                                   V1 actually uses.
  GitHubAppInstallationStrategy — installation access tokens from a GitHub
                                   App. Interface only: every method raises.
                                   Wiring this up later is a strategy swap,
                                   not a rewrite of the client, sync engine or
                                   API layer, which only ever call through
                                   `GitHubAuthStrategy` and never branch on
                                   which one is active.

This is the one place GitHub-specific auth detail is allowed to leak past the
connector boundary - see the module docstring in `app.connectors.base`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.secrets import manager as secrets_manager
from app.models.github import GithubInstallation

OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"
REFRESH_EARLY_S = 120     # refresh two minutes before actual expiry


class GitHubAuthError(RuntimeError):
    pass


class TokenExpired(GitHubAuthError):
    """Raised when a token is expired and cannot (or could not) be refreshed.
    The caller (service.py) is responsible for marking the connector expired -
    the strategy itself never touches `connector_installations.status`."""


@dataclass(slots=True)
class ExchangedToken:
    access_token: str
    refresh_token: str | None
    expires_in: int | None            # seconds; None means non-expiring (classic OAuth App token)
    scopes: list[str] = field(default_factory=list)
    account_id: int = 0
    account_login: str = ""
    account_type: str = "User"


class GitHubAuthStrategy(ABC):
    @abstractmethod
    def build_authorize_url(self, *, state: str, code_challenge: str) -> str: ...

    @abstractmethod
    def exchange_code(self, *, code: str, code_verifier: str) -> ExchangedToken: ...

    @abstractmethod
    def get_valid_token(self, db: Session, installation: GithubInstallation) -> str: ...

    @abstractmethod
    def refresh(self, db: Session, installation: GithubInstallation) -> bool: ...

    @abstractmethod
    def revoke(self, db: Session, installation: GithubInstallation) -> None: ...


class OAuthAppStrategy(GitHubAuthStrategy):
    def build_authorize_url(self, *, state: str, code_challenge: str) -> str:
        if not settings.github_client_id:
            raise GitHubAuthError("GITHUB_CLIENT_ID is not set")
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_redirect_uri,
            "scope": "repo read:user",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "allow_signup": "false",
        }
        query = httpx.QueryParams(params)
        return f"{OAUTH_AUTHORIZE_URL}?{query}"

    def _fetch_account(self, access_token: str) -> tuple[int, str, str]:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "fantom-connector/1.0"}
        with httpx.Client(base_url=settings.github_api_base, headers=headers, timeout=20) as c:
            r = c.get("/user")
        if r.status_code != 200:
            raise GitHubAuthError(f"could not fetch the authenticated user: {r.status_code} {r.text[:200]}")
        d = r.json()
        return d.get("id", 0), d.get("login", ""), d.get("type", "User")

    def exchange_code(self, *, code: str, code_verifier: str) -> ExchangedToken:
        if not (settings.github_client_id and settings.github_client_secret):
            raise GitHubAuthError("GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET are not set")
        payload = {
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "code": code,
            "redirect_uri": settings.github_redirect_uri,
            "code_verifier": code_verifier,
        }
        with httpx.Client(timeout=20) as c:
            r = c.post(OAUTH_TOKEN_URL, data=payload, headers={"Accept": "application/json"})
        if r.status_code != 200:
            raise GitHubAuthError(f"token exchange failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        if "error" in data:
            raise GitHubAuthError(f"token exchange rejected: {data.get('error_description', data['error'])}")

        access_token = data["access_token"]
        account_id, login, acct_type = self._fetch_account(access_token)
        return ExchangedToken(
            access_token=access_token,
            refresh_token=data.get("refresh_token"),
            expires_in=data.get("expires_in"),      # present only for expiring user-to-server tokens
            scopes=[s for s in (data.get("scope") or "").split(",") if s],
            account_id=account_id, account_login=login, account_type=acct_type,
        )

    def get_valid_token(self, db: Session, installation: GithubInstallation) -> str:
        if installation.token_expires_at is None:
            # Classic non-expiring OAuth token - never assume a refresh token exists.
            return secrets_manager.read_secret(installation.access_token_encrypted)

        expires_at = installation.token_expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) < expires_at - timedelta(seconds=REFRESH_EARLY_S):
            return secrets_manager.read_secret(installation.access_token_encrypted)

        if not self.refresh(db, installation):
            raise TokenExpired(f"installation {installation.id} has expired and cannot be refreshed")
        return secrets_manager.read_secret(installation.access_token_encrypted)

    def refresh(self, db: Session, installation: GithubInstallation) -> bool:
        if not installation.refresh_token_encrypted:
            return False        # never assume a refresh token exists
        if not (settings.github_client_id and settings.github_client_secret):
            raise GitHubAuthError("GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET are not set")

        refresh_token = secrets_manager.read_secret(installation.refresh_token_encrypted)
        payload = {
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        with httpx.Client(timeout=20) as c:
            r = c.post(OAUTH_TOKEN_URL, data=payload, headers={"Accept": "application/json"})
        data = r.json() if r.status_code == 200 else {}
        if r.status_code != 200 or "error" in data or "access_token" not in data:
            return False

        installation.access_token_encrypted = secrets_manager.store_secret(data["access_token"])
        if data.get("refresh_token"):
            installation.refresh_token_encrypted = secrets_manager.store_secret(data["refresh_token"])
        expires_in = data.get("expires_in")
        installation.token_expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=expires_in) if expires_in else None
        )
        db.flush()
        return True

    def revoke(self, db: Session, installation: GithubInstallation) -> None:
        """DELETE /applications/{client_id}/grant, Basic-authed with the OAuth
        app's own client id/secret - revokes upstream, not just the local row."""
        if not (settings.github_client_id and settings.github_client_secret):
            return
        access_token = secrets_manager.read_secret(installation.access_token_encrypted)
        with httpx.Client(timeout=20, auth=(settings.github_client_id, settings.github_client_secret)) as c:
            r = c.request(
                "DELETE",
                f"{settings.github_api_base}/applications/{settings.github_client_id}/grant",
                json={"access_token": access_token},
            )
        if r.status_code not in (204, 404):
            raise GitHubAuthError(f"upstream token revocation failed: {r.status_code} {r.text[:200]}")


class GitHubAppInstallationStrategy(GitHubAuthStrategy):
    """Interface only. GitHub App installation tokens are a different auth
    shape (app JWT -> installation access token, no user consent screen, no
    refresh token) and a real implementation is out of scope for Connector V1
    - see the legacy `app.integrations.github.app_auth` module, which already
    does this for the pre-connector code path and is left untouched."""

    def build_authorize_url(self, *, state: str, code_challenge: str) -> str:
        raise NotImplementedError("GitHub App installation auth is not implemented")

    def exchange_code(self, *, code: str, code_verifier: str) -> ExchangedToken:
        raise NotImplementedError("GitHub App installation auth is not implemented")

    def get_valid_token(self, db: Session, installation: GithubInstallation) -> str:
        raise NotImplementedError("GitHub App installation auth is not implemented")

    def refresh(self, db: Session, installation: GithubInstallation) -> bool:
        raise NotImplementedError("GitHub App installation auth is not implemented")

    def revoke(self, db: Session, installation: GithubInstallation) -> None:
        raise NotImplementedError("GitHub App installation auth is not implemented")


def strategy_for(installation: GithubInstallation) -> GitHubAuthStrategy:
    """The only branch point on auth mode, anywhere - and it only selects an
    object, never a code path."""
    if installation.auth_strategy == "oauth_app":
        return OAuthAppStrategy()
    if installation.auth_strategy == "github_app":
        return GitHubAppInstallationStrategy()
    raise GitHubAuthError(f"unknown auth strategy '{installation.auth_strategy}'")
