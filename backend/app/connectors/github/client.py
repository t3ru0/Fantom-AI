"""Async GitHub REST client.

One retry path for 403/429/5xx (exponential backoff, `Retry-After` honoured
when GitHub sends it), proactive rate-limit awareness (checked from the last
response's `X-RateLimit-Remaining`, not only discovered via a 403), ETag
support for conditional GETs, automatic pagination, and automatic token
refresh on a 401 - all funnelled through one `_request()` so callers never
duplicate this logic.

The client never branches on which `GitHubAuthStrategy` is behind
`installation` - it asks the strategy for a token and, on 401, asks it to
refresh. That is the only auth-mode-agnostic contract it needs.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.github.oauth import GitHubAuthError, GitHubAuthStrategy, TokenExpired
from app.models.github import GithubInstallation

log = logging.getLogger(__name__)

ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"
USER_AGENT = "fantom-connector/1.0"
MAX_ATTEMPTS = 5
BASE_BACKOFF_S = 1.0


class GitHubApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimited(GitHubApiError):
    pass


@dataclass(slots=True)
class Page:
    items: list[dict[str, Any]]
    etag: str | None
    not_modified: bool = False


class GitHubClient:
    def __init__(self, db: Session, installation: GithubInstallation, strategy: GitHubAuthStrategy):
        self._db = db
        self._installation = installation
        self._strategy = strategy
        self._rate_remaining: int | None = None
        self._rate_reset_epoch: int | None = None

    async def _token(self) -> str:
        return await asyncio.to_thread(self._strategy.get_valid_token, self._db, self._installation)

    async def _maybe_wait_for_rate_limit(self) -> None:
        """Proactive: if the last response said we're nearly out, sleep until
        reset instead of firing a request we already know will 403/429."""
        if self._rate_remaining is not None and self._rate_remaining <= 1 and self._rate_reset_epoch:
            import time
            wait = self._rate_reset_epoch - int(time.time())
            if wait > 0:
                log.warning("GitHub rate limit nearly exhausted, sleeping %ds", wait)
                await asyncio.sleep(min(wait + 1, 120))

    def _record_rate_limit(self, headers: httpx.Headers) -> None:
        remaining = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        if remaining is not None:
            self._rate_remaining = int(remaining)
        if reset is not None:
            self._rate_reset_epoch = int(reset)

    async def _request(
        self, method: str, path: str, *, params: dict | None = None,
        json_body: dict | None = None, etag: str | None = None, retried_auth: bool = False,
    ) -> httpx.Response:
        await self._maybe_wait_for_rate_limit()
        token = await self._token()
        headers = {
            "Authorization": f"Bearer {token}", "Accept": ACCEPT,
            "X-GitHub-Api-Version": API_VERSION, "User-Agent": USER_AGENT,
        }
        if etag:
            headers["If-None-Match"] = etag

        last_exc: Exception | None = None
        async with httpx.AsyncClient(base_url=settings.github_api_base, timeout=30) as client:
            for attempt in range(1, MAX_ATTEMPTS + 1):
                try:
                    resp = await client.request(method, path, params=params, json=json_body, headers=headers)
                except httpx.TransportError as exc:
                    last_exc = exc
                    await asyncio.sleep(BASE_BACKOFF_S * (2 ** (attempt - 1)))
                    continue

                self._record_rate_limit(resp.headers)

                if resp.status_code == 401 and not retried_auth:
                    try:
                        await asyncio.to_thread(self._strategy.refresh, self._db, self._installation)
                    except (GitHubAuthError, TokenExpired) as exc:
                        raise GitHubApiError(f"401 and refresh failed: {exc}", status_code=401) from exc
                    return await self._request(
                        method, path, params=params, json_body=json_body, etag=etag, retried_auth=True
                    )

                if resp.status_code in (403, 429, 500, 502, 503, 504):
                    retry_after = resp.headers.get("retry-after")
                    if attempt == MAX_ATTEMPTS:
                        break
                    if retry_after and retry_after.isdigit():
                        delay = float(retry_after)
                    elif resp.status_code in (403, 429) and self._rate_remaining == 0 and self._rate_reset_epoch:
                        import time
                        delay = max(self._rate_reset_epoch - int(time.time()), 1)
                    else:
                        delay = BASE_BACKOFF_S * (2 ** (attempt - 1))
                    log.warning("GitHub %s %s -> %d, retrying in %.1fs (attempt %d/%d)",
                                method, path, resp.status_code, delay, attempt, MAX_ATTEMPTS)
                    await asyncio.sleep(delay)
                    continue

                return resp

        if last_exc:
            raise GitHubApiError(f"{method} {path} failed after retries: {last_exc}") from last_exc
        raise RateLimited(f"{method} {path} exhausted retries", status_code=resp.status_code)

    async def _paginated(self, path: str, *, per_page: int | None = None) -> list[dict[str, Any]]:
        per_page = per_page or settings.github_sync_page_size
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._request("GET", path, params={"per_page": per_page, "page": page})
            if resp.status_code >= 400:
                raise GitHubApiError(f"GET {path} -> {resp.status_code}: {resp.text[:200]}", status_code=resp.status_code)
            batch = resp.json()
            if not batch:
                break
            items.extend(batch)
            if len(batch) < per_page or "next" not in (resp.links or {}):
                break
            page += 1
        return items

    # ------------------------------------------------------------- methods --
    async def get_current_user(self) -> dict:
        resp = await self._request("GET", "/user")
        if resp.status_code != 200:
            raise GitHubApiError(f"GET /user -> {resp.status_code}", status_code=resp.status_code)
        return resp.json()

    async def validate_token(self) -> bool:
        try:
            await self.get_current_user()
            return True
        except GitHubApiError:
            return False

    async def refresh_token(self) -> bool:
        return await asyncio.to_thread(self._strategy.refresh, self._db, self._installation)

    async def list_repositories(self, etag: str | None = None) -> Page:
        """Paginates until exhausted. `etag` is checked against the first page
        only - if GitHub says that page hasn't changed, the whole collection
        is treated as unchanged and no further pages are fetched, which is
        what makes incremental sync of a large account cheap."""
        first = await self._request(
            "GET", "/user/repos",
            params={"per_page": settings.github_sync_page_size, "page": 1, "sort": "full_name",
                    "affiliation": "owner,collaborator,organization_member"},
            etag=etag,
        )
        if first.status_code == 304:
            return Page(items=[], etag=etag, not_modified=True)
        if first.status_code >= 400:
            raise GitHubApiError(f"GET /user/repos -> {first.status_code}: {first.text[:200]}", status_code=first.status_code)

        new_etag = first.headers.get("etag")
        items: list[dict[str, Any]] = first.json()
        page = 1
        last_links = first.links or {}
        while "next" in last_links and items and len(items) % settings.github_sync_page_size == 0:
            page += 1
            resp = await self._request(
                "GET", "/user/repos",
                params={"per_page": settings.github_sync_page_size, "page": page, "sort": "full_name"},
            )
            if resp.status_code >= 400:
                break
            batch = resp.json()
            if not batch:
                break
            items.extend(batch)
            last_links = resp.links or {}
        return Page(items=items, etag=new_etag)

    async def get_repository(self, full_name: str) -> dict:
        resp = await self._request("GET", f"/repos/{full_name}")
        if resp.status_code == 404:
            raise GitHubApiError(f"{full_name} not found or access revoked", status_code=404)
        if resp.status_code >= 400:
            raise GitHubApiError(f"GET /repos/{full_name} -> {resp.status_code}", status_code=resp.status_code)
        return resp.json()

    async def get_permissions(self, full_name: str) -> dict[str, bool]:
        repo = await self.get_repository(full_name)
        perms = repo.get("permissions") or {}
        return {
            "admin": bool(perms.get("admin")), "push": bool(perms.get("push")),
            "pull": bool(perms.get("pull")), "maintain": bool(perms.get("maintain")),
            "triage": bool(perms.get("triage")),
        }

    async def list_branches(self, full_name: str) -> list[dict]:
        return await self._paginated(f"/repos/{full_name}/branches")

    async def get_commit(self, full_name: str, ref: str) -> dict:
        """Resolves a branch name or SHA to the full commit object, so a clone
        can pin an exact commit instead of a moving branch head."""
        resp = await self._request("GET", f"/repos/{full_name}/commits/{ref}")
        if resp.status_code >= 400:
            raise GitHubApiError(f"GET /repos/{full_name}/commits/{ref} -> {resp.status_code}: {resp.text[:200]}", status_code=resp.status_code)
        return resp.json()

    async def list_topics(self, full_name: str) -> list[str]:
        resp = await self._request("GET", f"/repos/{full_name}/topics")
        if resp.status_code >= 400:
            return []
        return resp.json().get("names", [])

    async def repository_security_settings(self, full_name: str) -> dict:
        has_policy = False
        resp = await self._request("GET", f"/repos/{full_name}/community/profile")
        if resp.status_code == 200:
            files = resp.json().get("files") or {}
            has_policy = files.get("security") is not None

        has_dependabot = False
        resp = await self._request("GET", f"/repos/{full_name}/vulnerability-alerts")
        has_dependabot = resp.status_code == 204
        return {"has_security_policy": has_policy, "has_dependabot": has_dependabot}

    async def create_webhook(self, full_name: str, *, callback_url: str, secret: str,
                              events: list[str]) -> dict:
        resp = await self._request(
            "POST", f"/repos/{full_name}/hooks",
            json_body={
                "name": "web", "active": True, "events": events,
                "config": {"url": callback_url, "content_type": "json", "secret": secret, "insecure_ssl": "0"},
            },
        )
        if resp.status_code not in (200, 201):
            raise GitHubApiError(f"create webhook on {full_name} -> {resp.status_code}: {resp.text[:200]}", status_code=resp.status_code)
        return resp.json()

    async def update_webhook_secret(self, full_name: str, webhook_id: int, secret: str) -> None:
        resp = await self._request(
            "PATCH", f"/repos/{full_name}/hooks/{webhook_id}",
            json_body={"config": {"secret": secret, "content_type": "json"}},
        )
        if resp.status_code >= 400:
            raise GitHubApiError(f"update webhook {webhook_id} secret on {full_name} -> {resp.status_code}", status_code=resp.status_code)

    async def get_webhook(self, full_name: str, webhook_id: int) -> dict:
        resp = await self._request("GET", f"/repos/{full_name}/hooks/{webhook_id}")
        if resp.status_code >= 400:
            raise GitHubApiError(f"get webhook {webhook_id} on {full_name} -> {resp.status_code}", status_code=resp.status_code)
        return resp.json()

    async def delete_webhook(self, full_name: str, webhook_id: int) -> None:
        resp = await self._request("DELETE", f"/repos/{full_name}/hooks/{webhook_id}")
        if resp.status_code not in (204, 404):
            raise GitHubApiError(f"delete webhook {webhook_id} on {full_name} -> {resp.status_code}", status_code=resp.status_code)

    async def download_archive(self, full_name: str, ref: str, *, dest_path: str) -> None:
        """Streams the tarball straight to disk - never buffers it in memory."""
        token = await self._token()
        headers = {"Authorization": f"Bearer {token}", "Accept": ACCEPT,
                   "X-GitHub-Api-Version": API_VERSION, "User-Agent": USER_AGENT}
        url = f"{settings.github_api_base}/repos/{full_name}/tarball/{ref}"
        async with httpx.AsyncClient(timeout=settings.github_clone_timeout, follow_redirects=True) as client:
            async with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code >= 400:
                    body = await resp.aread()
                    raise GitHubApiError(f"archive download for {full_name}@{ref} -> {resp.status_code}: {body[:200]}", status_code=resp.status_code)
                with open(dest_path, "wb") as fh:
                    async for chunk in resp.aiter_bytes(chunk_size=1024 * 256):
                        fh.write(chunk)
