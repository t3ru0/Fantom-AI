"""Local, no-internet walkthrough of the GitHub connector, end to end.

Runs entirely against your local MySQL (`fantom` db) via an in-process
TestClient - no real GitHub account, no OAuth App, no network calls. GitHub's
API responses are faked at the same boundary the pytest suite fakes them
(`OAuthAppStrategy.exchange_code`, `GitHubClient` methods), so what's actually
under test is this connector's own wiring: OAuth state, encryption, webhook
HMAC + replay guard, repository selection, and the webhook -> Run pipeline.

Usage:
    .venv/Scripts/python.exe scripts/demo_connector.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("DATABASE_URL", "mysql+pymysql://root:@localhost:3306/fantom")
os.environ.setdefault("GITHUB_ENCRYPTION_KEY", "3LDUT18c2ERpJC56jqF0tEFJizbUZOHdlnGcMhh38lw=")
os.environ.setdefault("GITHUB_CLIENT_ID", "demo-client-id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "demo-client-secret")
os.environ.setdefault("JWT_SECRET", "dev-insecure-secret-change-me-32bytes-minimum")


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    from fastapi.testclient import TestClient
    from app.main import app
    from app.services import orchestrator

    # This demo proves the connector's own wiring (OAuth, sync, selection,
    # webhook -> Run creation) - not the downstream scanner pipeline, which
    # needs a real, clonable repository to mean anything. The background scan
    # worker (started by the app's own lifespan, polling independently of
    # `wake_worker`) would otherwise pick up the Run this script creates and
    # try to actually clone "demo-octocat/hello-world" over the real network.
    # Patched *before* the app starts: the worker loop resolves `execute` once
    # at startup via `from ... import execute`, so patching it after the
    # worker thread is already running would not reach that thread's own
    # bound reference.
    def _fake_execute(run_id) -> None:
        pass

    with mock.patch.object(orchestrator, "execute", _fake_execute), TestClient(app) as client:
        email = f"demo-{uuid.uuid4().hex[:8]}@example.com"

        step("1. Register a user + org")
        r = client.post("/api/auth/register", json={
            "email": email, "password": "password123", "name": "Demo User", "org_name": "Demo Org",
        })
        assert r.status_code == 201, r.text
        tok = r.json()
        headers = {"Authorization": f"Bearer {tok['access_token']}"}
        me = client.get("/api/auth/me", headers=headers).json()
        org_id = me["memberships"][0]["org_id"]
        headers["X-Org-Id"] = org_id
        print(f"user={email}  org_id={org_id}")

        step("2. GET /connectors/github/status (before connecting)")
        print(json.dumps(client.get("/connectors/github/status", headers=headers).json(), indent=2))

        step("3. GET /connectors/github/authorize (real PKCE + signed state, no network)")
        r = client.get("/connectors/github/authorize", headers=headers)
        authorize_url = r.json()["authorize_url"]
        print(authorize_url)
        import urllib.parse
        state = urllib.parse.unquote(authorize_url.split("state=")[1].split("&")[0])

        step("4. GitHub redirects back to /callback - faking GitHub's responses only")
        from app.connectors.github.oauth import ExchangedToken, OAuthAppStrategy
        from app.connectors.github.client import GitHubClient, Page
        fake_token = ExchangedToken(
            access_token="gho_demo_fake_token", refresh_token=None, expires_in=None,
            scopes=["repo", "read:user"], account_id=1, account_login="demo-octocat", account_type="User",
        )
        # A real installation calls GitHub's /user/repos; here we fake that one
        # response so `sync_installation`'s real upsert/permission/dedup logic
        # still runs against real MySQL rows. This also covers the automatic
        # post-connect sync the /callback route triggers, so nothing in this
        # step touches the network.
        fake_repo_json = {
            "id": 123456, "full_name": "demo-octocat/hello-world", "name": "hello-world",
            "owner": {"login": "demo-octocat"}, "private": True, "archived": False,
            "default_branch": "main", "language": "Python", "stargazers_count": 3,
            "forks_count": 1, "open_issues_count": 0,
            "permissions": {"admin": True, "push": True, "pull": True, "maintain": True, "triage": True},
        }
        with mock.patch.object(OAuthAppStrategy, "exchange_code", return_value=fake_token), \
             mock.patch.object(GitHubClient, "list_repositories", return_value=Page(items=[fake_repo_json], etag=None)):
            r = client.get("/connectors/github/callback", params={"code": "fake-code", "state": state},
                           follow_redirects=False)
        print(f"redirect -> {r.headers.get('location')}")

        step("5. GET /connectors/github/status (connected, already synced)")
        print(json.dumps(client.get("/connectors/github/status", headers=headers).json(), indent=2, default=str))

        step("6. POST /connectors/github/sync again (idempotent - re-fetches the same fake list)")
        with mock.patch.object(GitHubClient, "list_repositories", return_value=Page(items=[fake_repo_json], etag=None)):
            r = client.post("/connectors/github/sync", headers=headers)
        print(json.dumps(r.json(), indent=2))

        step("7. GET /connectors/github/repositories")
        repos = client.get("/connectors/github/repositories", headers=headers).json()
        print(json.dumps(repos, indent=2, default=str))
        repo_id = repos["repositories"][0]["id"]

        step("8. Select it for monitoring (creates a Project + fakes webhook creation)")
        # `github_webhooks.webhook_id` is globally unique, and this script runs
        # against your real local `fantom` db (not a throwaway test schema),
        # so a fixed fake id would collide with a previous run's leftover row.
        fake_webhook_id = uuid.uuid4().int % 1_000_000_000
        # repositories.py imported `enrich_repository` by name at module load,
        # so it must be patched where it's *used*, not where it's defined.
        with mock.patch.object(GitHubClient, "create_webhook", return_value={"id": fake_webhook_id}), \
             mock.patch("app.connectors.github.repositories.enrich_repository", return_value=None):
            r = client.post("/connectors/github/repositories/select", headers=headers,
                            json={"repository_ids": [repo_id]})
        print(json.dumps(r.json(), indent=2, default=str))

        step("9. Simulate a real GitHub push webhook delivery (real HMAC, real replay guard)")
        from app.db import get_sessionmaker
        from app.models.github import GithubWebhook
        db = get_sessionmaker()()
        webhook = db.query(GithubWebhook).filter(GithubWebhook.webhook_id == fake_webhook_id).first()
        from app.core.secrets import manager as secrets_manager
        secret = secrets_manager.read_secret(webhook.secret_encrypted)
        db.close()

        body = json.dumps({
            "ref": "refs/heads/main", "before": "0" * 40, "after": "d" * 40, "deleted": False,
            "pusher": {"name": "demo-octocat"},
            "repository": {"id": 123456, "full_name": "demo-octocat/hello-world",
                           "default_branch": "main", "private": True},
            "head_commit": {"message": "demo commit"},
            "commits": [{"added": ["README.md"], "modified": [], "removed": []}],
        }).encode()
        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        delivery_id = f"demo-{uuid.uuid4()}"
        webhook_headers = {
            "x-github-hook-id": str(fake_webhook_id), "x-github-event": "push",
            "x-github-delivery": delivery_id, "x-hub-signature-256": signature,
            "content-length": str(len(body)),
        }
        r = client.post("/connectors/github/webhook", content=body, headers=webhook_headers)
        print(f"status={r.status_code}")
        print(json.dumps(r.json(), indent=2))

        step("10. Replay the *exact same* delivery id - must be rejected (409)")
        r2 = client.post("/connectors/github/webhook", content=body, headers=webhook_headers)
        print(f"status={r2.status_code}")
        print(json.dumps(r2.json(), indent=2))
        assert r2.status_code == 409, "replay guard did not reject a duplicate delivery id"

        step("11. GET /connectors/github/sync-history")
        print(json.dumps(client.get("/connectors/github/sync-history", headers=headers).json(), indent=2, default=str))

        print("\nAll steps completed against your local `fantom` MySQL database.")
        print(f"Log back in as {email} / password123 to keep poking at it via /docs.")


if __name__ == "__main__":
    main()
