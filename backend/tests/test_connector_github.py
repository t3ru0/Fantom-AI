"""Connector V1 (GitHub) acceptance tests.

Unit tests below need no database. Everything under `TestClient`/`auth_headers`
needs the real `fantom_test` MySQL schema (see `tests/conftest.py`) - same as
every other Part 4 test in this suite.

Outbound calls to api.github.com are monkeypatched at the `GitHubClient`
method / `OAuthAppStrategy` boundary - what's under test is this connector's
own wiring (dedup, replay, encryption, state signing), not GitHub's API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import tarfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("GITHUB_ENCRYPTION_KEY", "3LDUT18c2ERpJC56jqF0tEFJizbUZOHdlnGcMhh38lw=")
os.environ.setdefault("GITHUB_CLIENT_ID", "test-client-id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "test-client-secret")

from app.connectors.enums import ConnectorProvider, ConnectorStatus, MonitoringStatus
from app.connectors.github import security
from app.connectors.github.oauth import ExchangedToken, OAuthAppStrategy
from app.connectors.registry import registry
from app.core.secrets import manager as secrets_manager
from app.core.secrets.encryption import EncryptionError
from app.db import get_sessionmaker
from app.models import ConnectorInstallation, Run
from app.models.github import GithubInstallation, GithubRepository, GithubWebhook, GithubWebhookDelivery


# =============================================================================
# Unit: encryption
# =============================================================================
def test_encryption_roundtrip():
    ct = secrets_manager.store_secret("gho_supersecrettoken")
    assert secrets_manager.read_secret(ct) == "gho_supersecrettoken"


def test_encryption_ciphertext_is_not_plaintext():
    ct = secrets_manager.store_secret("gho_supersecrettoken")
    assert "gho_supersecrettoken" not in ct


def test_encryption_rejects_tampered_ciphertext():
    ct = secrets_manager.store_secret("a-token")
    raw = bytearray(base64.b64decode(ct))
    raw[-1] ^= 0xFF     # flip a bit inside the GCM tag/ciphertext
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(EncryptionError):
        secrets_manager.read_secret(tampered)


def test_encryption_rejects_garbage():
    with pytest.raises(EncryptionError):
        secrets_manager.read_secret("not-base64-!!!")


def test_rotate_secret_preserves_plaintext():
    ct = secrets_manager.store_secret("rotate-me")
    rotated = secrets_manager.rotate_secret(ct)
    assert secrets_manager.read_secret(rotated) == "rotate-me"


# =============================================================================
# Unit: PKCE + signed state
# =============================================================================
def test_pkce_pair_shapes():
    verifier, challenge = security.generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert verifier != challenge
    # challenge must be the S256 transform, not a copy of the verifier
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


def test_state_roundtrip_and_single_use(monkeypatch):
    db = get_sessionmaker()()
    try:
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        _make_org_and_user(db, org_id, user_id)
        verifier, _ = security.generate_pkce_pair()
        token = security.create_oauth_state(db, org_id=org_id, user_id=user_id, code_verifier=verifier)
        db.commit()

        resolved = security.consume_oauth_state(db, token)
        db.commit()
        assert resolved.org_id == org_id
        assert resolved.code_verifier == verifier

        with pytest.raises(security.StateError):
            security.consume_oauth_state(db, token)
    finally:
        db.close()


def test_state_tampered_signature_rejected():
    db = get_sessionmaker()()
    try:
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        _make_org_and_user(db, org_id, user_id)
        verifier, _ = security.generate_pkce_pair()
        token = security.create_oauth_state(db, org_id=org_id, user_id=user_id, code_verifier=verifier)
        db.commit()
        payload_b64, sig = token.split(".", 1)
        tampered = f"{payload_b64}.{'0' * len(sig)}"
        with pytest.raises(security.StateError, match="signature"):
            security.consume_oauth_state(db, tampered)
    finally:
        db.close()


def test_state_expired_rejected():
    db = get_sessionmaker()()
    try:
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        _make_org_and_user(db, org_id, user_id)
        verifier, _ = security.generate_pkce_pair()
        token = security.create_oauth_state(db, org_id=org_id, user_id=user_id, code_verifier=verifier)
        db.commit()
        sid = token.split(".", 1)[0]
        from app.models.github import GithubOAuthState
        import base64 as b64
        padded = sid + "=" * (-len(sid) % 4)
        row_sid = json.loads(b64.urlsafe_b64decode(padded))["sid"]
        row = db.get(GithubOAuthState, row_sid)
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        with pytest.raises(security.StateError, match="expired"):
            security.consume_oauth_state(db, token)
    finally:
        db.close()


# =============================================================================
# Unit: webhook HMAC + replay
# =============================================================================
def _fake_webhook(secret: str, previous_secret: str | None = None, previous_expired: bool = False) -> GithubWebhook:
    wh = GithubWebhook(
        id=uuid.uuid4(), repository_id=uuid.uuid4(), webhook_id=1, callback_url="http://x/webhook",
        active=True, secret_encrypted=secrets_manager.store_secret(secret),
        delivery_secret_hash=security.hash_secret(secret),
    )
    if previous_secret:
        wh.previous_secret_encrypted = secrets_manager.store_secret(previous_secret)
        wh.previous_secret_hash = security.hash_secret(previous_secret)
        wh.previous_secret_expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1) if previous_expired
            else datetime.now(timezone.utc) + timedelta(hours=1)
        )
    return wh


def test_valid_signature_verifies():
    wh = _fake_webhook("s3cr3t")
    body = b'{"zen":"ok"}'
    sig = "sha256=" + hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    security.verify_delivery_signature(body, sig, wh)     # must not raise


def test_tampered_body_rejected():
    wh = _fake_webhook("s3cr3t")
    body = b'{"repo":"good/repo"}'
    sig = "sha256=" + hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    with pytest.raises(security.BadSignature):
        security.verify_delivery_signature(b'{"repo":"evil/repo"}', sig, wh)


def test_previous_secret_valid_inside_grace_window():
    wh = _fake_webhook("new-secret", previous_secret="old-secret")
    body = b'{"a":1}'
    sig = "sha256=" + hmac.new(b"old-secret", body, hashlib.sha256).hexdigest()
    security.verify_delivery_signature(body, sig, wh)      # old secret still verifies


def test_previous_secret_rejected_after_grace_window():
    wh = _fake_webhook("new-secret", previous_secret="old-secret", previous_expired=True)
    body = b'{"a":1}'
    sig = "sha256=" + hmac.new(b"old-secret", body, hashlib.sha256).hexdigest()
    with pytest.raises(security.BadSignature):
        security.verify_delivery_signature(body, sig, wh)


def test_oversized_payload_rejected_by_content_length():
    with pytest.raises(security.PayloadTooLarge):
        security.check_content_length(security.MAX_WEBHOOK_BODY_BYTES + 1)


def test_replay_detection():
    db = get_sessionmaker()()
    try:
        delivery_id = f"dlv-{uuid.uuid4()}"
        security.check_replay(db, delivery_id)     # first time: no raise
        db.add(GithubWebhookDelivery(id=uuid.uuid4(), delivery_id=delivery_id, event="push", signature_verified=True))
        db.commit()
        with pytest.raises(security.ReplayDetected):
            security.check_replay(db, delivery_id)
    finally:
        db.close()


# =============================================================================
# Unit: registry
# =============================================================================
def test_registry_resolves_github():
    connector = registry.get(ConnectorProvider.GITHUB)
    assert connector.provider == ConnectorProvider.GITHUB


def test_registry_unknown_provider_raises():
    with pytest.raises(LookupError):
        registry.get("not-a-real-provider")     # type: ignore[arg-type]


# =============================================================================
# Security: archive path traversal
# =============================================================================
def test_archive_path_traversal_rejected(tmp_path):
    from app.connectors.github.clone import _safe_extract

    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../../etc/passwd")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(Exception):     # tarfile's own "data" filter raises on traversal
        _safe_extract(evil, dest)
    assert not (tmp_path / "etc" / "passwd").exists()


# =============================================================================
# Integration helpers
# =============================================================================
def _make_org_and_user(db, org_id: uuid.UUID, user_id: uuid.UUID) -> None:
    from app.models import Org, User
    db.add(Org(id=org_id, name="T", slug=f"t-{org_id.hex[:8]}"))
    db.add(User(id=user_id, email=f"{user_id.hex[:8]}@example.com", password_hash="x", name="T"))
    db.flush()


def _connected_installation(db, org_id: uuid.UUID, user_id: uuid.UUID) -> GithubInstallation:
    connector_row = ConnectorInstallation(
        id=uuid.uuid4(), provider=ConnectorProvider.GITHUB.value, organization_id=org_id,
        user_id=user_id, status=ConnectorStatus.HEALTHY.value,
    )
    db.add(connector_row)
    db.flush()
    gh = GithubInstallation(
        id=uuid.uuid4(), connector_installation_id=connector_row.id, organization_id=org_id, user_id=user_id,
        auth_strategy="oauth_app", access_token_encrypted=secrets_manager.store_secret("gho_test_token"),
        github_account_id=1, github_account_login="octocat", github_account_type="User",
    )
    db.add(gh)
    db.flush()
    return gh


def _monitored_repo_with_webhook(db, gh: GithubInstallation, *, secret: str, full_name="octo/demo"):
    from app.models import Project
    project = Project(id=uuid.uuid4(), org_id=gh.organization_id, name="demo", source="github",
                       origin=full_name, branch="main", context_complete=False)
    db.add(project)
    db.flush()
    repo = GithubRepository(
        id=uuid.uuid4(), github_installation_id=gh.id, project_id=project.id,
        github_repo_id=999, full_name=full_name, owner_login="octo", name="demo",
        private=True, permission_admin=True, permission_push=True, permission_pull=True,
        monitoring_status=MonitoringStatus.MONITORED.value,
    )
    db.add(repo)
    db.flush()
    webhook = GithubWebhook(
        id=uuid.uuid4(), repository_id=repo.id, webhook_id=555, callback_url="http://x/webhook",
        active=True, secret_encrypted=secrets_manager.store_secret(secret),
        delivery_secret_hash=security.hash_secret(secret),
    )
    db.add(webhook)
    db.commit()
    return project, repo, webhook


def PUSH_BODY(repo_id: int, sha: str) -> bytes:
    return json.dumps({
        "ref": "refs/heads/main", "before": "0" * 40, "after": sha, "deleted": False,
        "pusher": {"name": "octocat"},
        "repository": {"id": repo_id, "full_name": "octo/demo", "default_branch": "main", "private": True},
        "head_commit": {"message": "fix bug"},
        "commits": [{"added": ["a.py"], "modified": [], "removed": []}],
    }).encode()


def _sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _webhook_headers(body: bytes, secret: str, *, hook_id: int, event: str, delivery_id: str) -> dict:
    return {
        "x-github-hook-id": str(hook_id), "x-github-event": event, "x-github-delivery": delivery_id,
        "x-hub-signature-256": _sign(body, secret), "content-length": str(len(body)),
    }


@pytest.fixture
def gh_db():
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()


# =============================================================================
# Integration: OAuth callback
# =============================================================================
def test_oauth_authorize_and_callback_happy_path(client, auth_headers, monkeypatch):
    headers, org_id, _ = auth_headers()

    r = client.get("/connectors/github/authorize", headers=headers)
    assert r.status_code == 200, r.text
    authorize_url = r.json()["authorize_url"]
    assert "code_challenge=" in authorize_url and "state=" in authorize_url
    state = authorize_url.split("state=")[1].split("&")[0]
    import urllib.parse
    state = urllib.parse.unquote(state)

    def fake_exchange_code(self, *, code, code_verifier):
        return ExchangedToken(access_token="gho_fake", refresh_token=None, expires_in=None,
                              scopes=["repo"], account_id=42, account_login="octocat", account_type="User")

    monkeypatch.setattr(OAuthAppStrategy, "exchange_code", fake_exchange_code)
    # /callback triggers an automatic post-connect sync - fake that too, so
    # this test never depends on real network reachability.
    from app.connectors.github.client import GitHubClient, Page

    async def fake_list_repositories(self, etag=None):
        return Page(items=[], etag=None)

    monkeypatch.setattr(GitHubClient, "list_repositories", fake_list_repositories)

    r = client.get("/connectors/github/callback", params={"code": "abc", "state": state}, follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "status=connected" in r.headers["location"]

    r = client.get("/connectors/github/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["connected"] is True
    assert body["account_login"] == "octocat"


def test_oauth_callback_invalid_state_rejected(client):
    r = client.get("/connectors/github/callback", params={"code": "abc", "state": "garbage.sig"}, follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "status=error" in r.headers["location"]


def test_oauth_callback_expired_state_rejected(client, auth_headers):
    headers, org_id, _ = auth_headers("expire@example.com", "Expire Org")
    r = client.get("/connectors/github/authorize", headers=headers)
    authorize_url = r.json()["authorize_url"]
    import urllib.parse
    state = urllib.parse.unquote(authorize_url.split("state=")[1].split("&")[0])

    db = get_sessionmaker()()
    from app.models.github import GithubOAuthState
    import base64 as b64, json as j
    payload_b64 = state.split(".", 1)[0]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    sid = j.loads(b64.urlsafe_b64decode(padded))["sid"]
    row = db.get(GithubOAuthState, sid)
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    db.close()

    r = client.get("/connectors/github/callback", params={"code": "abc", "state": state}, follow_redirects=False)
    assert "status=error" in r.headers["location"]


# =============================================================================
# Integration: webhook delivery -> Run, replay, dedup
# =============================================================================
def test_push_webhook_creates_exactly_one_run(client, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    secret = "webhook-secret-1"
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret=secret)

    body = PUSH_BODY(repo.github_repo_id, "a" * 40)
    headers = _webhook_headers(body, secret, hook_id=webhook.webhook_id, event="push", delivery_id=f"d-{uuid.uuid4()}")
    r = client.post("/connectors/github/webhook", content=body, headers=headers)
    assert r.status_code == 202, r.text
    assert r.json()["ok"] is True
    run_id = r.json()["run_id"]
    assert run_id is not None

    count = gh_db.query(Run).filter(Run.project_id == project.id).count()
    assert count == 1


def test_duplicate_delivery_id_rejected_as_replay(client, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    secret = "webhook-secret-2"
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret=secret)

    body = PUSH_BODY(repo.github_repo_id, "b" * 40)
    delivery_id = f"d-{uuid.uuid4()}"
    headers = _webhook_headers(body, secret, hook_id=webhook.webhook_id, event="push", delivery_id=delivery_id)

    r1 = client.post("/connectors/github/webhook", content=body, headers=headers)
    assert r1.status_code == 202
    r2 = client.post("/connectors/github/webhook", content=body, headers=headers)
    assert r2.status_code == 409
    assert r2.json()["error"] == "replay_detected"

    count = gh_db.query(Run).filter(Run.project_id == project.id).count()
    assert count == 1


def test_invalid_signature_rejected(client, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret="correct-secret")

    body = PUSH_BODY(repo.github_repo_id, "c" * 40)
    headers = _webhook_headers(body, "wrong-secret", hook_id=webhook.webhook_id, event="push", delivery_id=f"d-{uuid.uuid4()}")
    r = client.post("/connectors/github/webhook", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"] == "bad_signature"
    assert gh_db.query(Run).filter(Run.project_id == project.id).count() == 0


def test_push_for_unselected_repo_is_a_noop(client, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    secret = "webhook-secret-3"
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret=secret)
    repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value    # user just unselected it
    gh_db.commit()

    body = PUSH_BODY(repo.github_repo_id, "d" * 40)
    headers = _webhook_headers(body, secret, hook_id=webhook.webhook_id, event="push", delivery_id=f"d-{uuid.uuid4()}")
    r = client.post("/connectors/github/webhook", content=body, headers=headers)
    assert r.status_code == 202
    assert r.json()["run_id"] is None
    assert gh_db.query(Run).filter(Run.project_id == project.id).count() == 0


def test_concurrent_push_webhooks_create_exactly_one_run(client, gh_db):
    """Two deliveries for the same repository, fired from two threads at
    once, must serialize on the `Project` row lock rather than both seeing
    'nothing running yet'."""
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    secret = "webhook-secret-4"
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret=secret)

    def _fire(i: int):
        body = PUSH_BODY(repo.github_repo_id, f"{i:040d}")
        headers = _webhook_headers(body, secret, hook_id=webhook.webhook_id, event="push", delivery_id=f"race-{i}-{uuid.uuid4()}")
        return client.post("/connectors/github/webhook", content=body, headers=headers)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_fire, [1, 2]))

    assert all(r.status_code == 202 for r in results)
    active = gh_db.query(Run).filter(
        Run.project_id == project.id, Run.state.in_(("queued", "running"))
    ).count()
    assert active == 1


def test_manual_scan_creates_run(client, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret="s")

    # The manual-scan route is org-scoped through the real auth dependency,
    # so drive it through a real registered+logged-in user for that same org.
    from app.services import auth as auth_svc
    from app.models import Membership
    gh_db.add(Membership(id=uuid.uuid4(), user_id=user_id, org_id=org_id, role="owner"))
    gh_db.commit()
    token = auth_svc.create_access_token(user_id)
    req_headers = {"Authorization": f"Bearer {token}", "X-Org-Id": str(org_id)}

    r = client.post(f"/connectors/github/repositories/{repo.id}/scan", headers=req_headers)
    assert r.status_code == 202, r.text
    assert gh_db.query(Run).filter(Run.project_id == project.id, Run.trigger == "manual").count() == 1


def test_disconnect_removes_webhooks_and_preserves_audit(client, monkeypatch, gh_db):
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    _make_org_and_user(gh_db, org_id, user_id)
    gh = _connected_installation(gh_db, org_id, user_id)
    project, repo, webhook = _monitored_repo_with_webhook(gh_db, gh, secret="s")

    from app.models import Membership
    gh_db.add(Membership(id=uuid.uuid4(), user_id=user_id, org_id=org_id, role="owner"))
    gh_db.commit()

    from app.connectors.github.client import GitHubClient
    from app.connectors.github.oauth import OAuthAppStrategy

    async def fake_delete_webhook(self, full_name, webhook_id):
        return None
    monkeypatch.setattr(GitHubClient, "delete_webhook", fake_delete_webhook)
    monkeypatch.setattr(OAuthAppStrategy, "revoke", lambda self, db, installation: None)

    from app.services import auth as auth_svc
    token = auth_svc.create_access_token(user_id)
    req_headers = {"Authorization": f"Bearer {token}", "X-Org-Id": str(org_id)}

    from app.models import AuditLog
    audit_before = gh_db.query(AuditLog).filter(AuditLog.org_id == org_id).count()
    gh_db.commit()  # end this read's transaction - MySQL is REPEATABLE READ, and the
                    # disconnect call below runs on a separate session/connection

    r = client.delete("/connectors/github/disconnect", headers=req_headers)
    assert r.status_code == 200, r.text
    gh_db.commit()  # likewise: start a fresh transaction before reading what the request committed

    assert gh_db.query(GithubWebhook).filter(GithubWebhook.repository_id == repo.id).count() == 0
    assert gh_db.query(GithubInstallation).filter(GithubInstallation.id == gh.id).first() is None
    audit_after = gh_db.query(AuditLog).filter(AuditLog.org_id == org_id).count()
    assert audit_after > audit_before      # nothing already written was removed, more was appended

    connector_row = gh_db.get(ConnectorInstallation, gh.connector_installation_id)
    assert connector_row.status == ConnectorStatus.DISCONNECTED.value
