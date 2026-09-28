"""Phase A/L: registration, login, refresh rotation, logout, audit log."""
from __future__ import annotations


def test_register_creates_user_and_owner_membership(client):
    r = client.post("/api/auth/register", json={
        "email": "alice@example.com", "password": "password123",
        "name": "Alice", "org_name": "Alice Co",
    })
    assert r.status_code == 201
    tok = r.json()
    assert "access_token" in tok and "refresh_token" in tok

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok['access_token']}"})
    assert me.status_code == 200
    body = me.json()
    assert body["user"]["email"] == "alice@example.com"
    assert len(body["memberships"]) == 1
    assert body["memberships"][0]["role"] == "owner"


def test_register_duplicate_email_rejected(client):
    payload = {"email": "dup@example.com", "password": "password123", "name": "A", "org_name": "Org A"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    r2 = client.post("/api/auth/register", json=payload)
    assert r2.status_code == 409


def test_login_wrong_password_rejected(client, auth_headers):
    auth_headers("bob@example.com", "Bob Co")
    r = client.post("/api/auth/login", json={"email": "bob@example.com", "password": "wrong"})
    assert r.status_code == 401


def test_me_requires_bearer_token(client):
    assert client.get("/api/auth/me").status_code == 401


def test_refresh_rotates_and_old_token_dies(client, auth_headers):
    _, _, tok = auth_headers("carol@example.com", "Carol Co")
    r1 = client.post("/api/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert r1.status_code == 200
    # the original refresh token was revoked by rotation - reusing it must fail
    r2 = client.post("/api/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert r2.status_code == 401


def test_logout_revokes_refresh_token(client, auth_headers):
    _, _, tok = auth_headers("dave@example.com", "Dave Co")
    assert client.post("/api/auth/logout", json={"refresh_token": tok["refresh_token"]}).status_code == 204
    r = client.post("/api/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert r.status_code == 401


def test_password_reset_round_trip(client, auth_headers):
    auth_headers("erin@example.com", "Erin Co")
    req = client.post("/api/auth/password-reset/request", json={"email": "erin@example.com"})
    assert req.status_code == 202

    from app.db import get_sessionmaker
    from app.models import User
    from app.services import auth as auth_svc
    db = get_sessionmaker()()
    user = db.query(User).filter(User.email == "erin@example.com").first()
    token = auth_svc.create_reset_token(user.id)
    db.close()

    confirm = client.post("/api/auth/password-reset/confirm", json={"token": token, "new_password": "newpassword456"})
    assert confirm.status_code == 204

    old = client.post("/api/auth/login", json={"email": "erin@example.com", "password": "password123"})
    assert old.status_code == 401
    new = client.post("/api/auth/login", json={"email": "erin@example.com", "password": "newpassword456"})
    assert new.status_code == 200


def test_register_writes_audit_log(client, auth_headers):
    headers, org_id, _ = auth_headers("frank@example.com", "Frank Co")
    r = client.get("/api/audit", headers=headers)
    assert r.status_code == 200
    actions = [row["action"] for row in r.json()]
    assert "user.register" in actions
