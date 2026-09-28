"""Shared test fixtures.

Points DATABASE_URL at a dedicated `fantom_test` schema on the same local
MySQL - not SQLite, because `app.db.get_engine()` passes a MySQL-specific
`connect_timeout` connect_arg that SQLite's driver rejects, and testing
against the real target dialect avoids MySQL/SQLite behavioural divergence
bugs anyway. Must be set before `app.config` is imported anywhere, which is
why it's the first thing this file does.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "mysql+pymysql://root:@localhost:3306/fantom_test")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production-use-32bytes")

import pytest
from sqlalchemy import text

from app import db as db_module
from app.models import Base


@pytest.fixture(scope="session", autouse=True)
def _schema():
    engine = db_module.get_engine()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _clean_tables():
    yield
    engine = db_module.get_engine()
    with engine.begin() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Registers a fresh user+org and returns (headers_with_org, org_id, user_email)."""
    def _make(email: str = "user@example.com", org_name: str = "Test Org"):
        r = client.post("/api/auth/register", json={
            "email": email, "password": "password123", "name": "Test User", "org_name": org_name,
        })
        assert r.status_code == 201, r.text
        tok = r.json()
        headers = {"Authorization": f"Bearer {tok['access_token']}"}
        org_id = client.get("/api/auth/me", headers=headers).json()["memberships"][0]["org_id"]
        headers["X-Org-Id"] = org_id
        return headers, org_id, tok
    return _make
