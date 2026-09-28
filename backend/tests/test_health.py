"""Part 0 acceptance: the app boots and reports honestly with no database."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "FANTOM"
    # Phase-agnostic: this must not need editing every time a phase ships.
    assert isinstance(body["build_phase"], int) and body["build_phase"] >= 0
    assert body["phase_name"]


def test_health_always_200_even_without_db():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert set(body["components"]) == {"database", "github_app", "llm"}


def test_health_names_what_is_missing():
    body = client.get("/health").json()
    db = body["components"]["database"]
    if not db["ok"]:
        assert "docker compose" in db["hint"]


def test_ready_503_when_db_down():
    r = client.get("/ready")
    assert r.status_code in (200, 503)
    if r.status_code == 503:
        assert r.json()["ready"] is False
