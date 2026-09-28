"""Phase J/K: report generation (run synchronously for a deterministic test,
not via the background pool) and in-app notifications + outbound channels.
"""
from __future__ import annotations

import uuid

from app.db import get_sessionmaker
from app.models import Report


def _project(client, headers, repo="acme/widget-service"):
    r = client.post("/api/projects", json={"repo": repo, "branch": "master"}, headers=headers)
    assert r.status_code == 201
    return r.json()["id"]


def test_report_generation_and_download(client, auth_headers):
    headers, org_id, _ = auth_headers("r1@example.com", "Report Co")
    project_id = _project(client, headers)

    created = client.post("/api/reports", json={"kind": "executive", "project_id": project_id}, headers=headers)
    assert created.status_code == 202
    report_id = created.json()["id"]

    from app.services.reports import generate
    generate(uuid.UUID(report_id))

    status_row = client.get(f"/api/reports/{report_id}", headers=headers)
    assert status_row.json()["status"] == "done"

    dl = client.get(f"/api/reports/{report_id}/download", headers=headers)
    assert dl.status_code == 200
    assert "Executive risk summary" in dl.text
    assert "acme/widget-service" in dl.text


def test_report_rejects_unknown_kind(client, auth_headers):
    headers, org_id, _ = auth_headers("r2@example.com", "Bad Kind Co")
    r = client.post("/api/reports", json={"kind": "not-a-real-kind"}, headers=headers)
    assert r.status_code == 400


def test_download_before_ready_rejected(client, auth_headers):
    headers, org_id, _ = auth_headers("r3@example.com", "Not Ready Co")
    created = client.post("/api/reports", json={"kind": "technical"}, headers=headers)
    report_id = created.json()["id"]
    # queued, generate() not called yet
    dl = client.get(f"/api/reports/{report_id}/download", headers=headers)
    assert dl.status_code == 409


def test_notification_created_and_marked_read(client, auth_headers):
    headers, org_id, _ = auth_headers("n1@example.com", "Notify Co")
    project_id = _project(client, headers)

    from app.db import get_sessionmaker
    from app.models import Project
    from app.services.notify import on_repo_connected
    db = get_sessionmaker()()
    project = db.get(Project, uuid.UUID(project_id))
    on_repo_connected(db, project)
    db.close()

    listed = client.get("/api/notifications", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    notif = listed.json()[0]
    assert notif["kind"] == "repo_connected"
    assert notif["read_at"] is None

    mark = client.put(f"/api/notifications/{notif['id']}/read", headers=headers)
    assert mark.status_code == 204

    unread = client.get("/api/notifications", params={"unread_only": True}, headers=headers)
    assert unread.json() == []


def test_notification_channel_outbound_send(client, auth_headers, monkeypatch):
    headers, org_id, _ = auth_headers("n2@example.com", "Webhook Co")
    project_id = _project(client, headers)

    ch = client.post("/api/notifications/channels", json={"kind": "webhook", "target": "https://example.test/hook"},
                     headers=headers)
    assert ch.status_code == 201

    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"] = url
        sent["json"] = json
        class R:
            status_code = 200
        return R()

    import app.services.notify as notify_mod
    monkeypatch.setattr(notify_mod.httpx, "post", fake_post)

    from app.db import get_sessionmaker
    from app.models import Project
    db = get_sessionmaker()()
    project = db.get(Project, uuid.UUID(project_id))
    notify_mod.on_repo_connected(db, project)
    db.close()

    assert sent["url"] == "https://example.test/hook"
    assert "acme/widget-service" in sent["json"]["text"]
