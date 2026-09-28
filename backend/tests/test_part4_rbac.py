"""Phase B: org scoping and role-gated membership/invitation mutations."""
from __future__ import annotations


def test_viewer_cannot_change_roles(client, auth_headers):
    owner_headers, org_id, owner_tok = auth_headers("owner1@example.com", "RBAC Co")

    # invite a second user as viewer, accept it, then try a role change as them
    inv = client.post("/api/orgs/current/invitations", json={"email": "viewer1@example.com", "role": "viewer"},
                      headers=owner_headers)
    assert inv.status_code == 201

    from app.db import get_sessionmaker
    from app.models import Invitation
    db = get_sessionmaker()()
    token = db.query(Invitation).filter(Invitation.email == "viewer1@example.com").first().token
    db.close()

    accept = client.post("/api/invitations/accept",
                         json={"token": token, "password": "password123", "name": "Viewer One"})
    assert accept.status_code == 200
    viewer_tok = accept.json()
    viewer_headers = {"Authorization": f"Bearer {viewer_tok['access_token']}", "X-Org-Id": org_id}

    members = client.get("/api/orgs/current/members", headers=viewer_headers)
    assert members.status_code == 200
    assert len(members.json()) == 2

    other_user_id = next(m["user_id"] for m in members.json() if m["email"] == "owner1@example.com")
    forbidden = client.put(f"/api/orgs/current/members/{other_user_id}", json={"role": "admin"},
                           headers=viewer_headers)
    assert forbidden.status_code == 403


def test_cross_org_project_not_visible(client, auth_headers):
    headers_a, org_a, _ = auth_headers("orga@example.com", "Org A")
    headers_b, org_b, _ = auth_headers("orgb@example.com", "Org B")

    created = client.post("/api/projects", json={"repo": "acme/widget-service", "branch": "master"},
                          headers=headers_a)
    assert created.status_code == 201
    project_id = created.json()["id"]

    same_org = client.get(f"/api/projects/{project_id}", headers=headers_a)
    assert same_org.status_code == 200

    cross_org = client.get(f"/api/projects/{project_id}", headers=headers_b)
    assert cross_org.status_code == 404


def test_invitation_expired_rejected(client, auth_headers):
    headers, org_id, _ = auth_headers("owner2@example.com", "Expiry Co")
    client.post("/api/orgs/current/invitations", json={"email": "late@example.com", "role": "developer"},
               headers=headers)

    from datetime import datetime, timedelta, timezone
    from app.db import get_sessionmaker
    from app.models import Invitation
    db = get_sessionmaker()()
    inv = db.query(Invitation).filter(Invitation.email == "late@example.com").first()
    inv.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    token = inv.token
    db.commit()
    db.close()

    r = client.post("/api/invitations/accept", json={"token": token, "password": "password123", "name": "Late"})
    assert r.status_code == 410
