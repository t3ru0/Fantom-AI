"""Phase F/G/H: findings list/detail/state, portfolio pricing (aggregated, not
summed), and org/project risk rollups — seeded directly with Finding rows
(as the orchestrator would write them) rather than a live network scan.
"""
from __future__ import annotations

import uuid

from app.db import get_sessionmaker
from app.models import Finding, Project


def _seed_project_with_finding(client, headers, project_id, **overrides):
    Session = get_sessionmaker()
    db = Session()
    defaults = dict(
        id=uuid.uuid4(), project_id=uuid.UUID(project_id), fingerprint=str(uuid.uuid4()),
        agent_slug="lib", scanner="osv", title="Prototype pollution in lodash",
        cve="CVE-2021-23337", cwe="CWE-1321", package="lodash", version="4.17.15",
        fixed_version="4.17.21", cvss=7.4, epss=0.45, kev=True, context_score=91, state="open",
        annual_loss=185_000.0, fix_hours=8.0, fix_cost=1200.0, loss_per_hour=23_125.0,
        impact_breakdown={"components": [{"name": "Regulatory penalty", "amount": 400_000, "basis": "test"}],
                          "p_wild_year": 0.7},
    )
    defaults.update(overrides)
    db.add(Finding(**defaults))
    db.commit()
    db.close()


def _project(client, headers, repo="acme/widget-service"):
    r = client.post("/api/projects", json={"repo": repo, "branch": "master"}, headers=headers)
    assert r.status_code == 201
    return r.json()["id"]


def test_findings_list_filters_and_sorts(client, auth_headers):
    headers, org_id, _ = auth_headers("f1@example.com", "Findings Co")
    project_id = _project(client, headers)
    _seed_project_with_finding(client, headers, project_id)
    _seed_project_with_finding(client, headers, project_id, cve="CVE-0000-0001", context_score=20,
                               kev=False, title="Low severity thing")

    all_findings = client.get("/api/findings", params={"project_id": project_id}, headers=headers)
    assert all_findings.json()["total"] == 2

    critical_only = client.get("/api/findings", params={"project_id": project_id, "tier": "Critical"},
                               headers=headers)
    assert critical_only.json()["total"] == 1
    assert critical_only.json()["items"][0]["cve"] == "CVE-2021-23337"

    kev_only = client.get("/api/findings", params={"project_id": project_id, "kev": True}, headers=headers)
    assert kev_only.json()["total"] == 1


def test_finding_detail_and_state_update(client, auth_headers):
    headers, org_id, _ = auth_headers("f2@example.com", "Detail Co")
    project_id = _project(client, headers)
    _seed_project_with_finding(client, headers, project_id)

    listing = client.get("/api/findings", params={"project_id": project_id}, headers=headers).json()
    finding_id = listing["items"][0]["id"]

    detail = client.get(f"/api/findings/{finding_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["tier"] == "Critical"

    update = client.put(f"/api/findings/{finding_id}/state",
                        json={"state": "false_positive", "note": "confirmed safe"}, headers=headers)
    assert update.status_code == 200
    assert update.json()["state"] == "false_positive"
    assert update.json()["note"] == "confirmed safe"

    # excluded from open-findings pricing/risk once no longer open
    pricing = client.get(f"/api/projects/{project_id}/pricing", headers=headers).json()
    assert pricing["priced"] is False


def test_pricing_gated_on_business_context(client, auth_headers):
    # A scan against a project with no business context never prices anything
    # (see money.price() returning None) - so the finding it writes carries no
    # impact_breakdown, exactly like this fixture, not the fully-priced one
    # the other tests use.
    headers, org_id, _ = auth_headers("f3@example.com", "Pricing Co")
    project_id = _project(client, headers)
    _seed_project_with_finding(client, headers, project_id,
                               annual_loss=None, fix_hours=None, fix_cost=None,
                               loss_per_hour=None, impact_breakdown=None)

    unpriced = client.get(f"/api/projects/{project_id}/pricing", headers=headers).json()
    assert unpriced["context_complete"] is False
    assert unpriced["priced"] is False


def test_pricing_aggregates_not_sums(client, auth_headers):
    headers, org_id, _ = auth_headers("f4@example.com", "Aggregate Co")
    project_id = _project(client, headers)
    ctx = client.put(f"/api/projects/{project_id}/context", json={
        "revenue_supported": 2_000_000, "downtime_cost_hour": 5000,
        "users_count": 50_000, "records_count": 100_000, "regimes": ["GDPR"],
    }, headers=headers)
    assert ctx.json()["complete"] is True

    _seed_project_with_finding(client, headers, project_id)

    pricing = client.get(f"/api/projects/{project_id}/pricing", headers=headers).json()
    assert pricing["priced"] is True
    # worst_shared(400000) * p_any(1-(1-0.7)) = 280000, not the naive 185000 annual_loss sum
    assert pricing["exposure"] == 280_000.0
    assert pricing["naive_sum"] == 185_000.0
    assert pricing["exposure"] != pricing["naive_sum"]


def test_org_risk_rollup(client, auth_headers):
    headers, org_id, _ = auth_headers("f5@example.com", "Risk Co")
    project_id = _project(client, headers)
    _seed_project_with_finding(client, headers, project_id)

    risk = client.get("/api/risk/org", headers=headers)
    assert risk.status_code == 200
    body = risk.json()
    assert body["findings_open"] == 1
    assert body["findings_critical"] == 1
    assert body["org_risk_score"] == 91.0

    project_risk = client.get(f"/api/risk/projects/{project_id}", headers=headers).json()
    assert project_risk["tier_distribution"]["Critical"] == 1
