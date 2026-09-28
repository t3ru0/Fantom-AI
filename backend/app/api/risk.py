"""Risk aggregates for charts: org-wide rollup and per-project breakdown +
trend. Reads straight from `Finding` (current state) and `ExposureHistory`
(the daily rollup the orchestrator writes at the end of every run) — nothing
here is recomputed from scratch on every request.
"""
from __future__ import annotations

import uuid
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.findings import tier_name
from app.db import get_db
from app.deps import get_current_org
from app.models import ExposureHistory, Finding, Membership, Org, Project
from app.schemas_findings import OrgRiskOut, ProjectRiskOut
from app.services.money import portfolio_from_rows

router = APIRouter(prefix="/api", tags=["risk"])


@router.get("/risk/org", response_model=OrgRiskOut)
def org_risk(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> OrgRiskOut:
    org, _ = ctx
    projects = db.query(Project).filter(Project.org_id == org.id).all()

    open_q = db.query(Finding).join(Project, Project.id == Finding.project_id).filter(
        Project.org_id == org.id, Finding.state == "open")
    findings_open = open_q.count()
    findings_critical = open_q.filter(Finding.context_score >= 80).count()
    avg_score = open_q.with_entities(func.avg(Finding.context_score)).scalar()

    per_project = []
    total_exposure = 0.0
    any_exposure = False
    for p in projects:
        open_findings = db.query(Finding).filter(Finding.project_id == p.id, Finding.state == "open").all()
        pv = portfolio_from_rows(open_findings, float(p.revenue_supported) if p.revenue_supported else None)
        exposure = pv["exposure"] if p.context_complete and pv["priced"] else None
        if exposure is not None:
            total_exposure += exposure
            any_exposure = True
        scores = [f.context_score for f in open_findings if f.context_score is not None]
        per_project.append({
            "project_id": str(p.id), "repo": p.origin,
            "findings_open": len(open_findings),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
            "exposure": exposure,
        })

    return OrgRiskOut(
        org_risk_score=round(float(avg_score), 1) if avg_score is not None else None,
        findings_open=findings_open, findings_critical=findings_critical,
        total_exposure=round(total_exposure, 2) if any_exposure else None,
        projects=per_project,
    )


@router.get("/risk/projects/{project_id}", response_model=ProjectRiskOut)
def project_risk(project_id: uuid.UUID, days: int = Query(90, ge=1, le=365),
                  ctx: tuple[Org, Membership] = Depends(get_current_org),
                  db: Session = Depends(get_db)) -> ProjectRiskOut:
    org, _ = ctx
    project = db.get(Project, project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="project not found")

    open_findings = db.query(Finding).filter(Finding.project_id == project.id, Finding.state == "open").all()
    scores = [f.context_score for f in open_findings if f.context_score is not None]
    findings_open = len(open_findings)
    findings_critical = sum(1 for s in scores if s >= 80)
    pv = portfolio_from_rows(open_findings, float(project.revenue_supported) if project.revenue_supported else None)
    exposure = pv["exposure"] if project.context_complete and pv["priced"] else None

    tiers = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for s in scores:
        name = tier_name(s)
        if name:
            tiers[name] += 1

    since = date.today() - timedelta(days=days)
    trend_rows = (
        db.query(ExposureHistory)
        .filter(ExposureHistory.project_id == project.id, ExposureHistory.day >= since)
        .order_by(ExposureHistory.day.asc())
        .all()
    )
    trend = [
        {"day": r.day.isoformat(), "exposure": float(r.exposure) if r.exposure is not None else None,
         "findings_open": r.findings_open, "findings_critical": r.findings_critical}
        for r in trend_rows
    ]

    return ProjectRiskOut(
        project_id=str(project.id),
        context_score_avg=round(sum(scores) / len(scores), 1) if scores else None,
        context_score_max=max(scores) if scores else None,
        tier_distribution=tiers,
        findings_open=findings_open, findings_critical=findings_critical,
        exposure=exposure,
        trend=trend,
    )
