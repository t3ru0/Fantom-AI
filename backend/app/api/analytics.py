"""Aggregation queries for dashboard charts. Org-scoped, optionally narrowed
to one project. Everything reads straight off Finding/ExposureHistory - no
new tables, no recomputation of anything the orchestrator already wrote.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org
from app.models import ExposureHistory, Finding, Membership, Org, Project
from app.schemas_findings import AnalyticsOut, TimeseriesPoint

router = APIRouter(prefix="/api", tags=["analytics"])

SLA_DAYS_BY_TIER = {4: 1, 3: 7, 2: 30, 1: 90}
EPSS_BUCKETS = [("0-1%", 0.0, 0.01), ("1-10%", 0.01, 0.10), ("10-50%", 0.10, 0.50), ("50-100%", 0.50, 1.01)]


def _tier(score: int | None) -> int:
    if score is None:
        return 0
    return 4 if score >= 80 else 3 if score >= 60 else 2 if score >= 35 else 1


@router.get("/analytics", response_model=AnalyticsOut)
def analytics(
    project_id: uuid.UUID | None = None,
    days: int = Query(30, ge=1, le=365),
    ctx: tuple[Org, Membership] = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> AnalyticsOut:
    org, _ = ctx
    since_day = date.today() - timedelta(days=days)
    since_dt = datetime.now(timezone.utc) - timedelta(days=days)

    base_findings = db.query(Finding).join(Project, Project.id == Finding.project_id).filter(
        Project.org_id == org.id)
    if project_id is not None:
        base_findings = base_findings.filter(Finding.project_id == project_id)

    # findings over time: count of findings first seen per day
    fot_rows = (
        base_findings.filter(Finding.first_seen_at >= since_dt)
        .with_entities(func.date(Finding.first_seen_at).label("d"), func.count())
        .group_by("d").order_by("d").all()
    )
    findings_over_time = [TimeseriesPoint(day=r[0], value=r[1]) for r in fot_rows]

    # exposure over time: from the daily rollup table
    eh_q = db.query(ExposureHistory).join(Project, Project.id == ExposureHistory.project_id).filter(
        Project.org_id == org.id, ExposureHistory.day >= since_day)
    if project_id is not None:
        eh_q = eh_q.filter(ExposureHistory.project_id == project_id)
    eh_rows = eh_q.order_by(ExposureHistory.day.asc()).all()
    if project_id is not None:
        exposure_over_time = [TimeseriesPoint(day=r.day, value=float(r.exposure or 0)) for r in eh_rows]
    else:
        by_day: dict[date, float] = {}
        for r in eh_rows:
            by_day[r.day] = by_day.get(r.day, 0.0) + float(r.exposure or 0)
        exposure_over_time = [TimeseriesPoint(day=d, value=v) for d, v in sorted(by_day.items())]

    # MTTR: average days between first_seen_at and last_seen_at for fixed findings
    fixed = base_findings.filter(Finding.state == "fixed").with_entities(
        Finding.first_seen_at, Finding.last_seen_at).all()
    mttr_days = (
        round(sum((ls - fs).total_seconds() for fs, ls in fixed) / len(fixed) / 86400, 1)
        if fixed else None
    )

    # SLA compliance: fraction of open findings still within their tier's fix-by window
    open_findings = base_findings.filter(Finding.state == "open").with_entities(
        Finding.context_score, Finding.first_seen_at).all()
    now = datetime.now(timezone.utc)
    scored_open = [(score, fs) for score, fs in open_findings if score is not None]
    if scored_open:
        within = sum(
            1 for score, fs in scored_open
            if (now - (fs if fs.tzinfo else fs.replace(tzinfo=timezone.utc))).days <= SLA_DAYS_BY_TIER[_tier(score)]
        )
        sla_compliance_pct = round(100 * within / len(scored_open), 1)
    else:
        sla_compliance_pct = None

    scanner_breakdown = dict(
        base_findings.filter(Finding.state == "open")
        .with_entities(Finding.scanner, func.count()).group_by(Finding.scanner).all()
    )

    epss_distribution = {}
    epss_vals = [float(e) for (e,) in base_findings.filter(
        Finding.state == "open", Finding.epss.isnot(None)).with_entities(Finding.epss).all()]
    for label, lo, hi in EPSS_BUCKETS:
        epss_distribution[label] = sum(1 for v in epss_vals if lo <= v < hi)

    kev_count = base_findings.filter(Finding.state == "open", Finding.kev.is_(True)).count()

    repo_q = db.query(Project).filter(Project.org_id == org.id)
    if project_id is not None:
        repo_q = repo_q.filter(Project.id == project_id)
    repo_comparison = []
    for p in repo_q.all():
        pf = db.query(Finding).filter(Finding.project_id == p.id, Finding.state == "open")
        repo_comparison.append({
            "project_id": str(p.id), "repo": p.origin,
            "findings_open": pf.count(),
            "findings_critical": pf.filter(Finding.context_score >= 80).count(),
        })

    return AnalyticsOut(
        findings_over_time=findings_over_time,
        exposure_over_time=exposure_over_time,
        mttr_days=mttr_days,
        sla_compliance_pct=sla_compliance_pct,
        scanner_breakdown=scanner_breakdown,
        epss_distribution=epss_distribution,
        kev_count=kev_count,
        repo_comparison=repo_comparison,
    )
