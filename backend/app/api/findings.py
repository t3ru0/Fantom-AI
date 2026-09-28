"""Findings: paginated, filtered, sorted, searched. Every query is org-scoped
by joining through Project - a finding is never reachable outside its org.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org
from app.models import Finding, Membership, Org, Project
from app.models.tables import FINDING_STATES
from app.schemas_findings import FindingDetailOut, FindingListItem, FindingListOut, FindingStateUpdate
from app.services.audit import log_action

router = APIRouter(prefix="/api", tags=["findings"])

SORT_FIELDS = {
    "score": Finding.context_score,
    "cvss": Finding.cvss,
    "epss": Finding.epss,
    "first_seen": Finding.first_seen_at,
    "last_seen": Finding.last_seen_at,
    "annual_loss": Finding.annual_loss,
}


def tier_name(score: int | None) -> str | None:
    if score is None:
        return None
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _item(f: Finding, repo: str) -> FindingListItem:
    return FindingListItem(
        id=str(f.id), project_id=str(f.project_id), repo=repo, scanner=f.scanner,
        title=f.title, cve=f.cve, cwe=f.cwe, package=f.package, file=f.file,
        cvss=float(f.cvss) if f.cvss is not None else None,
        epss=float(f.epss) if f.epss is not None else None,
        kev=f.kev, context_score=f.context_score, tier=tier_name(f.context_score),
        state=f.state, annual_loss=float(f.annual_loss) if f.annual_loss is not None else None,
        first_seen_at=f.first_seen_at, last_seen_at=f.last_seen_at,
    )


@router.get("/findings", response_model=FindingListOut)
def list_findings(
    project_id: uuid.UUID | None = None,
    state: str | None = Query(None, description=f"One of {FINDING_STATES}"),
    scanner: str | None = None,
    tier: str | None = Query(None, description="Low, Medium, High, or Critical"),
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0, le=1),
    search: str | None = None,
    sort: str = Query("score", description=f"One of {', '.join(SORT_FIELDS)}"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    ctx: tuple[Org, Membership] = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> FindingListOut:
    org, _ = ctx
    q = db.query(Finding, Project.origin).join(Project, Project.id == Finding.project_id).filter(
        Project.org_id == org.id)

    if project_id is not None:
        q = q.filter(Finding.project_id == project_id)
    if state is not None:
        if state not in FINDING_STATES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"state must be one of {FINDING_STATES}")
        q = q.filter(Finding.state == state)
    if scanner is not None:
        q = q.filter(Finding.scanner == scanner)
    if kev is not None:
        q = q.filter(Finding.kev == kev)
    if epss_min is not None:
        q = q.filter(Finding.epss >= epss_min)
    if tier is not None:
        bounds = {"Critical": (80, 100), "High": (60, 79), "Medium": (35, 59), "Low": (0, 34)}.get(tier)
        if not bounds:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="tier must be Low, Medium, High, or Critical")
        q = q.filter(Finding.context_score.between(*bounds))
    if search:
        like = f"%{search}%"
        q = q.filter(or_(Finding.title.like(like), Finding.package.like(like),
                         Finding.file.like(like), Finding.cve.like(like)))

    total = q.count()
    col = SORT_FIELDS.get(sort, Finding.context_score)
    col = col.desc() if order == "desc" else col.asc()
    rows = q.order_by(col).offset((page - 1) * page_size).limit(page_size).all()

    return FindingListOut(total=total, page=page, page_size=page_size,
                          items=[_item(f, repo) for f, repo in rows])


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                 db: Session = Depends(get_db)) -> FindingDetailOut:
    org, _ = ctx
    row = db.query(Finding, Project.origin).join(Project, Project.id == Finding.project_id).filter(
        Finding.id == finding_id, Project.org_id == org.id).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="finding not found")
    f, repo = row
    return FindingDetailOut(
        id=str(f.id), project_id=str(f.project_id), repo=repo, fingerprint=f.fingerprint,
        scanner=f.scanner, agent_slug=f.agent_slug, title=f.title, cve=f.cve, cwe=f.cwe,
        rule_id=f.rule_id, file=f.file, line=f.line, package=f.package, version=f.version,
        fixed_version=f.fixed_version,
        cvss=float(f.cvss) if f.cvss is not None else None,
        epss=float(f.epss) if f.epss is not None else None,
        kev=f.kev, exploit_maturity=f.exploit_maturity,
        context_score=f.context_score, tier=tier_name(f.context_score), state=f.state,
        annual_loss=float(f.annual_loss) if f.annual_loss is not None else None,
        fix_hours=float(f.fix_hours) if f.fix_hours is not None else None,
        fix_cost=float(f.fix_cost) if f.fix_cost is not None else None,
        loss_per_hour=float(f.loss_per_hour) if f.loss_per_hour is not None else None,
        remediation=f.remediation,
        first_seen_run=str(f.first_seen_run) if f.first_seen_run else None,
        last_seen_run=str(f.last_seen_run) if f.last_seen_run else None,
        first_seen_at=f.first_seen_at, last_seen_at=f.last_seen_at,
        owner=f.owner, note=f.note,
    )


@router.put("/findings/{finding_id}/state", response_model=FindingDetailOut)
def update_finding_state(finding_id: uuid.UUID, payload: FindingStateUpdate,
                          ctx: tuple[Org, Membership] = Depends(get_current_org),
                          db: Session = Depends(get_db)) -> FindingDetailOut:
    org, actor = ctx
    row = db.query(Finding, Project.origin).join(Project, Project.id == Finding.project_id).filter(
        Finding.id == finding_id, Project.org_id == org.id).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="finding not found")
    f, repo = row
    if payload.state not in FINDING_STATES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"state must be one of {FINDING_STATES}")
    f.state = payload.state
    if payload.note is not None:
        f.note = payload.note
    if payload.owner is not None:
        f.owner = payload.owner
    log_action(db, org_id=org.id, project_id=f.project_id, action="finding.state_change",
               detail=f"{finding_id} -> {payload.state}")
    db.commit()
    return get_finding(finding_id, ctx, db)
