"""Report generation, status, download, history."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org
from app.models import Membership, Org, Project, Report
from app.models.tables import REPORT_KINDS
from app.schemas_findings import ReportCreate, ReportOut
from app.services.audit import log_action

router = APIRouter(prefix="/api", tags=["reports"])


def _out(r: Report) -> ReportOut:
    return ReportOut(id=str(r.id), org_id=str(r.org_id), project_id=str(r.project_id) if r.project_id else None,
                     kind=r.kind, status=r.status, created_at=r.created_at, finished_at=r.finished_at)


@router.post("/reports", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
def create_report(payload: ReportCreate, ctx: tuple[Org, Membership] = Depends(get_current_org),
                   db: Session = Depends(get_db)) -> ReportOut:
    org, actor = ctx
    if payload.kind not in REPORT_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"kind must be one of {REPORT_KINDS}")
    project_uuid = None
    if payload.project_id:
        project_uuid = uuid.UUID(payload.project_id)
        p = db.get(Project, project_uuid)
        if p is None or p.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="project not found")

    report = Report(id=uuid.uuid4(), org_id=org.id, project_id=project_uuid,
                    kind=payload.kind, status="queued", requested_by=actor.user_id)
    db.add(report)
    log_action(db, org_id=org.id, project_id=project_uuid, action="report.create", detail=payload.kind)
    db.commit()

    from app.services.reports import generate
    from app.workers.runner import submit
    submit(generate, report.id)
    return _out(report)


@router.get("/reports", response_model=list[ReportOut])
def list_reports(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[ReportOut]:
    org, _ = ctx
    rows = db.query(Report).filter(Report.org_id == org.id).order_by(Report.created_at.desc()).limit(50).all()
    return [_out(r) for r in rows]


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                db: Session = Depends(get_db)) -> ReportOut:
    org, _ = ctx
    r = db.get(Report, report_id)
    if r is None or r.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="report not found")
    return _out(r)


@router.get("/reports/{report_id}/download")
def download_report(report_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                     db: Session = Depends(get_db)):
    org, _ = ctx
    r = db.get(Report, report_id)
    if r is None or r.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="report not found")
    if r.status != "done" or not r.file_path:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"report is {r.status}, not ready")
    return FileResponse(r.file_path, filename=f"fantom-{r.kind}-report-{str(r.id)[:8]}.md",
                        media_type="text/markdown")
