"""Server-sent events over a run's event log.

No pub/sub - `RunEvent` rows are already the durable, seq-ordered event log
the orchestrator writes to as it works, so this endpoint just tails the table:
poll for rows with `seq` greater than the last one sent, emit them, sleep, and
send a heartbeat comment when nothing changed. A reconnect resumes from the
browser's own `Last-Event-ID` header (the SSE spec's mechanism for exactly
this), so a dropped connection loses nothing.
"""
from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session
from starlette.responses import StreamingResponse

from app.db import get_db, get_sessionmaker
from app.deps import get_current_org
from app.models import Membership, Org, Project, Run, RunEvent

router = APIRouter(prefix="/api", tags=["live"])

POLL_S = 0.5
HEARTBEAT_EVERY = 15.0


def _sse(event: RunEvent) -> str:
    data = {
        "seq": event.seq, "ts": event.ts.isoformat(), "agent_slug": event.agent_slug,
        "event": event.event, "message": event.message, "payload": event.payload,
    }
    return f"id: {event.seq}\nevent: {event.event}\ndata: {json.dumps(data)}\n\n"


async def _stream(run_id: uuid.UUID, from_seq: int, request: Request):
    session_factory = get_sessionmaker()
    last_seq = from_seq
    elapsed_since_heartbeat = 0.0
    while True:
        if await request.is_disconnected():
            return
        db = session_factory()
        try:
            rows = (
                db.query(RunEvent)
                .filter(RunEvent.run_id == run_id, RunEvent.seq > last_seq)
                .order_by(RunEvent.seq.asc())
                .all()
            )
            run = db.get(Run, run_id)
        finally:
            db.close()

        if rows:
            for row in rows:
                yield _sse(row)
                last_seq = row.seq
            elapsed_since_heartbeat = 0.0
        else:
            elapsed_since_heartbeat += POLL_S
            if elapsed_since_heartbeat >= HEARTBEAT_EVERY:
                yield ": heartbeat\n\n"
                elapsed_since_heartbeat = 0.0

        if run is not None and run.state in ("done", "failed", "cancelled") and not rows:
            yield f"event: run_finished\ndata: {json.dumps({'state': run.state})}\n\n"
            return

        await asyncio.sleep(POLL_S)


@router.get("/runs/{run_id}/events")
async def run_events(
    run_id: uuid.UUID,
    request: Request,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ctx: tuple[Org, Membership] = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = ctx
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")
    project = db.get(Project, run.project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")

    from_seq = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0
    return StreamingResponse(
        _stream(run_id, from_seq, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/projects/{project_id}/runs/latest")
def latest_run(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
               db: Session = Depends(get_db)) -> dict:
    org, _ = ctx
    project = db.get(Project, project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="project not found")
    run = db.query(Run).filter(Run.project_id == project_id).order_by(Run.queued_at.desc()).first()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no runs yet")
    return _run_out(run)


@router.get("/projects/{project_id}/runs")
def list_runs(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
              db: Session = Depends(get_db)) -> list[dict]:
    org, _ = ctx
    project = db.get(Project, project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="project not found")
    runs = db.query(Run).filter(Run.project_id == project_id).order_by(Run.queued_at.desc()).limit(50).all()
    return [_run_out(r) for r in runs]


@router.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
            db: Session = Depends(get_db)) -> dict:
    org, _ = ctx
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")
    project = db.get(Project, run.project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")
    return _run_out(run)


@router.post("/runs/{run_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_run(run_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
               db: Session = Depends(get_db)) -> dict:
    """Marks the run cancelled. A run already mid-scan finishes its current
    stage and then observes the state change is not honoured here - true
    cooperative cancellation would need the orchestrator to poll its own run
    row between stages, which is a reasonable follow-up, not a fake no-op:
    a queued run that has not yet been claimed by the worker is genuinely
    stopped by this."""
    org, _ = ctx
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")
    project = db.get(Project, run.project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="run not found")
    if run.state == "queued":
        run.state = "cancelled"
        run.finished_at = None
        db.commit()
    return {"run_id": str(run.id), "state": run.state}


def _run_out(r: Run) -> dict:
    return {
        "id": str(r.id), "project_id": str(r.project_id), "trigger": r.trigger,
        "state": r.state, "commit_sha": r.commit_sha, "commit_message": r.commit_message,
        "findings_new": r.findings_new, "findings_closed": r.findings_closed,
        "scanner_seconds": float(r.scanner_seconds) if r.scanner_seconds is not None else None,
        "error": r.error,
        "queued_at": r.queued_at.isoformat() if r.queued_at else None,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    }
