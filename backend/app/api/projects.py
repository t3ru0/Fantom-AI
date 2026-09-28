"""Projects and pricing.

`/price/preview` is stateless and needs no database, so the loss model can be
exercised and argued with directly. The project routes persist the same context.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org, require_role
from app.enrich.epss import EpssScore
from app.enrich.kev import KevEntry
from app.integrations.github.app_auth import GitHubAuthError, repo_meta
from app.models import Finding, Membership, Org, Project, Run
from app.scanners.base import RawFinding
from app.schemas import (
    BusinessContextIn,
    ComponentOut,
    ContextStatus,
    EffortOut,
    PriceOut,
    PricePreviewIn,
    ProjectCreate,
    ProjectOut,
)
from app.services import money as money_svc
from app.services.audit import log_action
from app.services.scoring import score

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["projects"])

WHY_IT_MATTERS = {
    "revenue_supported": "Scales customer-churn loss. Without it, churn cannot be valued.",
    "downtime_cost_hour": "Prices an outage. Without it, availability findings have no cost.",
    "users_count": "Sizes how many people an incident reaches.",
    "records_count": "Drives the regulatory penalty, which is usually the largest single component.",
    "regimes": ("Selects the penalty regime. DPDP, GDPR and PCI differ by an order of "
                "magnitude per record."),
}


def _ctx_from(payload: BusinessContextIn) -> money_svc.BusinessContext:
    return money_svc.BusinessContext(
        revenue_supported=payload.revenue_supported,
        downtime_cost_hour=payload.downtime_cost_hour,
        users_count=payload.users_count,
        records_count=payload.records_count,
        regimes=payload.regimes,
        eng_rate_hour=payload.eng_rate_hour,
    )


def _status(ctx: money_svc.BusinessContext) -> ContextStatus:
    return ContextStatus(
        complete=ctx.complete,
        missing=ctx.missing,
        supplied={f: getattr(ctx, f) for f in money_svc.BusinessContext.REQUIRED
                  if getattr(ctx, f) not in (None, [], "")},
        why_it_matters={k: v for k, v in WHY_IT_MATTERS.items() if k in ctx.missing},
        effect=("Findings are priced." if ctx.complete else
                "Findings are ranked by contextual score but NOT priced. "
                "No exposure figure is produced, and none is guessed."),
    )


# ===========================================================================
# Stateless preview — the loss model, with nothing persisted.
# ===========================================================================
@router.post("/price/preview", response_model=PriceOut)
def price_preview(payload: PricePreviewIn) -> PriceOut:
    ctx = _ctx_from(payload.context)
    fin = payload.finding

    raw = RawFinding(
        scanner=fin.scanner,
        agent_slug={"osv": "lib", "gitleaks": "secret"}.get(fin.scanner, "flaw_py"),
        title=fin.title, cve=fin.cve, cwe=fin.cwe, rule_id=fin.rule_id,
        cvss=fin.cvss, package=fin.package, version=fin.version,
        fixed_version=fin.fixed_version, file=fin.file, line=fin.line,
        extra={"direct": fin.direct, "confidence": 0.8},
    )
    epss = EpssScore(fin.cve or "CVE-0000-0000", fin.epss, 0.5, "") if fin.epss is not None else None
    kev = KevEntry(fin.cve or "", "", "", "", "", "", False, "") if fin.kev else None

    result = score(raw, epss, kev)
    priced = money_svc.price(raw, result, ctx)

    if priced is None:
        return PriceOut(
            priced=False,
            context_missing=ctx.missing,
            context_score=result.score,
            tier=result.tier_name,
            sla=result.sla,
            p_wild_year=result.p_wild_year,
            note=("Business context is incomplete, so this finding is ranked but not priced. "
                  f"Still needed: {', '.join(ctx.missing)}."),
        )

    return PriceOut(
        priced=True,
        context_score=result.score,
        tier=result.tier_name,
        sla=result.sla,
        if_it_happens=priced.if_it_happens,
        annual_loss_upper_bound=priced.annual_loss,
        loss_per_hour=priced.loss_per_hour,
        p_wild_year=priced.p_wild_year,
        p_here_year=None,
        components=[ComponentOut(name=c.name, amount=round(c.amount, 2), basis=c.basis)
                    for c in priced.components],
        effort=EffortOut(
            build_hours=priced.effort.build_hours,
            loaded_hours=priced.effort.loaded_hours,
            cost=priced.effort.cost,
            change_risk=priced.effort.change_risk,
            basis=priced.effort.basis,
            sprint_share=round(priced.effort.sprint_share, 3),
        ) if priced.effort else None,
        assumptions=priced.assumptions,
        note=priced.note,
    )


@router.post("/context/validate", response_model=ContextStatus)
def validate_context(payload: BusinessContextIn) -> ContextStatus:
    """Check a context without saving it. Used by the form as the user types."""
    return _status(_ctx_from(payload))


@router.get("/regimes")
def regimes() -> dict:
    return {
        "regimes": [
            {"code": r.code, "name": r.name, "per_record_usd": r.per_record,
             "cap_usd": r.cap_usd, "cap_revenue_pct": r.cap_revenue_pct}
            for r in money_svc.REGIMES.values()
        ],
        "note": ("Per-record figures are policy estimates, not statutory rates. "
                 "Real enforcement varies and usually settles below the maximum."),
    }


@router.get("/assumptions")
def assumptions() -> dict:
    """Everything in the model that is a judgement rather than a measurement."""
    return {"assumptions": money_svc.ASSUMPTIONS,
            "principle": ("Any figure a CFO signs has to be defensible line by line. "
                          "These are the lines that are judgement calls.")}


# ===========================================================================
# Persisted projects — every route below is scoped to the caller's org.
# ===========================================================================
def _to_out(db: Session, p: Project) -> ProjectOut:
    findings_open = db.query(Finding).filter(Finding.project_id == p.id, Finding.state == "open").count()
    exposure = (
        db.query(Finding.annual_loss)
        .filter(Finding.project_id == p.id, Finding.state == "open", Finding.annual_loss.isnot(None))
        .all()
    )
    total_exposure = sum(float(row[0]) for row in exposure) if exposure else None
    return ProjectOut(
        id=str(p.id), repo=p.origin, branch=p.branch, state=p.state,
        context_complete=p.context_complete, missing_context=p.missing_context,
        complexity_score=p.complexity_score, complexity_tier=p.complexity_tier,
        findings_open=findings_open,
        exposure=total_exposure if p.context_complete else None,
    )


def _get_owned_project(db: Session, org: Org, project_id: uuid.UUID) -> Project:
    p = db.get(Project, project_id)
    if not p or p.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="project not found")
    return p


def build_project(org_id: uuid.UUID, repo: str, branch: str = "main",
                   installation_id: uuid.UUID | None = None) -> Project:
    """Shared by the manual `/projects` route and demo-repo seeding - fetches
    whatever public metadata is reachable and falls back gracefully when it
    isn't (e.g. no installation yet)."""
    meta: dict = {}
    try:
        meta = repo_meta(repo, installation_id)
    except GitHubAuthError as exc:
        log.warning("could not fetch metadata for %s: %s", repo, exc)

    return Project(
        id=uuid.uuid4(), org_id=org_id, name=repo.split("/")[-1],
        source="github", origin=repo, branch=branch,
        gh_repo_id=meta.get("id"), gh_installation_id=installation_id,
        is_private=meta.get("private", True), default_branch=meta.get("default_branch"),
        context_complete=False,
    )


@router.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate,
                    ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                    db: Session = Depends(get_db)) -> ProjectOut:
    org, actor = ctx
    existing = db.query(Project).filter(Project.org_id == org.id, Project.origin == payload.repo).first()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail=f"{payload.repo} is already connected")

    p = build_project(org.id, payload.repo, payload.branch, payload.installation_id)
    db.add(p)
    db.flush()
    log_action(db, org_id=org.id, project_id=p.id, action="project.create", detail=payload.repo)
    db.commit()
    log.info("connected %s to org %s", payload.repo, org.slug)
    return _to_out(db, p)


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(ctx: tuple[Org, Membership] = Depends(get_current_org),
                   db: Session = Depends(get_db)) -> list[ProjectOut]:
    org, _ = ctx
    projects = db.query(Project).filter(Project.org_id == org.id).order_by(Project.created_at.desc()).all()
    return [_to_out(db, p) for p in projects]


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                 db: Session = Depends(get_db)) -> ProjectOut:
    org, _ = ctx
    return _to_out(db, _get_owned_project(db, org, project_id))


@router.post("/projects/{project_id}/sync", response_model=ProjectOut)
def sync_project(project_id: uuid.UUID,
                  ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                  db: Session = Depends(get_db)) -> ProjectOut:
    """Re-fetches live GitHub metadata (default branch, visibility) for this repo."""
    org, actor = ctx
    p = _get_owned_project(db, org, project_id)
    try:
        meta = repo_meta(p.origin, p.gh_installation_id)
    except GitHubAuthError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=f"GitHub sync failed: {exc}") from exc
    p.gh_repo_id = meta.get("id")
    p.is_private = meta.get("private", p.is_private)
    p.default_branch = meta.get("default_branch")
    log_action(db, org_id=org.id, project_id=p.id, action="project.sync")
    db.commit()
    return _to_out(db, p)


@router.post("/projects/{project_id}/disconnect", response_model=ProjectOut)
def disconnect_project(project_id: uuid.UUID,
                        ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                        db: Session = Depends(get_db)) -> ProjectOut:
    org, actor = ctx
    p = _get_owned_project(db, org, project_id)
    p.state = "disconnected"
    log_action(db, org_id=org.id, project_id=p.id, action="project.disconnect")
    db.commit()
    return _to_out(db, p)


@router.get("/projects/{project_id}/stats")
def project_stats(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                   db: Session = Depends(get_db)) -> dict:
    org, _ = ctx
    p = _get_owned_project(db, org, project_id)
    last_run = (
        db.query(Run).filter(Run.project_id == p.id).order_by(Run.queued_at.desc()).first()
    )
    return {
        "default_branch": p.default_branch,
        "languages": p.languages,
        "dep_count": p.dep_count,
        "loc_count": p.loc_count,
        "complexity_tier": p.complexity_tier,
        "last_run_at": p.last_run_at.isoformat() if p.last_run_at else None,
        "last_run_state": last_run.state if last_run else None,
        "findings_open": db.query(Finding).filter(Finding.project_id == p.id, Finding.state == "open").count(),
    }


@router.post("/projects/{project_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(project_id: uuid.UUID,
                  ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                  db: Session = Depends(get_db)) -> dict:
    org, actor = ctx
    p = _get_owned_project(db, org, project_id)
    run = Run(id=uuid.uuid4(), project_id=p.id, trigger="manual", full_sweep=True, state="queued")
    db.add(run)
    log_action(db, org_id=org.id, project_id=p.id, action="scan.trigger", detail="manual")
    db.commit()

    from app.workers.runner import wake_worker
    wake_worker()
    return {"run_id": str(run.id), "state": run.state}


@router.get("/projects/{project_id}/pricing")
def project_pricing(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                     db: Session = Depends(get_db)) -> dict:
    """Portfolio-level exposure: aggregated (worst shared breach + accumulating
    response cost), not summed - see money.portfolio_from_rows for why."""
    org, _ = ctx
    p = _get_owned_project(db, org, project_id)
    open_findings = db.query(Finding).filter(Finding.project_id == p.id, Finding.state == "open").all()
    revenue = float(p.revenue_supported) if p.revenue_supported else None
    result = money_svc.portfolio_from_rows(open_findings, revenue)
    result["context_complete"] = p.context_complete
    if not p.context_complete:
        result["reason"] = f"business context incomplete: missing {', '.join(p.missing_context)}"
    return result


@router.get("/projects/{project_id}/context", response_model=ContextStatus)
def get_context(project_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                 db: Session = Depends(get_db)) -> ContextStatus:
    org, _ = ctx
    p = _get_owned_project(db, org, project_id)
    return _status(money_svc.BusinessContext(
        revenue_supported=float(p.revenue_supported) if p.revenue_supported else None,
        downtime_cost_hour=float(p.downtime_cost_hour) if p.downtime_cost_hour else None,
        users_count=p.users_count, records_count=p.records_count,
        regimes=p.regimes, eng_rate_hour=float(p.eng_rate_hour) if p.eng_rate_hour else None,
    ))


@router.put("/projects/{project_id}/context", response_model=ContextStatus)
def set_context(project_id: uuid.UUID, payload: BusinessContextIn, response: Response,
                ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                db: Session = Depends(get_db)) -> ContextStatus:
    org, actor = ctx
    p = _get_owned_project(db, org, project_id)

    for field in ("revenue_supported", "downtime_cost_hour", "users_count",
                  "records_count", "regimes", "eng_rate_hour"):
        value = getattr(payload, field)
        if value is not None:
            setattr(p, field, value)

    ctx_obj = money_svc.BusinessContext(
        revenue_supported=float(p.revenue_supported) if p.revenue_supported else None,
        downtime_cost_hour=float(p.downtime_cost_hour) if p.downtime_cost_hour else None,
        users_count=p.users_count, records_count=p.records_count,
        regimes=p.regimes, eng_rate_hour=float(p.eng_rate_hour) if p.eng_rate_hour else None,
    )
    was = p.context_complete
    p.context_complete = ctx_obj.complete
    log_action(db, org_id=org.id, project_id=p.id, action="project.context_update")
    db.commit()

    if ctx_obj.complete and not was:
        log.info("%s is now priceable", p.origin)
        response.status_code = status.HTTP_200_OK
    return _status(ctx_obj)
