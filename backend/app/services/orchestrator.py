"""One function that turns a queued Run into a finished one.

Clone -> lockfiles -> osv/secrets/code/infra scanners -> EPSS/KEV enrichment ->
contextual scoring -> fingerprint -> price -> upsert Finding rows -> roll up
ExposureHistory. Each stage commits its own RunEvent row immediately (not at
the end) so `GET /api/runs/{id}/events` can tail progress on a scan that is
still running - that's the whole point of the seq-ordered event log.

Runs on its own session (not `session_scope`, which only commits once at the
end) because partial progress has to be visible to readers before the run
finishes.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import date, datetime, timezone

from sqlalchemy import func

from app.db import get_sessionmaker
from app.enrich import epss as epss_svc
from app.enrich.kev import catalog as kev_catalog
from app.integrations.github.app_auth import GitHubAuthError, installation_token
from app.models import ExposureHistory, Finding, Project, Run, RunEvent
from app.models.github import GithubRepository
from app.scanners import code as code_scanner
from app.scanners import infra as infra_scanner
from app.scanners import lockfiles
from app.scanners import osv as osv_scanner
from app.scanners import secrets as secrets_scanner
from app.scanners.base import ScanContext
from app.services import money as money_svc
from app.services import repo as repo_svc
from app.services.fingerprint import fingerprint
from app.services.scoring import score_all

log = logging.getLogger(__name__)


def _emit(db, run: Run, seq: int, event: str, message: str | None = None,
          agent_slug: str | None = None, payload: dict | None = None) -> None:
    db.add(RunEvent(run_id=run.id, seq=seq, event=event, message=message,
                    agent_slug=agent_slug, payload=payload))
    db.commit()


def _business_context(project: Project) -> money_svc.BusinessContext:
    return money_svc.BusinessContext(
        revenue_supported=float(project.revenue_supported) if project.revenue_supported else None,
        downtime_cost_hour=float(project.downtime_cost_hour) if project.downtime_cost_hour else None,
        users_count=project.users_count, records_count=project.records_count,
        regimes=project.regimes,
        eng_rate_hour=float(project.eng_rate_hour) if project.eng_rate_hour else None,
    )


def _rollup_exposure(db, project_id: uuid.UUID) -> None:
    today = date.today()
    total = db.query(func.sum(Finding.annual_loss)).filter(
        Finding.project_id == project_id, Finding.state == "open").scalar()
    open_ct = db.query(Finding).filter(Finding.project_id == project_id, Finding.state == "open").count()
    crit_ct = db.query(Finding).filter(
        Finding.project_id == project_id, Finding.state == "open", Finding.context_score >= 80).count()
    row = db.get(ExposureHistory, (project_id, today))
    if row:
        row.exposure, row.findings_open, row.findings_critical = total, open_ct, crit_ct
    else:
        db.add(ExposureHistory(project_id=project_id, day=today,
                               exposure=total, findings_open=open_ct, findings_critical=crit_ct))
    db.commit()


def execute(run_id: uuid.UUID) -> None:
    db = get_sessionmaker()()
    seq = 0
    started = time.time()
    run: Run | None = None
    try:
        run = db.get(Run, run_id)
        if run is None:
            return
        project = db.get(Project, run.project_id)
        run.state = "running"
        run.started_at = datetime.now(timezone.utc)
        db.commit()
        seq += 1
        _emit(db, run, seq, "working", "scan started")

        # A repository connected through the connector framework clones via
        # its own OAuth strategy and the safer archive-first path; everything
        # else (the pre-connector GitHub App flow, public repos) is unchanged.
        connector_repo = db.query(GithubRepository).filter(GithubRepository.project_id == project.id).first()
        if connector_repo is not None:
            from app.connectors.github.clone import fetch_workspace
            from app.connectors.github.oauth import strategy_for
            clone_ctx = fetch_workspace(
                db, connector_repo.installation, strategy_for(connector_repo.installation),
                connector_repo.full_name, project.branch,
            )
        else:
            token = None
            if project.gh_installation_id:
                try:
                    token = installation_token(project.gh_installation_id)
                except GitHubAuthError as exc:
                    log.warning("no installation token for %s: %s", project.origin, exc)
            clone_ctx = repo_svc.checkout(project.origin, ref=project.branch, token=token)

        all_findings = []
        with clone_ctx as (root, meta):
            run.commit_sha = meta["commit"]
            run.commit_message = meta["subject"]
            run.pusher = meta["author"]
            db.commit()
            seq += 1
            _emit(db, run, seq, "working", f"cloned {meta['commit'][:8]}", payload=meta)

            ctx = ScanContext(root=root, repo=project.origin,
                              changed_files=None if run.full_sweep else run.changed_files)

            packages, lockfile_paths = lockfiles.collect_packages(root)
            seq += 1
            _emit(db, run, seq, "working", f"{len(packages)} packages in {len(lockfile_paths)} lockfiles",
                  agent_slug="lib")
            dep_findings = osv_scanner.scan(ctx, packages) if packages else []
            all_findings += dep_findings
            seq += 1
            _emit(db, run, seq, "found", f"{len(dep_findings)} dependency findings", agent_slug="lib")

            secret_findings = secrets_scanner.scan(ctx)
            all_findings += secret_findings
            seq += 1
            _emit(db, run, seq, "found", f"{len(secret_findings)} secret findings", agent_slug="secret")

            languages = code_scanner.detect_languages(root)
            code_findings = code_scanner.scan(ctx, set(languages))
            all_findings += code_findings
            seq += 1
            _emit(db, run, seq, "found", f"{len(code_findings)} code findings", agent_slug="flaw_py")

            infra_findings = infra_scanner.scan(ctx)
            all_findings += infra_findings
            seq += 1
            _emit(db, run, seq, "found", f"{len(infra_findings)} infra findings", agent_slug="infra")

            project.languages = list(languages.keys())
            project.dep_count = len(packages)
            project.loc_count = repo_svc.count_lines(root)

        seq += 1
        _emit(db, run, seq, "working", "enriching with EPSS + CISA KEV")
        cves = [f.cve for f in all_findings if f.cve]
        epss_map = epss_svc.lookup(cves)
        kev = kev_catalog()

        scored = score_all(all_findings, epss_map, kev)
        seq += 1
        _emit(db, run, seq, "working", "scored", payload={"count": len(scored)})

        biz_ctx = _business_context(project)
        seen_fp: set[str] = set()
        new_count = closed_count = 0

        for f, result in scored:
            fp = fingerprint(f)
            seen_fp.add(fp)
            priced = money_svc.price(f, result, biz_ctx)
            e = epss_map.get((f.cve or "").upper()) if f.cve else None
            k = kev.get(f.cve) if f.cve else None
            existing = db.query(Finding).filter(
                Finding.project_id == project.id, Finding.fingerprint == fp).first()

            fields = dict(
                cvss=f.cvss, epss=e.p30 if e else None, kev=bool(k),
                context_score=result.score,
                annual_loss=priced.annual_loss if priced else None,
                fix_hours=priced.effort.build_hours if priced and priced.effort else None,
                fix_cost=priced.effort.cost if priced and priced.effort else None,
                loss_per_hour=priced.loss_per_hour if priced else None,
                remediation={"steps": f.remediation} if f.remediation else None,
                impact_breakdown=(
                    {"components": [{"name": c.name, "amount": c.amount, "basis": c.basis}
                                    for c in priced.components],
                     "p_wild_year": priced.p_wild_year}
                    if priced else None
                ),
            )
            if existing:
                for k2, v in fields.items():
                    setattr(existing, k2, v)
                existing.last_seen_run = run.id
                if existing.state == "fixed":
                    existing.state = "open"
            else:
                new_count += 1
                db.add(Finding(
                    id=uuid.uuid4(), project_id=project.id, fingerprint=fp,
                    agent_slug=f.agent_slug, scanner=f.scanner, title=f.title,
                    cve=f.cve, cwe=f.cwe, rule_id=f.rule_id, file=f.file, line=f.line,
                    package=f.package, version=f.version, fixed_version=f.fixed_version,
                    first_seen_run=run.id, last_seen_run=run.id, state="open",
                    **fields,
                ))

        if run.full_sweep:
            still_open = db.query(Finding).filter(
                Finding.project_id == project.id, Finding.state == "open").all()
            for existing in still_open:
                if existing.fingerprint not in seen_fp:
                    existing.state = "fixed"
                    closed_count += 1

        run.findings_new = new_count
        run.findings_closed = closed_count
        run.scanner_seconds = round(time.time() - started, 2)
        run.state = "done"
        run.finished_at = datetime.now(timezone.utc)
        project.last_run_at = run.finished_at
        project.state = "watching"
        db.commit()

        _rollup_exposure(db, project.id)

        seq += 1
        _emit(db, run, seq, "idle", f"scan complete: {new_count} new, {closed_count} closed",
              payload={"new": new_count, "closed": closed_count})

        from app.services.notify import on_scan_completed
        on_scan_completed(db, project, run, new_count)

        from app.connectors.github.webhooks import maybe_queue_pending_rescan
        maybe_queue_pending_rescan(db, project)

    except Exception as exc:  # noqa: BLE001 — a scan failure must be recorded, not raised into the worker thread
        log.exception("scan failed for run %s", run_id)
        db.rollback()
        if run is not None:
            run = db.get(Run, run_id)
            if run:
                run.state = "failed"
                run.error = str(exc)[:2000]
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
                try:
                    _emit(db, run, seq + 1, "error", str(exc)[:500])
                except Exception:
                    pass
                project = db.get(Project, run.project_id)
                if project is not None:
                    from app.connectors.github.webhooks import maybe_queue_pending_rescan
                    maybe_queue_pending_rescan(db, project)
    finally:
        db.close()
