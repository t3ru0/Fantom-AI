"""Report generation. Markdown, not PDF - a real, openable, diffable document
that needs no new heavy dependency (a PDF renderer) to produce honestly. Runs
on the same worker pool a scan does; writes the file under `workspace_dir`
and points `Report.file_path` at it.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.api.findings import tier_name
from app.config import settings
from app.db import get_sessionmaker
from app.models import Finding, Org, Project, Report
from app.services.money import portfolio_from_rows

log = logging.getLogger(__name__)


def _executive(org: Org, projects: list[Project], findings: list[Finding]) -> str:
    critical = [f for f in findings if (f.context_score or 0) >= 80]
    lines = [f"# Executive risk summary — {org.name}", "",
             f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}. "
             f"{len(projects)} repositories, {len(findings)} open findings, "
             f"{len(critical)} at Critical tier.", ""]
    for p in projects:
        pf = [f for f in findings if f.project_id == p.id]
        pv = portfolio_from_rows(pf, float(p.revenue_supported) if p.revenue_supported else None)
        exp = f"${pv['exposure']:,.0f}" if p.context_complete and pv["priced"] else "not priced (business context incomplete)"
        lines.append(f"## {p.origin}")
        lines.append(f"- Open findings: {len(pf)} · Exposure: {exp}")
        top = sorted(pf, key=lambda f: -(f.context_score or 0))[:5]
        for f in top:
            lines.append(f"  - [{tier_name(f.context_score)}] {f.title[:100]} "
                        f"({f.cve or f.rule_id or f.scanner})")
        lines.append("")
    return "\n".join(lines)


def _technical(org: Org, projects: list[Project], findings: list[Finding]) -> str:
    lines = [f"# Technical finding detail — {org.name}", "",
             f"{len(findings)} open findings across {len(projects)} repositories.", "",
             "| Repo | Tier | Score | CVE/Rule | File | Package |", "|---|---|---|---|---|---|"]
    by_project = {p.id: p.origin for p in projects}
    for f in sorted(findings, key=lambda f: -(f.context_score or 0)):
        lines.append(
            f"| {by_project.get(f.project_id, '?')} | {tier_name(f.context_score) or '-'} | "
            f"{f.context_score or '-'} | {f.cve or f.rule_id or '-'} | {f.file or '-'} | {f.package or '-'} |"
        )
    return "\n".join(lines)


def _compliance(org: Org, projects: list[Project], findings: list[Finding]) -> str:
    lines = [f"# Compliance exposure — {org.name}", ""]
    for p in projects:
        pf = [f for f in findings if f.project_id == p.id]
        regimes = p.regimes or []
        lines.append(f"## {p.origin}")
        lines.append(f"- Regulated data regimes in scope: {', '.join(regimes) or 'none configured'}")
        lines.append(f"- Records at risk: {p.records_count if p.records_count is not None else 'not supplied'}")
        confidentiality_findings = [f for f in pf if (f.impact_breakdown or {}).get("components")]
        lines.append(f"- Findings with a modelled confidentiality impact: {len(confidentiality_findings)}")
        lines.append("")
    return "\n".join(lines)


def _repository(org: Org, projects: list[Project], findings: list[Finding]) -> str:
    lines = [f"# Repository report — {org.name}", ""]
    for p in projects:
        pf = [f for f in findings if f.project_id == p.id]
        lines.append(f"## {p.origin}")
        lines.append(f"- Branch: {p.branch} · Languages: {', '.join(p.languages or []) or 'unknown'}")
        lines.append(f"- Dependencies: {p.dep_count if p.dep_count is not None else '?'} · "
                     f"LOC: {p.loc_count if p.loc_count is not None else '?'}")
        lines.append(f"- Open findings: {len(pf)} · Last scanned: "
                     f"{p.last_run_at.isoformat() if p.last_run_at else 'never'}")
        lines.append("")
    return "\n".join(lines)


RENDERERS = {
    "executive": _executive, "technical": _technical,
    "compliance": _compliance, "repository": _repository,
}


def generate(report_id: uuid.UUID) -> None:
    db = get_sessionmaker()()
    try:
        report = db.get(Report, report_id)
        if report is None:
            return
        report.status = "running"
        db.commit()

        org = db.get(Org, report.org_id)
        if report.project_id:
            projects = [db.get(Project, report.project_id)]
        else:
            projects = db.query(Project).filter(Project.org_id == org.id).all()
        project_ids = [p.id for p in projects]
        findings = (
            db.query(Finding).filter(Finding.project_id.in_(project_ids), Finding.state == "open").all()
            if project_ids else []
        )

        body = RENDERERS[report.kind](org, projects, findings)

        out_dir = Path(settings.workspace_dir) / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{report.id}.md"
        path.write_text(body, encoding="utf-8")

        report.file_path = str(path)
        report.status = "done"
        report.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        log.exception("report generation failed for %s", report_id)
        db.rollback()
        report = db.get(Report, report_id)
        if report:
            report.status = "failed"
            report.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
