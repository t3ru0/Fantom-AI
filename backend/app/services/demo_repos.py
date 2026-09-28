"""Example repositories shown to a new org before it has connected a real
GitHub account, so the product isn't a blank screen on first login. Removed
automatically the moment a real GitHub connection succeeds (`service.py`
callback) - they exist purely to demonstrate the flow, not as real assets.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from app.models import Project

log = logging.getLogger(__name__)

DEMO_REPOS = ["octocat/Hello-World", "octocat/Spoon-Knife"]


def seed_demo_projects(db: Session, org_id: uuid.UUID) -> None:
    from app.api.projects import build_project

    for repo in DEMO_REPOS:
        if db.query(Project).filter(Project.org_id == org_id, Project.origin == repo).first():
            continue
        db.add(build_project(org_id, repo))
    db.flush()


def remove_demo_projects(db: Session, org_id: uuid.UUID) -> None:
    removed = (
        db.query(Project)
        .filter(Project.org_id == org_id, Project.origin.in_(DEMO_REPOS))
        .delete(synchronize_session=False)
    )
    if removed:
        log.info("removed %d demo project(s) from org %s after real GitHub connect", removed, org_id)
