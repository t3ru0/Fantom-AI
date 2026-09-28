"""Health and readiness.

/health   — always 200 if the process is alive. Reports every component's real
            state so a half-configured machine tells you exactly what is missing
            instead of failing opaquely.
/ready    — 200 only when the database is reachable AND migrated. This is what a
            load balancer or `docker compose --wait` should poll.
"""
from __future__ import annotations

import platform
import sys
import time

from fastapi import APIRouter, Response, status

from app.config import settings
from app.db import migration_revision, ping

router = APIRouter(tags=["health"])
STARTED = time.time()


def _components() -> dict[str, dict]:
    db_ok, db_err = ping()
    rev = migration_revision() if db_ok else None
    return {
        "database": {
            "ok": db_ok,
            "migrated": rev is not None,
            "revision": rev,
            "error": db_err,
            "hint": None if db_ok else "start Postgres:  docker compose up -d db",
        },
        "github_app": {
            "ok": settings.github_ready,
            "hint": None if settings.github_ready
            else "set GITHUB_APP_ID, GITHUB_WEBHOOK_SECRET, GITHUB_PRIVATE_KEY (Part 1)",
        },
        "llm": {
            "ok": settings.llm_ready,
            "hint": None if settings.llm_ready else "set OPENROUTER_API_KEY (Part 5)",
        },
    }


@router.get("/health")
def health() -> dict:
    comps = _components()
    ready = comps["database"]["ok"] and comps["database"]["migrated"]
    return {
        "status": "ok" if ready else "degraded",
        "app": settings.app_name,
        "env": settings.env,
        "uptime_s": round(time.time() - STARTED, 1),
        "python": sys.version.split()[0],
        "platform": platform.system(),
        "components": comps,
    }


@router.get("/ready")
def ready(response: Response) -> dict:
    comps = _components()
    ok = comps["database"]["ok"] and comps["database"]["migrated"]
    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"ready": ok, "components": comps}
