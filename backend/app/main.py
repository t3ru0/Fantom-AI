"""FANTOM API.

Part 0 — the skeleton. Boots with or without a database and tells you which.
Later parts mount their routers here; nothing else about this file changes.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    analytics,
    audit,
    auth,
    findings,
    health,
    live,
    notifications,
    orgs,
    projects,
    reports,
    risk,
    webhooks,
)
from app.api.v1.endpoints import connectors as connectors_v1
from app.api.v1.endpoints import github as github_connector_v1
from app.config import settings
from app.core.logging_conf import setup_logging

setup_logging()
log = logging.getLogger("fantom")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.db import ping
    ok, err = ping()
    log.info("starting env=%s db=%s", settings.env, "up" if ok else f"down ({err})")
    if not ok:
        log.warning("database unreachable - /health will report degraded until it is up")
    else:
        from app.workers.runner import start as start_worker
        start_worker()
        from app.workers.connector_scheduler import start as start_connector_scheduler
        start_connector_scheduler()
    yield
    log.info("shutting down")


app = FastAPI(
    title="FANTOM",
    description="Continuous cyber risk quantification from a GitHub repository.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["x-request-id"] = rid
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "?")
    log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
    # Never leak a stack trace to the client.
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "request_id": rid},
    )


app.include_router(health.router)
app.include_router(webhooks.router)
app.include_router(auth.router)
app.include_router(orgs.router)
app.include_router(audit.router)
app.include_router(projects.router)
app.include_router(live.router)
app.include_router(findings.router)
app.include_router(risk.router)
app.include_router(analytics.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(connectors_v1.router)
app.include_router(github_connector_v1.router)


@app.get("/")
def root() -> dict:
    return {
        "name": "FANTOM",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
        "build_phase": 4,
        "phase_name": "auth, orgs, scan orchestration, live floor",
    }
