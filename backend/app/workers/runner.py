"""In-process job runner. No Redis, no Celery.

`Run.state` (queued/running/done/failed/cancelled) is already a durable job
queue sitting in MySQL, and `RunEvent` is already a progress stream. A single
polling thread claims one queued `Run` at a time and hands it to a small
thread pool; `wake_worker()` short-circuits the poll interval so a manually
triggered scan starts immediately instead of waiting for the next tick.

Restart-safe by construction: on the next poll after a process restart, any
row still sitting at `state="queued"` gets picked up same as ever. A run that
was `state="running"` when the process died stays stuck that way - acceptable
for a single-process dev/demo deployment; a multi-process one would need a
lease/heartbeat column, which is out of scope here.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.db import get_sessionmaker
from app.models import Run

log = logging.getLogger(__name__)

POLL_S = 2.0
MAX_WORKERS = 2

_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="scan-worker")
_wake = threading.Event()
_started = False
_lock = threading.Lock()


def _claim_next(db) -> Run | None:
    run = (
        db.query(Run)
        .filter(Run.state == "queued")
        .order_by(Run.queued_at.asc())
        .first()
    )
    if run is None:
        return None
    run.state = "running"     # claimed here; orchestrator.execute() sets started_at
    db.commit()
    return run


def _loop() -> None:
    from app.services.orchestrator import execute

    session_factory = get_sessionmaker()
    log.info("scan worker polling every %.1fs, %d concurrent slots", POLL_S, MAX_WORKERS)
    while True:
        _wake.wait(timeout=POLL_S)
        _wake.clear()
        db = session_factory()
        try:
            run = _claim_next(db)
            run_id = run.id if run else None
        finally:
            db.close()
        if run_id is not None:
            _pool.submit(execute, run_id)


def start() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
        threading.Thread(target=_loop, daemon=True, name="scan-worker-poller").start()


def wake_worker() -> None:
    start()
    _wake.set()


def submit(fn, *args) -> None:
    """Run an arbitrary job (report generation) on the same worker pool a scan
    uses. Unlike a scan, a report has no push-trigger reason to be queued and
    picked up later - the API route that creates it submits it directly."""
    start()
    _pool.submit(fn, *args)
