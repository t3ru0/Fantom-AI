"""Phase D/E: the orchestrator wires scanners -> enrichment -> scoring ->
pricing -> persistence, and the SSE endpoint tails the RunEvent log it writes.

Network-dependent pieces (git clone, OSV, EPSS, KEV) are monkeypatched so this
test is fast and deterministic - the orchestration *wiring* is what's under
test here, not the scanners or the public feeds themselves (those already
have their own unit tests in test_part1.py / test_part2.py).
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from pathlib import Path

from app.models.tables import RUN_STATES


def _project(client, headers, repo="acme/widget-service"):
    r = client.post("/api/projects", json={"repo": repo, "branch": "master"}, headers=headers)
    assert r.status_code == 201
    return r.json()["id"]


def _queue_run(project_id: str) -> str:
    """Creates a Run directly for a manual execute() call in these tests.

    Deliberately NOT state="queued": the `client` fixture's real lifespan
    starts the actual background worker (app.workers.runner), which polls
    for queued rows every 2s independent of whether /scan was called. A row
    left at "queued" can race a manual execute() call in the test against
    that poller claiming the same run. "running" is invisible to the
    poller's WHERE state='queued' filter, and execute() sets it again anyway.
    """
    from app.db import get_sessionmaker
    from app.models import Run
    db = get_sessionmaker()()
    run = Run(id=uuid.uuid4(), project_id=uuid.UUID(project_id), trigger="manual",
             full_sweep=True, state="running")
    db.add(run)
    db.commit()
    run_id = str(run.id)
    db.close()
    return run_id


def _patch_scan_pipeline(monkeypatch, secret_finding=None):
    from app.scanners.base import RawFinding

    @contextmanager
    def fake_checkout(repo, ref=None, token=None, keep=False):
        yield Path("."), {"commit": "a" * 40, "subject": "test commit", "author": "tester",
                          "committed_at": "2026-09-22T00:00:00Z", "branch": ref or "master",
                          "size_mb": 0.1, "clone_s": 0.01}

    monkeypatch.setattr("app.services.repo.checkout", fake_checkout)
    monkeypatch.setattr("app.scanners.lockfiles.collect_packages", lambda root: ([], []))
    monkeypatch.setattr("app.scanners.osv.scan", lambda ctx, packages: [])
    monkeypatch.setattr("app.scanners.secrets.scan", lambda ctx: [secret_finding] if secret_finding else [])
    monkeypatch.setattr("app.scanners.code.detect_languages", lambda root: {"Python": 10})
    monkeypatch.setattr("app.scanners.code.scan", lambda ctx, languages=None: [])
    monkeypatch.setattr("app.scanners.infra.scan", lambda ctx, surfaces=None: [])
    monkeypatch.setattr("app.enrich.epss.lookup", lambda cves, client=None: {})

    class FakeKev:
        def get(self, cve):
            return None
    monkeypatch.setattr("app.enrich.kev.catalog", lambda: FakeKev())


def test_orchestrator_runs_clean_repo_to_done(client, auth_headers, monkeypatch):
    headers, org_id, _ = auth_headers("o1@example.com", "Orchestrator Co")
    project_id = _project(client, headers)
    _patch_scan_pipeline(monkeypatch)
    run_id = _queue_run(project_id)

    from app.services.orchestrator import execute
    execute(uuid.UUID(run_id))

    run = client.get(f"/api/runs/{run_id}", headers=headers)
    assert run.status_code == 200
    body = run.json()
    assert body["state"] == "done"
    assert body["error"] is None
    assert body["findings_new"] == 0


def test_orchestrator_persists_a_finding(client, auth_headers, monkeypatch):
    from app.scanners.base import RawFinding
    headers, org_id, _ = auth_headers("o2@example.com", "Persist Co")
    project_id = _project(client, headers)

    secret = RawFinding(scanner="gitleaks", agent_slug="secret", title="AWS access key found",
                        file="config/aws.py", rule_id="aws-access-key", extra={"confidence": 0.9})
    _patch_scan_pipeline(monkeypatch, secret_finding=secret)
    run_id = _queue_run(project_id)

    from app.services.orchestrator import execute
    execute(uuid.UUID(run_id))

    findings = client.get("/api/findings", params={"project_id": project_id}, headers=headers)
    assert findings.json()["total"] == 1
    item = findings.json()["items"][0]
    assert item["package"] is None
    assert item["file"] == "config/aws.py"

    notifs = client.get("/api/notifications", headers=headers)
    kinds = [n["kind"] for n in notifs.json()]
    assert "scan_completed" in kinds


def test_orchestrator_failure_marks_run_failed(client, auth_headers, monkeypatch):
    headers, org_id, _ = auth_headers("o3@example.com", "Failure Co")
    project_id = _project(client, headers)

    def boom(repo, ref=None, token=None, keep=False):
        raise RuntimeError("clone exploded")
    monkeypatch.setattr("app.services.repo.checkout", boom)
    run_id = _queue_run(project_id)

    from app.services.orchestrator import execute
    execute(uuid.UUID(run_id))

    run = client.get(f"/api/runs/{run_id}", headers=headers)
    assert run.json()["state"] == "failed"
    assert "clone exploded" in run.json()["error"]


def test_sse_stream_replays_seeded_events(client, auth_headers):
    headers, org_id, _ = auth_headers("o4@example.com", "SSE Co")
    project_id = _project(client, headers)

    import uuid as uuid_mod
    from app.db import get_sessionmaker
    from app.models import Run, RunEvent
    db = get_sessionmaker()()
    run = Run(id=uuid_mod.uuid4(), project_id=uuid_mod.UUID(project_id), trigger="manual",
             full_sweep=True, state="done")
    db.add(run)
    db.flush()
    db.add(RunEvent(run_id=run.id, seq=1, event="working", message="scan started"))
    db.add(RunEvent(run_id=run.id, seq=2, event="idle", message="scan complete: 0 new, 0 closed"))
    db.commit()
    run_id = str(run.id)
    db.close()

    with client.stream("GET", f"/api/runs/{run_id}/events", headers=headers) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        chunks = []
        for chunk in r.iter_text():
            chunks.append(chunk)
            if "run_finished" in "".join(chunks):
                break
        text = "".join(chunks)
    assert "scan started" in text
    assert "scan complete" in text
    assert "run_finished" in text
