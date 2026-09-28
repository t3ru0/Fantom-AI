"""Periodic connector maintenance: token health, repository list refresh,
webhook repair - every `CONNECTOR_SYNC_INTERVAL_HOURS` (default 6), per active
installation.

No new scheduling dependency: the interval timer is the same
threading-and-sleep shape `app.workers.runner` already uses, and each tick's
actual work is submitted onto *that* module's existing thread pool via
`runner.submit()` - one execution path, not two.
"""
from __future__ import annotations

import logging
import threading
import time

from app.config import settings
from app.db import get_sessionmaker
from app.workers import runner

log = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()


def _sweep_once() -> None:
    from app.connectors.enums import ConnectorProvider, ConnectorStatus
    from app.connectors.github import security
    from app.connectors.github.service import GitHubConnector, require_github_installation
    from app.connectors.github.webhooks import repair_webhook
    from app.models import ConnectorInstallation

    db = get_sessionmaker()()
    connector = GitHubConnector()
    try:
        installations = (
            db.query(ConnectorInstallation)
            .filter(
                ConnectorInstallation.provider == ConnectorProvider.GITHUB.value,
                ConnectorInstallation.status != ConnectorStatus.DISCONNECTED.value,
            )
            .all()
        )
        for row in installations:
            try:
                gh = require_github_installation(db, row.id)
            except LookupError:
                continue
            try:
                health = connector.health(db, installation_id=row.id)
                if not health.token_valid:
                    row.status = ConnectorStatus.EXPIRED.value
                    db.commit()
                    continue

                # Repository list, permissions, stars/forks/archived state all
                # come from the same upsert path a manual sync uses.
                connector.sync(db, installation_id=row.id)

                for repo in gh.repositories:
                    if repo.monitoring_status == "monitored" and not repo.webhooks:
                        repair_webhook(db, repo, callback_url=security.webhook_callback_url())
                db.commit()
            except Exception:  # noqa: BLE001 — one bad installation must not stop the sweep
                log.exception("connector maintenance sweep failed for installation %s", row.id)
                db.rollback()
    finally:
        db.close()


def _loop() -> None:
    interval_s = max(settings.connector_sync_interval_hours, 0.1) * 3600
    log.info("connector maintenance scheduled every %.1fh", settings.connector_sync_interval_hours)
    while True:
        time.sleep(interval_s)
        runner.submit(_sweep_once)


def start() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
        threading.Thread(target=_loop, daemon=True, name="connector-scheduler").start()
