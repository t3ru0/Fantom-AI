"""CISA Known Exploited Vulnerabilities.

A CVE in this catalogue is not "might be exploited" — it is "has been observed
being exploited against real targets, and US federal agencies are ordered to fix
it by a date". It is the single strongest signal available for free, so it gets
the heaviest weight in the contextual score.

The catalogue is one ~1.7 MB JSON, refreshed roughly daily. We cache it on disk
and only re-download when stale.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_S = 6 * 3600
TIMEOUT = 45.0


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool
    action: str

    @property
    def days_since_added(self) -> int | None:
        try:
            added = time.strptime(self.date_added, "%Y-%m-%d")
            return int((time.time() - time.mktime(added)) / 86400)
        except (ValueError, TypeError):
            return None


class KevCatalog:
    """Loaded once per process; refreshed from disk cache when stale."""

    def __init__(self, cache_dir: str | Path = ".cache") -> None:
        self.cache_path = Path(cache_dir) / "cisa_kev.json"
        self._by_cve: dict[str, KevEntry] = {}
        self._released: str = ""
        self._loaded = False

    # -- loading ------------------------------------------------------------
    def _fresh_on_disk(self) -> bool:
        if not self.cache_path.exists():
            return False
        return (time.time() - self.cache_path.stat().st_mtime) < CACHE_TTL_S

    def _download(self) -> dict | None:
        try:
            with httpx.Client(timeout=TIMEOUT, headers={"user-agent": "fantom/0.1"}) as c:
                r = c.get(KEV_URL)
                r.raise_for_status()
                data = r.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            log.warning("KEV download failed: %s", exc)
            return None
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(data), encoding="utf-8")
        except OSError as exc:
            log.warning("could not cache KEV: %s", exc)
        return data

    def load(self, force: bool = False) -> None:
        if self._loaded and not force:
            return
        data: dict | None = None
        if not force and self._fresh_on_disk():
            try:
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = None
        if data is None:
            data = self._download()
        if data is None and self.cache_path.exists():
            # Stale cache beats no catalogue at all — but say so.
            try:
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                log.warning("using a stale KEV cache; exploitation flags may lag")
            except (OSError, json.JSONDecodeError):
                data = None
        if data is None:
            log.error("KEV unavailable — every finding will report kev=False, which understates risk")
            self._loaded = True
            return

        self._released = str(data.get("dateReleased", ""))[:10]
        for v in data.get("vulnerabilities") or []:
            cve = v.get("cveID")
            if not cve:
                continue
            self._by_cve[cve] = KevEntry(
                cve=cve,
                vendor=v.get("vendorProject", ""),
                product=v.get("product", ""),
                name=v.get("vulnerabilityName", ""),
                date_added=v.get("dateAdded", ""),
                due_date=v.get("dueDate", ""),
                ransomware=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                action=v.get("requiredAction", ""),
            )
        self._loaded = True
        log.info("KEV loaded: %d entries, released %s", len(self._by_cve), self._released)

    # -- queries ------------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(self._by_cve)

    @property
    def released(self) -> str:
        return self._released

    def __len__(self) -> int:
        return len(self._by_cve)

    def get(self, cve: str | None) -> KevEntry | None:
        if not cve:
            return None
        self.load()
        return self._by_cve.get(cve.upper())

    def contains(self, cve: str | None) -> bool:
        return self.get(cve) is not None


_catalog: KevCatalog | None = None


def catalog() -> KevCatalog:
    global _catalog
    if _catalog is None:
        _catalog = KevCatalog()
        _catalog.load()
    return _catalog
