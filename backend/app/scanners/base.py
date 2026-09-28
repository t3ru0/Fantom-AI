"""Scanner contract.

Every scanner turns a checked-out repository into a list of RawFinding.
Nothing here knows about the database, money, or agents — a scanner reports
what it saw and stops.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Package:
    """One resolved dependency, as read from a lockfile."""
    name: str
    version: str
    ecosystem: str          # OSV ecosystem: npm, PyPI, Go, RubyGems, crates.io, Packagist
    source_file: str        # lockfile it came from, repo-relative
    direct: bool = True

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass(slots=True)
class RawFinding:
    """Pre-enrichment, pre-scoring. The scanner's honest output."""
    scanner: str                       # osv | semgrep | gitleaks | trivy | checkov
    agent_slug: str                    # which specialist owns it
    title: str
    # location
    file: str | None = None
    line: int | None = None
    # dependency findings
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None
    # identity
    cve: str | None = None
    cwe: str | None = None
    rule_id: str | None = None
    aliases: list[str] = field(default_factory=list)
    # severity as reported by the source, before our own scoring
    cvss: float | None = None
    severity_label: str | None = None
    summary: str | None = None
    references: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanContext:
    """What a scanner is given."""
    root: Path                          # checked-out repo
    repo: str                           # owner/name
    changed_files: list[str] | None = None   # None means full sweep
    timeout_s: int = 300

    def is_full_sweep(self) -> bool:
        return self.changed_files is None

    def touched(self, path: str) -> bool:
        """True when a full sweep, or when this path changed in the push."""
        if self.changed_files is None:
            return True
        return any(c == path or c.endswith("/" + path) for c in self.changed_files)
