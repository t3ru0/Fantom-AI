"""Stable finding identity.

The single most load-bearing function in the system. Without it, a reformat or a
moved file resurrects every finding as brand new, and age, trend and forecast
all become lies.

Rule: fingerprint from what the finding IS, never from where it currently sits.
Line numbers are excluded on purpose. File paths are excluded for dependency
findings (a lockfile can move) but kept for code findings, where the file is
part of the identity.
"""
from __future__ import annotations

import hashlib
import re

from app.scanners.base import RawFinding


def _norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _version_free(pkg: str | None) -> str:
    """Strip any embedded version so an upgrade does not mint a new finding."""
    return re.sub(r"[@:]\s*v?\d[\w.+-]*$", "", _norm(pkg))


def fingerprint(f: RawFinding) -> str:
    """64-char hex. Deterministic for the same logical finding across scans."""
    if f.scanner == "osv":
        # A dependency advisory is identified by (advisory, package). The
        # version deliberately does NOT participate: bumping 4.17.15 -> 4.17.16
        # while still vulnerable is the same finding, still ageing.
        parts = ["osv", _norm(f.rule_id or f.cve), _version_free(f.package), _norm(f.ecosystem)]
    elif f.scanner in ("semgrep", "checkov"):
        # Code and config findings are identified by (rule, file). Line excluded.
        parts = [f.scanner, _norm(f.rule_id), _norm(f.file)]
    elif f.scanner == "gitleaks":
        # A secret is identified by where it is and what kind it is — never by
        # the secret value, which must not be hashed into anything we store.
        parts = ["gitleaks", _norm(f.rule_id), _norm(f.file)]
    elif f.scanner == "trivy":
        parts = ["trivy", _norm(f.cve or f.rule_id), _version_free(f.package), _norm(f.file)]
    else:
        parts = [f.scanner, _norm(f.rule_id or f.title), _norm(f.file)]

    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def explain(f: RawFinding) -> str:
    """Human-readable account of what the fingerprint was built from."""
    if f.scanner == "osv":
        return f"advisory {f.rule_id or f.cve} on package {f.package} ({f.ecosystem})"
    if f.scanner == "gitleaks":
        return f"rule {f.rule_id} in {f.file} (secret value never hashed)"
    return f"rule {f.rule_id} in {f.file}"
