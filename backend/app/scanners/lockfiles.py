"""Lockfile parsing.

Every parser reads text. Nothing is installed, resolved or executed — that rule
is what makes it safe to point this at a stranger's repository.

Supported: npm (package-lock, pnpm-lock, yarn.lock v1), PyPI (requirements.txt,
poetry.lock, Pipfile.lock), Go (go.mod), RubyGems, crates.io, Packagist.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from app.scanners.base import Package

log = logging.getLogger(__name__)

# Filename -> (ecosystem, parser name). Order matters only for reporting.
LOCKFILES = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "go.mod": "Go",
    "Gemfile.lock": "RubyGems",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
}

# Directories never worth walking into.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".next", ".nuxt", "site-packages", ".tox", ".mypy_cache",
}


def _clean_version(v: str) -> str:
    return (v or "").strip().lstrip("=^~ ").strip()


# ---------------------------------------------------------------- npm -------
def parse_package_lock(text: str, rel: str) -> list[Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[Package] = []
    # lockfileVersion 2/3: the "packages" map, keyed by path
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue                                  # "" is the root project
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver and not meta.get("link"):
            out.append(Package(name, ver, "npm", rel, direct=path.count("node_modules") <= 1))
    if out:
        return out
    # lockfileVersion 1: nested "dependencies"
    def walk(deps: dict, depth: int = 0) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(Package(name, meta["version"], "npm", rel, direct=depth == 0))
                walk(meta.get("dependencies") or {}, depth + 1)
    walk(data.get("dependencies") or {})
    return out


def parse_pnpm_lock(text: str, rel: str) -> list[Package]:
    """pnpm keys look like  /lodash@4.17.15  or  /@scope/pkg@1.0.0(peer@1)."""
    out: list[Package] = []
    for m in re.finditer(r"^\s{2}(/[^:\s]+):", text, re.M):
        key = m.group(1).lstrip("/")
        key = key.split("(")[0]                       # drop peer-dep suffix
        if "@" not in key:
            continue
        idx = key.rfind("@")
        if idx <= 0:
            continue
        name, ver = key[:idx], key[idx + 1:]
        if name and ver:
            out.append(Package(name, ver, "npm", rel))
    return out


def parse_yarn_lock(text: str, rel: str) -> list[Package]:
    """yarn v1 is a flat text format: a header line then an indented version."""
    out: list[Package] = []
    current: str | None = None
    for line in text.splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            head = line.split(",")[0].strip().strip('"').rstrip(":")
            idx = head.rfind("@")
            current = head[:idx] if idx > 0 else None
        elif current and line.strip().startswith("version"):
            ver = line.split(None, 1)[-1].strip().strip('"')
            out.append(Package(current, ver, "npm", rel))
            current = None
    return out


# --------------------------------------------------------------- PyPI -------
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9._+!-]+)")


def parse_requirements(text: str, rel: str) -> list[Package]:
    """Only pinned (==) lines. A range is not a fact about what ships."""
    out: list[Package] = []
    for line in text.splitlines():
        line = line.split("#")[0]
        if not line.strip() or line.strip().startswith("-"):
            continue
        m = REQ_LINE.match(line)
        if m:
            out.append(Package(m.group(1), m.group(2), "PyPI", rel))
    return out


def parse_poetry_lock(text: str, rel: str) -> list[Package]:
    out: list[Package] = []
    name = ver = None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = ver = None
        elif s.startswith("name = "):
            name = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version = "):
            ver = s.split("=", 1)[1].strip().strip('"')
        if name and ver:
            out.append(Package(name, ver, "PyPI", rel))
            name = ver = None
    return out


def parse_pipfile_lock(text: str, rel: str) -> list[Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[Package] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = _clean_version(str(meta.get("version", "")))
            if ver:
                out.append(Package(name, ver, "PyPI", rel, direct=section == "default"))
    return out


# ----------------------------------------------------------------- Go -------
def parse_go_mod(text: str, rel: str) -> list[Package]:
    """OSV's Go ecosystem wants the version without its leading v."""
    out: list[Package] = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("//") or not s:
            continue
        if in_block or s.startswith("require "):
            parts = s.removeprefix("require ").split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                if "// indirect" in line:
                    out.append(Package(parts[0], parts[1].lstrip("v"), "Go", rel, direct=False))
                else:
                    out.append(Package(parts[0], parts[1].lstrip("v"), "Go", rel))
    return out


# -------------------------------------------------------------- others -----
def parse_gemfile_lock(text: str, rel: str) -> list[Package]:
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() in ("specs:",):
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)$", line)
            if m:
                out.append(Package(m.group(1), m.group(2), "RubyGems", rel))
            elif line and not line.startswith(" "):
                in_specs = False
    return out


def parse_cargo_lock(text: str, rel: str) -> list[Package]:
    out, name, ver = [], None, None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = ver = None
        elif s.startswith("name = "):
            name = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version = "):
            ver = s.split("=", 1)[1].strip().strip('"')
        if name and ver:
            out.append(Package(name, ver, "crates.io", rel))
            name = ver = None
    return out


def parse_composer_lock(text: str, rel: str) -> list[Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for section, direct in (("packages", True), ("packages-dev", False)):
        for meta in data.get(section) or []:
            n, v = meta.get("name"), _clean_version(meta.get("version", ""))
            if n and v:
                out.append(Package(n, v, "Packagist", rel, direct=direct))
    return out


PARSERS = {
    "package-lock.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "requirements.txt": parse_requirements,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
}


def find_lockfiles(root: Path) -> list[Path]:
    found: list[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in PARSERS:
            found.append(p)
    return sorted(found)


def collect_packages(root: Path) -> tuple[list[Package], list[str]]:
    """Returns (deduplicated packages, lockfiles read)."""
    seen: dict[str, Package] = {}
    files: list[str] = []
    for path in find_lockfiles(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("cannot read %s: %s", rel, exc)
            continue
        try:
            pkgs = PARSERS[path.name](text, rel)
        except Exception as exc:  # noqa: BLE001 — one bad lockfile must not kill the scan
            log.warning("parser failed on %s: %s", rel, exc)
            continue
        files.append(rel)
        for pkg in pkgs:
            seen.setdefault(pkg.key, pkg)
    return list(seen.values()), files
