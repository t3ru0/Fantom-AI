"""Getting a repository onto disk, safely.

The whole security posture of this product rests on one rule: we read the
repository, we never run it. No install step, no build, no hooks, no submodules.
Everything below exists to keep that true even for a hostile repository.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

from app.config import settings

log = logging.getLogger(__name__)


class RepoError(RuntimeError):
    pass


class RepoTooLarge(RepoError):
    pass


# Hardening applied to every git invocation.
GIT_HARDENING = [
    "-c", "core.hooksPath=/dev/null",          # never run a hook shipped by the repo
    "-c", "core.symlinks=false",               # no symlink escapes on checkout
    "-c", "protocol.version=2",
    "-c", "credential.helper=",                # never consult the host keychain
    "-c", "core.fsmonitor=false",
    "-c", "gc.auto=0",
]

SAFE_ENV = {
    "GIT_TERMINAL_PROMPT": "0",                # fail instead of prompting for auth
    "GIT_ASKPASS": "echo",
    "GIT_CONFIG_NOSYSTEM": "1",                # ignore /etc/gitconfig
    "GCM_INTERACTIVE": "never",
    "PATH": os.environ.get("PATH", ""),
    "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),   # git on Windows needs this
    "TEMP": os.environ.get("TEMP", ""),
    "TMP": os.environ.get("TMP", ""),
}


def _run(args: list[str], cwd: Path | None = None, timeout: int = 300) -> str:
    proc = subprocess.run(  # noqa: S603 — fixed argv, never a shell
        ["git", *GIT_HARDENING, *args],
        cwd=cwd,
        env=SAFE_ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",      # git speaks UTF-8; the Windows locale does not
        errors="replace",
        timeout=timeout,
        shell=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise RepoError(f"git {args[0]} failed: {err[-1] if err else 'unknown error'}")
    return proc.stdout


def clone_url(repo: str, token: str | None = None) -> str:
    """repo is 'owner/name'. A token is injected only for private repositories."""
    if token:
        return f"https://x-access-token:{token}@github.com/{repo}.git"
    return f"https://github.com/{repo}.git"


def dir_size_mb(path: Path) -> float:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            continue
    return total / (1024 * 1024)


def _force_rm(path: Path) -> None:
    """Windows leaves .git objects read-only; chmod then retry."""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerror)


@contextmanager
def checkout(repo: str, ref: str | None = None, token: str | None = None,
             keep: bool = False) -> Iterator[tuple[Path, dict]]:
    """Shallow-clone into a temp dir and always clean up.

    Yields (path, meta) where meta carries the resolved commit and timings.
    """
    Path(settings.workspace_dir).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="fantom-", dir=settings.workspace_dir))
    dest = work / "repo"
    started = time.time()
    try:
        args = ["clone", "--depth=1", "--no-tags", "--no-recurse-submodules",
                "--quiet", clone_url(repo, token), str(dest)]
        if ref:
            args[1:1] = ["--branch", ref, "--single-branch"]
        _run(args, timeout=settings.scanner_timeout_s)

        size = dir_size_mb(dest)
        if size > settings.max_repo_mb:
            raise RepoTooLarge(
                f"{repo} is {size:.0f} MB, over the {settings.max_repo_mb} MB limit"
            )

        sha = _run(["rev-parse", "HEAD"], cwd=dest).strip()
        subject = _run(["log", "-1", "--pretty=%s"], cwd=dest).strip()
        author = _run(["log", "-1", "--pretty=%an"], cwd=dest).strip()
        when = _run(["log", "-1", "--pretty=%aI"], cwd=dest).strip()
        branch = ref or _run(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest).strip()

        meta = {
            "commit": sha, "subject": subject, "author": author,
            "committed_at": when, "branch": branch,
            "size_mb": round(size, 1), "clone_s": round(time.time() - started, 2),
        }
        log.info("cloned %s@%s (%.1f MB, %.1fs)", repo, sha[:8], size, meta["clone_s"])
        yield dest, meta
    finally:
        if keep:
            log.info("workspace kept at %s", work)
        else:
            _force_rm(work)


def count_lines(root: Path, exts: set[str] | None = None) -> int:
    """Rough LOC for the complexity score. Cheap and good enough."""
    from app.scanners.lockfiles import SKIP_DIRS
    exts = exts or {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
        ".rs", ".c", ".cpp", ".cs", ".kt", ".swift", ".scala", ".sh",
    }
    total = 0
    for p in root.rglob("*"):
        if p.suffix.lower() not in exts:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            with p.open("rb") as fh:
                total += sum(1 for _ in fh)
        except OSError:
            continue
    return total
