"""Getting a connector-linked repository onto disk, safely.

Archive download is preferred (`GET .../tarball/{sha}`, streamed to disk, no
git process at all); a shallow HTTPS clone is the fallback, used only when
the archive endpoint fails. Either way: pinned to an exact commit SHA (never
a moving branch head), a sandboxed temp directory that is always cleaned up,
a bounded timeout, and - the one rule that matters most here - the OAuth
token never touches a file on disk. The archive path never sees the token at
all outside the Authorization header of one HTTP request; the clone fallback
passes it as a transient `-c http.extraHeader` flag on the `git` argv, which
git uses for that invocation only and never writes into `.git/config`.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.github.client import GitHubApiError, GitHubClient
from app.connectors.github.oauth import GitHubAuthStrategy
from app.models.github import GithubInstallation
from app.services.repo import GIT_HARDENING, SAFE_ENV, RepoError, RepoTooLarge, _force_rm, dir_size_mb

log = logging.getLogger(__name__)


def _safe_extract(archive_path: Path, dest: Path) -> None:
    """`filter="data"` is the stdlib's own tar-extraction hardening (PEP 706,
    Python 3.12+): it refuses absolute paths, `..` traversal, device/fifo
    members and symlinks that would land outside `dest`, and strips setuid
    bits - every member is still validated to resolve inside `dest` before
    anything is written."""
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(dest, filter="data")


def _flatten_single_root(dest: Path) -> Path:
    """GitHub's tarball wraps everything in one `owner-repo-<sha7>/` dir."""
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


async def _via_archive(
    db: Session, installation: GithubInstallation, strategy: GitHubAuthStrategy,
    full_name: str, ref: str, workdir: Path,
) -> tuple[Path, dict]:
    client = GitHubClient(db, installation, strategy)
    commit = await client.get_commit(full_name, ref)
    sha = commit["sha"]
    info = commit.get("commit", {})
    subject = (info.get("message") or "").splitlines()[0][:500] if info.get("message") else ""
    author = (info.get("author") or {}).get("name", "")
    committed_at = (info.get("author") or {}).get("date", "")

    archive_path = workdir / "archive.tar.gz"
    started = time.time()
    await client.download_archive(full_name, sha, dest_path=str(archive_path))

    extract_to = workdir / "extracted"
    extract_to.mkdir()
    _safe_extract(archive_path, extract_to)
    root = _flatten_single_root(extract_to)

    size = dir_size_mb(root)
    if size > settings.max_repo_mb:
        raise RepoTooLarge(f"{full_name} is {size:.0f} MB, over the {settings.max_repo_mb} MB limit")

    return root, {
        "commit": sha, "subject": subject, "author": author, "committed_at": committed_at,
        "branch": ref, "size_mb": round(size, 1), "clone_s": round(time.time() - started, 2),
        "method": "archive",
    }


def _via_shallow_clone(
    db: Session, installation: GithubInstallation, strategy: GitHubAuthStrategy,
    full_name: str, ref: str, workdir: Path,
) -> tuple[Path, dict]:
    # ponytail: clones the branch head, not the exact SHA the archive path
    # would have pinned - a shallow `git clone` can't reliably fetch an
    # arbitrary historical commit over smart HTTP without extra server
    # support. Upgrade path: `git fetch --depth=1 origin <sha>` once we
    # confirm GitHub has allowReachableSHA1InWant enabled for this repo.
    token = strategy.get_valid_token(db, installation)
    dest = workdir / "repo"
    started = time.time()
    url = f"https://github.com/{full_name}.git"
    # A transient per-invocation header, never persisted to .git/config.
    auth_header = f"AUTHORIZATION: basic {_basic(token)}"

    args = [
        "git", *GIT_HARDENING, "-c", f"http.extraHeader={auth_header}",
        "clone", "--depth=1", "--no-tags", "--no-recurse-submodules", "--quiet",
        "--branch", ref, "--single-branch", url, str(dest),
    ]
    proc = subprocess.run(   # noqa: S603 — fixed argv, never a shell
        args, env=SAFE_ENV, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=settings.github_clone_timeout, shell=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise RepoError(f"clone fallback for {full_name}@{ref} failed: {err[-1] if err else 'unknown error'}")

    def _git(args: list[str]) -> str:
        r = subprocess.run(["git", *GIT_HARDENING, *args], cwd=dest, env=SAFE_ENV,
                            capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=30, shell=False)
        return r.stdout.strip()

    size = dir_size_mb(dest)
    if size > settings.max_repo_mb:
        raise RepoTooLarge(f"{full_name} is {size:.0f} MB, over the {settings.max_repo_mb} MB limit")

    return dest, {
        "commit": _git(["rev-parse", "HEAD"]), "subject": _git(["log", "-1", "--pretty=%s"]),
        "author": _git(["log", "-1", "--pretty=%an"]), "committed_at": _git(["log", "-1", "--pretty=%aI"]),
        "branch": ref, "size_mb": round(size, 1), "clone_s": round(time.time() - started, 2),
        "method": "clone",
    }


def _basic(token: str) -> str:
    import base64
    return base64.b64encode(f"x-access-token:{token}".encode()).decode()


@contextmanager
def fetch_workspace(
    db: Session, installation: GithubInstallation, strategy: GitHubAuthStrategy,
    full_name: str, ref: str,
) -> Iterator[tuple[Path, dict]]:
    """Archive download first, shallow clone on any failure. Always cleans up."""
    Path(settings.workspace_dir).mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="fantom-connector-", dir=settings.workspace_dir))
    try:
        try:
            root, meta = asyncio.run(_via_archive(db, installation, strategy, full_name, ref, workdir))
        except (GitHubApiError, tarfile.TarError, OSError) as exc:
            log.warning("archive download for %s@%s failed (%s), falling back to shallow clone", full_name, ref, exc)
            root, meta = _via_shallow_clone(db, installation, strategy, full_name, ref, workdir)
        log.info("workspace ready for %s@%s via %s (%.1f MB, %.1fs)",
                  full_name, ref, meta["method"], meta["size_mb"], meta["clone_s"])
        yield root, meta
    finally:
        _force_rm(workdir)
