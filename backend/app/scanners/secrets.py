"""The Secret Hunter.

Two detectors, in order of confidence:

  1. Provider patterns — a string that can only be one thing. An `AKIA...` is an
     AWS key; there is no ambiguity and no entropy threshold needed.
  2. Shannon entropy — a high-entropy string assigned to a suspiciously named
     variable. Lower confidence, so it is reported as such.

**The secret value is never stored, never logged, and never hashed into the
fingerprint.** Only a redacted preview (first 4 characters) survives, which is
enough for a human to find it and useless to anyone who steals our database.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from pathlib import Path

from app.scanners.base import RawFinding, ScanContext

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 2_000_000
MAX_LINE_LEN = 4_000

# Directories and files that produce nothing but false positives.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".next", ".nuxt", "site-packages", ".tox", "coverage",
}
SKIP_SUFFIX = {
    ".min.js", ".min.css", ".map", ".lock", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".wasm", ".pyc", ".so", ".dll", ".exe", ".class", ".jar",
}
# Lockfiles are wall-to-wall base64 integrity hashes. Entropy is meaningless there.
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
}

# ---------------------------------------------------------------- patterns --
# (rule id, human name, regex, severity 1-4)
PROVIDER_PATTERNS: list[tuple[str, str, re.Pattern[str], int]] = [
    ("aws-access-key", "AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 4),
    ("github-pat", "GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), 4),
    ("github-fine-grained", "GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), 4),
    ("gitlab-pat", "GitLab personal access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), 4),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 4),
    ("slack-webhook", "Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9/_+-]{20,}"), 3),
    ("stripe-live", "Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"), 4),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 3),
    ("openai-key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"), 4),
    ("anthropic-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}\b"), 4),
    ("sendgrid-key", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b"), 4),
    ("twilio-sid", "Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 3),
    ("npm-token", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 4),
    ("private-key", "Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), 4),
    ("jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 2),
    ("db-uri-password", "Database URI with an inline password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{3,}@[^\s/]+"), 4),
    ("slack-legacy", "Slack legacy token", re.compile(r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b"), 4),
]

# Entropy detector: a suspicious assignment target plus a high-entropy value.
ASSIGN = re.compile(
    r"""(?ix)
    \b(
      (?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|
         private[_-]?key|client[_-]?secret|password|passwd|pwd|credential|
         encryption[_-]?key|signing[_-]?key|session[_-]?secret|bearer)
    )
    \s*[:=]\s*
    ['"]([^'"\s]{16,200})['"]
    """
)

# Values that are obviously not secrets.
PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[a-z_]+%|"
    r"your[-_ ]?[a-z]*|change[-_ ]?me|example|sample|dummy|placeholder|redacted|"
    r"test|todo|none|null|undefined|password|secret|abc123|insert[-_ ]?[a-z]*)$"
)
HEXISH = re.compile(r"^[0-9a-f]+$", re.I)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ENTROPY_MIN = 4.0


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """First four characters, then the length. Enough to find it, useless to steal."""
    head = value[:4]
    return f"{head}{'*' * min(12, max(0, len(value) - 4))} ({len(value)} chars)"


def _looks_like_a_secret(value: str) -> bool:
    if PLACEHOLDER.match(value.strip()):
        return False
    if UUID.match(value):
        return False
    if HEXISH.match(value) and len(value) in (32, 40, 64, 128):
        return False                       # md5/sha1/sha256/sha512 digest
    if value.count(" ") > 1 or "/" in value and value.startswith(("./", "../", "/")):
        return False                       # a sentence or a path
    return shannon(value) >= ENTROPY_MIN


def _should_read(path: Path, root: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name in SKIP_NAMES:
        return False
    low = path.name.lower()
    if any(low.endswith(sfx) for sfx in SKIP_SUFFIX):
        return False
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return True


def _is_example_file(rel: str) -> bool:
    low = rel.lower()
    return any(k in low for k in (".example", ".sample", ".template", ".dist", "fixtures/", "testdata/"))


def scan(ctx: ScanContext) -> list[RawFinding]:
    findings: list[RawFinding] = []
    root = ctx.root

    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if not _should_read(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        if not ctx.touched(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "\x00" in text[:1024]:          # binary
            continue

        example = _is_example_file(rel)

        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > MAX_LINE_LEN:
                continue

            # 1. provider patterns — unambiguous
            for rule_id, name, pattern, sev in PROVIDER_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                value = m.group(0)
                findings.append(
                    RawFinding(
                        scanner="gitleaks", agent_slug="secret",
                        title=f"{name} committed to the repository",
                        file=rel, line=lineno, rule_id=rule_id,
                        cwe="CWE-798",
                        cvss=None,
                        severity_label=("LOW" if example else
                                        {4: "CRITICAL", 3: "HIGH", 2: "MODERATE"}.get(sev, "MODERATE")),
                        summary=(
                            f"A {name.lower()} appears in {rel} at line {lineno}."
                            + (" This looks like an example or fixture file, so confidence is lower."
                               if example else "")
                        ),
                        remediation=[
                            "Revoke the credential at the provider first. Removing it from the "
                            "repository does not invalidate it.",
                            "Rotate anything that credential could reach.",
                            "Purge the value from git history, then force-update every mirror and fork.",
                            "Move the value to a secret manager and inject it at deploy time.",
                        ],
                        extra={
                            "detector": "pattern",
                            "confidence": 0.55 if example else 0.95,
                            "redacted": redact(value),
                            "example_file": example,
                        },
                    )
                )

            # 2. entropy — a suspicious name holding a random-looking value
            for m in ASSIGN.finditer(line):
                var, value = m.group(1), m.group(2)
                if not _looks_like_a_secret(value):
                    continue
                if any(f.file == rel and f.line == lineno for f in findings[-6:]):
                    continue               # already caught by a provider pattern
                findings.append(
                    RawFinding(
                        scanner="gitleaks", agent_slug="secret",
                        title=f"High-entropy value assigned to {var}",
                        file=rel, line=lineno, rule_id="entropy-assignment",
                        cwe="CWE-798",
                        severity_label="LOW" if example else "HIGH",
                        summary=(
                            f"`{var}` in {rel} holds a {len(value)}-character value with "
                            f"{shannon(value):.1f} bits of entropy per character. That is "
                            f"consistent with a real credential rather than a placeholder."
                        ),
                        remediation=[
                            "Confirm whether this is a live credential.",
                            "If it is, revoke and rotate it before removing it from the code.",
                            "Replace it with an environment variable or a secret manager reference.",
                        ],
                        extra={
                            "detector": "entropy",
                            "confidence": 0.4 if example else 0.7,
                            "entropy": round(shannon(value), 2),
                            "redacted": redact(value),
                            "example_file": example,
                        },
                    )
                )

    log.info("secrets: %d candidates", len(findings))
    return findings
