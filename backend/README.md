# fantom.ai

**AI-powered continuous cyber risk quantification and investment optimization platform.**

Connect a GitHub repository. FANTOM inspects it on every push, finds vulnerable
dependencies, leaked secrets, code flaws and infrastructure misconfigurations,
ranks them by how dangerous they are *in your system* rather than by CVSS, and —
once you supply business context — prices them in engineer hours and expected
annual loss.

```
WHERE THIS DISAGREES WITH CVSS   (band moves, not point moves)
  ESCALATED      CVSS 5.5 → 94  [Med → Critical]   jquery
                 on the CISA KEV catalogue since 2025-01-23 · EPSS 83.8% (top 1%)
  DEPRIORITISED  CVSS 9.5 → 59  [Crit → Medium]    bson
                 no exploit maturity signal · EPSS 2.2% (82nd percentile)
```

A CVSS 5.5 that is *actually being exploited* outranks a CVSS 9.5 that nobody has
ever touched. That is the product in two lines.

---

## Contents

- [Status](#status)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Scanning a repository from the command line](#scanning-a-repository-from-the-command-line)
- [HTTP API](#http-api)
- [Configuration](#configuration)
- [Scanners](#scanners)
- [Enrichment](#enrichment)
- [Contextual scoring](#contextual-scoring)
- [The loss model](#the-loss-model)
- [Data model](#data-model)
- [Security model](#security-model)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Known limitations](#known-limitations)

---

## Status

Version `0.1.0`. Built in phases; phases 0–3 are complete and covered by 81 tests.

| Phase | Scope | State |
|---|---|---|
| **0** | Skeleton — config, schema, health, migrations | done |
| **1** | GitHub App auth, webhook verification, safe clone, OSV dependency scanning | done |
| **2** | Secret, code and infrastructure scanners · EPSS + CISA KEV enrichment · contextual score | done |
| **3** | Business context, loss model, portfolio aggregation, pricing API | done |
| 4 | Repository survey, agent recruiter, wave scheduler, live run floor over SSE | planned |
| 5 | LLM reachability analysis, referee, attack-chain builder, chat | planned |
| 6 | Heartbeat loop, exposure forecast, reports | planned |
| 7 | Sandbox hardening, multi-tenancy, audit | planned |

---

## How it works

```mermaid
flowchart LR
    GH[GitHub push] -->|HMAC-verified webhook| WH[/webhooks/github/]
    CLI[scripts/scan_repo.py] --> CL
    WH -.->|Phase 4: enqueue| CL[Safe shallow clone]
    CL --> LF[Lockfile parser] --> OSV[(osv.dev)]
    CL --> SEC[Secret Hunter]
    CL --> CODE[Code Flaw Hunter]
    CL --> INFRA[Infra scanner]
    OSV --> EN[Enrichment<br/>EPSS · CISA KEV]
    SEC --> EN
    CODE --> EN
    INFRA --> EN
    EN --> SC[Contextual score<br/>0–100, tier, SLA]
    SC --> FP[Stable fingerprint]
    FP --> MON{Business context<br/>complete?}
    MON -->|no| RANK[Ranked, not priced]
    MON -->|yes| PRICE[Priced: loss, effort,<br/>portfolio exposure]
```

1. **Clone** — shallow, hardened, size-capped, always deleted afterwards. Repository code is read, never run.
2. **Scan** — pure-Python scanners read lockfiles, source and config as text.
3. **Enrich** — CVEs are looked up in FIRST.org EPSS and the CISA Known Exploited Vulnerabilities catalogue.
4. **Score** — each finding gets a 0–100 contextual score, a tier and a fix-by SLA.
5. **Fingerprint** — each finding gets an identity that survives reformatting, moved files and version bumps.
6. **Price** — only if all five business-context inputs are present. Otherwise the money fields stay `null`.

---

## Quick start

### Requirements

- **Python 3.12+** (3.14 verified)
- **Docker** (for local Postgres 17 and Redis 7)
- **git** on `PATH` (used for cloning scanned repositories)

### One command

```powershell
# Windows PowerShell
.\scripts\dev.ps1            # add -Fresh to drop and re-create the schema
```

```bash
# macOS / Linux / Git Bash
./scripts/dev.sh
```

Both scripts create `.venv`, copy `.env.example` to `.env`, install dependencies,
start Postgres, run migrations and start the API on port 8000.

### Step by step

```bash
# 1. dependencies
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt       # Windows
# source .venv/bin/activate && pip install -r requirements.txt    # macOS/Linux
# exact versions that were verified: requirements.lock.txt

# 2. config
cp .env.example .env

# 3. database
docker compose up -d db
.venv/Scripts/python.exe -m alembic upgrade head

# 4. api
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

Then open:

| URL | What |
|---|---|
| http://localhost:8000/ | version and current build phase |
| http://localhost:8000/health | every component's real state; always 200 |
| http://localhost:8000/ready | 503 until the database is up **and** migrated |
| http://localhost:8000/docs | interactive OpenAPI docs |

**The app boots without Postgres on purpose.** `/health` reports what is missing
and how to fix it instead of crashing, so a half-configured machine is still
debuggable. The CLI scanner and the stateless pricing endpoints need no database
at all.

---

## Scanning a repository from the command line

`scripts/scan_repo.py` runs the full pipeline against any public GitHub
repository with nothing configured — no database, no GitHub App, no API keys.

```bash
.venv/Scripts/python.exe scripts/scan_repo.py owner/repo [options]
```

| Option | Default | Meaning |
|---|---|---|
| `--branch NAME` | default branch | branch to clone |
| `--only lib,secret,code` | all three | which scanners to run |
| `--limit N` | 15 | rows shown in the work order |
| `--json FILE` | — | write every unique finding, with score factors and money, as JSON |
| `--keep` | off | keep the cloned workspace under `.workspaces/` |
| `--context FILE` | — | JSON file with business context |
| `--revenue USD` | — | annual revenue the project supports |
| `--downtime USD` | — | cost of one hour of downtime |
| `--users N` | — | users the project serves |
| `--records N` | — | personal or regulated records it can reach |
| `--regimes A,B` | — | e.g. `DPDP,PCI` (see [regimes](#regulatory-regimes)) |

### Examples

```bash
# dependencies, secrets and code, ranked but not priced
.venv/Scripts/python.exe scripts/scan_repo.py snyk-labs/nodejs-goof --limit 10

# code only
.venv/Scripts/python.exe scripts/scan_repo.py anxolerd/dvpwa --only code

# priced
.venv/Scripts/python.exe scripts/scan_repo.py snyk-labs/nodejs-goof \
  --revenue 24000000 --downtime 38000 --users 180000 --records 180000 \
  --regimes DPDP,PCI

# export
.venv/Scripts/python.exe scripts/scan_repo.py OWASP/NodeGoat --json findings.json
```

### Real output

On `snyk-labs/nodejs-goof`:

```
  clone      add14ba59e  1.8 MB  2.16s
  lockfiles  1 found: package-lock.json
  packages   980 resolved
  osv.dev    293 advisories  (8.9s)

FINDINGS  293 advisories · 100 packages · 214 unique fingerprints
          271 carry a CVE · 285 have a fixed version · 8 do not
```

Priced, with the context above:

```
exposure                $6,435,424 / year
worst single breach     $3,610,800  from typeorm
P(any exploited/yr)     100.0%
cost to fix everything  $1,318,730  (6,536 loaded hours · 40.85 sprints)
naive sum would say $90,312,515 - that double-counts the
same records across every finding, so it is not used.
```

On `anxolerd/dvpwa`:

```
  1. 68 ###. High    SQL statement assembled by string interpolation
     sqli/dao/student.py:45
```

Line 42 builds the query with `%`, line 45 executes it. A rule that only looked at
the call site would see a parameterised query and miss the injection — which is
why the Python scanner tracks taint within a function.

The CLI output has four sections: **FINDINGS** (counts by tier and scanner, KEV
hits), **WHERE THIS DISAGREES WITH CVSS**, **MONEY** (or the reason it is not
priced) and **WORK ORDER** (ranked by contextual score, with SLA, EPSS,
confidence and, when priced, loss and fix cost per finding).

---

## HTTP API

All application routes are under `/api`. Full schemas at `/docs`.

### Health

| Method | Route | Returns |
|---|---|---|
| GET | `/` | name, version, build phase |
| GET | `/health` | `status` (`ok` / `degraded`), uptime, and per-component state for `database`, `github_app`, `llm`, each with a fix hint |
| GET | `/ready` | `200` when the database is reachable and migrated, else `503` |

### Pricing and context (no database needed)

| Method | Route | Does |
|---|---|---|
| POST | `/api/price/preview` | scores and prices one finding statelessly |
| POST | `/api/context/validate` | reports which business-context fields are missing and why each matters |
| GET | `/api/assumptions` | every judgement call in the loss model |
| GET | `/api/regimes` | regulatory regimes, per-record rates and caps |

Example — price one finding:

```bash
curl -s localhost:8000/api/price/preview -H 'content-type: application/json' -d '{
  "context": {
    "revenue_supported": 24000000, "downtime_cost_hour": 38000,
    "users_count": 180000, "records_count": 180000, "regimes": ["DPDP", "PCI"]
  },
  "finding": {
    "scanner": "osv", "title": "Prototype pollution", "cve": "CVE-2020-8203",
    "cwe": "CWE-1321", "cvss": 7.4, "package": "lodash",
    "version": "4.17.15", "fixed_version": "4.17.19", "epss": 0.03, "kev": false
  }
}'
```

The response carries `context_score`, `tier`, `sla`, `if_it_happens`,
`annual_loss_upper_bound`, `loss_per_hour`, a `components` breakdown (each with
its basis), an `effort` estimate and the `assumptions` used. Drop any of the five
context fields and the same request returns `"priced": false` with
`context_missing` listing what is needed.

### Projects (Postgres required)

| Method | Route | Does |
|---|---|---|
| POST | `/api/projects` | connect a repository (`{"repo": "owner/name", "branch": "main"}`); `409` if already connected |
| GET | `/api/projects` | list projects; `exposure` is `null` unless context is complete |
| GET | `/api/projects/{id}/context` | context status for a project |
| PUT | `/api/projects/{id}/context` | set business context; flips `context_complete` when all five are present |

`repo` must be `owner/name`. URLs are rejected rather than guessed at.

### Webhooks

| Method | Route | Does |
|---|---|---|
| POST | `/webhooks/github` | GitHub App webhook receiver |

| Case | Response |
|---|---|
| `GITHUB_WEBHOOK_SECRET` unset | `503 {"error": "webhook_not_configured"}` |
| missing or wrong `X-Hub-Signature-256` | `401 {"error": "bad_signature"}` |
| body is not JSON | `400` |
| `ping` | `202 {"ok": true, "pong": true}` |
| `push` to a branch | `202` with repo, branch, commit, changed-file count |
| tag push, branch delete, empty push | `202` with `skipped` |
| `installation`, `installation_repositories` | `202` with action, account, repo count |
| any other event | `202 {"ignored": "<event>"}` |

The signature is checked in constant time **before** the body is parsed. The
handler never does slow work, because GitHub times out at 10 seconds and disables
webhooks that keep failing.

### Errors

Every unhandled error returns `500 {"error": "internal_error", "request_id": "..."}`.
The stack trace is logged server-side and never sent to the client. Every response
carries an `x-request-id` header (taken from the request if supplied).

---

## Configuration

All settings come from environment variables or `.env` (see `.env.example`).
Names are case-insensitive. Nothing required to boot is secret.

| Variable | Default | Purpose |
|---|---|---|
| `ENV` | `dev` | `dev`, `test` or `prod`; `prod` switches logs to JSON |
| `DEBUG` | `false` | debug mode |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | comma-separated allowed origins |
| `DATABASE_URL` | `postgresql+psycopg://fantom:fantom@localhost:5432/fantom` | Postgres only |
| `DB_POOL_SIZE` | `5` | SQLAlchemy pool size (overflow is 2×) |
| `DB_ECHO` | `false` | log SQL |
| `DB_CONNECT_TIMEOUT` | `3` | seconds; keeps `/health` bounded |
| `REDIS_URL` | `redis://localhost:6379/0` | queue (Phase 4) |
| `GITHUB_APP_ID` | — | GitHub App id (pre-connector flow, still running as-is) |
| `GITHUB_WEBHOOK_SECRET` | — | GitHub App webhook HMAC secret; that flow's webhooks are refused without it |
| `GITHUB_PRIVATE_KEY` | — | App private key PEM, newlines written as literal `\n` |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | — | GitHub connector's OAuth App credentials |
| `GITHUB_REDIRECT_URI` | `http://localhost:8000/connectors/github/callback` | must match the OAuth App's callback URL exactly |
| `GITHUB_ENCRYPTION_KEY` | — | base64, decodes to exactly 32 bytes; AES-256-GCM key for every stored connector credential |
| `GITHUB_ENCRYPTION_KEY_PREVIOUS` | — | optional; set only while rotating `GITHUB_ENCRYPTION_KEY` |
| `GITHUB_API_BASE` | `https://api.github.com` | optional |
| `GITHUB_SYNC_PAGE_SIZE` | `100` | optional; repositories fetched per page during sync |
| `GITHUB_CLONE_TIMEOUT` | `120` | optional; seconds, connector archive download / shallow clone |
| `CONNECTOR_SYNC_INTERVAL_HOURS` | `6` | scheduled connector maintenance sweep interval |
| `OPENROUTER_API_KEY` | — | LLM access (Phase 5) |
| `MAX_REPO_MB` | `500` | clones larger than this are refused |
| `SCANNER_TIMEOUT_S` | `300` | clone and scanner timeout |
| `WORKSPACE_DIR` | `./.workspaces` | where clones are made (and deleted) |
| `DEFAULT_ENG_RATE_HOUR` | `120` | loaded engineer cost; the only money default in the system |
| `OH_REVIEW_MULTIPLE` | `0.8` | review overhead as a multiple of build hours |
| `OH_SHIP_HOURS` | `8` | fixed hours to ship a change |
| `OH_COORD_HOURS` | `6` | fixed coordination hours per change |
| `SPRINT_HOURS` | `160` | hours in one sprint, for sprint-share figures |

`/health` reports `github_app` ready only when `GITHUB_APP_ID`,
`GITHUB_WEBHOOK_SECRET` and `GITHUB_PRIVATE_KEY` are all set.

### Setting up the GitHub App

1. Create a GitHub App with **read-only** `Contents` and `Metadata` permissions and subscribe to `Push` events.
2. Point its webhook URL at `https://<your-host>/webhooks/github` and set a webhook secret.
3. Generate a private key and put the App id, webhook secret and key in `.env`.

The app requests an RS256 JWT (valid ≤ 10 minutes), exchanges it for a
one-hour installation token, caches the token in memory only and refreshes it two
minutes early. It never asks users for personal access tokens and cannot push,
merge or modify a repository.

### Setting up the GitHub connector (Connector V1, OAuth App)

This is the production connector: `app/connectors/` is a provider-agnostic
framework (`ConnectorRegistry`, generic `connector_installations` /
`connector_metrics` tables) that GitHub is the first real implementation of.
Gmail, Drive, GitLab, Slack, Jira, etc. plug into the same interface later
without touching the framework.

1. Create an OAuth App at <https://github.com/settings/developers>. Set its
   callback URL to exactly `GITHUB_REDIRECT_URI`.
2. Put the client id/secret in `.env` as `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.
3. Generate an encryption key and put it in `.env` as `GITHUB_ENCRYPTION_KEY`:
   ```
   python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
   ```
4. Run the migration: `alembic upgrade head`.

Flow: `GET /connectors/github/authorize` (bearer-authenticated) returns an
`authorize_url` with a PKCE challenge; the frontend navigates there; GitHub
redirects to `GET /connectors/github/callback` (no bearer token - identity
comes from the signed, single-use `state` param instead), which exchanges the
code, stores the encrypted token pair, and redirects to `FRONTEND_URL`.
Repositories are listed via `GET /connectors/github/repositories` and
selected via `POST .../repositories/select`, which creates a webhook
automatically wherever the installation has admin permission on that repo. A
push then flows webhook → signature + replay check → `Run` → the existing
scanner pipeline, exactly like the GitHub App path above, just authenticated
differently.

Credentials are AES-256-GCM encrypted at rest (`app/core/secrets/`) and never
logged; webhook secrets are rotatable with a grace window; disconnecting
revokes the OAuth grant upstream (`DELETE /applications/{client_id}/grant`),
removes webhooks, and clears local connector state while leaving Projects,
Runs, Findings and audit history untouched.

---

## Scanners

Every scanner reads files as text and returns `RawFinding` objects. None of them
installs, builds or executes anything from the repository. Directories such as
`.git`, `node_modules`, `vendor`, `dist`, `build` and virtualenvs are skipped.

### Library Inspector — dependencies (`app/scanners/lockfiles.py`, `osv.py`)

Parses 10 lockfile formats in pure Python and queries the [OSV](https://osv.dev)
batch API (the same database as Google's `osv-scanner`), then fetches each
advisory for severity and fixed version.

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (v1) |
| PyPI | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| Go | `go.mod` |
| RubyGems | `Gemfile.lock` |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |

**No lockfile means no dependency findings.** A `package.json` holds ranges
(`^4.17.15`), not what shipped. Guessing from a range would be inventing evidence,
so the scan reports the gap instead.

### Secret Hunter (`app/scanners/secrets.py`)

1. **17 provider patterns** — AWS access keys, GitHub classic and fine-grained tokens, GitLab PATs, Slack tokens and webhooks, Stripe live keys, Google API keys, OpenAI and Anthropic keys, SendGrid, Twilio, npm tokens, private key blocks, JWTs and database URIs with inline passwords.
2. **Shannon entropy** — a high-entropy value assigned to a suspiciously named variable (`api_key`, `client_secret`, `password`, …). Lower confidence, and reported as such.

**The secret value is never stored, logged or hashed.** Only the first four
characters and the length survive. Lockfiles, minified assets and binaries are
skipped.

### Code Flaw Hunter (`app/scanners/code.py`)

Python is analysed with the real `ast` module and intra-function taint tracking,
so `eval("1+1")` is not flagged but `eval(user_input)` is — including when the
string is built on one line and executed on another. JavaScript, TypeScript and
Go use anchored patterns, which are weaker and carry lower confidence. Vendored
front-end libraries (jQuery, Bootstrap, …) are skipped; their advisories belong to
the dependency scanner.

| Language | Rules |
|---|---|
| Python | `py.sql-injection`, `py.dynamic-exec`, `py.unsafe-deserialize`, `py.yaml-unsafe-load`, `py.shell-injection`, `py.weak-hash`, `py.tls-verify-disabled`, `py.insecure-temp`, `py.weak-random`, `py.assert-auth`, `py.debug-enabled` |
| JavaScript / TypeScript | `js.eval`, `js.new-function`, `js.child-process-interpolated`, `js.innerhtml`, `js.dangerously-set-html`, `js.jwt-none`, `js.sql-template`, `js.tls-disabled`, `js.math-random-token` |
| Go | `go.sql-sprintf`, `go.command-injection`, `go.tls-skip-verify`, `go.weak-hash` |

This is a focused rule set for flaw classes that turn into incidents, not a
replacement for Semgrep's full catalogue.

### Infrastructure scanner (`app/scanners/infra.py`)

| Surface | Rules |
|---|---|
| Dockerfile | unpinned base image · `ADD` from a URL · `curl \| sh` during build · secret in `ENV`/`ARG` · container runs as root |
| GitHub Actions | `pull_request_target` checking out PR code (pwn request) · third-party action pinned to a movable tag · `${{ github.event.* }}` interpolated into `run:` (script injection) |
| Kubernetes | `privileged`, `hostNetwork`, `hostPID`, `allowPrivilegeEscalation`, `runAsUser: 0` |
| docker-compose | privileged or host-network services · mounted Docker socket |
| Terraform | `0.0.0.0/0` ingress · public bucket ACL · encryption disabled · publicly accessible database · wildcard IAM action |

Scanners accept a `ScanContext` with an optional `changed_files` list, so a push
only re-inspects the files it touched; `None` means a full sweep.

---

## Enrichment

Both feeds are free and need no API key.

- **EPSS** (FIRST.org) — the published probability a CVE is exploited in the next
  30 days, queried in batches of 100. Annualised as `1 − (1 − p30)^(365/30)`; a
  CVE absent from EPSS is treated as *unknown*, not zero risk.
- **CISA KEV** — CVEs observed being exploited against real targets, including the
  `knownRansomwareCampaignUse` flag. Downloaded once and cached at
  `.cache/cisa_kev.json` for 6 hours. It is the heaviest signal in the score.

---

## Contextual scoring

CVSS describes a flaw in the abstract. The contextual score (`app/services/scoring.py`)
describes the flaw **here**, from five factors:

| Factor | Source | Available |
|---|---|---|
| Exploitability | EPSS, KEV, CVSS, exploit maturity, detector confidence | now |
| Blast radius | direct vs transitive dependency, production path | now |
| Reachability | is the vulnerable symbol actually called | Phase 5 |
| Exposure | is the asset reachable from the internet | Phase 4 |
| Criticality | what the project supports | Phase 3+ |

**Unmeasured factors are neutral and named.** Each contributes exactly 1.0 and is
listed in `ScoreResult.pending`, so no score is inflated by something not measured.

| Score | Tier | Fix within |
|---|---|---|
| 80–100 | Critical | 24 hours |
| 60–79 | High | 7 days |
| 35–59 | Medium | 30 days |
| 0–34 | Low | next cycle |

**Probability is never presented as yours.** EPSS says how likely a flaw is to be
exploited *somewhere in the world*. The API publishes `p_wild_30d` and
`p_wild_year` and keeps `p_here_year` as `null` until reachability and exposure
exist. The annual figure is capped at 95% so the column still discriminates.

### Fingerprints

`app/services/fingerprint.py` builds a SHA-256 identity from what a finding *is*,
never where it currently sits:

| Scanner | Built from |
|---|---|
| Dependencies (OSV) | advisory id, package name without version, ecosystem |
| Code and infra | rule id, file |
| Secrets | rule id, file — never the secret value |

Line numbers are excluded, so a reformat does not resurrect every finding as new
and "age", "trend" and "forecast" stay truthful.

---

## The loss model

`app/services/money.py`. Ordinary arithmetic; no model output ever becomes a figure.

### Rule zero: no money without business context

Five inputs are required. **Four of five is still not priced**: `price()` returns
`None`, `portfolio()` returns `exposure: null` — never `0.0`, never a sector median.
An unpriced finding still ranks by contextual score.

| Input | Why it cannot be derived |
|---|---|
| `revenue_supported` | scales customer churn |
| `downtime_cost_hour` | prices an outage |
| `users_count` | sizes the blast |
| `records_count` | drives the regulatory penalty, usually the largest component |
| `regimes` | DPDP, GDPR, PCI and HIPAA differ by an order of magnitude per record |

`eng_rate_hour` is optional and defaults to $120/h loaded.

### Per-finding loss

| Component | Basis |
|---|---|
| Business interruption | outage hours by tier (12 / 6 / 2 / 0.5) × availability impact × downtime cost |
| Regulatory penalty | records × confidentiality impact × per-record rate, capped per regime |
| Customer churn | churn rate by tier × confidentiality impact × supported revenue |
| Incident response | $18,000 + $9,000 × (confidentiality + integrity) |
| Emergency engineering | build hours × 3.2 incident multiplier × engineer rate |
| Brand and communications | 18% of churn plus penalty |

The **impact profile** (confidentiality, integrity, availability) comes from the
CWE — 27 weakness classes are mapped (CWE-400 is 90% availability; CWE-89 is
mostly confidentiality and integrity) — or from the credential type for secrets.

`if_it_happens` is the sum. `annual_loss_upper_bound` multiplies it by
`p_wild_year` and is labelled an upper bound until reachability and exposure land.
`loss_per_hour` divides annual loss by loaded fix hours — the best use of
engineering time.

### Remediation effort

| Finding | Build hours |
|---|---|
| Dependency, patch bump | 1 h |
| Dependency, minor bump | 4 h |
| Dependency, major bump | 12 h, +4 h per extra major |
| Dependency, no patched release | 24 h |
| Transitive dependency | +2 h |
| Secret | 3–14 h by type (revoke, rotate, purge history); ×0.4 in example files |
| Code rule | 1–16 h by rule |

Loaded hours = build × (1 + 0.8 review) + 8 h ship + 6 h coordination. Cost
applies a change-risk multiplier (High 1.9, Medium 1.4, Low 1.05).

### Portfolio aggregation

Naively summing per-finding losses once produced **$91M of exposure on a $24M
project**: 214 findings each charged the full penalty for the same 180,000 records,
which can only leak once. `portfolio()` therefore:

1. takes the **worst single breach** against the shared pool (penalty, churn, brand),
2. weights it by `P(any finding exploited) = 1 − Π(1 − p_i)`,
3. adds only the genuinely additive costs (interruption, response, engineering), each weighted by its own probability,
4. caps the result at supported revenue.

The naive sum is still reported, labelled and refused, so the difference is visible.

### Regulatory regimes

Per-record figures are policy estimates, not statutory rates.

| Code | Regime | Per record | Cap |
|---|---|---|---|
| `DPDP` | Digital Personal Data Protection Act 2023 (India) | $18 | $30M |
| `GDPR` | General Data Protection Regulation (EU) | $22 | $24M or 4% of revenue |
| `PCI` | PCI DSS 4.0 | $12 | $500K |
| `HIPAA` | HIPAA (US health data) | $45 | $1.9M |
| `RBI` | RBI Cyber Security Framework (India) | $14 | $12M |
| `SOC2` | SOC 2 (contractual) | $4 | $250K |
| `NONE` | No regulated data in scope | $0 | — |

When several regimes apply, the largest penalty is used. Every judgement call in
the model is returned by `GET /api/assumptions`.

---

## Data model

Postgres only — the schema uses `jsonb`, `text[]` and `uuid`. Controlled
vocabularies are `CHECK` constraints rather than Postgres enums, so adding a value
does not need an awkward migration.

| Table | Holds |
|---|---|
| `orgs` | GitHub account / installation |
| `projects` | one repository, its business context, `context_complete` gate and survey output |
| `agents` | the roster — one row per agent per project; agents go dormant, never deleted |
| `runs` | one inspection cycle: trigger, commit, changed files, exposure before/after, cost |
| `run_events` | append-only event stream the live floor will replay |
| `findings` | fingerprinted, enriched, scored and (nullable) priced; unique per project + fingerprint |
| `exposure_history` | one row per project per day |
| `audit_log` | every model run, decision and AI answer, with the state it saw |

Sources are **GitHub only** — `projects.source` has a check constraint with a single
permitted value.

### Migrations

```bash
.venv/Scripts/python.exe -m alembic upgrade head      # apply
.venv/Scripts/python.exe -m alembic downgrade base    # drop everything
.venv/Scripts/python.exe -m alembic revision --autogenerate -m "describe change"
```

The initial migration builds the schema directly from model metadata, so it cannot
drift from the models on day one. Later migrations are normal autogenerate diffs.

---

## Security model

FANTOM points at code it does not trust, so these rules are enforced in code:

- **Repository code is never executed.** No `npm install`, `pip install`, `docker build`, `terraform plan` or hooks. Scanners read text.
- **Hardened clones.** `--depth=1`, no tags, no submodules; `core.hooksPath=/dev/null`, `core.symlinks=false`, `credential.helper=` (the host keychain is never consulted), `GIT_TERMINAL_PROMPT=0`, a minimal environment, `shell=False`, a timeout, a size cap and guaranteed cleanup.
- **Webhook HMAC first.** Constant-time `X-Hub-Signature-256` check before parsing; unsigned deliveries are rejected, and webhooks are refused entirely if no secret is configured.
- **Short-lived credentials.** GitHub installation tokens live one hour, in memory, and are never logged or persisted. Permissions are read-only.
- **Secrets are redacted at source** and never hashed into fingerprints.
- **Errors never leak.** Clients get an error code and request id; traces stay in server logs.
- **`.env` is git-ignored.** Only `.env.example`, which holds no secrets, is committed.

---

## Project layout

```
app/
  main.py                    FastAPI app: CORS, request id, error handler, routers
  config.py                  every setting, env-driven, validated by pydantic
  db.py                      lazy engine, bounded connect timeout, ping, revision check
  schemas.py                 request/response models and validation
  api/
    health.py                /health and /ready
    projects.py              pricing, context, regimes, assumptions, projects
    webhooks.py              /webhooks/github
  core/logging_conf.py       plain logs in dev, JSON in prod
  integrations/github/
    app_auth.py              App JWT, installation tokens, repo metadata
    webhook.py               HMAC verification, push/installation parsing
  scanners/
    base.py                  Package, RawFinding, ScanContext contracts
    lockfiles.py             10 lockfile parsers
    osv.py                   OSV batch queries and advisory details
    secrets.py               provider patterns + entropy
    code.py                  Python AST taint rules; JS/TS/Go patterns
    infra.py                 Dockerfile, Actions, Kubernetes, compose, Terraform
  enrich/
    epss.py                  FIRST.org EPSS lookup and annualisation
    kev.py                   CISA KEV catalogue with disk cache
  services/
    repo.py                  hardened clone and cleanup
    scoring.py               contextual score, tiers, SLAs
    fingerprint.py           stable finding identity
    money.py                 business context, loss model, effort, portfolio
  models/
    base.py                  declarative base, naming convention, column helpers
    tables.py                full schema
migrations/                  alembic environment and versions
scripts/
  scan_repo.py               end-to-end CLI scanner
  dev.ps1 / dev.sh           one-command dev loop
tests/                       phase acceptance tests
docker-compose.yml           Postgres 17 + Redis 7 for local development
requirements.txt             direct dependencies (minimum versions)
requirements.lock.txt        exact versions verified to work
```

---

## Testing

```bash
.venv/Scripts/python.exe -m pytest tests -q
```

81 tests; no running database or credentials needed:

| File | Covers |
|---|---|
| `tests/test_health.py` | root route, `/health` always 200 and naming what is missing, `/ready` 503 without a database |
| `tests/test_part1.py` | webhook HMAC (tampered body, wrong secret, missing header, unsigned delivery to the endpoint), push parsing, lockfile parsers, fingerprint stability |
| `tests/test_part2.py` | EPSS annualisation and bands, KEV escalation, scoring bounds and neutral factors, secret detection and redaction, Python taint tracking, vendored-JS skipping, Go TLS rule |
| `tests/test_part3.py` | the context gate, loss components, effort estimates, regimes and caps, portfolio aggregation, pricing and context endpoints |

---

## Roadmap

- **Phase 4** — repository survey (languages, dependency count, LOC, complexity tier), recruiter that hires specialist agents per surface, wave scheduler on Redis, webhook pushes enqueued as runs, live run floor over Server-Sent Events.
- **Phase 5** — LLM reachability analysis (via OpenRouter) to fill `reachable` and `p_here_year`, a referee to challenge findings, attack-chain builder, chat over findings.
- **Phase 6** — heartbeat re-scoring when EPSS/KEV change, 90-day exposure history and forecast, reports.
- **Phase 7** — execution sandboxing, multi-tenant isolation, full audit trail.

---

## Known limitations

- The webhook verifies and acknowledges pushes but does not yet enqueue a scan; that arrives with the Phase 4 queue.
- `scripts/scan_repo.py` runs the dependency, secret and code scanners; the infrastructure scanner is implemented but not yet wired into the CLI and has no tests yet.
- Reachability, internet exposure and criticality are not measured yet, so scores are technical and annual losses are upper bounds.
- JavaScript, TypeScript and Go analysis is pattern-based and less precise than the Python AST analysis.
- Scanning private repositories requires a configured GitHub App installation.
