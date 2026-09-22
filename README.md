# fantom.ai — frontend

React/Vite dashboard for fantom.ai, a continuous cyber risk quantification
platform. This repo is the UI only — it talks to the FANTOM FastAPI backend
over HTTP and expects that backend to be running separately.

## Prerequisites

- **Node.js 24**
- **pnpm** (`npm install -g pnpm`)
- The **FANTOM backend** running and reachable at `http://localhost:8000`
  (see that project's own README for setup — Python 3.12+, MySQL/Postgres,
  `uvicorn app.main:app --port 8000`)

## Setup

```bash
pnpm install
```

## Run the dashboard

The dev server requires two environment variables:

```bash
# Windows PowerShell
$env:PORT="5173"; $env:BASE_PATH="/"; pnpm --filter @workspace/fantom-ai run dev

# macOS / Linux / Git Bash
PORT=5173 BASE_PATH=/ pnpm --filter @workspace/fantom-ai run dev
```

Open **http://localhost:5173**. Sign up for a new account, or log in if the
backend already has one.

## Build

```bash
pnpm --filter @workspace/fantom-ai run build
```

Output goes to `artifacts/fantom-ai/dist/public`.

## Project structure

```
artifacts/fantom-ai/       the actual dashboard app
  src/App.tsx               all pages (dashboard, repositories, findings, live scan, ...)
  src/lib/api.ts             API client — every call to the FANTOM backend goes through here
artifacts/api-server/      unused scaffold, not wired to anything
artifacts/mockup-sandbox/  unused scaffold, not wired to anything
lib/                        shared TypeScript packages (API types, DB schema) — not currently consumed
```

## How it talks to the backend

`src/lib/api.ts` hardcodes the backend URL as `http://localhost:8000`. If
you're running the backend elsewhere, change `API_BASE` at the top of that
file. Auth uses a JWT bearer token stored in `localStorage`; once logged in,
every request also carries an `X-Org-Id` header for the org you belong to.

## What's real vs. mock

Wired to the live backend: login/signup, repositories (add/list/scan),
findings (list/filter/mark fixed), the live scan view (real-time via
server-sent events), dashboard KPIs, portfolio pricing.

Still on placeholder data: Risk Score, Analytics, Reports, and Settings
pages.
