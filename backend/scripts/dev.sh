#!/usr/bin/env bash
# FANTOM dev loop (macOS / Linux / Git Bash)
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d .venv ] || python -m venv .venv
[ -f .env ]  || cp .env.example .env
PY=".venv/bin/python"; [ -x "$PY" ] || PY=".venv/Scripts/python.exe"

"$PY" -m pip install -q -r requirements.txt
echo "-> starting postgres"; docker compose up -d db
"$PY" -m alembic upgrade head
echo "-> api on http://localhost:8000"
"$PY" -m uvicorn app.main:app --reload --port 8000
