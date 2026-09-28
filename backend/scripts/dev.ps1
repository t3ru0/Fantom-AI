# FANTOM dev loop (Windows PowerShell)
param([switch]$Fresh)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path ".venv")) { python -m venv .venv }
if (-not (Test-Path ".env"))  { Copy-Item .env.example .env }

.venv\Scripts\python.exe -m pip install -q -r requirements.txt

Write-Host "-> starting postgres" -ForegroundColor Cyan
docker compose up -d db
if ($Fresh) { .venv\Scripts\python.exe -m alembic downgrade base }
.venv\Scripts\python.exe -m alembic upgrade head

Write-Host "-> api on http://localhost:8000" -ForegroundColor Cyan
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
