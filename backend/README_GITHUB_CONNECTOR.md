# GitHub Connector — OAuth setup

Connector V1 authenticates with a GitHub **OAuth App** (not a GitHub App —
that's the separate, pre-existing `app/integrations/github/` flow, left
running as-is). This doc is the fast path to a working local connection; see
`README.md` → "Setting up the GitHub connector" for the architecture.

## 1. Create the OAuth App

GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**.

| Field | Local value | Production value |
|---|---|---|
| Homepage URL | `http://localhost:5173` | your real frontend origin |
| Authorization callback URL | `http://localhost:8000/connectors/github/callback` | `https://<your-api-host>/connectors/github/callback` |

The callback URL must match `GITHUB_REDIRECT_URI` **exactly** (scheme, host,
port, path) or GitHub will refuse the redirect.

## 2. Configure the backend (`fantom.ai-main/.env`)

```env
GITHUB_CLIENT_ID=<from the OAuth App>
GITHUB_CLIENT_SECRET=<from the OAuth App>
GITHUB_REDIRECT_URI=http://localhost:8000/connectors/github/callback
GITHUB_ENCRYPTION_KEY=<base64, decodes to exactly 32 bytes>
FRONTEND_URL=http://localhost:5173
```

Generate the encryption key:

```bash
python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
```

`GITHUB_WEBHOOK_SECRET` is **not** used by this connector — each repository
gets its own generated, per-webhook secret at selection time, stored
encrypted. That env var belongs to the separate legacy GitHub App flow.

## 3. Configure the frontend (`Fantom-AI/artifacts/fantom-ai/.env.local`)

```env
VITE_API_BASE_URL=http://localhost:8000
```

## 4. Run it

```bash
# backend
cd fantom.ai-main
.venv/Scripts/python.exe -m alembic upgrade head
.venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

# frontend
cd Fantom-AI/artifacts/fantom-ai
PORT=5173 BASE_PATH=/ pnpm dev
```

Sign in, go to **Settings → Integrations**, click **Connect GitHub**.

## Why the backend doesn't refuse to start without these variables

By design (see `app/config.py`'s own docstring): the app always boots, even
half-configured, and reports what's missing on `/health` and via a 404 on
`/connectors/github/*` routes with a clear "GitHub is not connected" or an
upstream `GitHubAuthError` instead. A hard startup crash would take down
every *other* working feature (scanning, findings, reports, ...) over one
missing integration — the existing GitHub App flow already follows the same
principle (`settings.github_ready`), and this connector matches it
(`settings.github_oauth_ready`) rather than introducing a second convention.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `GITHUB_CLIENT_ID is not set` on `/connectors/github/authorize` | Backend env not loaded — check `.env` is in `fantom.ai-main/` and the process was restarted after editing it. |
| GitHub shows "redirect_uri_mismatch" | `GITHUB_REDIRECT_URI` doesn't byte-for-byte match the OAuth App's callback URL. |
| Callback redirects to `.../settings/integrations?status=error&message=...` | The `message` query param has the reason (expired/invalid state, or GitHub rejected the code exchange - check backend logs for the full `GitHubAuthError`). |
| `GITHUB_ENCRYPTION_KEY must decode to exactly 32 bytes` | The key isn't valid base64 of a 32-byte value — regenerate with the command above, don't hand-write one. |
| Repositories list is empty after connecting | Click **Sync now** on the Integrations panel, or check the OAuth App's granted scopes include `repo`. |
