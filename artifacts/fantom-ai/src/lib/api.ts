/** Real client for the FANTOM FastAPI backend. */
export const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const REQUEST_TIMEOUT_MS = 20_000;

const TOKEN_KEY = 'fantom_access_token';
const REFRESH_KEY = 'fantom_refresh_token';
const ORG_KEY = 'fantom_org_id';

export function getToken() { return localStorage.getItem(TOKEN_KEY); }
export function getRefreshToken() { return localStorage.getItem(REFRESH_KEY); }
export function getOrgId() { return localStorage.getItem(ORG_KEY); }
export function isLoggedIn() { return !!getToken(); }

export function setSession(access: string, refresh: string, orgId?: string) {
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
  if (orgId) localStorage.setItem(ORG_KEY, orgId);
}

export function setOrgId(orgId: string) { localStorage.setItem(ORG_KEY, orgId); }

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(ORG_KEY);
}

/** Session ended and could not be renewed - listened for by AuthProvider to
 * bounce the user to /login without every call site handling it by hand. */
function announceSessionExpired() {
  clearSession();
  window.dispatchEvent(new CustomEvent('fantom:session-expired'));
}

let refreshInFlight: Promise<boolean> | null = null;

/** One refresh attempt, shared across any requests that 401 at the same time. */
async function refreshAccessToken(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    const refresh_token = getRefreshToken();
    if (!refresh_token) return false;
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token }),
      });
      if (!res.ok) return false;
      const tok = await res.json();
      setSession(tok.access_token, tok.refresh_token, getOrgId() || undefined);
      return true;
    } catch {
      return false;
    }
  })();
  const ok = await refreshInFlight;
  refreshInFlight = null;
  return ok;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

async function request<T>(path: string, options: RequestInit = {}, _retried = false): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(options.headers as any) };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const orgId = getOrgId();
  if (orgId) headers['X-Org-Id'] = orgId;

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, headers, signal: controller.signal });
  } catch (err) {
    if ((err as any)?.name === 'AbortError') throw new ApiError(0, 'Request timed out. Check your connection.');
    throw new ApiError(0, 'Network error - is the backend running?');
  } finally {
    window.clearTimeout(timeout);
  }

  // One retry after a silent token refresh; a fully expired session (no
  // refresh token, or the refresh itself is rejected) bounces to /login.
  if (res.status === 401 && !_retried && path !== '/api/auth/refresh' && token) {
    const ok = await refreshAccessToken();
    if (ok) return request<T>(path, options, true);
    announceSessionExpired();
    throw new ApiError(401, 'Your session expired. Please sign in again.');
  }

  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof body.detail === 'string' ? body.detail : body.detail ? JSON.stringify(body.detail) : `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, detail);
  }
  return body as T;
}

/** For endpoints that return a file (report download) rather than JSON. */
async function requestBlob(path: string): Promise<Blob> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const orgId = getOrgId();
  if (orgId) headers['X-Org-Id'] = orgId;
  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.detail ? String(body.detail) : `${res.status} ${res.statusText}`);
  }
  return res.blob();
}

export function health() {
  return request<{ status: string; env: string; components: Record<string, { ok: boolean; hint?: string | null }> }>('/health');
}

// ------------------------------------------------------------------- auth --
export async function register(email: string, password: string, name: string, orgName: string) {
  const tok = await request<{ access_token: string; refresh_token: string }>('/api/auth/register', {
    method: 'POST', body: JSON.stringify({ email, password, name, org_name: orgName }),
  });
  setSession(tok.access_token, tok.refresh_token);
  const me = await request<{ memberships: { org_id: string }[] }>('/api/auth/me');
  setSession(tok.access_token, tok.refresh_token, me.memberships[0]?.org_id);
  return tok;
}

export async function login(email: string, password: string) {
  const tok = await request<{ access_token: string; refresh_token: string }>('/api/auth/login', {
    method: 'POST', body: JSON.stringify({ email, password }),
  });
  setSession(tok.access_token, tok.refresh_token);
  const me = await request<{ memberships: { org_id: string }[] }>('/api/auth/me');
  setSession(tok.access_token, tok.refresh_token, me.memberships[0]?.org_id);
  return tok;
}

export function me() {
  return request<{ user: { email: string; name: string }; memberships: MembershipOut[] }>('/api/auth/me');
}

export function requestPasswordReset(email: string) {
  return request('/api/auth/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) });
}

// ---------------------------------------------------------------- projects --
export type ProjectOut = {
  id: string; repo: string; branch: string; state: string;
  context_complete: boolean; missing_context: string[];
  complexity_score: number | null; complexity_tier: string | null;
  findings_open: number; exposure: number | null;
};

export function listProjects() {
  return request<ProjectOut[]>('/api/projects');
}

export function createProject(repo: string, branch = 'main') {
  return request<ProjectOut>('/api/projects', { method: 'POST', body: JSON.stringify({ repo, branch }) });
}

export function triggerScan(projectId: string) {
  return request<{ run_id: string; state: string }>(`/api/projects/${projectId}/scan`, { method: 'POST' });
}

export function getProjectPricing(projectId: string) {
  return request<any>(`/api/projects/${projectId}/pricing`);
}

export function setProjectContext(projectId: string, ctx: Record<string, unknown>) {
  return request(`/api/projects/${projectId}/context`, { method: 'PUT', body: JSON.stringify(ctx) });
}

// ----------------------------------------------------------------- runs ----
export function getRun(runId: string) {
  return request<any>(`/api/runs/${runId}`);
}

export function streamRunEvents(runId: string, onEvent: (data: any) => void, onDone: () => void): () => void {
  const token = getToken();
  const orgId = getOrgId();
  const url = new URL(`${API_BASE}/api/runs/${runId}/events`);
  // EventSource cannot set headers, so the org/auth context rides as query
  // params the backend also accepts would be ideal; simplest working path
  // here is a fetch-based reader since we already need custom headers.
  const controller = new AbortController();
  (async () => {
    try {
      const res = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token}`, 'X-Org-Id': orgId || '' },
        signal: controller.signal,
      });
      const reader = res.body?.getReader();
      if (!reader) return;
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split('\n\n');
        buf = parts.pop() || '';
        for (const part of parts) {
          const dataLine = part.split('\n').find((l) => l.startsWith('data: '));
          const eventLine = part.split('\n').find((l) => l.startsWith('event: '));
          if (eventLine?.includes('run_finished')) { onDone(); return; }
          if (dataLine) {
            try { onEvent(JSON.parse(dataLine.slice(6))); } catch { /* heartbeat or malformed, skip */ }
          }
        }
      }
      onDone();
    } catch (err) {
      if ((err as any).name !== 'AbortError') console.error('SSE stream error', err);
    }
  })();
  return () => controller.abort();
}

// -------------------------------------------------------------- findings ---
export type FindingItem = {
  id: string; project_id: string; repo: string; scanner: string; title: string;
  cve: string | null; cwe: string | null; package: string | null; file: string | null;
  cvss: number | null; epss: number | null; kev: boolean;
  context_score: number | null; tier: string | null; state: string;
  annual_loss: number | null; first_seen_at: string; last_seen_at: string;
};

export function listFindings(params: Record<string, string | number | boolean | undefined> = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) qs.set(k, String(v));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return request<{ total: number; items: FindingItem[] }>(`/api/findings${suffix}`);
}

export function updateFindingState(id: string, state: string) {
  return request(`/api/findings/${id}/state`, { method: 'PUT', body: JSON.stringify({ state }) });
}

export type FindingDetail = FindingItem & {
  fingerprint: string; scanner: string; agent_slug: string; rule_id: string | null; line: number | null;
  version: string | null; fixed_version: string | null; exploit_maturity: string | null;
  fix_hours: number | null; fix_cost: number | null; loss_per_hour: number | null;
  remediation: { steps?: string[] } | null; owner: string | null; note: string | null;
};

export function getFinding(id: string) {
  return request<FindingDetail>(`/api/findings/${id}`);
}

// ------------------------------------------------------------------- risk --
export function orgRisk() {
  return request<{ org_risk_score: number | null; findings_open: number; findings_critical: number;
    total_exposure: number | null; projects: any[] }>('/api/risk/org');
}

export function projectRisk(projectId: string) {
  return request<any>(`/api/risk/projects/${projectId}`);
}

export function analytics(days = 30) {
  return request<any>(`/api/analytics?days=${days}`);
}

export function pricePreview(context: Record<string, unknown>, finding: Record<string, unknown>) {
  return request<{
    priced: boolean; context_missing: string[]; context_score: number | null; tier: string | null;
    sla: string | null; if_it_happens: number | null; annual_loss_upper_bound: number | null;
    loss_per_hour: number | null; note?: string | null;
  }>('/api/price/preview', { method: 'POST', body: JSON.stringify({ context, finding }) });
}

// ------------------------------------------------------------------- orgs --
export type MembershipOut = { org_id: string; org_name: string; org_slug: string; role: string };

export function currentOrg() {
  return request<{ id: string; name: string; slug: string; created_at: string }>('/api/orgs/current');
}

export function listMembers() {
  return request<{ user_id: string; email: string; name: string; role: string; joined_at: string }[]>('/api/orgs/current/members');
}

// ---------------------------------------------------------------- reports --
export type ReportOut = { id: string; org_id: string; project_id: string | null; kind: string; status: string; created_at: string; finished_at: string | null };

export function listReports() {
  return request<ReportOut[]>('/api/reports');
}

export function createReport(kind: string, projectId?: string) {
  return request<ReportOut>('/api/reports', { method: 'POST', body: JSON.stringify({ kind, project_id: projectId ?? null }) });
}

export function getReport(id: string) {
  return request<ReportOut>(`/api/reports/${id}`);
}

export async function downloadReport(id: string, filename: string) {
  const blob = await requestBlob(`/api/reports/${id}/download`);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ----------------------------------------------------------- notifications --
export type NotificationOut = { id: string; kind: string; title: string; body: string | null; read_at: string | null; created_at: string };

export function listNotifications(unreadOnly = false) {
  return request<NotificationOut[]>(`/api/notifications${unreadOnly ? '?unread_only=true' : ''}`);
}

export function markNotificationRead(id: string) {
  return request<void>(`/api/notifications/${id}/read`, { method: 'PUT' });
}

export type NotificationChannelOut = { id: string; kind: string; target: string; enabled: boolean; created_at: string };

export function listNotificationChannels() {
  return request<NotificationChannelOut[]>('/api/notifications/channels');
}

export function createNotificationChannel(kind: string, target: string) {
  return request<NotificationChannelOut>('/api/notifications/channels', { method: 'POST', body: JSON.stringify({ kind, target }) });
}

export function deleteNotificationChannel(id: string) {
  return request<void>(`/api/notifications/channels/${id}`, { method: 'DELETE' });
}

// -------------------------------------------------------- github connector --
export type ConnectorStatusOut = {
  connected: boolean; status: string | null; account_login: string | null; account_type: string | null;
  scopes: string[]; token_expires_at: string | null; last_sync_at: string | null;
  repository_count: number; monitored_repository_count: number;
};

export type GithubRepositoryOut = {
  id: string; github_repo_id: number; full_name: string; owner_login: string; name: string;
  private: boolean; archived: boolean; default_branch: string | null; language: string | null;
  topics: string[]; license: string | null; stars: number; forks: number; open_issues: number;
  has_security_policy: boolean; has_dependabot: boolean;
  permissions: { admin: boolean; push: boolean; pull: boolean; maintain: boolean; triage: boolean };
  monitoring_status: string; monitoring_reason: string | null; project_id: string | null; last_synced_at: string | null;
};

export function githubAuthorizeUrl() {
  return request<{ authorize_url: string }>('/connectors/github/authorize');
}

export function githubStatus() {
  return request<ConnectorStatusOut>('/connectors/github/status');
}

export function githubDisconnect() {
  return request<{ disconnected: boolean }>('/connectors/github/disconnect', { method: 'DELETE' });
}

export function githubSync() {
  return request<{ accepted: boolean; detail: string }>('/connectors/github/sync', { method: 'POST' });
}

export function githubRefresh() {
  return request<{ refreshed: boolean }>('/connectors/github/refresh', { method: 'POST' });
}

export function githubRepositories(params: Record<string, string | number | boolean | undefined> = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) qs.set(k, String(v));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return request<{ repositories: GithubRepositoryOut[]; total: number; page: number; page_size: number }>(`/connectors/github/repositories${suffix}`);
}

export function githubSelectRepositories(repositoryIds: string[]) {
  return request<{ selected: GithubRepositoryOut[]; skipped: Record<string, string> }>(
    '/connectors/github/repositories/select', { method: 'POST', body: JSON.stringify({ repository_ids: repositoryIds }) });
}

export function githubUnselectRepositories(repositoryIds: string[]) {
  return request<GithubRepositoryOut[]>(
    '/connectors/github/repositories/unselect', { method: 'POST', body: JSON.stringify({ repository_ids: repositoryIds }) });
}

export function githubScanRepository(repositoryId: string) {
  return request<{ run_id: string; state: string }>(`/connectors/github/repositories/${repositoryId}/scan`, { method: 'POST' });
}

export function githubResyncWebhook(repositoryId: string) {
  return request<{ repaired: boolean; webhook_id: number | null; detail: string }>(
    `/connectors/github/repositories/${repositoryId}/webhook/resync`, { method: 'POST' });
}

/** Consumes the real `/connectors/github/events` lifecycle stream (the same
 * `event_bus` the backend's sync/webhook code publishes to). Same manual
 * fetch-reader shape as `streamRunEvents`, for the same reason - EventSource
 * can't carry the auth headers this endpoint needs. */
export function watchConnectorEvents(onEvent: (kind: string, payload: any) => void): () => void {
  const token = getToken();
  const orgId = getOrgId();
  const controller = new AbortController();
  (async () => {
    try {
      const res = await fetch(`${API_BASE}/connectors/github/events`, {
        headers: { Authorization: `Bearer ${token}`, 'X-Org-Id': orgId || '' },
        signal: controller.signal,
      });
      const reader = res.body?.getReader();
      if (!reader) return;
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split('\n\n');
        buf = parts.pop() || '';
        for (const part of parts) {
          const eventLine = part.split('\n').find((l) => l.startsWith('event: '));
          const dataLine = part.split('\n').find((l) => l.startsWith('data: '));
          if (!eventLine) continue;
          let payload = {};
          try { payload = dataLine ? JSON.parse(dataLine.slice(6)) : {}; } catch { /* skip malformed frame */ }
          onEvent(eventLine.slice(7), payload);
        }
      }
    } catch (err) {
      if ((err as any)?.name !== 'AbortError') console.error('connector event stream error', err);
    }
  })();
  return () => controller.abort();
}

export function githubSyncHistory() {
  return request<{ id: string; sync_type: string; repositories_added: number; repositories_updated: number;
    repositories_removed: number; duration_ms: number; success: boolean; error_message: string | null; created_at: string }[]>(
    '/connectors/github/sync-history');
}
