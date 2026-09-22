/** Real client for the FANTOM FastAPI backend (localhost:8000). */
const API_BASE = 'http://localhost:8000';

const TOKEN_KEY = 'fantom_access_token';
const REFRESH_KEY = 'fantom_refresh_token';
const ORG_KEY = 'fantom_org_id';

export function getToken() { return localStorage.getItem(TOKEN_KEY); }
export function getOrgId() { return localStorage.getItem(ORG_KEY); }
export function isLoggedIn() { return !!getToken(); }

export function setSession(access: string, refresh: string, orgId?: string) {
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
  if (orgId) localStorage.setItem(ORG_KEY, orgId);
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(ORG_KEY);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(options.headers as any) };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const orgId = getOrgId();
  if (orgId) headers['X-Org-Id'] = orgId;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail ? JSON.stringify(body.detail) : `${res.status} ${res.statusText}`);
  return body as T;
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
  return request<{ user: { email: string; name: string }; memberships: { org_id: string; org_name: string; role: string }[] }>('/api/auth/me');
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
