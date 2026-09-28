import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, Router as WouterRouter, useLocation, useParams, useSearch } from 'wouter';
import {
  Activity, AlertTriangle, ArrowLeft, ArrowRight, BarChart3, Bell, BookOpen,
  Bot, Building2, Calculator, Check, ChevronDown, ChevronRight, CircleHelp,
  Clock3, Code2, Download, FileBarChart, FileText, Filter, Github, Globe2,
  HeartPulse, Hexagon, Info, KeyRound, Layers3, LifeBuoy, LineChart, ListFilter,
  LockKeyhole, LogOut, Menu, MessageSquare, Network, Play, Plus, Radar, RefreshCw,
  Search, Server, Settings2, ShieldCheck, Sparkles, Target, Terminal, TrendingDown,
  TrendingUp, Unplug, UserRound, X, Zap
} from 'lucide-react';
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart as ReLineChart,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts';
import * as api from '@/lib/api';
import { AuthProvider, useAuth } from '@/lib/auth-context';
import { FantomLogo } from '@/components/logo';

const queryClient = new QueryClient();

type ToastFn = (message: string) => void;
type PageProps = { toast: ToastFn };

const navGroups: { label: string; items: [string, string, typeof Activity][] }[] = [
  { label: 'Command center', items: [
    ['Dashboard', '/dashboard', HeartPulse], ['Repositories', '/repositories', Github],
    ['Findings', '/findings', ShieldCheck], ['Risk score', '/risk-score', Radar],
  ]},
  { label: 'Intelligence', items: [
    ['Threat intelligence', '/threat-intelligence', Globe2], ['Business impact', '/business-impact', Calculator],
    ['Live scan', '/live-scan', Activity], ['Analytics', '/analytics', LineChart],
  ]},
  { label: 'Workspace', items: [
    ['Reports', '/reports', FileBarChart], ['Settings', '/settings', Settings2], ['Help center', '/help', CircleHelp],
  ]},
];

const TIER_COLOR: Record<string, string> = { Critical: '#B65D64', High: '#D99386', Medium: '#567C8D', Low: '#C8D9E6' };
// Matches app/services/demo_repos.py DEMO_REPOS - seeded on signup, removed
// server-side the moment a real GitHub account connects.
const DEMO_REPO_ORIGINS = ['octocat/Hello-World', 'octocat/Spoon-Knife'];

function NotificationsBell({ toast }: { toast: ToastFn }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<api.NotificationOut[]>([]);
  const [loading, setLoading] = useState(false);
  const unread = items.filter((n) => !n.read_at).length;

  function load(silent = false) {
    if (!silent) setLoading(true);
    api.listNotifications().then(setItems).catch(() => {}).finally(() => setLoading(false));
  }
  useEffect(load, []);

  // Poll while the tab is visible, plus an immediate refresh whenever
  // something in the app knows a scan just finished (see `LiveScan`) - no
  // dedicated notifications SSE endpoint exists, so polling is the honest
  // "live" here, same as the rest of this app's non-Run data.
  useEffect(() => {
    const id = window.setInterval(() => { if (document.visibilityState === 'visible') load(true); }, 30_000);
    const onScanDone = () => load(true);
    window.addEventListener('fantom:notifications-changed', onScanDone);
    return () => { window.clearInterval(id); window.removeEventListener('fantom:notifications-changed', onScanDone); };
  }, []);

  async function open_() {
    setOpen((v) => !v);
    if (!open) load();
  }

  async function markRead(n: api.NotificationOut) {
    if (n.read_at) return;
    try {
      await api.markNotificationRead(n.id);
      setItems((list) => list.map((x) => (x.id === n.id ? { ...x, read_at: new Date().toISOString() } : x)));
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not update notification.');
    }
  }

  return <div style={{ position: 'relative' }}>
    <button className="icon-button" data-testid="button-notifications" onClick={open_} aria-label="Notifications">
      <Bell size={16} />{unread > 0 && <span className="notif-dot" />}
    </button>
    {open && <div className="notif-panel">
      <div className="notif-panel-head"><strong>Notifications</strong>{loading && <small>Loading…</small>}</div>
      {items.length === 0 && !loading && <p className="subhead" style={{ padding: '14px 16px' }}>No notifications yet.</p>}
      {items.slice(0, 8).map((n) => <button key={n.id} className={`notif-row ${n.read_at ? '' : 'unread'}`} onClick={() => markRead(n)}>
        <strong>{n.title}</strong>{n.body && <p>{n.body}</p>}<small>{new Date(n.created_at).toLocaleString()}</small>
      </button>)}
    </div>}
  </div>;
}

function Shell({ children, toast }: { children: ReactNode; toast: ToastFn }) {
  const [location, setLocation] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user, role, logout } = useAuth();
  const current = navGroups.flatMap((g) => g.items).find((x) => x[1] === location)?.[0] ?? (location === '/dashboard' ? 'Dashboard' : 'Workspace');

  function logOut() {
    logout();
    toast('Signed out.');
    setLocation('/login');
  }

  const initials = user ? user.name.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase() : '…';

  return <div className="app-shell">
    <aside className="sidebar">
      <FantomLogo />
      {navGroups.map((group) => <div key={group.label} style={{ marginBottom: 27 }}>
        <div className="side-label">{group.label}</div>
        <nav className="side-nav">{group.items.map(([label, href, Icon]) => <Link data-testid={`link-${label.toLowerCase().replaceAll(' ', '-')}`} className={`side-link ${location === href ? 'active' : ''}`} href={href} key={href}><Icon /><span>{label}</span></Link>)}</nav>
      </div>)}
      <div className="sidebar-spacer" />
      <Link href="/settings/integrations" className="side-link"><Github /><span>Connect GitHub</span></Link>
      <div className="user-mini"><span className="avatar">{initials}</span><span><strong style={{ display: 'block', color: 'var(--paper)' }}>{user?.name ?? 'Loading…'}</strong><small style={{ color: 'rgba(245,239,235,.5)' }}>{role}</small></span><button className="icon-button" onClick={logOut} aria-label="Log out" title="Log out" style={{ marginLeft: 'auto', background: 'transparent', color: 'inherit' }}><LogOut size={14} /></button></div>
    </aside>
    <div className="mobile-top"><FantomLogo /><button className="icon-button" style={{ background: 'transparent', color: 'var(--sky)', borderColor: 'rgba(200,217,230,.2)' }} onClick={() => setMobileOpen((x) => !x)} aria-label="Open navigation"><Menu size={18} /></button></div>
    {mobileOpen && <nav className="mobile-menu">{navGroups.flatMap((g) => g.items).map(([label, href]) => <Link onClick={() => setMobileOpen(false)} className={location === href ? 'active' : ''} href={href} key={href}>{label}</Link>)}</nav>}
    <main className="main">
      <header className="topbar"><div className="crumb"><span>Workspace</span><ChevronRight size={13} /><strong>{current}</strong></div><div className="top-actions"><NotificationsBell toast={toast} /><button className="icon-button" data-testid="button-help" onClick={() => toast('Support is online — opening help center soon.')} aria-label="Help"><CircleHelp size={16} /></button></div></header>
      <AnimatePresence mode="wait"><motion.div key={location} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: .2 }}>{children}</motion.div></AnimatePresence>
    </main>
  </div>;
}

function SectionHead({ eyebrow, title, sub, action }: { eyebrow: string; title: string; sub?: string; action?: ReactNode }) {
  return <div className="page-head"><div><div className="eyebrow">{eyebrow}</div><h1 style={{ marginTop: 9 }}>{title}</h1>{sub && <p className="subhead">{sub}</p>}</div>{action}</div>;
}
function Button({ children, variant = 'primary', onClick, className = '', testId, disabled }: { children: ReactNode; variant?: string; onClick?: () => void; className?: string; testId?: string; disabled?: boolean }) {
  return <button data-testid={testId} onClick={onClick} disabled={disabled} className={`btn ${variant} ${className}`}>{children}</button>;
}
function Badge({ children, tone = 'info' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span>; }
function Kpi({ icon: Icon, label, value, note, tone }: { icon: typeof Activity; label: string; value: string; note: string; tone?: string }) { return <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="panel kpi"><div className="kpi-label"><span>{label}</span><Icon size={16} style={{ color: tone ?? 'var(--teal)' }} /></div><div className="kpi-value">{value}</div><div className="kpi-note">{note}</div></motion.div>; }
function RiskRing({ value = 42 }: { value?: number }) { return <div className="risk-ring" style={{ background: `conic-gradient(var(--teal) 0 ${value}%, var(--sky) ${value}% 100%)` }}><div className="risk-ring-content"><strong>{value}</strong><span>risk index</span></div></div>; }

const todayLabel = new Date().toLocaleDateString('en-US', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

function Dashboard({ toast }: PageProps) {
  const [risk, setRisk] = useState<Awaited<ReturnType<typeof api.orgRisk>> | null>(null);
  const [projects, setProjects] = useState<api.ProjectOut[]>([]);
  const [recentFindings, setRecentFindings] = useState<api.FindingItem[]>([]);
  const [trend, setTrend] = useState<{ day: string; exposure: number }[]>([]);
  const [notifications, setNotifications] = useState<api.NotificationOut[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    Promise.all([
      api.orgRisk(), api.listProjects(), api.listFindings({ state: 'open', sort: 'score', page_size: 4 }),
      api.analytics(30), api.listNotifications(true),
    ])
      .then(([r, p, f, a, n]) => {
        setRisk(r); setProjects(p); setRecentFindings(f.items);
        setTrend(a.exposure_over_time.map((pt: any) => ({ day: pt.day, exposure: pt.value })));
        setNotifications(n.slice(0, 4));
      })
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load dashboard'))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  async function startAllScans() {
    if (projects.length === 0) { toast('Connect a repository first.'); return; }
    await Promise.all(projects.map((p) => api.triggerScan(p.id).catch(() => null)));
    toast(`Scan queued for ${projects.length} repositor${projects.length === 1 ? 'y' : 'ies'}.`);
  }

  const score = risk?.org_risk_score;
  const repoRisk = risk?.projects ?? [];

  return <div className="page"><SectionHead eyebrow={todayLabel} title="Good morning." sub="Your real, connected repositories and their current exposure." action={<Button onClick={startAllScans} testId="button-start-scan"><Play size={15} /> Start a scan</Button>} />
    <div className="grid grid-4"><Kpi icon={ShieldCheck} label="Overall risk score" value={score != null ? `${score} / 100` : '— / 100'} note={loading ? 'Loading…' : `${projects.length} repositor${projects.length === 1 ? 'y' : 'ies'} connected`} /><Kpi icon={AlertTriangle} label="Open findings" value={String(risk?.findings_open ?? 0)} note={`${risk?.findings_critical ?? 0} critical`} tone="var(--danger)" /><Kpi icon={Server} label="Repositories" value={String(projects.length).padStart(2, '0')} note={projects.length ? 'Connected via GitHub' : 'None yet'} /><Kpi icon={TrendingDown} label="Total exposure" value={risk?.total_exposure != null ? `$${(risk.total_exposure / 1000).toFixed(0)}k` : 'Not priced'} note="Aggregated, not summed" /></div>
    <div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Exposure over time</h3><span>Last 30 days</span></div><div className="chart-wrap">{trend.length === 0 ? <p className="subhead">Not enough scan history yet.</p> : <ResponsiveContainer width="100%" height="100%"><AreaChart data={trend}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#567C8D" stopOpacity=".3" /><stop offset="100%" stopColor="#567C8D" stopOpacity="0" /></linearGradient></defs><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} tickFormatter={(d) => new Date(d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, border: '1px solid #C8D9E6', fontSize: 11 }} formatter={(v: number) => [`$${v.toLocaleString()}`, 'Exposure']} /><Area type="monotone" dataKey="exposure" stroke="#567C8D" strokeWidth={2.5} fill="url(#riskFill)" /></AreaChart></ResponsiveContainer>}</div></div>
      <div className="panel panel-pad"><div className="section-title"><h3>Risk by repository</h3><Link href="/repositories"><span>View all <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div>{repoRisk.length === 0 && <p className="subhead">No repositories connected yet.</p>}{repoRisk.slice(0, 4).map((r: any) => <div key={r.project_id} style={{ margin: '19px 0' }}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 7 }}><strong>{r.repo}</strong><span style={{ color: (r.avg_score ?? 0) > 70 ? 'var(--danger)' : 'var(--teal)', fontFamily: 'var(--font-mono)' }}>{r.avg_score ?? '—'}</span></div><div className="progress"><i style={{ width: `${r.avg_score ?? 0}%`, background: (r.avg_score ?? 0) > 70 ? 'var(--danger)' : undefined }} /></div></div>)}</div></div>
    <div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Needs your attention</h3><Link href="/findings"><span>Open findings <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div><div className="activity">{recentFindings.length === 0 && <p className="subhead">No open findings.</p>}{recentFindings.map((f) => <Link href="/findings" className="activity-row" key={f.id}><span className={`dot ${f.tier === 'Critical' || f.tier === 'High' ? 'danger' : ''}`} /><div><p><strong>{f.title}</strong> in {f.repo}</p><small>{f.tier ?? 'Unscored'} · {f.package ?? f.file ?? f.cve ?? ''}</small></div><Badge tone={f.tier === 'Critical' ? 'high' : f.tier === 'High' ? 'high' : f.tier === 'Medium' ? 'medium' : 'low'}>{f.tier ?? '—'}</Badge></Link>)}</div></div><div className="panel panel-pad"><div className="section-title"><h3>Connected repositories</h3><Link href="/repositories"><span>Manage <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div><div className="activity">{projects.length === 0 && <p className="subhead">Connect your first repository to start scanning.</p>}{projects.slice(0, 4).map((p) => <div className="activity-row" key={p.id}><span className="dot" /><div><p><strong>{p.repo}</strong></p><small>{p.findings_open} open findings · {p.state}</small></div></div>)}</div></div></div>
    <div className="panel panel-pad" style={{ marginTop: 18 }}><div className="section-title"><h3>Recent notifications</h3><span>Unread</span></div><div className="activity">{notifications.length === 0 && <p className="subhead">You're all caught up.</p>}{notifications.map((n) => <div className="activity-row" key={n.id}><span className="dot" /><div><p><strong>{n.title}</strong></p><small>{n.body ?? new Date(n.created_at).toLocaleString()}</small></div></div>)}</div></div>
  </div>;
}

function Repositories({ toast }: PageProps) {
  const [query, setQuery] = useState('');
  const [projects, setProjects] = useState<api.ProjectOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [ghConnected, setGhConnected] = useState(false);
  const [, setLocation] = useLocation();

  const load = () => {
    setLoading(true);
    api.listProjects().then(setProjects)
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load repositories'))
      .finally(() => setLoading(false));
    // Only used to decide what "Add repository" does below - a disconnected
    // org can't pick from a real repo list yet, so it still gets the manual
    // fallback; a connected one is pointed at the verified picker instead of
    // a free-text prompt (which happily "connects" any public repo by name,
    // e.g. octocat/Hello-World, with no real access behind it).
    api.githubStatus().then((s) => setGhConnected(s.connected)).catch(() => setGhConnected(false));
  };
  useEffect(load, []);

  async function addRepository() {
    if (ghConnected) { setLocation('/settings/integrations'); return; }
    const repo = window.prompt('GitHub repository (owner/name):');
    if (!repo) return;
    try {
      await api.createProject(repo.trim());
      toast(`${repo} connected.`);
      load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not connect repository.');
    }
  }

  async function scanNow(p: api.ProjectOut) {
    try {
      await api.triggerScan(p.id);
      toast(`Scan queued for ${p.repo}.`);
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not start scan.');
    }
  }

  const filtered = projects.filter((r) => r.repo.toLowerCase().includes(query.toLowerCase()));
  const hasDemoRepos = !ghConnected && projects.some((r) => DEMO_REPO_ORIGINS.includes(r.repo));
  return <div className="page"><SectionHead eyebrow="Asset inventory" title="Repositories" sub={hasDemoRepos ? "These are example repositories so you can see how Fantom works. Connect your GitHub account to replace them with your real repositories." : `${projects.length} connected codebase${projects.length === 1 ? '' : 's'}, continuously observed across your attack surface.`} action={<Button onClick={addRepository}><Plus size={15} /> Add repository</Button>} /><div className="filterbar"><div className="search"><Search /><input data-testid="input-repository-search" placeholder="Search repositories" value={query} onChange={(e) => setQuery(e.target.value)} /></div><Button variant="ghost" onClick={load}><RefreshCw size={14} /> Refresh</Button></div><div className="grid grid-3">{filtered.map((r) => <motion.div layout key={r.id} className="panel repo-card"><div className="repo-title"><span className="repo-icon"><Code2 size={16} /></span><span style={{ flex: 1 }}>{r.repo}<small style={{ display: 'block', color: 'var(--muted)', fontWeight: 400, fontSize: 11, marginTop: 2 }}>{r.branch} · {r.state}</small></span>{!ghConnected && DEMO_REPO_ORIGINS.includes(r.repo) && <Badge tone="medium">Example</Badge>}</div><div className="repo-meta"><span><Github size={13} /> {r.context_complete ? 'Priced' : 'Not priced'}</span><span><AlertTriangle size={13} /> {r.findings_open} findings</span></div><div style={{ marginTop: 19 }}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)', marginBottom: 7 }}><span>Exposure</span><strong style={{ color: 'var(--teal)' }}>{r.exposure != null ? `$${(r.exposure / 1000).toFixed(0)}k` : '—'}</strong></div></div><div className="repo-foot"><span style={{ color: 'var(--muted)', fontSize: 11 }}>{r.complexity_tier ?? 'Not yet scanned'}</span><Button variant="ghost" className="small" onClick={() => scanNow(r)}>Scan now</Button></div></motion.div>)}</div>{!loading && filtered.length === 0 && <div className="panel coming"><Search size={25} /><h3>No repositories found</h3><p>{projects.length === 0 ? 'Connect your first repository to get started.' : 'Try a different search term.'}</p></div>}</div>;
}

const TIER_TONE: Record<string, string> = { Critical: 'high', High: 'high', Medium: 'medium', Low: 'low' };

function Findings({ toast }: PageProps) {
  const [query, setQuery] = useState(''); const [tier, setTier] = useState('All severities');
  const [selected, setSelected] = useState<api.FindingItem | null>(null);
  const [items, setItems] = useState<api.FindingItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api.listFindings({ state: 'open', sort: 'score', page_size: 100,
      tier: tier === 'All severities' ? undefined : tier })
      .then((r) => setItems(r.items))
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load findings'))
      .finally(() => setLoading(false));
  };
  useEffect(load, [tier]);

  const visible = items.filter((f) => `${f.title} ${f.repo} ${f.cve ?? ''}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="page"><SectionHead eyebrow="Prioritization queue" title="Findings" sub="A focused view of the vulnerabilities that change your business risk." action={<Button variant="ghost" onClick={load}><RefreshCw size={15} /> Refresh</Button>} /><div className="filterbar"><div className="search"><Search /><input data-testid="input-findings-search" placeholder="Search findings, repos, or CVEs" value={query} onChange={(e) => setQuery(e.target.value)} /></div><select className="select" value={tier} onChange={(e) => setTier(e.target.value)} data-testid="select-findings-severity"><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><Button variant="ghost" onClick={() => { setQuery(''); setTier('All severities'); }}><Filter size={14} /> Clear</Button></div><div className="panel table-wrap"><table className="data-table"><thead><tr><th>Finding</th><th>Tier</th><th>Score</th><th>Repository</th><th>EPSS</th><th>Detected</th></tr></thead><tbody>{visible.map((f) => <tr onClick={() => setSelected(f)} key={f.id} style={{ cursor: 'pointer' }}><td><div className="finding-name">{f.title}</div><div className="finding-meta">{f.cve ?? f.package ?? f.file ?? f.scanner}</div></td><td><Badge tone={TIER_TONE[f.tier ?? ''] ?? 'info'}>{f.tier ?? 'Unscored'}</Badge></td><td><strong style={{ color: f.tier === 'Critical' ? 'var(--danger)' : 'var(--ink)' }}>{f.context_score ?? '—'}</strong></td><td>{f.repo}</td><td style={{ color: 'var(--muted)' }}>{f.epss != null ? `${(f.epss * 100).toFixed(1)}%` : '—'}</td><td style={{ color: 'var(--muted)' }}>{new Date(f.first_seen_at).toLocaleDateString()}</td></tr>)}</tbody></table>{!loading && visible.length === 0 && <div className="coming"><Search size={23} /><h3>Nothing matched</h3><p>{items.length === 0 ? 'No open findings - run a scan first.' : 'Try clearing your filters.'}</p></div>}</div>{selected && <FindingDrawer finding={selected} close={() => setSelected(null)} toast={toast} onChanged={load} />}</div>;
}
function FindingDrawer({ finding: f, close, toast, onChanged }: { finding: api.FindingItem; close: () => void; toast: ToastFn; onChanged: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [close]);

  async function setState(state: string) {
    try {
      await api.updateFindingState(f.id, state);
      toast(`Finding marked ${state}.`);
      onChanged();
      close();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not update finding.');
    }
  }
  return <><div className="drawer-backdrop" onClick={close} /><aside className="drawer" role="dialog" aria-modal="true" aria-label={`${f.title} finding detail`}><div className="drawer-head"><div><div className="eyebrow">{f.cve ?? f.scanner} · Detected {new Date(f.first_seen_at).toLocaleDateString()}</div><h2 style={{ marginTop: 9, fontSize: 27 }}>{f.title}</h2><div style={{ marginTop: 11, display: 'flex', gap: 7 }}><Badge tone={TIER_TONE[f.tier ?? ''] ?? 'info'}>{f.tier ?? 'Unscored'} severity</Badge><Badge tone="info">{f.state}</Badge>{f.kev && <Badge tone="high">CISA KEV</Badge>}</div></div><button className="icon-button" onClick={close} aria-label="Close finding detail"><X size={16} /></button></div><div className="drawer-section"><h4>Signals</h4><p className="subhead">CVSS {f.cvss ?? '—'} · EPSS {f.epss != null ? `${(f.epss * 100).toFixed(1)}%` : '—'} · Contextual score {f.context_score ?? '—'}/100.{f.annual_loss != null && <> Estimated annual loss <strong style={{ color: 'var(--ink)' }}>${f.annual_loss.toLocaleString()}</strong>.</>}</p></div><div className="drawer-section"><h4>Location</h4><div className="code-diff"><span className="dim">{f.file ?? f.package ?? 'unknown location'}</span></div></div><div style={{ display: 'flex', gap: 9, marginTop: 22 }}><Button onClick={() => setState('fixed')}><Check size={15} /> Mark fixed</Button><Button variant="ghost" onClick={() => setState('accepted')}>Accept risk</Button><Button variant="ghost" onClick={() => setState('false_positive')}>False positive</Button></div></aside></>;
}

function RiskScore({ toast }: PageProps) {
  const [risk, setRisk] = useState<Awaited<ReturnType<typeof api.orgRisk>> | null>(null);
  const [analytics, setAnalytics] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.orgRisk(), api.analytics(30)])
      .then(([r, a]) => { setRisk(r); setAnalytics(a); })
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load risk score'))
      .finally(() => setLoading(false));
  }, []);

  const score = risk?.org_risk_score ?? 0;
  const scannerBreakdown: Record<string, number> = analytics?.scanner_breakdown ?? {};
  const scannerBars = Object.entries(scannerBreakdown).map(([n, v]) => ({ n, v }));
  const topScanner = scannerBars.slice().sort((a, b) => b.v - a.v)[0];

  return <div className="page"><SectionHead eyebrow="Decision signal" title="Risk score" sub="One measured signal for the exposure your organization can absorb today." /><div className="grid grid-2"><div className="panel panel-pad risk-panel"><div><div className="eyebrow">Current posture</div><h2 style={{ marginTop: 10 }}>{loading ? 'Loading…' : risk?.org_risk_score == null ? 'Not enough data yet.' : score >= 70 ? 'Elevated exposure.' : score >= 40 ? 'Controlled, with open work.' : 'Well controlled.'}</h2><p className="subhead">{risk?.findings_open ?? 0} open finding{(risk?.findings_open ?? 0) === 1 ? '' : 's'} across your connected repositories.</p><div className="legend" style={{ marginTop: 24 }}><div className="legend-row"><i className="dot" /> <span>Current risk <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>{risk?.org_risk_score ?? '—'}</strong></span></div><div className="legend-row"><i className="dot sky" /> <span>Open findings <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>{risk?.findings_open ?? 0}</strong></span></div><div className="legend-row"><i className="dot danger" /> <span>Critical findings <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>{risk?.findings_critical ?? 0}</strong></span></div></div></div><RiskRing value={risk?.org_risk_score ?? 0} /></div><div className="panel panel-pad"><div className="section-title"><h3>Open findings by scanner</h3><span>Live</span></div><div className="chart-wrap">{scannerBars.length === 0 ? <p className="subhead">No open findings to break down yet.</p> : <ResponsiveContainer width="100%" height="100%"><BarChart data={scannerBars} layout="vertical" margin={{ left: 10, right: 15 }}><CartesianGrid horizontal={false} stroke="rgba(47,65,86,.08)" /><XAxis type="number" hide /><YAxis dataKey="n" type="category" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} width={85} /><Bar dataKey="v" fill="#567C8D" radius={[0, 5, 5, 0]} barSize={19} /></BarChart></ResponsiveContainer>}</div></div></div><div className="grid grid-3" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="eyebrow">Top scanner category</div><h3 style={{ marginTop: 11 }}>{topScanner ? `${topScanner.n} (${topScanner.v})` : '—'}</h3><p className="subhead">The scanner surfacing the most open findings right now.</p></div><div className="panel panel-pad"><div className="eyebrow">Known exploited</div><h3 style={{ marginTop: 11 }}>{analytics?.kev_count ?? 0} on CISA KEV</h3><p className="subhead">Open findings that match the CISA Known Exploited Vulnerabilities catalogue.</p></div><div className="panel panel-pad"><div className="eyebrow">SLA compliance</div><h3 style={{ marginTop: 11 }}>{analytics?.sla_compliance_pct != null ? `${analytics.sla_compliance_pct}%` : '—'}</h3><p className="subhead">Open findings still inside their tier's fix-by window.</p></div></div></div>;
}

function ThreatIntel({ toast }: PageProps) {
  const [analytics, setAnalytics] = useState<any>(null);
  const [advisories, setAdvisories] = useState<api.FindingItem[]>([]);
  const [loading, setLoading] = useState(true);

  function load() {
    setLoading(true);
    Promise.all([api.analytics(30), api.listFindings({ state: 'open', kev: true, page_size: 5, sort: 'epss' })])
      .then(([a, f]) => { setAnalytics(a); setAdvisories(f.items); })
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load threat intelligence'))
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  const kevCount = analytics?.kev_count ?? 0;
  const epssDist: Record<string, number> = analytics?.epss_distribution ?? {};
  const topEpssBucket = Object.entries(epssDist).filter(([k]) => k !== '0-1%').sort((a, b) => b[1] - a[1])[0];
  const intel: [string, string, string][] = [
    ['CISA KEV', kevCount > 0 ? `${kevCount} open finding${kevCount === 1 ? '' : 's'} match known exploited vulnerabilities` : 'No open findings on the CISA KEV catalogue', kevCount > 0 ? 'high' : 'low'],
    ['EPSS', topEpssBucket ? `${topEpssBucket[1]} open finding(s) in the ${topEpssBucket[0]} exploit-probability band` : 'No EPSS-scored findings yet', topEpssBucket && topEpssBucket[1] > 0 ? 'medium' : 'low'],
    ['Coverage', `${analytics?.repo_comparison?.length ?? 0} repositories monitored`, 'low'],
  ];
  const trend = (analytics?.findings_over_time ?? []).map((p: any) => ({ day: p.day, value: p.value }));

  return <div className="page"><SectionHead eyebrow="External context" title="Threat intelligence" sub="Turn global signals into local urgency. Fantom enriches each finding with what attackers are doing now." action={<Button variant="ghost" onClick={load}><RefreshCw size={15} /> Refresh signals</Button>} /><div className="grid grid-3">{intel.map(([source, desc, tone]) => <div className="panel panel-pad" key={source}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span className="eyebrow">{source}</span><Badge tone={tone}>{tone === 'low' ? 'Clear' : 'Watch'}</Badge></div><h3 style={{ marginTop: 22, lineHeight: 1.35 }}>{desc}</h3></div>)}</div><div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Findings opened</h3><span>Last 30 days</span></div><div className="chart-wrap tall">{trend.length === 0 ? <p className="subhead">No findings in this window.</p> : <ResponsiveContainer width="100%" height="100%"><ReLineChart data={trend}><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /><Line type="monotone" dataKey="value" stroke="#567C8D" strokeWidth={2.5} dot={false} /></ReLineChart></ResponsiveContainer>}</div></div><div className="panel panel-pad"><div className="section-title"><h3>Active advisories</h3><Badge tone="info">{advisories.length} on KEV</Badge></div><div className="timeline">{advisories.length === 0 && !loading && <div className="timeline-item muted"><h4>No known-exploited findings open</h4><p>Nothing on the CISA KEV catalogue is currently open.</p></div>}{advisories.map((f) => <div className="timeline-item" key={f.id}><h4>{f.cve ?? f.title}</h4><p>{f.title} · Affected in {f.repo}</p></div>)}</div></div></div></div>;
}

function BusinessImpact({ toast }: PageProps) {
  const [users, setUsers] = useState(42000); const [revenue, setRevenue] = useState(18); const [criticality, setCriticality] = useState(3);
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.pricePreview>> | null>(null);
  const [busy, setBusy] = useState(false);

  // A representative Critical/CVSS-9.1 finding, priced through the real
  // stateless loss model - the calculator's inputs become real business
  // context, not a fabricated multiplier.
  const REPRESENTATIVE_FINDING = { scanner: 'osv', title: 'Material exposed vulnerability', cvss: 9.1, direct: true };

  useEffect(() => {
    setBusy(true);
    const context = {
      users_count: users, revenue_supported: users * revenue,
      downtime_cost_hour: Math.round((users * revenue) / (24 * 30)),
      records_count: users, regimes: [criticality >= 4 ? 'GDPR' : 'NONE'],
    };
    const t = window.setTimeout(() => {
      api.pricePreview(context, REPRESENTATIVE_FINDING)
        .then(setResult)
        .catch((err) => toast(err instanceof Error ? err.message : 'Could not price this scenario.'))
        .finally(() => setBusy(false));
    }, 300);
    return () => window.clearTimeout(t);
  }, [users, revenue, criticality]);

  // annual_loss_upper_bound needs a published exploit probability (EPSS); this
  // synthetic finding has none, so the model falls back to the cost if it
  // happens at all - real backend behavior, not a frontend guess (see `note`).
  const exposure = result?.priced ? result.annual_loss_upper_bound ?? result.if_it_happens ?? 0 : null;

  return <div className="page"><SectionHead eyebrow="Translate risk" title="Business impact" sub="Make the cost of exposure legible to the people who fund the fix, using the same loss model that prices real findings." action={<Button onClick={() => toast('Impact brief added to Reports.')}><FileText size={15} /> Add to report</Button>} /><div className="calculator"><div className="panel panel-pad"><div className="section-title"><h3>Exposure model</h3><Badge tone="info">Live pricing</Badge></div><p className="subhead">Adjust the context to see how a material, Critical-severity finding changes your potential business exposure.</p><div className="field"><label>Potentially affected users</label><input data-testid="input-affected-users" type="number" value={users} onChange={(e) => setUsers(Number(e.target.value))} /><small>Accounts or customers within the service boundary.</small></div><div className="field"><label>Average revenue at risk per user ($)</label><input data-testid="input-revenue" type="number" value={revenue} onChange={(e) => setRevenue(Number(e.target.value))} /></div><div className="field"><label>Service criticality</label><select data-testid="select-criticality" value={criticality} onChange={(e) => setCriticality(Number(e.target.value))}><option value="1">1 · Low</option><option value="2">2 · Moderate</option><option value="3">3 · Important</option><option value="4">4 · Business critical</option><option value="5">5 · Mission critical</option></select></div></div><div className="calc-output"><div><div className="eyebrow" style={{ color: 'var(--sky)' }}>Estimated exposure</div><div className="calc-number">{busy ? '…' : exposure != null ? `$${Math.round(exposure).toLocaleString()}` : 'Not priced'}</div><p>{result?.note ?? 'Modeled annualized impact if the vulnerable path is exploited without mitigation.'}</p></div><div><hr /><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 18 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Contextual score</span><strong style={{ color: 'var(--sky)' }}>{result?.context_score ?? '—'} · {result?.tier ?? '—'}</strong></div><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 12 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Recommended action</span><strong>{result?.sla ? `Fix within ${result.sla}` : '—'}</strong></div></div></div></div></div>;
}

const EXPECTED_STAGES = 11; // roughly matches app/services/orchestrator.py's _emit() call count

function LiveScan({ toast }: PageProps) {
  const [projects, setProjects] = useState<api.ProjectOut[]>([]);
  const [projectId, setProjectId] = useState('');
  const [running, setRunning] = useState(false);
  const [state, setState] = useState<'idle' | 'running' | 'done' | 'failed'>('idle');
  const [log, setLog] = useState<{ event: string; message: string }[]>([]);
  const stopRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    api.listProjects().then((p) => { setProjects(p); if (p[0]) setProjectId(p[0].id); })
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load repositories'));
    return () => stopRef.current?.();
  }, []);

  async function run() {
    if (!projectId) { toast('Connect a repository first.'); return; }
    setLog([]); setRunning(true); setState('running');
    try {
      const { run_id } = await api.triggerScan(projectId);
      stopRef.current = api.streamRunEvents(run_id, (data) => {
        setLog((l) => [...l, { event: data.event, message: data.message || data.event }]);
      }, async () => {
        setRunning(false);
        try {
          const finalRun = await api.getRun(run_id);
          setState(finalRun.state === 'failed' ? 'failed' : 'done');
          if (finalRun.state === 'failed') toast(`Scan failed: ${finalRun.error ?? 'unknown error'}`);
          else toast(`Scan complete — ${finalRun.findings_new} new finding(s).`);
        } catch { setState('done'); }
        window.dispatchEvent(new CustomEvent('fantom:notifications-changed'));
      });
    } catch (err) {
      setRunning(false); setState('failed');
      toast(err instanceof Error ? err.message : 'Could not start scan.');
    }
  }

  const progress = state === 'done' ? 100 : Math.min(95, Math.round((log.length / EXPECTED_STAGES) * 100));
  const stages: [string, boolean][] = [
    ['Clone & repository sync', log.some((l) => l.message.includes('cloned'))],
    ['Dependency, secret, code & infra scan', log.some((l) => l.event === 'found')],
    ['EPSS + CISA KEV enrichment', log.some((l) => l.message.includes('enriching'))],
    ['Contextual scoring & pricing', log.some((l) => l.message.includes('scored'))],
  ];

  return <div className="page"><SectionHead eyebrow="Continuous observation" title="Live scan" sub="Watch Fantom build an evidence-backed view of your current exposure, from a real scan of a real repository." action={<div style={{ display: 'flex', gap: 8 }}>{projects.length > 1 && <select className="select" value={projectId} onChange={(e) => setProjectId(e.target.value)}>{projects.map((p) => <option key={p.id} value={p.id}>{p.repo}</option>)}</select>}<Button onClick={run} disabled={running}><Play size={15} /> {running ? 'Scanning…' : 'Run scan'}</Button></div>} /><div className="grid grid-2"><div className="panel panel-pad"><div className="section-title"><h3>Scan progress</h3><Badge tone={state === 'running' ? 'medium' : state === 'done' ? 'low' : state === 'failed' ? 'high' : 'info'}>{state === 'running' ? 'In progress' : state === 'done' ? 'Complete' : state === 'failed' ? 'Failed' : 'Idle'}</Badge></div><div style={{ display: 'flex', alignItems: 'center', gap: 18, margin: '26px 0' }}><div style={{ fontFamily: 'var(--font-display)', fontSize: 46, letterSpacing: '-.08em' }}>{progress}%</div><div style={{ flex: 1 }}><div className="progress" style={{ height: 9 }}><i style={{ width: `${progress}%` }} /></div><small style={{ color: 'var(--muted)', display: 'block', marginTop: 8 }}>{state === 'idle' ? 'Pick a repository and run a scan' : state === 'running' ? `${log.length} events so far` : state === 'failed' ? 'Scan failed - see log' : 'Finished'}</small></div></div><div className="timeline">{stages.map(([title, done]) => <div className={`timeline-item ${done ? '' : 'muted'}`} key={title}><h4>{title} {done && <Check size={13} style={{ color: 'var(--teal)', verticalAlign: 'middle' }} />}</h4></div>)}</div></div><div><div className="panel panel-pad" style={{ marginBottom: 18 }}><div className="section-title"><h3>Connection status</h3><span className={`badge ${state === 'failed' ? 'high' : 'low'}`}><i className="dot" style={{ width: 6, height: 6 }} /> {projects.length} repositor{projects.length === 1 ? 'y' : 'ies'} connected</span></div></div><div className="console">{log.length === 0 ? <div className="dim">$ waiting for a scan to run…</div> : log.map((l, i) => <div key={i} className={l.event === 'error' ? 'warn' : l.event === 'found' ? 'ok' : undefined}>→ {l.message}</div>)}<div className="dim">_</div></div></div></div></div>;
}

function Vulnerability({ toast }: PageProps) {
  const { id } = useParams(); const [tab, setTab] = useState('Overview');
  const [f, setF] = useState<api.FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true); setError(null);
    api.getFinding(id).then(setF)
      .catch((err) => setError(err instanceof Error ? err.message : 'Finding not found.'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="page"><p className="subhead">Loading finding…</p></div>;
  if (error || !f) return <div className="page"><Link href="/findings" className="crumb" style={{ marginBottom: 22, display: 'inline-flex' }}><ArrowLeft size={14} /> Back to findings</Link><div className="panel coming"><AlertTriangle size={28} /><h3>Finding not found</h3><p>{error ?? 'This finding no longer exists or you do not have access to it.'}</p></div></div>;

  const tone = f.tier === 'Critical' || f.tier === 'High' ? 'high' : f.tier === 'Medium' ? 'medium' : 'low';
  const steps = f.remediation?.steps ?? [];

  return <div className="page"><Link href="/findings" className="crumb" style={{ marginBottom: 22, display: 'inline-flex' }}><ArrowLeft size={14} /> Back to findings</Link><SectionHead eyebrow={f.cve ?? f.scanner} title={f.title} sub={f.package ? `Affects package ${f.package}${f.version ? ` @ ${f.version}` : ''}.` : f.file ? `Found in ${f.file}.` : 'Detected by continuous scanning.'} action={<Badge tone={tone}>{f.tier ?? 'Unscored'}{f.cvss != null ? ` · ${f.cvss}` : ''}</Badge>} /><div className="tabs">{['Overview', 'Remediation', 'Activity'].map((t) => <button className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)} key={t}>{t}</button>)}</div>
    {tab === 'Overview' && <div className="grid grid-2"><div className="panel panel-pad"><div className="section-title"><h3>Finding context</h3><Badge tone="info">{f.state}</Badge></div><div className="grid grid-2" style={{ marginTop: 20 }}><div><small style={{ color: 'var(--muted)' }}>Repository</small><strong style={{ display: 'block', marginTop: 5 }}>{f.repo}</strong></div><div><small style={{ color: 'var(--muted)' }}>Detected</small><strong style={{ display: 'block', marginTop: 5 }}>{new Date(f.first_seen_at).toLocaleDateString()}</strong></div><div><small style={{ color: 'var(--muted)' }}>CWE</small><strong style={{ display: 'block', marginTop: 5 }}>{f.cwe ?? '—'}</strong></div><div><small style={{ color: 'var(--muted)' }}>Owner</small><strong style={{ display: 'block', marginTop: 5 }}>{f.owner ?? 'Unassigned'}</strong></div></div><div className="drawer-section" style={{ marginTop: 23 }}><h4>Signals</h4><p className="subhead">CVSS {f.cvss ?? '—'} · EPSS {f.epss != null ? `${(f.epss * 100).toFixed(1)}%` : '—'} · Contextual score {f.context_score ?? '—'}/100.{f.kev && ' On the CISA KEV catalogue.'}{f.annual_loss != null && <> Estimated annual loss <strong style={{ color: 'var(--ink)' }}>${f.annual_loss.toLocaleString()}</strong>.</>}</p></div></div><div className="panel panel-pad"><div className="section-title"><h3>Location</h3><span>{f.scanner}</span></div><div className="code-diff"><span className="dim">{f.file ?? f.package ?? 'unknown location'}{f.line != null ? `:${f.line}` : ''}</span>{f.rule_id && <><br /><span className="dim">rule: {f.rule_id}</span></>}</div></div></div>}
    {tab === 'Remediation' && <div className="panel panel-pad"><h3>Recommended fix</h3><p className="subhead" style={{ marginBottom: 18 }}>{steps.length} step{steps.length === 1 ? '' : 's'}{f.fix_hours != null ? ` · ~${f.fix_hours}h estimated` : ''}.</p>{steps.length === 0 ? <p className="subhead">No automated remediation guidance for this finding yet.{f.fixed_version && ` Upgrade to ${f.fixed_version} to resolve it.`}</p> : <div className="timeline">{steps.map((s, i) => <div className={`timeline-item ${i === steps.length - 1 ? 'muted' : ''}`} key={i}><h4>{s}</h4></div>)}</div>}</div>}
    {tab === 'Activity' && <div className="panel panel-pad"><div className="timeline"><div className="timeline-item muted"><h4>Finding detected</h4><p>{f.scanner} · {new Date(f.first_seen_at).toLocaleString()}</p></div>{f.last_seen_at !== f.first_seen_at && <div className="timeline-item"><h4>Last observed</h4><p>{new Date(f.last_seen_at).toLocaleString()}</p></div>}</div></div>}
  </div>;
}

function Analytics({ toast }: PageProps) {
  const [analytics, setAnalytics] = useState<any>(null);
  const [tierCounts, setTierCounts] = useState<{ name: string; value: number; color: string }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([api.analytics(30), api.listFindings({ state: 'open', page_size: 200 })])
      .then(([a, f]) => {
        setAnalytics(a);
        const counts: Record<string, number> = {};
        for (const item of f.items) { const t = item.tier ?? 'Unscored'; counts[t] = (counts[t] ?? 0) + 1; }
        setTierCounts(Object.entries(counts).map(([name, value]) => ({ name, value, color: TIER_COLOR[name] ?? '#748697' })));
      })
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load analytics'))
      .finally(() => setLoading(false));
  }, []);

  const opened = (analytics?.findings_over_time ?? []).map((p: any) => ({ day: p.day, opened: p.value }));
  const totalOpen = tierCounts.reduce((s, t) => s + t.value, 0);

  return <div className="page"><SectionHead eyebrow="Trends & patterns" title="Analytics" sub="Measure how your security program is changing, not just what it found." /><div className="grid grid-4"><Kpi icon={TrendingDown} label="Mean time to remediate" value={analytics?.mttr_days != null ? `${analytics.mttr_days}d` : '—'} note="Fixed findings, avg" /><Kpi icon={Target} label="SLA compliance" value={analytics?.sla_compliance_pct != null ? `${analytics.sla_compliance_pct}%` : '—'} note="Open findings within SLA" /><Kpi icon={Zap} label="Known exploited" value={String(analytics?.kev_count ?? 0)} note="Open, on CISA KEV" /><Kpi icon={Server} label="Repos covered" value={String(analytics?.repo_comparison?.length ?? 0)} note="With at least one scan" /></div><div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Findings opened</h3><span>Last 30 days</span></div><div className="chart-wrap tall">{opened.length === 0 ? <p className="subhead">No findings in this window.</p> : <ResponsiveContainer width="100%" height="100%"><AreaChart data={opened}><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /><Area type="monotone" dataKey="opened" stroke="#567C8D" fill="#C8D9E6" fillOpacity=".55" /></AreaChart></ResponsiveContainer>}</div></div><div className="panel panel-pad"><div className="section-title"><h3>Severity distribution</h3><span>{totalOpen} open</span></div><div className="chart-wrap tall">{tierCounts.length === 0 ? <p className="subhead">No open findings.</p> : <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={tierCounts} dataKey="value" innerRadius={70} outerRadius={100} paddingAngle={3}>{tierCounts.map((x) => <Cell key={x.name} fill={x.color} />)}</Pie><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /></PieChart></ResponsiveContainer>}</div><div className="legend" style={{ flexDirection: 'row', flexWrap: 'wrap' }}>{tierCounts.map((x) => <div className="legend-row" key={x.name}><i className="dot" style={{ background: x.color }} /> {x.name} {x.value}</div>)}</div></div></div></div>;
}

const REPORT_KINDS = ['executive', 'technical', 'compliance', 'repository'];

function Reports({ toast }: PageProps) {
  const [reports, setReports] = useState<api.ReportOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  function load() {
    setLoading(true);
    api.listReports().then(setReports)
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load reports'))
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  async function create() {
    setCreating(true);
    try {
      await api.createReport('executive');
      toast('Report queued - it will appear here once generated.');
      load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not create report.');
    } finally {
      setCreating(false);
    }
  }

  async function download(r: api.ReportOut) {
    try {
      await api.downloadReport(r.id, `fantom-${r.kind}-report-${r.id.slice(0, 8)}.md`);
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not download report.');
    }
  }

  return <div className="page"><SectionHead eyebrow="Share the signal" title="Reports" sub="Clear, decision-ready views for the people who need confidence, not another dashboard." action={<Button onClick={create} disabled={creating}><Plus size={15} /> {creating ? 'Queuing…' : 'Create report'}</Button>} /><div className="grid grid-3">{reports.map((r) => <div className="panel panel-pad" key={r.id}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span className="repo-icon"><FileText size={16} /></span><Badge tone={r.status === 'done' ? 'low' : r.status === 'failed' ? 'high' : 'info'}>{r.status}</Badge></div><h3 style={{ marginTop: 25, textTransform: 'capitalize' }}>{r.kind} report</h3><p className="subhead">{new Date(r.created_at).toLocaleString()}{r.project_id ? '' : ' · Org-wide'}</p><div style={{ display: 'flex', gap: 8, marginTop: 24 }}><Button variant="soft" className="small" disabled={r.status !== 'done'} onClick={() => download(r)}><Download size={13} /> Download</Button><Button variant="ghost" className="small" onClick={load}><RefreshCw size={13} /> Refresh</Button></div></div>)}</div>{!loading && reports.length === 0 && <div className="panel coming" style={{ marginTop: 18 }}><FileBarChart size={28} /><h3>No reports yet</h3><p>Create your first report to get a decision-ready view of your current exposure.</p></div>}</div>;
}

const HEALTH_POLL_MS = 45_000;

/** The backend stores the raw GitHub API error as `monitoring_reason`
 * (e.g. `webhook creation failed: create webhook on x/y -> 422: {"message":...}`).
 * Map the ones users can actually act on to plain language; keep the raw
 * text as a title tooltip for anyone who needs to debug further. */
function friendlyMonitoringReason(reason: string): string {
  if (reason.includes("isn't reachable over the public Internet")) {
    return "Webhook needs a public URL - localhost/private addresses are rejected by GitHub. Use a tunnel (ngrok, etc.) in local dev.";
  }
  if (reason.toLowerCase().includes('webhook creation failed')) {
    return "Couldn't create the webhook for this repository. Push-based scanning is unavailable; use \"Scan now\" manually.";
  }
  return reason;
}

function GithubIntegrationPanel({ toast }: PageProps) {
  const [status, setStatus] = useState<api.ConnectorStatusOut | null>(null);
  const [repos, setRepos] = useState<api.GithubRepositoryOut[]>([]);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [visibility, setVisibility] = useState<'all' | 'private' | 'public'>('all');
  const [pending, setPending] = useState<Record<string, boolean>>({}); // repo id -> desired monitored state
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Debounce so every keystroke doesn't fire a request against a live GitHub call.
  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedSearch(search), 300);
    return () => window.clearTimeout(t);
  }, [search]);

  function load(silent = false) {
    if (!silent) setRefreshing(true);
    api.githubStatus()
      .then((s) => {
        setStatus(s);
        return s.connected ? api.githubRepositories({
          page_size: 100, search: debouncedSearch || undefined,
          visibility: visibility === 'all' ? undefined : visibility,
        }) : null;
      })
      .then((r) => {
        if (!r) { setRepos([]); return; }
        setRepos(r.repositories);
        setPending(Object.fromEntries(r.repositories.map((x) => [x.id, x.monitoring_status === 'monitored'])));
      })
      .catch((err) => { if (!silent) toast(err instanceof Error ? err.message : 'Failed to load GitHub status'); })
      .finally(() => { setLoading(false); setRefreshing(false); });
  }
  useEffect(load, [debouncedSearch, visibility]);

  // Connector health, refreshed quietly while this panel stays open - status
  // only, never yanks the repository list or the user's pending checkboxes.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') api.githubStatus().then(setStatus).catch(() => {});
    }, HEALTH_POLL_MS);
    return () => window.clearInterval(id);
  }, []);

  async function connect() {
    setBusy(true);
    try {
      const { authorize_url } = await api.githubAuthorizeUrl();
      window.location.href = authorize_url;
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not start GitHub connection.');
      setBusy(false);
    }
  }

  async function disconnect() {
    if (!window.confirm('Disconnect GitHub? Webhooks will be removed and monitoring paused for its repositories.')) return;
    setBusy(true);
    try {
      await api.githubDisconnect();
      toast('GitHub disconnected.');
      load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not disconnect GitHub.');
    } finally {
      setBusy(false);
    }
  }

  async function syncNow() {
    setBusy(true); setSyncing(true);
    const stopWatching = api.watchConnectorEvents((kind) => {
      if (kind === 'connector.sync.completed' || kind === 'connector.sync.failed') setSyncing(false);
    });
    try {
      await api.githubSync();
      toast('Repositories synced.');
      load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Sync failed.');
    } finally {
      setBusy(false);
      window.setTimeout(() => { setSyncing(false); stopWatching(); }, 4000);
    }
  }

  const dirty = repos.some((r) => pending[r.id] !== (r.monitoring_status === 'monitored') && r.monitoring_status !== 'permission_lost');
  const visibleSelectable = repos.filter((r) => r.monitoring_status !== 'permission_lost');
  const allSelected = visibleSelectable.length > 0 && visibleSelectable.every((r) => pending[r.id]);

  function toggleAll() {
    const next = !allSelected;
    setPending((p) => ({ ...p, ...Object.fromEntries(visibleSelectable.map((r) => [r.id, next])) }));
  }

  async function applySelection() {
    const toSelect = repos.filter((r) => pending[r.id] && r.monitoring_status !== 'monitored').map((r) => r.id);
    const toUnselect = repos.filter((r) => !pending[r.id] && r.monitoring_status === 'monitored').map((r) => r.id);
    if (toSelect.length === 0 && toUnselect.length === 0) return;
    setBusy(true);
    try {
      if (toSelect.length) {
        const { skipped } = await api.githubSelectRepositories(toSelect);
        Object.values(skipped).forEach((reason) => toast(reason));
      }
      if (toUnselect.length) await api.githubUnselectRepositories(toUnselect);
      toast(`Monitoring updated for ${toSelect.length + toUnselect.length} repositor${toSelect.length + toUnselect.length === 1 ? 'y' : 'ies'}.`);
      load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not update monitoring.');
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <p className="subhead">Loading GitHub connection…</p>;

  if (!status?.connected) return <>
    <h3>GitHub</h3>
    <p className="subhead" style={{ marginBottom: 22 }}>Connect a GitHub account to import repositories and monitor them on every push.</p>
    <Button onClick={connect} disabled={busy}><Github size={15} /> {busy ? 'Redirecting…' : 'Connect GitHub'}</Button>
  </>;

  return <>
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
      <span className="repo-icon"><Github size={16} /></span>
      <span style={{ flex: 1 }}>
        <strong style={{ display: 'block', fontSize: 13 }}>{status.account_login}</strong>
        <small style={{ color: 'var(--muted)' }}>{status.status} · {status.repository_count} repositories · {status.monitored_repository_count} monitored{status.last_sync_at ? ` · synced ${new Date(status.last_sync_at).toLocaleString()}` : ''}{status.token_expires_at ? ` · token expires ${new Date(status.token_expires_at).toLocaleDateString()}` : ''}</small>
      </span>
      {syncing && <Badge tone="info">Syncing…</Badge>}
      <Button variant="ghost" className="small" onClick={syncNow} disabled={busy}><RefreshCw size={13} /> Sync now</Button>
      <Button variant="ghost" className="small" onClick={disconnect} disabled={busy}><Unplug size={13} /> Disconnect</Button>
    </div>
    <div className="filterbar" style={{ marginBottom: 14 }}>
      <div className="search"><Search /><input aria-label="Search repositories" placeholder="Search repositories" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
      <select className="select" value={visibility} onChange={(e) => setVisibility(e.target.value as any)}><option value="all">All visibility</option><option value="private">Private</option><option value="public">Public</option></select>
      {refreshing && <Badge tone="info">Searching…</Badge>}
      <Button variant={dirty ? 'primary' : 'ghost'} className="small" onClick={applySelection} disabled={busy || !dirty}><Check size={13} /> Apply selection</Button>
    </div>
    <div className="table-wrap" style={{ border: '1px solid var(--line)', borderRadius: 12 }}>
      <table className="data-table"><thead><tr><th><input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="Select all" /></th><th>Repository</th><th>Visibility</th><th>Permission</th><th>Monitoring</th></tr></thead>
        <tbody>{repos.map((r) => <tr key={r.id}>
          <td><input type="checkbox" checked={!!pending[r.id]} disabled={r.monitoring_status === 'permission_lost'} onChange={(e) => setPending((p) => ({ ...p, [r.id]: e.target.checked }))} aria-label={`Monitor ${r.full_name}`} /></td>
          <td><div className="finding-name">{r.full_name}</div><div className="finding-meta">{r.language ?? 'Unknown language'}{r.stars ? ` · ★${r.stars}` : ''}</div></td>
          <td>{r.private ? 'Private' : 'Public'}</td>
          <td><Badge tone={r.permissions.admin ? 'low' : r.permissions.push ? 'info' : 'medium'}>{r.permissions.admin ? 'Admin' : r.permissions.push ? 'Push' : 'Read'}</Badge></td>
          <td><Badge tone={r.monitoring_status === 'monitored' ? 'low' : r.monitoring_status === 'permission_lost' ? 'high' : 'info'}>{r.monitoring_status.replace('_', ' ')}</Badge>{r.monitoring_status === 'manual_only' && !r.permissions.admin && <div className="finding-meta">No admin permission - webhook can't be created</div>}{r.monitoring_reason && <div className="finding-meta" title={r.monitoring_reason} style={{ whiteSpace: 'normal', maxWidth: 260 }}>{friendlyMonitoringReason(r.monitoring_reason)}</div>}</td>
        </tr>)}</tbody>
      </table>
      {repos.length === 0 && <p className="subhead" style={{ padding: 18 }}>No repositories found{search || visibility !== 'all' ? ' for this filter' : ' - try syncing'}.</p>}
    </div>
  </>;
}

function WorkspaceTab({ toast }: PageProps) {
  const [org, setOrg] = useState<{ id: string; name: string; slug: string; created_at: string } | null>(null);
  useEffect(() => { api.currentOrg().then(setOrg).catch((err) => toast(err instanceof Error ? err.message : 'Failed to load organization')); }, []);
  return <><h3>Workspace profile</h3><p className="subhead" style={{ marginBottom: 25 }}>This information appears on reports and decision briefs.</p>
    <div className="field"><label>Workspace name</label><input value={org?.name ?? ''} readOnly /></div>
    <div className="field"><label>Slug</label><input value={org?.slug ?? ''} readOnly /></div>
    <div className="field"><label>Created</label><input value={org ? new Date(org.created_at).toLocaleDateString() : ''} readOnly /></div>
    <p className="subhead" style={{ marginTop: 10 }}>Workspace name and domain editing isn't available yet.</p>
  </>;
}

function NotificationsTab({ toast }: PageProps) {
  const [channels, setChannels] = useState<api.NotificationChannelOut[]>([]);
  const [kind, setKind] = useState('webhook');
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);

  function load() { api.listNotificationChannels().then(setChannels).catch(() => {}); }
  useEffect(load, []);

  async function add() {
    if (!target.trim()) return;
    setBusy(true);
    try {
      await api.createNotificationChannel(kind, target.trim());
      setTarget(''); load();
      toast('Notification channel added.');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not add channel.');
    } finally { setBusy(false); }
  }

  async function remove(id: string) {
    try { await api.deleteNotificationChannel(id); load(); } catch (err) { toast(err instanceof Error ? err.message : 'Could not remove channel.'); }
  }

  return <><h3>Notification routing</h3><p className="subhead" style={{ marginBottom: 22 }}>Outbound channels that get a message when a scan finds something critical.</p>
    {channels.map((c) => <div key={c.id} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '15px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}><Badge tone="info">{c.kind}</Badge><span style={{ flex: 1 }}>{c.target}</span><Button variant="ghost" className="small" onClick={() => remove(c.id)}>Remove</Button></div>)}
    {channels.length === 0 && <p className="subhead">No outbound channels configured.</p>}
    <div style={{ display: 'flex', gap: 8, marginTop: 18 }}>
      <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}><option value="webhook">Webhook</option><option value="slack">Slack</option><option value="discord">Discord</option><option value="teams">Teams</option><option value="email">Email</option></select>
      <input placeholder="URL or address" value={target} onChange={(e) => setTarget(e.target.value)} style={{ flex: 1 }} />
      <Button onClick={add} disabled={busy}><Plus size={14} /> Add</Button>
    </div>
  </>;
}

function TeamTab({ toast }: PageProps) {
  const [members, setMembers] = useState<{ user_id: string; email: string; name: string; role: string; joined_at: string }[]>([]);
  useEffect(() => { api.listMembers().then(setMembers).catch((err) => toast(err instanceof Error ? err.message : 'Failed to load members')); }, []);
  return <><h3>People & access</h3><p className="subhead" style={{ marginBottom: 22 }}>Everyone with access to this workspace.</p>
    {members.map((m) => <div key={m.user_id} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '15px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}><span className="avatar" style={{ background: 'var(--sky)' }}>{m.name.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase()}</span><span style={{ flex: 1 }}><strong style={{ display: 'block' }}>{m.name}</strong><small style={{ color: 'var(--muted)' }}>{m.email}</small></span><Badge tone="info">{m.role}</Badge></div>)}
  </>;
}

function Settings({ toast }: PageProps) {
  const [tab, setTab] = useState('Workspace');
  return <div className="page"><SectionHead eyebrow="Workspace controls" title="Settings" sub="Tune how Fantom sees your organization and routes the signal." /><div className="grid grid-2"><div className="panel panel-pad" style={{ alignSelf: 'start' }}>{['Workspace', 'Integrations', 'Notifications', 'Team access'].map((t) => <button className={`tab ${tab === t ? 'active' : ''}`} style={{ display: 'block', width: '100%', textAlign: 'left', padding: '14px 0' }} onClick={() => setTab(t)} key={t}>{t}<ChevronRight size={14} style={{ float: 'right' }} /></button>)}</div><div className="panel panel-pad">
    {tab === 'Workspace' && <WorkspaceTab toast={toast} />}
    {tab === 'Integrations' && <GithubIntegrationPanel toast={toast} />}
    {tab === 'Notifications' && <NotificationsTab toast={toast} />}
    {tab === 'Team access' && <TeamTab toast={toast} />}
  </div></div></div>;
}

/** Landing page for the backend's post-OAuth redirect
 * (`{FRONTEND_URL}/settings/integrations?provider=github&status=connected|error`) -
 * required as a real route, not just a Settings tab, because that's the exact
 * URL the backend redirects the browser to. */
function SettingsIntegrations({ toast }: PageProps) {
  const search = useSearch();
  const [, setLocation] = useLocation();
  useEffect(() => {
    const params = new URLSearchParams(search);
    const status = params.get('status');
    if (status === 'connected') toast('GitHub connected.');
    else if (status === 'error') toast(`GitHub connection failed: ${params.get('message') ?? 'unknown error'}`);
    if (status) setLocation('/settings/integrations', { replace: true });
  }, [search]);
  return <div className="page"><SectionHead eyebrow="Workspace controls" title="Integrations" sub="Connect and manage the sources Fantom scans." /><div className="panel panel-pad"><GithubIntegrationPanel toast={toast} /></div></div>;
}

function Help() {
  return <div className="page"><SectionHead eyebrow="We're here to help" title="Help center" sub="Find your way from first connection to an evidence-backed risk decision." action={<Button variant="soft"><MessageSquare size={15} /> Contact support</Button>} /><div className="grid grid-3">{[['Start with Fantom', 'Connect a repository, understand your first score, and invite your team.', BookOpen], ['Understand your score', 'How reachability, threat signals, and business criticality combine.', Radar], ['Remediate with confidence', 'Prioritize the fix that changes your actual exposure.', Check]].map(([t,d,I]) => <div className="panel panel-pad" key={t as string}><div className="feature-icon"><I size={18} /></div><h3>{t as string}</h3><p className="subhead">{d as string}</p><Link href="/help" className="eyebrow" style={{ display: 'block', marginTop: 20 }}>Read guide <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></Link></div>)}</div><div className="panel panel-pad" style={{ marginTop: 18 }}><div className="section-title"><h3>Popular questions</h3><span>Knowledge base</span></div>{['How does Fantom calculate risk score?', 'What does a high finding mean for my business?', 'How often are repositories scanned?', 'Can I connect a self-hosted GitHub instance?'].map((q) => <div key={q} style={{ display: 'flex', justifyContent: 'space-between', padding: '17px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}>{q}<ChevronRight size={15} color="var(--muted)" /></div>)}</div></div>;
}

function AuthPage({ kind, toast }: { kind: 'login' | 'signup' | 'forgot' | 'github'; toast: ToastFn }) {
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [, setLocation] = useLocation();
  const { refresh } = useAuth();
  const config = { login: ['Welcome back', 'Sign in to your security command center.', 'Sign in'], signup: ['Start with clarity', 'Create your workspace and see your first risk signal in minutes.', 'Create workspace'], forgot: ['Reset your access', 'Enter your work email and we will send a secure reset link.', 'Send reset link'], github: ['Connect GitHub', 'Give Fantom read-only access to the codebases you want to protect.', 'Authorize GitHub'] }[kind];

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const email = String(data.get('email') || '');
    const password = String(data.get('password') || '');
    const workspace = String(data.get('workspace') || '');
    setBusy(true);
    try {
      if (kind === 'login') {
        await api.login(email, password);
        await refresh();
        toast('Signed in.');
        setLocation('/dashboard');
      } else if (kind === 'signup') {
        await api.register(email, password, email.split('@')[0], workspace || 'My Workspace');
        await refresh();
        toast('Workspace created.');
        setLocation('/dashboard');
      } else if (kind === 'forgot') {
        await api.requestPasswordReset(email);
        setSubmitted(true);
      } else {
        const { authorize_url } = await api.githubAuthorizeUrl();
        window.location.href = authorize_url;
        return;
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  return <div className="auth-page"><div className="auth-visual"><FantomLogo /><div className="auth-copy"><div className="eyebrow" style={{ color: 'var(--sky)' }}>Continuous cyber risk quantification</div><h1>Know what matters.<br /><em style={{ color: 'var(--sky)', fontStyle: 'normal' }}>Act with confidence.</em></h1><p>Fantom turns a thousand noisy signals into one clear view of the exposure your business can absorb.</p></div><div style={{ color: 'rgba(245,239,235,.46)', fontSize: 11 }}>© 2026 Fantom AI · Demo environment</div></div><div className="auth-form-wrap"><div className="auth-box"><Link href="/" className="crumb"><ArrowLeft size={14} /> Back to fantom.ai</Link><div className="eyebrow" style={{ marginTop: 46 }}>Fantom AI</div><h2>{config[0]}</h2><p>{config[1]}</p>{submitted ? <div className="panel panel-pad" style={{ background: 'var(--mint)' }}><Check color="var(--teal)" size={25} /><h3 style={{ marginTop: 14 }}>{kind === 'forgot' ? 'Check your inbox' : 'You are all set'}</h3><p className="subhead">{kind === 'github' ? 'GitHub is connected. Your first scan is ready to start.' : kind === 'forgot' ? 'If that email has an account, a reset link was sent (check the backend log in dev - no SMTP configured).' : 'This is a demo flow. Continue to see the workspace.'}</p><Link href={kind === 'github' ? '/live-scan' : '/dashboard'} className="btn primary" style={{ marginTop: 16 }}>{kind === 'github' ? 'Start first scan' : 'Open workspace'} <ArrowRight size={15} /></Link></div> : <form onSubmit={onSubmit}><div className="field">{kind !== 'github' && <><label>Work email</label><input name="email" data-testid="input-auth-email" required type="email" placeholder="you@company.com" /></>}{kind !== 'forgot' && kind !== 'github' && <><label>Password</label><input name="password" data-testid="input-auth-password" required type="password" placeholder="At least 8 characters" minLength={8} /></>}{kind === 'signup' && <><label>Workspace name</label><input name="workspace" required placeholder="Acme security" /></>}{kind === 'github' && <div className="panel panel-pad" style={{ background: 'rgba(200,217,230,.28)', marginBottom: 16 }}><Github size={19} /><p className="subhead" style={{ marginTop: 10 }}>Read-only repository metadata, code scanning, and commit history. Fantom never writes to your repositories.</p></div>}</div><Button testId="button-auth-submit" className="auth-submit">{kind === 'github' && <Github size={15} />}{busy ? 'Working…' : config[2]} <ArrowRight size={15} /></Button></form>}<div className="auth-foot">{kind === 'login' && <>New to Fantom? <Link href="/signup">Create a workspace</Link> · <Link href="/forgot-password">Forgot password?</Link></>}{kind === 'signup' && <>Already have an account? <Link href="/login">Sign in</Link></>}{kind === 'forgot' && <>Remembered it? <Link href="/login">Back to sign in</Link></>}{kind === 'github' && <>Need an account? <Link href="/signup">Create one</Link></>}</div></div></div></div>;
}

function Landing() {
  return <div className="landing"><nav className="landing-nav"><Link href="/"><FantomLogo /></Link><div className="landing-links"><a href="#platform">Platform</a><a href="#workflow">How it works</a><a href="#trust">Trust</a><Link href="/login">Sign in</Link><Link href="/signup" className="btn primary small">Request access <ArrowRight size={13} /></Link></div></nav><section className="hero"><div><div className="eyebrow">Cyber risk, with a point of view.</div><h1>Stop chasing noise.<br /><em>Start seeing risk.</em></h1><p className="hero-copy">Fantom continuously turns your GitHub footprint, threat intelligence, and business context into one calm, defensible picture of cyber risk.</p><div className="hero-actions"><Link href="/signup" className="btn primary">See your risk clearly <ArrowRight size={15} /></Link><a href="#platform" className="btn ghost">Explore the platform</a></div><div className="hero-note"><span style={{ color: 'var(--teal)' }}>●</span> Read-only by design · Built for security leaders</div></div><div className="hero-visual"><div className="visual-top"><span>FANTOM / COMMAND CENTER</span><span><span style={{ color: '#B8D9C9' }}>●</span> MONITORING</span></div><div className="visual-grid"><div className="visual-card wide"><small>ORGANIZATION RISK INDEX</small><strong>42 <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: '#B8D9C9', letterSpacing: 0 }}>↓ 8 this week</span></strong><div className="mini-bars">{[45,62,52,76,60,84,70,91,66,78,88,74].map((h, i) => <i style={{ height: `${h}%` }} key={i} />)}</div></div><div className="visual-card"><small>OPEN FINDINGS</small><strong>47</strong><span style={{ color: '#B8D9C9', fontSize: 11 }}>3 high priority</span></div><div className="visual-card"><small>THREAT SIGNALS</small><strong>08</strong><span style={{ color: 'rgba(245,239,235,.55)', fontSize: 11 }}>2 need review</span></div></div></div></section><section className="landing-section" id="platform"><div className="landing-section-head"><div className="eyebrow">A clearer operating system for risk</div><h2 style={{ marginTop: 11, fontSize: 38 }}>The context your scanners leave out.</h2><p>Fantom sits above your existing security tools and makes their output useful. Not more alerts — a better decision surface.</p></div><div className="feature-grid"><div className="panel feature accent"><div className="feature-icon"><Radar size={18} /></div><h3>Quantify what is exposed</h3><p>Rank vulnerabilities by real reachability, exploit likelihood, and the business systems they touch.</p></div><div className="panel feature"><div className="feature-icon"><Globe2 size={18} /></div><h3>Enrich with the outside world</h3><p>Know when a theoretical issue becomes an active campaign with live threat signals.</p></div><div className="panel feature"><div className="feature-icon"><Target size={18} /></div><h3>Move the right fix first</h3><p>Give engineering a prioritized queue and leadership a language they can act on.</p></div></div></section><section className="landing-section tinted" id="workflow"><div className="tinted-inner"><div className="landing-section-head"><div className="eyebrow">From signal to decision</div><h2 style={{ marginTop: 11, fontSize: 38 }}>Four moves. One shared truth.</h2></div><div className="workflow">{[['01', 'Connect', 'Read-only GitHub access gives Fantom the context behind every change.'], ['02', 'Discover', 'Scan code, dependencies, infrastructure, and exposed paths continuously.'], ['03', 'Quantify', 'Join threat intelligence to business criticality and customer impact.'], ['04', 'Prioritize', 'Send teams toward the fix that changes your risk — not just your count.']].map(([n,t,d]) => <div className="step" key={n}><div className="step-num">{n}</div><h3>{t}</h3><p>{d}</p></div>)}</div></div></section><section className="landing-section" id="trust"><div className="grid grid-2" style={{ alignItems: 'center' }}><div><div className="eyebrow">Designed for trust</div><h2 style={{ marginTop: 11, fontSize: 38 }}>Quiet confidence for loud environments.</h2><p className="subhead" style={{ maxWidth: 490, marginTop: 17 }}>Your team already has tools that find problems. Fantom helps you explain which ones matter, why they matter now, and what happens if you wait.</p><div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 25 }}><Badge tone="info"><LockKeyhole size={12} /> Read-only access</Badge><Badge tone="info"><ShieldCheck size={12} /> Evidence-backed scoring</Badge><Badge tone="info"><Building2 size={12} /> Business-aware</Badge></div></div><div className="panel panel-pad" style={{ background: 'var(--mint)', minHeight: 240 }}><div className="eyebrow">The weekly conversation</div><h3 style={{ fontSize: 25, marginTop: 18, maxWidth: 360 }}>“We reduced risk by 8 points — and here is exactly how.”</h3><p className="subhead" style={{ marginTop: 15 }}>Every score has a traceable story your board, engineering team, and customers can trust.</p></div></div></section><section className="landing-section" style={{ paddingTop: 20 }}><div className="cta-band"><div><div className="eyebrow" style={{ color: 'var(--sky)' }}>Start with your real footprint</div><h2 style={{ color: 'var(--paper)', fontSize: 35, marginTop: 11 }}>Make the next security decision easier.</h2><p>Connect one repository. Get a point of view in minutes.</p></div><Link href="/signup" className="btn">Request access <ArrowRight size={15} /></Link></div></section><footer className="footer"><span>© 2026 fantom.ai</span><span>Continuous cyber risk quantification · Built for security leaders</span></footer></div>;
}

function ComingPage({ title, icon: Icon }: { title: string; icon: typeof Bot }) {
  return <div className="page"><SectionHead eyebrow="Future capability" title={title} sub="A more autonomous way to turn security context into action is on the way." /><div className="panel coming"><Icon size={33} /><h3>Coming soon</h3><p>We are shaping this capability with security teams who care about signal quality.</p><Badge tone="medium">On the roadmap</Badge></div></div>;
}

const PUBLIC_ROUTES = ['/', '/login', '/signup', '/forgot-password'];

function AppRouter({ toast }: PageProps) {
  const [location, setLocation] = useLocation();
  useEffect(() => {
    const title = location === '/' ? 'fantom.ai — See risk clearly' : `fantom.ai — ${location.slice(1).replaceAll('-', ' ')}`;
    document.title = title;
    const description = document.querySelector('meta[name="description"]') ?? document.createElement('meta');
    description.setAttribute('name', 'description');
    description.setAttribute('content', 'Fantom continuously turns vulnerability data into confident cyber risk decisions.');
    if (!description.parentNode) document.head.appendChild(description);
  }, [location]);
  useEffect(() => {
    if (!PUBLIC_ROUTES.includes(location) && !api.isLoggedIn()) setLocation('/login');
  }, [location]);
  if (location === '/') return <Landing />;
  if (location === '/login') return <AuthPage kind="login" toast={toast} />;
  if (location === '/signup') return <AuthPage kind="signup" toast={toast} />;
  if (location === '/forgot-password') return <AuthPage kind="forgot" toast={toast} />;
  if (location === '/github-connect') return <AuthPage kind="github" toast={toast} />;
  if (!api.isLoggedIn()) return null;
  let page: ReactNode;
  if (location === '/dashboard') page = <Dashboard toast={toast} />;
  else if (location === '/repositories') page = <Repositories toast={toast} />;
  else if (location === '/findings') page = <Findings toast={toast} />;
  else if (location === '/risk-score') page = <RiskScore toast={toast} />;
  else if (location === '/threat-intelligence') page = <ThreatIntel toast={toast} />;
  else if (location === '/business-impact') page = <BusinessImpact toast={toast} />;
  else if (location === '/live-scan') page = <LiveScan toast={toast} />;
  else if (location === '/settings/integrations') page = <SettingsIntegrations toast={toast} />;
  else if (location.startsWith('/vulnerabilities/')) page = <Vulnerability toast={toast} />;
  else if (location === '/analytics') page = <Analytics toast={toast} />;
  else if (location === '/reports') page = <Reports toast={toast} />;
  else if (location === '/settings') page = <Settings toast={toast} />;
  else if (location === '/help') page = <Help />;
  else if (location.includes('ai-repository-survey-agent')) page = <ComingPage title="AI Repository Survey Agent" icon={Bot} />;
  else if (location.includes('recruiter-agent')) page = <ComingPage title="Recruiter Agent" icon={UserRound} />;
  else if (location.includes('llm-reachability')) page = <ComingPage title="LLM Reachability Analysis" icon={Network} />;
  else if (location.includes('ai-fix-suggestions')) page = <ComingPage title="AI Fix Suggestions" icon={Sparkles} />;
  else page = <div className="page"><SectionHead eyebrow="Unknown route" title="Page not found" sub="The page you are looking for does not exist in this workspace." action={<Link href="/dashboard" className="btn primary">Return to dashboard</Link>} /></div>;
  return <Shell toast={toast}>{page}</Shell>;
}

function BackendStatusBanner() {
  const [down, setDown] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const check = () => api.health().then(() => { if (!cancelled) setDown(false); })
      .catch(() => { if (!cancelled) setDown(true); });
    check();
    const id = window.setInterval(check, 15_000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  if (!down) return null;
  return <div style={{ position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100, background: 'var(--danger)', color: '#fff', textAlign: 'center', padding: '8px 12px', fontSize: 12.5 }}>
    Can't reach the backend at {api.API_BASE}. Check it's running - the app will reconnect automatically.
  </div>;
}

function App() {
  const [toastMessage, setToastMessage] = useState('');
  const toast = (message: string) => { setToastMessage(message); window.setTimeout(() => setToastMessage(''), 2600); };
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  return <QueryClientProvider client={queryClient}><BackendStatusBanner /><WouterRouter base={base}><AuthProvider onSessionExpired={() => { window.location.href = `${base}/login`; }}><AppRouter toast={toast} /></AuthProvider></WouterRouter>{toastMessage && <div className="toast-local" data-testid="status-toast"><Check size={14} style={{ verticalAlign: 'middle', marginRight: 8, color: 'var(--sky)' }} />{toastMessage}</div>}</QueryClientProvider>;
}

export default App;