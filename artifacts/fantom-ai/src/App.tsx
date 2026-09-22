import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, Router as WouterRouter, useLocation, useParams } from 'wouter';
import {
  Activity, AlertTriangle, ArrowLeft, ArrowRight, BarChart3, Bell, BookOpen,
  Bot, Building2, Calculator, Check, ChevronDown, ChevronRight, CircleHelp,
  Clock3, Code2, Download, FileBarChart, FileText, Filter, Github, Globe2,
  HeartPulse, Hexagon, Info, KeyRound, Layers3, LifeBuoy, LineChart, ListFilter,
  LockKeyhole, LogOut, Menu, MessageSquare, Network, Play, Plus, Radar, RefreshCw,
  Search, Server, Settings2, ShieldCheck, Sparkles, Target, Terminal, TrendingDown,
  TrendingUp, UserRound, X, Zap
} from 'lucide-react';
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart as ReLineChart,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts';
import * as api from '@/lib/api';

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

const findings = [
  { id: 'FNT-4821', name: 'Hardcoded AWS access key', repo: 'atlas-api', severity: 'high', score: '9.1', age: '2h ago', owner: 'Platform', file: 'src/config/aws.ts', cve: 'CWE-798' },
  { id: 'FNT-4819', name: 'Prototype pollution in lodash', repo: 'checkout-web', severity: 'high', score: '8.7', age: '5h ago', owner: 'Commerce', file: 'package-lock.json', cve: 'CVE-2021-23337' },
  { id: 'FNT-4816', name: 'Missing authorization check', repo: 'partner-portal', severity: 'medium', score: '6.4', age: '1d ago', owner: 'Growth', file: 'api/routes/export.ts', cve: 'CWE-862' },
  { id: 'FNT-4808', name: 'Outdated OpenSSL dependency', repo: 'edge-gateway', severity: 'medium', score: '5.9', age: '1d ago', owner: 'Infrastructure', file: 'Dockerfile', cve: 'CVE-2024-0727' },
  { id: 'FNT-4799', name: 'Over-permissive S3 bucket', repo: 'data-pipeline', severity: 'low', score: '3.2', age: '3d ago', owner: 'Data', file: 'terraform/storage.tf', cve: 'CWE-732' },
  { id: 'FNT-4787', name: 'Verbose error response', repo: 'identity-service', severity: 'low', score: '2.7', age: '4d ago', owner: 'Platform', file: 'src/middleware/errors.ts', cve: 'CWE-209' },
];
const repos = [
  { name: 'atlas-api', owner: 'acme-platform', lang: 'TypeScript', findings: 14, risk: 81, scanned: '12 min ago', icon: 'AA' },
  { name: 'checkout-web', owner: 'acme-commerce', lang: 'React', findings: 9, risk: 67, scanned: '18 min ago', icon: 'CW' },
  { name: 'edge-gateway', owner: 'acme-infra', lang: 'Go', findings: 6, risk: 44, scanned: '23 min ago', icon: 'EG' },
  { name: 'partner-portal', owner: 'acme-growth', lang: 'Python', findings: 4, risk: 31, scanned: '31 min ago', icon: 'PP' },
  { name: 'data-pipeline', owner: 'acme-data', lang: 'Terraform', findings: 3, risk: 26, scanned: '42 min ago', icon: 'DP' },
  { name: 'identity-service', owner: 'acme-platform', lang: 'Kotlin', findings: 2, risk: 18, scanned: '1h ago', icon: 'IS' },
];
const areaData = [
  { name: 'Mon', risk: 59, resolved: 8 }, { name: 'Tue', risk: 57, resolved: 12 },
  { name: 'Wed', risk: 53, resolved: 11 }, { name: 'Thu', risk: 49, resolved: 17 },
  { name: 'Fri', risk: 46, resolved: 13 }, { name: 'Sat', risk: 44, resolved: 9 },
  { name: 'Sun', risk: 42, resolved: 15 },
];
const severityData = [{ name: 'Critical', value: 3, color: '#B65D64' }, { name: 'High', value: 12, color: '#D99386' }, { name: 'Medium', value: 24, color: '#567C8D' }, { name: 'Low', value: 18, color: '#C8D9E6' }];

function Logo() {
  return <div className="brand"><span className="brand-mark">ƒ</span><span>fantom<span style={{ color: 'var(--teal)' }}>.</span>ai</span></div>;
}

function Shell({ children, toast }: { children: ReactNode; toast: ToastFn }) {
  const [location, setLocation] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [user, setUser] = useState<{ name: string; email: string; role: string } | null>(null);
  const current = navGroups.flatMap((g) => g.items).find((x) => x[1] === location)?.[0] ?? (location === '/dashboard' ? 'Dashboard' : 'Workspace');

  useEffect(() => {
    api.me().then((m) => setUser({
      name: m.user.name, email: m.user.email,
      role: m.memberships.find((x) => x.org_id === api.getOrgId())?.role ?? m.memberships[0]?.role ?? 'member',
    })).catch(() => {});
  }, []);

  function logOut() {
    api.clearSession();
    toast('Signed out.');
    setLocation('/login');
  }

  const initials = user ? user.name.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase() : '…';

  return <div className="app-shell">
    <aside className="sidebar">
      <Logo />
      {navGroups.map((group) => <div key={group.label} style={{ marginBottom: 27 }}>
        <div className="side-label">{group.label}</div>
        <nav className="side-nav">{group.items.map(([label, href, Icon]) => <Link data-testid={`link-${label.toLowerCase().replaceAll(' ', '-')}`} className={`side-link ${location === href ? 'active' : ''}`} href={href} key={href}><Icon /><span>{label}</span></Link>)}</nav>
      </div>)}
      <div className="sidebar-spacer" />
      <Link href="/github-connect" className="side-link"><Github /><span>Connect GitHub</span></Link>
      <div className="user-mini"><span className="avatar">{initials}</span><span><strong style={{ display: 'block', color: 'var(--paper)' }}>{user?.name ?? 'Loading…'}</strong><small style={{ color: 'rgba(245,239,235,.5)' }}>{user?.role ?? ''}</small></span><button className="icon-button" onClick={logOut} aria-label="Log out" title="Log out" style={{ marginLeft: 'auto', background: 'transparent', color: 'inherit' }}><LogOut size={14} /></button></div>
    </aside>
    <div className="mobile-top"><Logo /><button className="icon-button" style={{ background: 'transparent', color: 'var(--sky)', borderColor: 'rgba(200,217,230,.2)' }} onClick={() => setMobileOpen((x) => !x)} aria-label="Open navigation"><Menu size={18} /></button></div>
    {mobileOpen && <nav className="mobile-menu">{navGroups.flatMap((g) => g.items).map(([label, href]) => <Link onClick={() => setMobileOpen(false)} className={location === href ? 'active' : ''} href={href} key={href}>{label}</Link>)}</nav>}
    <main className="main">
      <header className="topbar"><div className="crumb"><span>Workspace</span><ChevronRight size={13} /><strong>{current}</strong></div><div className="top-actions"><span className="badge info">DEMO ENVIRONMENT</span><button className="icon-button" data-testid="button-notifications" onClick={() => toast('No new alerts. Your workspace is up to date.')} aria-label="Notifications"><Bell size={16} /></button><button className="icon-button" data-testid="button-help" onClick={() => toast('Support is online — opening help center soon.')} aria-label="Help"><CircleHelp size={16} /></button></div></header>
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
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    Promise.all([api.orgRisk(), api.listProjects(), api.listFindings({ state: 'open', sort: 'score', page_size: 4 })])
      .then(([r, p, f]) => { setRisk(r); setProjects(p); setRecentFindings(f.items); })
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
    <div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Risk over time</h3><span>Demo trend <ChevronDown size={13} style={{ verticalAlign: 'middle' }} /></span></div><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={areaData}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#567C8D" stopOpacity=".3" /><stop offset="100%" stopColor="#567C8D" stopOpacity="0" /></linearGradient></defs><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><YAxis domain={[35,65]} axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, border: '1px solid #C8D9E6', fontSize: 11 }} /><Area type="monotone" dataKey="risk" stroke="#567C8D" strokeWidth={2.5} fill="url(#riskFill)" /></AreaChart></ResponsiveContainer></div></div>
      <div className="panel panel-pad"><div className="section-title"><h3>Risk by repository</h3><Link href="/repositories"><span>View all <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div>{repoRisk.length === 0 && <p className="subhead">No repositories connected yet.</p>}{repoRisk.slice(0, 4).map((r: any) => <div key={r.project_id} style={{ margin: '19px 0' }}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 7 }}><strong>{r.repo}</strong><span style={{ color: (r.avg_score ?? 0) > 70 ? 'var(--danger)' : 'var(--teal)', fontFamily: 'var(--font-mono)' }}>{r.avg_score ?? '—'}</span></div><div className="progress"><i style={{ width: `${r.avg_score ?? 0}%`, background: (r.avg_score ?? 0) > 70 ? 'var(--danger)' : undefined }} /></div></div>)}</div></div>
    <div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Needs your attention</h3><Link href="/findings"><span>Open findings <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div><div className="activity">{recentFindings.length === 0 && <p className="subhead">No open findings.</p>}{recentFindings.map((f) => <Link href="/findings" className="activity-row" key={f.id}><span className={`dot ${f.tier === 'Critical' || f.tier === 'High' ? 'danger' : ''}`} /><div><p><strong>{f.title}</strong> in {f.repo}</p><small>{f.tier ?? 'Unscored'} · {f.package ?? f.file ?? f.cve ?? ''}</small></div><Badge tone={f.tier === 'Critical' ? 'high' : f.tier === 'High' ? 'high' : f.tier === 'Medium' ? 'medium' : 'low'}>{f.tier ?? '—'}</Badge></Link>)}</div></div><div className="panel panel-pad"><div className="section-title"><h3>Connected repositories</h3><Link href="/repositories"><span>Manage <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></span></Link></div><div className="activity">{projects.length === 0 && <p className="subhead">Connect your first repository to start scanning.</p>}{projects.slice(0, 4).map((p) => <div className="activity-row" key={p.id}><span className="dot" /><div><p><strong>{p.repo}</strong></p><small>{p.findings_open} open findings · {p.state}</small></div></div>)}</div></div></div>
  </div>;
}

function Repositories({ toast }: PageProps) {
  const [query, setQuery] = useState('');
  const [projects, setProjects] = useState<api.ProjectOut[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api.listProjects().then(setProjects)
      .catch((err) => toast(err instanceof Error ? err.message : 'Failed to load repositories'))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  async function addRepository() {
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
  return <div className="page"><SectionHead eyebrow="Asset inventory" title="Repositories" sub={`${projects.length} connected codebase${projects.length === 1 ? '' : 's'}, continuously observed across your attack surface.`} action={<Button onClick={addRepository}><Plus size={15} /> Add repository</Button>} /><div className="filterbar"><div className="search"><Search /><input data-testid="input-repository-search" placeholder="Search repositories" value={query} onChange={(e) => setQuery(e.target.value)} /></div><Button variant="ghost" onClick={load}><RefreshCw size={14} /> Refresh</Button></div><div className="grid grid-3">{filtered.map((r) => <motion.div layout key={r.id} className="panel repo-card"><div className="repo-title"><span className="repo-icon"><Code2 size={16} /></span><span>{r.repo}<small style={{ display: 'block', color: 'var(--muted)', fontWeight: 400, fontSize: 11, marginTop: 2 }}>{r.branch} · {r.state}</small></span></div><div className="repo-meta"><span><Github size={13} /> {r.context_complete ? 'Priced' : 'Not priced'}</span><span><AlertTriangle size={13} /> {r.findings_open} findings</span></div><div style={{ marginTop: 19 }}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)', marginBottom: 7 }}><span>Exposure</span><strong style={{ color: 'var(--teal)' }}>{r.exposure != null ? `$${(r.exposure / 1000).toFixed(0)}k` : '—'}</strong></div></div><div className="repo-foot"><span style={{ color: 'var(--muted)', fontSize: 11 }}>{r.complexity_tier ?? 'Not yet scanned'}</span><Button variant="ghost" className="small" onClick={() => scanNow(r)}>Scan now</Button></div></motion.div>)}</div>{!loading && filtered.length === 0 && <div className="panel coming"><Search size={25} /><h3>No repositories found</h3><p>{projects.length === 0 ? 'Connect your first repository to get started.' : 'Try a different search term.'}</p></div>}</div>;
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
  return <><div className="drawer-backdrop" onClick={close} /><aside className="drawer"><div className="drawer-head"><div><div className="eyebrow">{f.cve ?? f.scanner} · Detected {new Date(f.first_seen_at).toLocaleDateString()}</div><h2 style={{ marginTop: 9, fontSize: 27 }}>{f.title}</h2><div style={{ marginTop: 11, display: 'flex', gap: 7 }}><Badge tone={TIER_TONE[f.tier ?? ''] ?? 'info'}>{f.tier ?? 'Unscored'} severity</Badge><Badge tone="info">{f.state}</Badge>{f.kev && <Badge tone="high">CISA KEV</Badge>}</div></div><button className="icon-button" onClick={close} aria-label="Close finding detail"><X size={16} /></button></div><div className="drawer-section"><h4>Signals</h4><p className="subhead">CVSS {f.cvss ?? '—'} · EPSS {f.epss != null ? `${(f.epss * 100).toFixed(1)}%` : '—'} · Contextual score {f.context_score ?? '—'}/100.{f.annual_loss != null && <> Estimated annual loss <strong style={{ color: 'var(--ink)' }}>${f.annual_loss.toLocaleString()}</strong>.</>}</p></div><div className="drawer-section"><h4>Location</h4><div className="code-diff"><span className="dim">{f.file ?? f.package ?? 'unknown location'}</span></div></div><div style={{ display: 'flex', gap: 9, marginTop: 22 }}><Button onClick={() => setState('fixed')}><Check size={15} /> Mark fixed</Button><Button variant="ghost" onClick={() => setState('accepted')}>Accept risk</Button><Button variant="ghost" onClick={() => setState('false_positive')}>False positive</Button></div></aside></>;
}

function RiskScore() {
  return <div className="page"><SectionHead eyebrow="Decision signal" title="Risk score" sub="One measured signal for the exposure your organization can absorb today." action={<Button variant="ghost"><Download size={15} /> Download brief</Button>} /><div className="grid grid-2"><div className="panel panel-pad risk-panel"><div><div className="eyebrow">Current posture</div><h2 style={{ marginTop: 10 }}>Controlled, with<br />two sharp edges.</h2><p className="subhead">Your score improved 8 points over the last 7 days, driven by faster remediation in checkout-web.</p><div className="legend" style={{ marginTop: 24 }}><div className="legend-row"><i className="dot" /> <span>Current risk <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>42</strong></span></div><div className="legend-row"><i className="dot sky" /> <span>Peer benchmark <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>37</strong></span></div><div className="legend-row"><i className="dot danger" /> <span>Board threshold <strong style={{ color: 'var(--ink)', marginLeft: 8 }}>65</strong></span></div></div></div><RiskRing value={42} /></div><div className="panel panel-pad"><div className="section-title"><h3>Score composition</h3><span>Updated 12 min ago</span></div><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={[{ n: 'Exposure', v: 32 }, { n: 'Exploitability', v: 47 }, { n: 'Reachability', v: 21 }, { n: 'Criticality', v: 58 }]} layout="vertical" margin={{ left: 10, right: 15 }}><CartesianGrid horizontal={false} stroke="rgba(47,65,86,.08)" /><XAxis type="number" domain={[0, 100]} hide /><YAxis dataKey="n" type="category" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} width={85} /><Bar dataKey="v" fill="#567C8D" radius={[0, 5, 5, 0]} barSize={19} /></BarChart></ResponsiveContainer></div></div></div><div className="grid grid-3" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="eyebrow">Top driver</div><h3 style={{ marginTop: 11 }}>Internet exposure</h3><p className="subhead">14 findings sit on internet-facing services, adding 11 points to your score.</p></div><div className="panel panel-pad"><div className="eyebrow">Fastest win</div><h3 style={{ marginTop: 11 }}>Close stale secrets</h3><p className="subhead">Three credential findings can remove an estimated 7 points this week.</p></div><div className="panel panel-pad"><div className="eyebrow">Confidence</div><h3 style={{ marginTop: 11 }}>High · 91%</h3><p className="subhead">Calculated from current repository, threat, and business context.</p></div></div></div>;
}

function ThreatIntel() {
  const intel = [['CISA KEV', '2 findings match known exploited vulnerabilities', 'high'], ['EPSS', 'OpenSSL issue crossed the 0.41 probability threshold', 'medium'], ['Dark web signals', 'No new mentions for your monitored domains', 'low']];
  return <div className="page"><SectionHead eyebrow="External context" title="Threat intelligence" sub="Turn global signals into local urgency. Fantom enriches each finding with what attackers are doing now." action={<Button variant="ghost"><RefreshCw size={15} /> Refresh signals</Button>} /><div className="grid grid-3">{intel.map(([source, desc, tone]) => <div className="panel panel-pad" key={source}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span className="eyebrow">{source}</span><Badge tone={tone}>{tone === 'low' ? 'Clear' : 'Watch'}</Badge></div><h3 style={{ marginTop: 22, lineHeight: 1.35 }}>{desc}</h3><div style={{ marginTop: 28, color: 'var(--muted)', fontSize: 11 }}>Signal updated 18 min ago <ArrowRight size={13} style={{ verticalAlign: 'middle', marginLeft: 5 }} /></div></div>)}</div><div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Threat signal activity</h3><span>Last 30 days</span></div><div className="chart-wrap tall"><ResponsiveContainer width="100%" height="100%"><ReLineChart data={areaData}><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /><Line type="monotone" dataKey="resolved" stroke="#567C8D" strokeWidth={2.5} dot={false} /></ReLineChart></ResponsiveContainer></div></div><div className="panel panel-pad"><div className="section-title"><h3>Active advisories</h3><Badge tone="info">3 monitored</Badge></div><div className="timeline"><div className="timeline-item"><h4>CVE-2024-0727 · OpenSSL</h4><p>Known exploitation reported by CISA. Affected in edge-gateway.</p></div><div className="timeline-item"><h4>CVE-2021-23337 · lodash</h4><p>Public proof of concept observed. Affected in checkout-web.</p></div><div className="timeline-item muted"><h4>No dark web exposure detected</h4><p>Monitored domains: acme.io, acme.dev</p></div></div></div></div></div>;
}

function BusinessImpact({ toast }: PageProps) {
  const [users, setUsers] = useState(42000); const [revenue, setRevenue] = useState(18); const [criticality, setCriticality] = useState(3);
  const exposure = Math.round((users * revenue * criticality) / 10000);
  /*
  return <div className="page"><SectionHead eyebrow="Translate risk" title="Business impact" sub="Make the cost of exposure legible to the people who fund the fix." action={<Button onClick={() => toast('Impact brief added to Reports.')}><FileText size={15} /> Add to report</Button>} /><div className="calculator"><div className="panel panel-pad"><div className="section-title"><h3>Exposure model</h3><Badge tone="info">Demo inputs</Badge></div><p className="subhead" style={{ marginBottom: 26 }}>Adjust the context to see how a material finding changes your potential business exposure.</p><div className="field"><label>Potentially affected users</label><input data-testid="input-affected-users" type="number" value={users} onChange={(e) => setUsers(Number(e.target.value))} /><small>Accounts or customers within the service boundary.</small></div><div className="field"><label>Average revenue at risk per user ($)</label><input data-testid="input-revenue" type="number" value={revenue} onChange={(e) => setRevenue(Number(e.target.value))} /></div><div className="field"><label>Service criticality</label><select data-testid="select-criticality" value={criticality} onChange={(e) => setCriticality(Number(e.target.value))}><option value="1">1 · Low</option><option value="2">2 · Moderate</option><option value="3">3 · Important</option><option value="4">4 · Business critical</option><option value="5">5 · Mission critical</option></select></div></div><div className="calc-output"><div><div className="eyebrow" style={{ color: 'var(--sky)' }}>Estimated exposure</div><div className="calc-number">${exposure.toLocaleString()}k</div><p>Modeled annualized impact if the vulnerable path is exploited without mitigation.</p></div><div><hr /><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 18 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Decision confidence</span><strong style={{ color: 'var(--sky)' }}>Medium</strong></div><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 12 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Recommended action</span><strong>Fix within 7 days</strong></div></div></div></div></div><div className="grid grid-3" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="eyebrow">Customer trust</div><h3 style={{ marginTop: 11 }}>Protect renewal confidence</h3><p className="subhead">A customer-facing service changes the conversation from technical severity to retained revenue.</p></div><div className="panel panel-pad"><div className="eyebrow">Operational cost</div><h3 style={{ marginTop: 11 }}>$38.4k avoided</h3><p className="subhead">Estimated response cost avoided when remediation happens before exploitation.</p></div><div className="panel panel-pad"><div className="eyebrow">Board language</div><h3 style={{ marginTop: 11 }}>Lead with exposure</h3><p className="subhead">Add the modeled range to your weekly risk brief for a shared decision frame.</p></div></div></div>;
  */
  return <div className="page"><SectionHead eyebrow="Translate risk" title="Business impact" sub="Make the cost of exposure legible to the people who fund the fix." action={<Button onClick={() => toast('Impact brief added to Reports.')}><FileText size={15} /> Add to report</Button>} /><div className="calculator"><div className="panel panel-pad"><div className="section-title"><h3>Exposure model</h3><Badge tone="info">Demo inputs</Badge></div><p className="subhead">Adjust the context to see how a material finding changes your potential business exposure.</p><div className="field"><label>Potentially affected users</label><input type="number" value={users} onChange={(e) => setUsers(Number(e.target.value))} /></div><div className="field"><label>Average revenue at risk per user ($)</label><input type="number" value={revenue} onChange={(e) => setRevenue(Number(e.target.value))} /></div><div className="field"><label>Service criticality</label><select value={criticality} onChange={(e) => setCriticality(Number(e.target.value))}><option value="1">1 · Low</option><option value="2">2 · Moderate</option><option value="3">3 · Important</option><option value="4">4 · Business critical</option><option value="5">5 · Mission critical</option></select></div></div><div className="calc-output"><div><div className="eyebrow" style={{ color: 'var(--sky)' }}>Estimated exposure</div><div className="calc-number">${exposure.toLocaleString()}k</div><p>Modeled annualized impact if the vulnerable path is exploited without mitigation.</p></div><div><hr /><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 18 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Decision confidence</span><strong style={{ color: 'var(--sky)' }}>Medium</strong></div><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginTop: 12 }}><span style={{ color: 'rgba(245,239,235,.6)' }}>Recommended action</span><strong>Fix within 7 days</strong></div></div></div></div></div>;
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

function Vulnerability() {
  const { id } = useParams(); const [tab, setTab] = useState('Overview');
  return <div className="page"><Link href="/findings" className="crumb" style={{ marginBottom: 22, display: 'inline-flex' }}><ArrowLeft size={14} /> Back to findings</Link><SectionHead eyebrow={id ?? 'FNT-4821'} title="Hardcoded AWS access key" sub="A secret was committed to a repository and is reachable from an internet-facing service." action={<Badge tone="high">High · 9.1</Badge>} /><div className="tabs">{['Overview', 'Evidence', 'Attack path', 'Activity'].map((t) => <button className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)} key={t}>{t}</button>)}</div>{tab === 'Overview' && <div className="grid grid-2"><div className="panel panel-pad"><div className="section-title"><h3>Finding context</h3><Badge tone="info">Open</Badge></div><div className="grid grid-2" style={{ marginTop: 20 }}><div><small style={{ color: 'var(--muted)' }}>Repository</small><strong style={{ display: 'block', marginTop: 5 }}>atlas-api</strong></div><div><small style={{ color: 'var(--muted)' }}>Detected</small><strong style={{ display: 'block', marginTop: 5 }}>2 hours ago</strong></div><div><small style={{ color: 'var(--muted)' }}>CWE</small><strong style={{ display: 'block', marginTop: 5 }}>CWE-798</strong></div><div><small style={{ color: 'var(--muted)' }}>Business owner</small><strong style={{ display: 'block', marginTop: 5 }}>Platform</strong></div></div><div className="drawer-section" style={{ marginTop: 23 }}><h4>Impact narrative</h4><p className="subhead">The credential can read from customer data services. It is exposed in a branch deployed to production infrastructure.</p></div></div><div className="panel panel-pad"><div className="section-title"><h3>Recommended fix</h3><span>3 steps</span></div><div className="timeline"><div className="timeline-item"><h4>Rotate key immediately</h4><p>Revoke the existing key from AWS IAM.</p></div><div className="timeline-item"><h4>Move value to secrets manager</h4><p>Use an injected environment variable at runtime.</p></div><div className="timeline-item muted"><h4>Rewrite repository history</h4><p>Remove the key from all reachable commits.</p></div></div></div></div>}{tab === 'Evidence' && <div className="panel panel-pad"><h3>Diff preview</h3><p className="subhead" style={{ marginBottom: 18 }}>The exact evidence that triggered this finding.</p><div className="code-diff"><span className="dim">src/config/aws.ts</span><br /><span className="remove">- const accessKey = "AKIA••••••••••••";</span><br /><span className="remove">- const secret = "••••••••••••••••";</span><br /><span className="add">+ const accessKey = process.env.AWS_ACCESS_KEY;</span><br /><span className="add">+ const secret = process.env.AWS_SECRET;</span></div></div>}{tab === 'Attack path' && <div className="panel panel-pad"><h3>Reachability graph</h3><p className="subhead">From the public edge to the affected resource.</p><div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, padding: '60px 10px', flexWrap: 'wrap' }}>{['Internet', '→', 'atlas-api', '→', 'AWS IAM key', '→', 'Customer data'].map((x, i) => x === '→' ? <ArrowRight key={i} size={17} color="var(--teal)" /> : <span key={i} className="badge info" style={{ padding: '10px 13px' }}>{x}</span>)}</div></div>}{tab === 'Activity' && <div className="panel panel-pad"><div className="timeline"><div className="timeline-item"><h4>Finding enriched with business impact</h4><p>Fantom · Today, 09:41</p></div><div className="timeline-item"><h4>Assigned to Platform</h4><p>Sarah Chen · Today, 09:30</p></div><div className="timeline-item muted"><h4>Finding detected</h4><p>Scanner · Today, 07:16</p></div></div></div>}</div>;
}

function Analytics() {
  return <div className="page"><SectionHead eyebrow="Trends & patterns" title="Analytics" sub="Measure how your security program is changing, not just what it found." action={<Button variant="ghost"><Download size={15} /> Export data</Button>} /><div className="grid grid-4"><Kpi icon={TrendingDown} label="Mean time to remediate" value="2.4d" note="↓ 18% this quarter" /><Kpi icon={TrendingUp} label="Findings resolved" value="83" note="↑ 14 vs last month" /><Kpi icon={Target} label="Coverage" value="96.8%" note="Across connected repos" /><Kpi icon={Zap} label="Fix efficiency" value="71%" note="Within SLA" /></div><div className="grid grid-2" style={{ marginTop: 18 }}><div className="panel panel-pad"><div className="section-title"><h3>Findings opened vs resolved</h3><span>Last 30 days</span></div><div className="chart-wrap tall"><ResponsiveContainer width="100%" height="100%"><AreaChart data={areaData}><CartesianGrid vertical={false} stroke="rgba(47,65,86,.08)" /><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#748697', fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /><Area type="monotone" dataKey="resolved" stroke="#2F4156" fill="#C8D9E6" fillOpacity=".55" /><Area type="monotone" dataKey="risk" stroke="#567C8D" fill="none" /></AreaChart></ResponsiveContainer></div></div><div className="panel panel-pad"><div className="section-title"><h3>Severity distribution</h3><span>47 open</span></div><div className="chart-wrap tall"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severityData} dataKey="value" innerRadius={70} outerRadius={100} paddingAngle={3}>{severityData.map((x) => <Cell key={x.name} fill={x.color} />)}</Pie><Tooltip contentStyle={{ borderRadius: 10, fontSize: 11 }} /></PieChart></ResponsiveContainer></div><div className="legend" style={{ flexDirection: 'row', flexWrap: 'wrap' }}>{severityData.map((x) => <div className="legend-row" key={x.name}><i className="dot" style={{ background: x.color }} /> {x.name} {x.value}</div>)}</div></div></div></div>;
}

function Reports({ toast }: PageProps) {
  const [reports, setReports] = useState([['Weekly risk brief', '15 September 2026', 'PDF'], ['Board exposure summary', '8 September 2026', 'PDF'], ['Remediation review', '1 September 2026', 'CSV']]);
  return <div className="page"><SectionHead eyebrow="Share the signal" title="Reports" sub="Clear, decision-ready views for the people who need confidence, not another dashboard." action={<Button onClick={() => { setReports((r) => [['New risk brief', 'Just now', 'PDF'], ...r]); toast('New report created.'); }}><Plus size={15} /> Create report</Button>} /><div className="grid grid-3">{reports.map(([name, date, type], i) => <div className="panel panel-pad" key={`${name}-${i}`}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span className="repo-icon"><FileText size={16} /></span><Badge tone="info">{type}</Badge></div><h3 style={{ marginTop: 25 }}>{name}</h3><p className="subhead">{date} · Demo workspace</p><div style={{ display: 'flex', gap: 8, marginTop: 24 }}><Button variant="soft" className="small" onClick={() => toast(`${name} downloaded.`)}><Download size={13} /> Download</Button><Button variant="ghost" className="small" onClick={() => toast('Share link copied.')}>Share</Button></div></div>)}</div><div className="panel coming" style={{ marginTop: 18 }}><FileBarChart size={28} /><h3>Executive workspace</h3><p>Automated board-ready narrative and scheduled delivery is coming soon.</p><Badge tone="medium">Coming soon</Badge></div></div>;
}

function Settings() {
  const [tab, setTab] = useState('Workspace'); const [saved, setSaved] = useState(false);
  return <div className="page"><SectionHead eyebrow="Workspace controls" title="Settings" sub="Tune how Fantom sees your organization and routes the signal." /><div className="grid grid-2"><div className="panel panel-pad" style={{ alignSelf: 'start' }}>{['Workspace', 'Integrations', 'Notifications', 'Team access'].map((t) => <button className={`tab ${tab === t ? 'active' : ''}`} style={{ display: 'block', width: '100%', textAlign: 'left', padding: '14px 0' }} onClick={() => setTab(t)} key={t}>{t}<ChevronRight size={14} style={{ float: 'right' }} /></button>)}</div><div className="panel panel-pad">{tab === 'Workspace' && <><h3>Workspace profile</h3><p className="subhead" style={{ marginBottom: 25 }}>This information appears on reports and decision briefs.</p><div className="field"><label>Workspace name</label><input defaultValue="Acme Platform Security" /></div><div className="field"><label>Primary domain</label><input defaultValue="acme.io" /></div><div className="field"><label>Risk threshold</label><select defaultValue="65"><option value="50">50 · Cautious</option><option value="65">65 · Balanced</option><option value="80">80 · Tolerant</option></select></div></>}{tab === 'Integrations' && <><h3>Connected integrations</h3><p className="subhead" style={{ marginBottom: 22 }}>Demo connections are shown for this workspace.</p>{[['GitHub Enterprise', 'Connected', Github], ['Slack alerts', 'Not connected', MessageSquare], ['AWS Security Hub', 'Coming soon', CloudIcon]].map(([n,s,I]) => <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderTop: '1px solid var(--line)', padding: '17px 0' }} key={n as string}><I size={18} color="var(--teal)" /><span style={{ flex: 1 }}><strong style={{ display: 'block', fontSize: 13 }}>{n as string}</strong><small style={{ color: 'var(--muted)' }}>{s as string}</small></span><Button variant="ghost" className="small">{s === 'Connected' ? 'Manage' : 'Connect'}</Button></div>)}</>}{tab === 'Notifications' && <><h3>Notification routing</h3><p className="subhead" style={{ marginBottom: 22 }}>Choose which events should interrupt your team.</p>{['High severity finding detected', 'Risk score crosses threshold', 'Weekly risk brief'].map((x) => <label key={x} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '15px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}><input type="checkbox" defaultChecked /> {x}</label>)}</>}{tab === 'Team access' && <><h3>People & access</h3><p className="subhead" style={{ marginBottom: 22 }}>Multi-tenancy and advanced roles are coming soon.</p><div className="coming" style={{ minHeight: 180 }}><UserRound size={25} /><h3>Team collaboration</h3><p>Invite workflows and role controls are on the way.</p><Badge tone="medium">Coming soon</Badge></div></>}<Button onClick={() => setSaved(true)}>Save changes</Button>{saved && <span style={{ color: 'var(--teal)', fontSize: 11, marginLeft: 12 }}><Check size={13} style={{ verticalAlign: 'middle' }} /> Saved</span>}</div></div></div>;
}
function CloudIcon() { return <Building2 size={18} />; }

function Help() {
  return <div className="page"><SectionHead eyebrow="We're here to help" title="Help center" sub="Find your way from first connection to an evidence-backed risk decision." action={<Button variant="soft"><MessageSquare size={15} /> Contact support</Button>} /><div className="grid grid-3">{[['Start with Fantom', 'Connect a repository, understand your first score, and invite your team.', BookOpen], ['Understand your score', 'How reachability, threat signals, and business criticality combine.', Radar], ['Remediate with confidence', 'Prioritize the fix that changes your actual exposure.', Check]].map(([t,d,I]) => <div className="panel panel-pad" key={t as string}><div className="feature-icon"><I size={18} /></div><h3>{t as string}</h3><p className="subhead">{d as string}</p><Link href="/help" className="eyebrow" style={{ display: 'block', marginTop: 20 }}>Read guide <ArrowRight size={13} style={{ verticalAlign: 'middle' }} /></Link></div>)}</div><div className="panel panel-pad" style={{ marginTop: 18 }}><div className="section-title"><h3>Popular questions</h3><span>Knowledge base</span></div>{['How does Fantom calculate risk score?', 'What does a high finding mean for my business?', 'How often are repositories scanned?', 'Can I connect a self-hosted GitHub instance?'].map((q) => <div key={q} style={{ display: 'flex', justifyContent: 'space-between', padding: '17px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}>{q}<ChevronRight size={15} color="var(--muted)" /></div>)}</div></div>;
}

function AuthPage({ kind, toast }: { kind: 'login' | 'signup' | 'forgot' | 'github'; toast: ToastFn }) {
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [, setLocation] = useLocation();
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
        toast('Signed in.');
        setLocation('/dashboard');
      } else if (kind === 'signup') {
        await api.register(email, password, email.split('@')[0], workspace || 'My Workspace');
        toast('Workspace created.');
        setLocation('/dashboard');
      } else if (kind === 'forgot') {
        await api.requestPasswordReset(email);
        setSubmitted(true);
      } else {
        setSubmitted(true);
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  return <div className="auth-page"><div className="auth-visual"><Logo /><div className="auth-copy"><div className="eyebrow" style={{ color: 'var(--sky)' }}>Continuous cyber risk quantification</div><h1>Know what matters.<br /><em style={{ color: 'var(--sky)', fontStyle: 'normal' }}>Act with confidence.</em></h1><p>Fantom turns a thousand noisy signals into one clear view of the exposure your business can absorb.</p></div><div style={{ color: 'rgba(245,239,235,.46)', fontSize: 11 }}>© 2026 Fantom AI · Demo environment</div></div><div className="auth-form-wrap"><div className="auth-box"><Link href="/" className="crumb"><ArrowLeft size={14} /> Back to fantom.ai</Link><div className="eyebrow" style={{ marginTop: 46 }}>Fantom AI</div><h2>{config[0]}</h2><p>{config[1]}</p>{submitted ? <div className="panel panel-pad" style={{ background: 'var(--mint)' }}><Check color="var(--teal)" size={25} /><h3 style={{ marginTop: 14 }}>{kind === 'forgot' ? 'Check your inbox' : 'You are all set'}</h3><p className="subhead">{kind === 'github' ? 'GitHub is connected. Your first scan is ready to start.' : kind === 'forgot' ? 'If that email has an account, a reset link was sent (check the backend log in dev - no SMTP configured).' : 'This is a demo flow. Continue to see the workspace.'}</p><Link href={kind === 'github' ? '/live-scan' : '/dashboard'} className="btn primary" style={{ marginTop: 16 }}>{kind === 'github' ? 'Start first scan' : 'Open workspace'} <ArrowRight size={15} /></Link></div> : <form onSubmit={onSubmit}><div className="field">{kind !== 'github' && <><label>Work email</label><input name="email" data-testid="input-auth-email" required type="email" placeholder="you@company.com" /></>}{kind !== 'forgot' && kind !== 'github' && <><label>Password</label><input name="password" data-testid="input-auth-password" required type="password" placeholder="At least 8 characters" minLength={8} /></>}{kind === 'signup' && <><label>Workspace name</label><input name="workspace" required placeholder="Acme security" /></>}{kind === 'github' && <div className="panel panel-pad" style={{ background: 'rgba(200,217,230,.28)', marginBottom: 16 }}><Github size={19} /><p className="subhead" style={{ marginTop: 10 }}>Read-only repository metadata, code scanning, and commit history. Fantom never writes to your repositories.</p></div>}</div><Button testId="button-auth-submit" className="auth-submit">{kind === 'github' && <Github size={15} />}{busy ? 'Working…' : config[2]} <ArrowRight size={15} /></Button></form>}<div className="auth-foot">{kind === 'login' && <>New to Fantom? <Link href="/signup">Create a workspace</Link> · <Link href="/forgot-password">Forgot password?</Link></>}{kind === 'signup' && <>Already have an account? <Link href="/login">Sign in</Link></>}{kind === 'forgot' && <>Remembered it? <Link href="/login">Back to sign in</Link></>}{kind === 'github' && <>Need an account? <Link href="/signup">Create one</Link></>}</div></div></div></div>;
}

function Landing() {
  return <div className="landing"><nav className="landing-nav"><Link href="/"><Logo /></Link><div className="landing-links"><a href="#platform">Platform</a><a href="#workflow">How it works</a><a href="#trust">Trust</a><Link href="/login">Sign in</Link><Link href="/signup" className="btn primary small">Request access <ArrowRight size={13} /></Link></div></nav><section className="hero"><div><div className="eyebrow">Cyber risk, with a point of view.</div><h1>Stop chasing noise.<br /><em>Start seeing risk.</em></h1><p className="hero-copy">Fantom continuously turns your GitHub footprint, threat intelligence, and business context into one calm, defensible picture of cyber risk.</p><div className="hero-actions"><Link href="/signup" className="btn primary">See your risk clearly <ArrowRight size={15} /></Link><a href="#platform" className="btn ghost">Explore the platform</a></div><div className="hero-note"><span style={{ color: 'var(--teal)' }}>●</span> Read-only by design · Built for security leaders</div></div><div className="hero-visual"><div className="visual-top"><span>FANTOM / COMMAND CENTER</span><span><span style={{ color: '#B8D9C9' }}>●</span> MONITORING</span></div><div className="visual-grid"><div className="visual-card wide"><small>ORGANIZATION RISK INDEX</small><strong>42 <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: '#B8D9C9', letterSpacing: 0 }}>↓ 8 this week</span></strong><div className="mini-bars">{[45,62,52,76,60,84,70,91,66,78,88,74].map((h, i) => <i style={{ height: `${h}%` }} key={i} />)}</div></div><div className="visual-card"><small>OPEN FINDINGS</small><strong>47</strong><span style={{ color: '#B8D9C9', fontSize: 11 }}>3 high priority</span></div><div className="visual-card"><small>THREAT SIGNALS</small><strong>08</strong><span style={{ color: 'rgba(245,239,235,.55)', fontSize: 11 }}>2 need review</span></div></div></div></section><section className="landing-section" id="platform"><div className="landing-section-head"><div className="eyebrow">A clearer operating system for risk</div><h2 style={{ marginTop: 11, fontSize: 38 }}>The context your scanners leave out.</h2><p>Fantom sits above your existing security tools and makes their output useful. Not more alerts — a better decision surface.</p></div><div className="feature-grid"><div className="panel feature accent"><div className="feature-icon"><Radar size={18} /></div><h3>Quantify what is exposed</h3><p>Rank vulnerabilities by real reachability, exploit likelihood, and the business systems they touch.</p></div><div className="panel feature"><div className="feature-icon"><Globe2 size={18} /></div><h3>Enrich with the outside world</h3><p>Know when a theoretical issue becomes an active campaign with live threat signals.</p></div><div className="panel feature"><div className="feature-icon"><Target size={18} /></div><h3>Move the right fix first</h3><p>Give engineering a prioritized queue and leadership a language they can act on.</p></div></div></section><section className="landing-section tinted" id="workflow"><div className="tinted-inner"><div className="landing-section-head"><div className="eyebrow">From signal to decision</div><h2 style={{ marginTop: 11, fontSize: 38 }}>Four moves. One shared truth.</h2></div><div className="workflow">{[['01', 'Connect', 'Read-only GitHub access gives Fantom the context behind every change.'], ['02', 'Discover', 'Scan code, dependencies, infrastructure, and exposed paths continuously.'], ['03', 'Quantify', 'Join threat intelligence to business criticality and customer impact.'], ['04', 'Prioritize', 'Send teams toward the fix that changes your risk — not just your count.']].map(([n,t,d]) => <div className="step" key={n}><div className="step-num">{n}</div><h3>{t}</h3><p>{d}</p></div>)}</div></div></section><section className="landing-section" id="trust"><div className="grid grid-2" style={{ alignItems: 'center' }}><div><div className="eyebrow">Designed for trust</div><h2 style={{ marginTop: 11, fontSize: 38 }}>Quiet confidence for loud environments.</h2><p className="subhead" style={{ maxWidth: 490, marginTop: 17 }}>Your team already has tools that find problems. Fantom helps you explain which ones matter, why they matter now, and what happens if you wait.</p><div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 25 }}><Badge tone="info"><LockKeyhole size={12} /> Read-only access</Badge><Badge tone="info"><ShieldCheck size={12} /> Evidence-backed scoring</Badge><Badge tone="info"><Building2 size={12} /> Business-aware</Badge></div></div><div className="panel panel-pad" style={{ background: 'var(--mint)', minHeight: 240 }}><div className="eyebrow">The weekly conversation</div><h3 style={{ fontSize: 25, marginTop: 18, maxWidth: 360 }}>“We reduced risk by 8 points — and here is exactly how.”</h3><p className="subhead" style={{ marginTop: 15 }}>Every score has a traceable story your board, engineering team, and customers can trust.</p></div></div></section><section className="landing-section" style={{ paddingTop: 20 }}><div className="cta-band"><div><div className="eyebrow" style={{ color: 'var(--sky)' }}>Start with your real footprint</div><h2 style={{ color: 'var(--paper)', fontSize: 35, marginTop: 11 }}>Make the next security decision easier.</h2><p>Connect one repository. Get a point of view in minutes.</p></div><Link href="/signup" className="btn">Request access <ArrowRight size={15} /></Link></div></section><footer className="footer"><span>© 2026 fantom.ai</span><span>Continuous cyber risk quantification · Built for security leaders</span></footer></div>;
}

function ComingPage({ title, icon: Icon }: { title: string; icon: typeof Bot }) {
  return <div className="page"><SectionHead eyebrow="Future capability" title={title} sub="A more autonomous way to turn security context into action is on the way." /><div className="panel coming"><Icon size={33} /><h3>Coming soon</h3><p>We are shaping this capability with security teams who care about signal quality.</p><Badge tone="medium">On the roadmap</Badge></div></div>;
}

const PUBLIC_ROUTES = ['/', '/login', '/signup', '/forgot-password', '/github-connect'];

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
  else if (location === '/risk-score') page = <RiskScore />;
  else if (location === '/threat-intelligence') page = <ThreatIntel />;
  else if (location === '/business-impact') page = <BusinessImpact toast={toast} />;
  else if (location === '/live-scan') page = <LiveScan toast={toast} />;
  else if (location.startsWith('/vulnerabilities/')) page = <Vulnerability />;
  else if (location === '/analytics') page = <Analytics />;
  else if (location === '/reports') page = <Reports toast={toast} />;
  else if (location === '/settings') page = <Settings />;
  else if (location === '/help') page = <Help />;
  else if (location.includes('ai-repository-survey-agent')) page = <ComingPage title="AI Repository Survey Agent" icon={Bot} />;
  else if (location.includes('recruiter-agent')) page = <ComingPage title="Recruiter Agent" icon={UserRound} />;
  else if (location.includes('llm-reachability')) page = <ComingPage title="LLM Reachability Analysis" icon={Network} />;
  else if (location.includes('ai-fix-suggestions')) page = <ComingPage title="AI Fix Suggestions" icon={Sparkles} />;
  else page = <div className="page"><SectionHead eyebrow="Unknown route" title="Page not found" sub="The page you are looking for does not exist in this workspace." action={<Link href="/dashboard" className="btn primary">Return to dashboard</Link>} /></div>;
  return <Shell toast={toast}>{page}</Shell>;
}

function App() {
  const [toastMessage, setToastMessage] = useState('');
  const toast = (message: string) => { setToastMessage(message); window.setTimeout(() => setToastMessage(''), 2600); };
  return <QueryClientProvider client={queryClient}><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><AppRouter toast={toast} /></WouterRouter>{toastMessage && <div className="toast-local" data-testid="status-toast"><Check size={14} style={{ verticalAlign: 'middle', marginRight: 8, color: 'var(--sky)' }} />{toastMessage}</div>}</QueryClientProvider>;
}

export default App;