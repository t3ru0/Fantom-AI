import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import * as api from '@/lib/api';

export type AuthUser = { name: string; email: string };
export type AuthState = {
  user: AuthUser | null;
  memberships: api.MembershipOut[];
  role: string;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthState | null>(null);

/** One `api.me()` call, shared - every component that needs the signed-in
 * user or their role reads it from here instead of re-fetching itself. Also
 * owns the "session expired" reaction so `api.ts` never needs router access. */
export function AuthProvider({ children, onSessionExpired }: { children: ReactNode; onSessionExpired: () => void }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [memberships, setMemberships] = useState<api.MembershipOut[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    if (!api.isLoggedIn()) { setUser(null); setMemberships([]); setLoading(false); return; }
    setLoading(true);
    try {
      const me = await api.me();
      setUser({ name: me.user.name, email: me.user.email });
      setMemberships(me.memberships);
    } catch {
      setUser(null);
      setMemberships([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  useEffect(() => {
    const onExpired = () => { setUser(null); setMemberships([]); onSessionExpired(); };
    window.addEventListener('fantom:session-expired', onExpired);
    return () => window.removeEventListener('fantom:session-expired', onExpired);
  }, [onSessionExpired]);

  function logout() {
    api.clearSession();
    setUser(null);
    setMemberships([]);
  }

  const role = memberships.find((m) => m.org_id === api.getOrgId())?.role ?? memberships[0]?.role ?? 'member';

  return <AuthContext.Provider value={{ user, memberships, role, loading, refresh, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
