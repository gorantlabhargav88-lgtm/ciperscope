import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import type { User, Role } from './AuthContext';
import { api } from '../../lib/api';

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const restoreSession = async () => {
      try {
        const data = await api.get('/auth/me');
        if (data && data.user) {
            const membership = data.user.memberships?.[0];
            const orgId = membership?.organizationId || '';
            setUser({
              id: data.user.id,
              name: `${data.user.firstName || ''} ${data.user.lastName || ''}`.trim() || 'User',
              email: data.user.email,
              role: (membership?.role?.name as Role) || 'VIEWER',
              organizationId: orgId,
            });
            api.setOrganizationId(orgId);
          }
      } catch (err) {
        console.error('Session restoration failed', err);
      } finally {
        setLoading(false);
      }
    };
    restoreSession();
  }, []);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      api.setOrganizationId(null);
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const login = (newUser: User) => {
    setUser(newUser);
    api.setOrganizationId(newUser.organizationId);
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      console.error('Logout failed', err);
    }
    setUser(null);
    api.setOrganizationId(null);
  };

  const hasRole = (roles: Role[]) => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">Loading session...</div>;
  }

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
};
