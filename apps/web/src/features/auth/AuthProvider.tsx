import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import type { User, Role } from './AuthContext';

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const restoreSession = async () => {
      try {
        const res = await fetch('http://localhost:3000/api/v1/auth/me', {
          credentials: 'include',
        });
        if (res.ok) {
          const data = await res.json();
          if (data.user) {
            const membership = data.user.memberships?.[0];
            setUser({
              id: data.user.id,
              name: `${data.user.firstName || ''} ${data.user.lastName || ''}`.trim() || 'User',
              email: data.user.email,
              role: (membership?.role?.name as Role) || 'VIEWER',
              organizationId: membership?.organizationId || '',
            });
          }
        }
      } catch (err) {
        console.error('Session restoration failed', err);
      } finally {
        setLoading(false);
      }
    };
    restoreSession();
  }, []);

  const login = (newUser: User) => setUser(newUser);

  const logout = async () => {
    try {
      await fetch('http://localhost:3000/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
    } catch (err) {
      console.error('Logout failed', err);
    }
    setUser(null);
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
