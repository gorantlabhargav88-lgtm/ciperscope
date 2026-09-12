import { useState } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import type { User, Role } from './AuthContext';

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  // In Phase 5, we simulate an authenticated user by default for development.
  const [user, setUser] = useState<User | null>({
    id: 'usr_1',
    name: 'Demo Analyst',
    email: 'analyst@ciperscope.demo',
    role: 'SOC_ANALYST',
    organizationId: 'org_1'
  });

  const login = (newUser: User) => setUser(newUser);
  const logout = () => setUser(null);

  const hasRole = (roles: Role[]) => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
};
