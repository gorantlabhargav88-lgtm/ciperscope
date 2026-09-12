import { createContext, useContext } from 'react';

export type Role = 'ADMIN' | 'SOC_ANALYST' | 'INVESTIGATOR' | 'AUDITOR' | 'VIEWER';

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  organizationId: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  login: (user: User) => void;
  logout: () => void;
  hasRole: (roles: Role[]) => boolean;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
