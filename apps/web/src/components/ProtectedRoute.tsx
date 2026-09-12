import type { FC } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import type { Role } from '../features/auth/AuthContext';

interface ProtectedRouteProps {
  allowedRoles?: Role[];
}

export const ProtectedRoute: FC<ProtectedRouteProps> = ({ allowedRoles }) => {
  const { isAuthenticated, hasRole } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !hasRole(allowedRoles)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <Outlet />;
};
