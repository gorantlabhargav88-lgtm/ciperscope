import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { EmailAnalysis } from './pages/EmailAnalysis';
import { PlaceholderPage } from './pages/PlaceholderPage';
import { AuthProvider } from './features/auth/AuthProvider';

const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/',
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppLayout />,
        children: [
          { index: true, element: <Navigate to="/overview" replace /> },
          { path: 'overview', element: <Overview /> },
          { path: 'investigations', element: <PlaceholderPage title="Investigations" /> },
          { path: 'investigations/:id', element: <PlaceholderPage title="Investigation Details" /> },
          { path: 'alerts', element: <PlaceholderPage title="Alerts" /> },
          { path: 'cases', element: <PlaceholderPage title="Cases" /> },
          { path: 'cases/:id', element: <PlaceholderPage title="Case Details" /> },
          { path: 'email-analysis', element: <EmailAnalysis /> },
          { path: 'email-analysis/:id', element: <EmailAnalysis /> },
          { path: 'indicators', element: <PlaceholderPage title="Indicators" /> },
          { path: 'infrastructure', element: <PlaceholderPage title="Infrastructure" /> },
          { path: 'geo-intelligence', element: <PlaceholderPage title="Geo Intelligence" /> },
          { path: 'evidence', element: <PlaceholderPage title="Evidence Vault" /> },
          { path: 'evidence/:id', element: <PlaceholderPage title="Evidence Details" /> },
          { path: 'chain-of-custody', element: <PlaceholderPage title="Chain of Custody" /> },
          { path: 'verification', element: <PlaceholderPage title="Evidence Verification" /> },
          { path: 'timeline', element: <PlaceholderPage title="Investigation Timeline" /> },
          { path: 'reports', element: <PlaceholderPage title="Reports" /> },
          { path: 'analytics', element: <PlaceholderPage title="Analytics" /> },
          { path: 'integrations', element: <PlaceholderPage title="Integrations" /> },
          { path: 'audit-log', element: <PlaceholderPage title="Audit Log" /> },
          { path: 'users', element: <PlaceholderPage title="Users & Roles" /> },
          { path: 'settings', element: <PlaceholderPage title="Settings" /> },
        ],
      },
    ],
  },
  {
    path: '*',
    element: <Navigate to="/" replace />,
  }
]);

export const AppRoutes = () => {
  return (
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  );
};
