import { lazy, Suspense } from 'react';
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { PlaceholderPage } from './pages/PlaceholderPage';
import { Cases } from './pages/Cases';
import { Alerts } from './pages/Alerts';
import { AuthProvider } from './features/auth/AuthProvider';
import Integrations from './pages/Integrations';
import { Unauthorized } from './pages/Unauthorized';
import { EvidenceVault } from './pages/EvidenceVault';
import { EvidenceDetail } from './pages/EvidenceDetail';
import { Webhooks } from './pages/Webhooks';
import { GeoIntelligence } from './pages/GeoIntelligence';
import { Infrastructure } from './pages/Infrastructure';
import { RouteLoading } from './components/RouteLoading';

// Route-level code splitting for the heaviest, least-immediately-needed
// pages (forensic detail views a user reaches by drilling in, never the
// first thing rendered after login) — keeps the initial bundle smaller
// without touching any of their internals.
const EmailAnalysis = lazy(() => import('./pages/EmailAnalysis').then((m) => ({ default: m.EmailAnalysis })));
const InvestigationWorkspace = lazy(() => import('./InvestigationWorkspace').then((m) => ({ default: m.InvestigationWorkspace })));
const CaseDetail = lazy(() => import('./pages/CaseDetail').then((m) => ({ default: m.CaseDetail })));

const lazyElement = (el: React.ReactNode) => <Suspense fallback={<RouteLoading />}>{el}</Suspense>;

const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/unauthorized',
    element: <Unauthorized />,
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
          // Investigations are case-scoped (there is no cross-case investigation
          // list endpoint on the backend) — the real entry point is a case's own
          // detail page, which lists and links to its investigations.
          { path: 'investigations', element: <Navigate to="/cases" replace /> },
          { path: 'alerts', element: <Alerts /> },
          { path: 'cases', element: <Cases /> },
          { path: 'cases/:caseId', element: lazyElement(<CaseDetail />) },
          { path: 'cases/:caseId/investigations/:investigationId/workspace', element: lazyElement(<InvestigationWorkspace />) },
          { path: 'email-analysis', element: lazyElement(<EmailAnalysis />) },
          { path: 'email-analysis/:id', element: lazyElement(<EmailAnalysis />) },
          // Indicators has no dedicated org-wide backend query today (IOCs
          // are matched per-email against the Indicator/ThreatIntelObservation
          // tables, never aggregated org-wide) — a genuine pending
          // capability, not implemented here to avoid fabricating an
          // aggregation the backend doesn't do.
          {
            path: 'indicators',
            element: (
              <PlaceholderPage
                title="Indicators"
                reason="Indicators are matched per-email (see an email's Threat Intelligence panel) — there is no org-wide indicator aggregation endpoint yet."
              />
            ),
          },
          { path: 'infrastructure', element: <Infrastructure /> },
          { path: 'geo-intelligence', element: <GeoIntelligence /> },
          { path: 'evidence', element: <EvidenceVault /> },
          { path: 'evidence/:id', element: <EvidenceDetail /> },
          // Chain of custody, timeline, and reports are all case-scoped on
          // the backend (no cross-case endpoint exists) — the real entry
          // point is a case's own detail page, which already renders each
          // of these for its evidence/investigations.
          { path: 'chain-of-custody', element: <Navigate to="/cases" replace /> },
          // Verification is per-evidence-item (GET /evidence/:id/integrity)
          // — the vault list is the real entry point, not a standalone page.
          { path: 'verification', element: <Navigate to="/evidence" replace /> },
          { path: 'timeline', element: <Navigate to="/cases" replace /> },
          { path: 'reports', element: <Navigate to="/cases" replace /> },
          {
            path: 'analytics',
            element: (
              <PlaceholderPage
                title="Analytics"
                reason="No aggregate analytics endpoint exists yet. Per-case and per-email metrics are available on Overview, CaseDetail, and Email Analysis."
              />
            ),
          },
          { path: 'webhooks', element: <Webhooks /> },
          { path: 'integrations', element: <Integrations /> },
          { path: 'settings/integrations', element: <Integrations /> },
          {
            path: 'audit-log',
            element: (
              <PlaceholderPage
                title="Audit Log"
                reason="There is no org-wide audit log endpoint yet — a case's own Change History (on its Case Detail page) is available today."
              />
            ),
          },
          {
            path: 'users',
            element: (
              <PlaceholderPage
                title="Users & Roles"
                reason="No user/role management API exists yet — organization membership and roles are currently managed only via direct database administration."
              />
            ),
          },
          {
            path: 'settings',
            element: (
              <PlaceholderPage
                title="Settings"
                reason="No organization settings API exists yet. Integration settings are available under Integrations."
              />
            ),
          },
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
