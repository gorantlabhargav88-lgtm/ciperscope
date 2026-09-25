import { lazy, Suspense } from 'react';
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { AcceptInvite } from './pages/AcceptInvite';
import { Overview } from './pages/Overview';
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
// Analytics pulls in recharts (a genuinely heavy dependency) — code-split
// alongside the other drill-in pages so it never bloats the initial bundle.
const Indicators = lazy(() => import('./pages/Indicators').then((m) => ({ default: m.Indicators })));
const Analytics = lazy(() => import('./pages/Analytics').then((m) => ({ default: m.Analytics })));
const AuditLog = lazy(() => import('./pages/AuditLog').then((m) => ({ default: m.AuditLog })));
const Users = lazy(() => import('./pages/Users').then((m) => ({ default: m.Users })));
const Settings = lazy(() => import('./pages/Settings').then((m) => ({ default: m.Settings })));

const lazyElement = (el: React.ReactNode) => <Suspense fallback={<RouteLoading />}>{el}</Suspense>;

const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/accept-invite/:token',
    element: <AcceptInvite />,
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
          // GET /intelligence/indicators aggregates the same Indicator/
          // ThreatIntelObservation tables the per-email Threat Intelligence
          // panel uses, across every email in the organization.
          { path: 'indicators', element: lazyElement(<Indicators />) },
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
          // GET /analytics/overview — real aggregate metrics computed from
          // persisted Email/Case/RiskAssessment/Indicator data.
          { path: 'analytics', element: lazyElement(<Analytics />) },
          { path: 'webhooks', element: <Webhooks /> },
          { path: 'integrations', element: <Integrations /> },
          { path: 'settings/integrations', element: <Integrations /> },
          // GET /audit-log — organization-wide AuditLog listing (AUDIT_LOG_READ).
          { path: 'audit-log', element: lazyElement(<AuditLog />) },
          // GET/POST/PATCH/DELETE /members (USER_READ/USER_MANAGE).
          { path: 'users', element: lazyElement(<Users />) },
          // GET/PATCH /settings (USER_READ/USER_MANAGE).
          { path: 'settings', element: lazyElement(<Settings />) },
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
