import { ShieldAlert, Activity, Server, Mail, Fingerprint, Search, Siren } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { StatCard } from '../components/dashboard/StatCard';
import { PriorityDistribution } from '../components/dashboard/PriorityDistribution';
import { PriorityBadge } from '../components/threats/PriorityBadge';
import type { DashboardOverview } from '../types/dashboard';

export const Overview = () => {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard', 'overview'],
    queryFn: () => api.get('/dashboard/overview') as Promise<DashboardOverview>,
    refetchInterval: 30000,
  });

  const { data: systemStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['system', 'status'],
    queryFn: async () => {
      const baseUrl = (import.meta.env.VITE_API_URL ?? 'http://localhost:3000/api/v1').replace(/\/api\/v1\/?$/, '');
      const res = await fetch(`${baseUrl}/readiness`);
      if (!res.ok) throw new Error('System unavailable');
      return res.json();
    },
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Command Center</h1>
        <p className="text-muted-foreground mt-1">SOC overview across your organization's cases and email intelligence</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          icon={<ShieldAlert className="w-5 h-5" />}
          label="Threats Detected"
          value={stats?.activeThreats ?? 0}
          loading={statsLoading}
          accentClassName="text-security-critical"
        />
        <Link to="/cases?priority=CRITICAL" className="block">
          <StatCard
            icon={<Siren className="w-5 h-5" />}
            label="Critical Alerts"
            value={stats?.criticalAlerts ?? 0}
            loading={statsLoading}
            accentClassName="text-security-critical"
          />
        </Link>
        <StatCard
          icon={<Activity className="w-5 h-5" />}
          label="Investigations"
          value={stats?.investigations ?? 0}
          loading={statsLoading}
          accentClassName="text-primary"
        />
        <StatCard
          icon={<Mail className="w-5 h-5" />}
          label="Emails Analyzed"
          value={stats?.emailsAnalyzed ?? 0}
          loading={statsLoading}
          accentClassName="text-security-info"
        />
        <StatCard
          icon={<Fingerprint className="w-5 h-5" />}
          label="Indicators Tracked"
          value={stats?.indicatorsTracked ?? 0}
          loading={statsLoading}
          accentClassName="text-security-verified"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-card border border-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-medium text-foreground">Priority Distribution</h2>
            <span className="text-xs text-muted-foreground">Open cases only</span>
          </div>
          {statsLoading ? (
            <div className="h-64 bg-secondary/40 rounded animate-pulse" />
          ) : (
            <PriorityDistribution breakdown={stats?.priorityBreakdown ?? { critical: 0, high: 0, medium: 0, low: 0 }} />
          )}
        </div>

        <div className="bg-card border border-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-medium text-foreground">Recent Incidents</h2>
            <Server className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="text-xs text-muted-foreground mb-3 flex items-center gap-1.5">
            <span className={statusLoading ? 'text-muted-foreground' : systemStatus?.status === 'ready' ? 'text-security-verified' : 'text-security-critical'}>
              ●
            </span>
            {statusLoading ? 'Checking system status...' : systemStatus?.status === 'ready' ? 'All systems nominal' : 'System status unavailable'}
          </div>
          <div className="space-y-3">
            {statsLoading && [1, 2, 3].map((i) => (
              <div key={i} className="h-16 bg-secondary/40 rounded animate-pulse" />
            ))}
            {!statsLoading && stats?.recentAlerts?.length === 0 && (
              <div className="text-sm text-muted-foreground p-4 text-center border border-dashed border-border rounded">
                No cases opened yet.
              </div>
            )}
            {!statsLoading && stats?.recentAlerts?.map((incident) => (
              <Link
                key={incident.id}
                to="/cases"
                className="block p-3 bg-background border border-border rounded-md hover:border-primary/40 transition-colors"
              >
                <div className="flex justify-between items-start gap-2">
                  <div className="font-medium text-sm text-foreground/90">{incident.title}</div>
                  <PriorityBadge priority={incident.priority} />
                </div>
                <div className="text-xs text-muted-foreground mt-2 flex items-center justify-between">
                  <span>{incident.status.replace('_', ' ')}</span>
                  <span>{new Date(incident.timestamp).toLocaleString()}</span>
                </div>
              </Link>
            ))}
          </div>
          <Link
            to="/cases"
            className="mt-4 flex items-center justify-center gap-1.5 text-xs text-primary hover:underline"
          >
            <Search className="w-3.5 h-3.5" /> View all cases
          </Link>
        </div>
      </div>
    </div>
  );
};
