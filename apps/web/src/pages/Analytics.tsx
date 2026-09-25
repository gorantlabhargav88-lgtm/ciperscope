import { useState, type ReactNode } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis, Legend,
} from 'recharts';
import { Loader2, AlertTriangle, ShieldOff, BarChart2, Mail, ShieldAlert, Link2, Paperclip, Briefcase } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { StatCard } from '../components/dashboard/StatCard';
import type { AnalyticsRange } from '@ciperscope/types';

const RANGE_OPTIONS: { value: AnalyticsRange; label: string }[] = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#e11d48',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
};

const INDICATOR_TYPE_COLORS: Record<string, string> = {
  IP: '#3b82f6',
  DOMAIN: '#8b5cf6',
  URL: '#e11d48',
  HASH: '#f97316',
  EMAIL_ADDRESS: '#14b8a6',
};

/**
 * Org-wide Security Analytics — GET /analytics/overview. Every stat card
 * and chart is backed by real, already-persisted data for the requesting
 * organization; nothing here is estimated or fabricated.
 */
export const Analytics = () => {
  const [range, setRange] = useState<AnalyticsRange>('30d');

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['analytics-overview', range],
    queryFn: () => apiClient.getAnalyticsOverview(range),
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });

  const classified = error ? classifyApiError(error, 'security analytics') : null;

  const hasActivity = (data?.emailsAnalyzed ?? 0) > 0 || (data?.threatsDetected ?? 0) > 0;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-2 border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <BarChart2 className="w-8 h-8 text-blue-500" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Security Overview</h1>
          </div>
          <p className="text-slate-400 mt-2">Aggregate threat and case metrics for your organization.</p>
        </div>
        <select
          value={range}
          onChange={(e) => setRange(e.target.value as AnalyticsRange)}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-600"
        >
          {RANGE_OPTIONS.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load analytics'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : (
        <>
          {isFetching && <div className="text-xs text-slate-500 flex items-center gap-1.5"><Loader2 className="w-3 h-3 animate-spin" /> Refreshing…</div>}

          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <StatCard icon={<Mail className="w-5 h-5" />} label="Emails Analyzed" value={data?.emailsAnalyzed ?? 0} accentClassName="text-security-info" />
            <StatCard icon={<ShieldAlert className="w-5 h-5" />} label="Threats Detected" value={data?.threatsDetected ?? 0} accentClassName="text-security-critical" />
            <StatCard icon={<ShieldAlert className="w-5 h-5" />} label="Critical Threats" value={data?.criticalThreats ?? 0} accentClassName="text-security-critical" />
            <Link to="/cases?priority=CRITICAL" className="block">
              <StatCard icon={<Briefcase className="w-5 h-5" />} label="Open Critical Cases" value={data?.openCriticalCases ?? 0} accentClassName="text-security-critical" />
            </Link>
            <Link to="/indicators?type=URL&severity=CRITICAL" className="block">
              <StatCard icon={<Link2 className="w-5 h-5" />} label="Malicious URLs" value={data?.maliciousUrls ?? 0} accentClassName="text-security-high" />
            </Link>
            <StatCard icon={<Paperclip className="w-5 h-5" />} label="Suspicious Attachments" value={data?.suspiciousAttachments ?? 0} accentClassName="text-security-medium" />
          </div>

          {!hasActivity ? (
            <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
              No threat activity recorded for this period.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ChartCard title="Threat Activity Over Time">
                {data && data.threatActivity.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <LineChart data={data.threatActivity} margin={{ left: 0, right: 12 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                      <XAxis dataKey="bucket" tick={{ fill: 'var(--color-muted-foreground)', fontSize: 10 }} stroke="var(--color-border)" />
                      <YAxis allowDecimals={false} tick={{ fill: 'var(--color-muted-foreground)', fontSize: 12 }} stroke="var(--color-border)" />
                      <Tooltip contentStyle={{ background: 'var(--color-popover)', border: '1px solid var(--color-border)', borderRadius: 8 }} labelStyle={{ color: 'var(--color-foreground)' }} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Line type="monotone" dataKey="total" name="Emails" stroke="#3b82f6" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="threats" name="Threats" stroke="#e11d48" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                ) : <EmptyChart />}
              </ChartCard>

              <ChartCard title="Severity Distribution">
                {data && data.severityDistribution.some((s) => s.count > 0) ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <PieChart>
                      <Pie data={data.severityDistribution} dataKey="count" nameKey="severity" cx="50%" cy="50%" outerRadius={90} label={(e: any) => `${e.severity}: ${e.count}`}>
                        {data.severityDistribution.map((s) => (
                          <Cell key={s.severity} fill={SEVERITY_COLORS[s.severity] ?? '#64748b'} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ background: 'var(--color-popover)', border: '1px solid var(--color-border)', borderRadius: 8 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <EmptyChart />}
              </ChartCard>

              <ChartCard title="Case Priority Distribution (open cases)">
                {data && data.casesByPriority.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={data.casesByPriority} layout="vertical" margin={{ left: 12, right: 24 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
                      <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--color-muted-foreground)', fontSize: 12 }} stroke="var(--color-border)" />
                      <YAxis type="category" dataKey="priority" width={70} tick={{ fill: 'var(--color-foreground)', fontSize: 12 }} stroke="var(--color-border)" />
                      <Tooltip contentStyle={{ background: 'var(--color-popover)', border: '1px solid var(--color-border)', borderRadius: 8 }} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={22}>
                        {data.casesByPriority.map((c) => (
                          <Cell key={c.priority} fill={SEVERITY_COLORS[c.priority] ?? '#64748b'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : <EmptyChart />}
              </ChartCard>

              <ChartCard title="Indicator Type Distribution">
                {data && data.indicatorTypeDistribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <PieChart>
                      <Pie data={data.indicatorTypeDistribution} dataKey="count" nameKey="type" cx="50%" cy="50%" outerRadius={90} label={(e: any) => `${e.type}: ${e.count}`}>
                        {data.indicatorTypeDistribution.map((t) => (
                          <Cell key={t.type} fill={INDICATOR_TYPE_COLORS[t.type] ?? '#64748b'} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ background: 'var(--color-popover)', border: '1px solid var(--color-border)', borderRadius: 8 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <EmptyChart />}
              </ChartCard>
            </div>
          )}

          {data && (data.topDomains.length > 0 || data.topIps.length > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <TopList title="Top Observed Domains" rows={data.topDomains.map((d) => ({ label: d.domain, count: d.count }))} linkPrefix="/indicators?type=DOMAIN&q=" />
              <TopList title="Top Observed IPs" rows={data.topIps.map((i) => ({ label: i.ip, count: i.count }))} linkPrefix="/indicators?type=IP&q=" />
            </div>
          )}

          {data?.truncated && (
            <div className="text-xs text-amber-400/80 text-center">
              Showing a bounded sample of recent activity — some older records may not be reflected in these metrics.
            </div>
          )}
        </>
      )}
    </div>
  );
};

const ChartCard = ({ title, children }: { title: string; children: ReactNode }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
    <h2 className="font-medium text-slate-200 mb-4 text-sm">{title}</h2>
    {children}
  </div>
);

const EmptyChart = () => (
  <div className="h-64 flex items-center justify-center text-slate-500 text-sm border border-dashed border-slate-800 rounded">
    No threat activity recorded for this period.
  </div>
);

const TopList = ({ title, rows, linkPrefix }: { title: string; rows: { label: string; count: number }[]; linkPrefix: string }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
    <h2 className="font-medium text-slate-200 mb-4 text-sm">{title}</h2>
    <div className="space-y-2">
      {rows.map((r) => (
        <Link
          key={r.label}
          to={`${linkPrefix}${encodeURIComponent(r.label)}`}
          className="flex items-center justify-between text-sm p-2 rounded hover:bg-slate-800/50 transition-colors"
        >
          <span className="font-mono text-slate-300 truncate">{r.label}</span>
          <span className="text-slate-500 shrink-0 ml-3">{r.count} email{r.count !== 1 ? 's' : ''}</span>
        </Link>
      ))}
    </div>
  </div>
);
