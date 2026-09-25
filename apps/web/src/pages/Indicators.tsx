import { Fragment, useState } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { Loader2, AlertTriangle, ShieldOff, Fingerprint, Search, ChevronDown, ChevronRight } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { SeverityBadge } from '../components/threats/SeverityBadge';
import { StatCard } from '../components/dashboard/StatCard';
import type { AlertSeverity } from '../types/severity';
import type { OrgIndicator } from '@ciperscope/types';

const TYPE_OPTIONS = ['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL_ADDRESS'] as const;
const SEVERITY_OPTIONS: AlertSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const REPUTATION_STYLES: Record<string, string> = {
  MALICIOUS: 'bg-security-critical/10 text-security-critical border-security-critical/20',
  SUSPICIOUS: 'bg-security-medium/10 text-security-medium border-security-medium/20',
  CLEAN: 'bg-security-low/10 text-security-low border-security-low/20',
  UNKNOWN: 'bg-slate-800 text-slate-400 border-slate-700',
};

function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 3) / 2);
  return `${value.slice(0, half)}...${value.slice(value.length - half)}`;
}

/**
 * Organization-wide Indicators of Compromise — GET /intelligence/indicators.
 * Aggregates the same Indicator/ThreatIntelObservation data the per-email
 * Threat Intelligence panel (EmailAnalysis.tsx) shows, across every email
 * this organization has ingested.
 */
export const Indicators = () => {
  // Seeded from the URL so cross-links from Analytics/Email Analysis (e.g.
  // "?type=URL&severity=CRITICAL") land pre-filtered. Only read once on
  // mount — after that, filters are owned by local state.
  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [limit] = useState(25);
  const [search, setSearch] = useState(searchParams.get('q') ?? '');
  const [type, setType] = useState<string>(searchParams.get('type') ?? '');
  const [severity, setSeverity] = useState<string>(searchParams.get('severity') ?? '');
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['indicators', page, limit, search, type, severity],
    queryFn: () =>
      apiClient.getIndicators({
        page,
        limit,
        q: search || undefined,
        type: type || undefined,
        severity: severity || undefined,
      }),
    placeholderData: keepPreviousData,
  });

  const classified = error ? classifyApiError(error, 'indicators') : null;

  const items = data?.items ?? [];
  const criticalOrHigh = items.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;
  const malicious = items.filter((i) => i.reputation === 'MALICIOUS').length;
  const recentlyObserved = items.filter((i) => Date.now() - new Date(i.lastSeen).getTime() < 24 * 60 * 60 * 1000).length;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-2 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Fingerprint className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Indicators of Compromise</h1>
        </div>
        <p className="text-slate-400 mt-2">
          IPs, domains, URLs, hashes, and sender addresses observed across your organization's analyzed emails, enriched with threat intelligence where available.
        </p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard icon={<Fingerprint className="w-5 h-5" />} label="Total Indicators (page)" value={data?.total ?? 0} loading={isLoading} accentClassName="text-primary" />
        <StatCard icon={<AlertTriangle className="w-5 h-5" />} label="Critical / High (page)" value={criticalOrHigh} loading={isLoading} accentClassName="text-security-critical" />
        <StatCard icon={<ShieldOff className="w-5 h-5" />} label="Malicious (page)" value={malicious} loading={isLoading} accentClassName="text-security-critical" />
        <StatCard icon={<Fingerprint className="w-5 h-5" />} label="Observed in last 24h (page)" value={recentlyObserved} loading={isLoading} accentClassName="text-security-info" />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search IP, domain, URL, hash, or email address..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-600"
          />
        </div>
        <select
          value={type}
          onChange={(e) => { setType(e.target.value); setPage(1); }}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-600"
        >
          <option value="">All types</option>
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-600"
        >
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load indicators'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No indicators of compromise have been observed for this organization's emails yet.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-4 py-4 font-medium w-6" />
                  <th className="px-4 py-4 font-medium">Type</th>
                  <th className="px-4 py-4 font-medium">Indicator</th>
                  <th className="px-4 py-4 font-medium">Severity</th>
                  <th className="px-4 py-4 font-medium">Confidence</th>
                  <th className="px-4 py-4 font-medium">Reputation</th>
                  <th className="px-4 py-4 font-medium">Source</th>
                  <th className="px-4 py-4 font-medium">First Seen</th>
                  <th className="px-4 py-4 font-medium">Last Seen</th>
                  <th className="px-4 py-4 font-medium">Related</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {items.map((item: OrgIndicator) => {
                  const key = `${item.type}:${item.value}`;
                  const isOpen = expanded === key;
                  return (
                    <Fragment key={key}>
                      <tr
                        className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                        onClick={() => setExpanded(isOpen ? null : key)}
                      >
                        <td className="px-4 py-3 text-slate-500">
                          {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-xs font-medium border bg-slate-800 text-slate-300 border-slate-700">{item.type}</span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-200 max-w-[280px] truncate" title={item.value}>
                          {truncateMiddle(item.value)}
                        </td>
                        <td className="px-4 py-3">
                          {item.severity ? <SeverityBadge level={item.severity as AlertSeverity} /> : <span className="text-slate-600 text-xs">—</span>}
                        </td>
                        <td className="px-4 py-3 text-slate-400">{item.confidence != null ? `${Math.round(item.confidence * 100)}%` : '—'}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${REPUTATION_STYLES[item.reputation] ?? REPUTATION_STYLES.UNKNOWN}`}>
                            {item.reputation}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-400">{item.source ?? '—'}</td>
                        <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{new Date(item.firstSeen).toLocaleDateString()}</td>
                        <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{new Date(item.lastSeen).toLocaleString()}</td>
                        <td className="px-4 py-3 text-slate-400">
                          {item.relatedEmailCount} email{item.relatedEmailCount !== 1 ? 's' : ''}
                          {item.relatedCaseCount > 0 ? `, ${item.relatedCaseCount} case${item.relatedCaseCount !== 1 ? 's' : ''}` : ''}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-950/40">
                          <td />
                          <td colSpan={9} className="px-4 py-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              <div>
                                <div className="text-slate-500 uppercase mb-1">Full value</div>
                                <div className="font-mono text-slate-300 break-all">{item.value}</div>
                              </div>
                              <div>
                                <div className="text-slate-500 uppercase mb-1">Related emails</div>
                                {item.relatedEmailIds.length > 0 ? (
                                  <div className="flex flex-col gap-1">
                                    {item.relatedEmailIds.map((id) => (
                                      <Link key={id} to={`/email-analysis/${id}`} className="text-blue-400 hover:text-blue-300 font-mono truncate">
                                        {id}
                                      </Link>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-slate-600">None</span>
                                )}
                              </div>
                              {item.cti && item.cti.observations.length > 0 && (
                                <div className="md:col-span-2">
                                  <div className="text-slate-500 uppercase mb-1">CTI observations</div>
                                  <div className="space-y-1">
                                    {item.cti.observations.map((o) => (
                                      <div key={o.id} className="flex items-center gap-3 text-slate-300">
                                        <span className="font-medium">{o.provider}</span>
                                        <span className={`px-1.5 py-0.5 rounded border ${REPUTATION_STYLES[o.verdict] ?? REPUTATION_STYLES.UNKNOWN}`}>{o.verdict}</span>
                                        {o.confidence != null && <span className="text-slate-500">{Math.round(o.confidence * 100)}% confidence</span>}
                                        <span className="text-slate-500">{new Date(o.observationTime).toLocaleString()}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          {data?.truncated && (
            <div className="p-3 text-xs text-amber-400/80 border-t border-slate-800 text-center">
              Showing a bounded sample of recent activity — some older indicators may not be reflected.
            </div>
          )}
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 text-xs text-slate-400">
            <span>
              Page {data?.page ?? 1} of {data?.totalPages ?? 1} · {data?.total ?? 0} total indicators
              {isFetching && <Loader2 className="inline w-3 h-3 ml-2 animate-spin" />}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={(data?.page ?? 1) <= 1}
                className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={(data?.page ?? 1) >= (data?.totalPages ?? 1)}
                className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
