import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Loader2, AlertTriangle, Server, ShieldOff } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';

const CLASSIFICATION_STYLES: Record<string, string> = {
  PUBLIC: 'bg-rose-950/30 text-rose-400 border-rose-900/50',
  PRIVATE: 'bg-slate-800 text-slate-400 border-slate-700',
  LOOPBACK: 'bg-slate-800 text-slate-500 border-slate-700',
  LINK_LOCAL: 'bg-slate-800 text-slate-500 border-slate-700',
  DOCUMENTATION: 'bg-amber-950/30 text-amber-400 border-amber-900/50',
};

/**
 * Org-wide Infrastructure Intelligence — same GET /intelligence/network
 * aggregation as GeoIntelligence.tsx, presented hop/ASN/hostname-first
 * rather than map-first. Deliberately reuses the one backend endpoint
 * instead of duplicating the aggregation query.
 */
export const Infrastructure = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['network-intelligence'],
    queryFn: () => apiClient.getNetworkIntelligence(),
  });

  const classified = error ? classifyApiError(error, 'infrastructure intelligence') : null;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Server className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Infrastructure Intelligence</h1>
        </div>
        <p className="text-slate-400 mt-2">Relay infrastructure observed across your organization's email transport hops.</p>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load infrastructure intelligence'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : !data || data.items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No relay infrastructure has been observed for this organization's emails yet.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4 font-medium">IP</th>
                  <th className="px-6 py-4 font-medium">Classification</th>
                  <th className="px-6 py-4 font-medium">Hostname (Received header)</th>
                  <th className="px-6 py-4 font-medium">Reverse DNS (PTR)</th>
                  <th className="px-6 py-4 font-medium">ASN / Org</th>
                  <th className="px-6 py-4 font-medium">Hops</th>
                  <th className="px-6 py-4 font-medium">Related Emails</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {data.items.map((item) => (
                  <tr key={item.ip} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-3 font-mono text-xs text-slate-200">{item.ip}</td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${CLASSIFICATION_STYLES[item.classification] ?? 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                        {item.classification}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-slate-400 max-w-[180px] truncate" title={item.receivedHopHostnames.join(', ') || undefined}>
                      {item.receivedHopHostnames.length > 0 ? item.receivedHopHostnames.join(', ') : 'Unknown'}
                    </td>
                    <td className="px-6 py-3 text-slate-400 max-w-[180px] truncate" title={item.reverseDns?.join(', ') ?? undefined}>
                      {item.reverseDns && item.reverseDns.length > 0 ? item.reverseDns.join(', ') : 'Not resolved'}
                    </td>
                    <td className="px-6 py-3 text-slate-400">
                      {item.geolocation?.asn ?? item.geolocation?.isp ? [item.geolocation.asn, item.geolocation.isp].filter(Boolean).join(' · ') : 'Unavailable'}
                    </td>
                    <td className="px-6 py-3 text-slate-400">{item.hopCount}</td>
                    <td className="px-6 py-3">
                      {item.relatedEmailIds.length > 0 ? (
                        <div className="flex flex-col gap-0.5">
                          {item.relatedEmailIds.slice(0, 2).map((id) => (
                            <Link key={id} to={`/email-analysis/${id}`} className="text-blue-400 hover:text-blue-300 text-xs font-mono truncate max-w-[140px]">
                              {id}
                            </Link>
                          ))}
                          {item.relatedEmailCount > 2 && (
                            <span className="text-slate-600 text-xs">+{item.relatedEmailCount - 2} more</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600 text-xs">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.truncated && (
            <div className="p-3 text-xs text-amber-400/80 border-t border-slate-800 text-center">
              Showing a bounded sample of relay hops — some older observations may not be reflected.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
