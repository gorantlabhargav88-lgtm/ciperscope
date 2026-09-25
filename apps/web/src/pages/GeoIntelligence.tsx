import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Loader2, AlertTriangle, Globe2, ShieldOff, MapPinOff } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import type { NetworkIntelligenceItem } from '@ciperscope/types';

const MAP_WIDTH = 720;
const MAP_HEIGHT = 340;

/** Equirectangular lat/long → SVG x/y — no map tiles, no invented basemap, just real coordinates plotted on a graticule. */
function project(lat: number, lon: number): { x: number; y: number } {
  const x = ((lon + 180) / 360) * MAP_WIDTH;
  const y = ((90 - lat) / 180) * MAP_HEIGHT;
  return { x, y };
}

/**
 * Org-wide Geo Intelligence — GET /intelligence/network
 * (services/api/src/modules/intelligence/intelligence.routes.ts).
 * Aggregates every relay-hop source IP observed across this org's emails
 * with the already-persisted GeoLocation/classification/reverse-DNS data.
 * Never queries an external GeoIP provider itself, and never fabricates a
 * location — a public IP with no GeoLocation row is honestly "not yet
 * enriched", and the page explains exactly why when MaxMind isn't
 * configured in this deployment.
 */
export const GeoIntelligence = () => {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['network-intelligence'],
    queryFn: () => apiClient.getNetworkIntelligence(),
  });

  const classified = error ? classifyApiError(error, 'geo intelligence') : null;
  const located = data?.items.filter((i) => i.geolocation?.latitude != null && i.geolocation?.longitude != null) ?? [];
  const selected = data?.items.find((i) => i.ip === selectedIp) ?? null;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Globe2 className="w-8 h-8 text-blue-500" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Geo Intelligence</h1>
          </div>
          <p className="text-slate-400 mt-2">Approximate network geolocation for every relay-hop IP observed across your organization's emails.</p>
        </div>
        {data && (
          <div className="text-xs px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 flex items-center gap-2 shrink-0">
            <span className={`w-1.5 h-1.5 rounded-full ${data.maxmindConfigured ? 'bg-emerald-500' : 'bg-slate-600'}`} />
            MaxMind: {data.maxmindConfigured ? 'Configured' : 'Not configured'}
          </div>
        )}
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load geo intelligence'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : !data || data.items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No relay-hop IP addresses have been observed for this organization's emails yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/*
            Distinguish the three honestly-different reasons a map might be
            empty (Phase 4 hardening): no MaxMind credentials configured in
            this deployment (a real, verifiable env-var gap — never
            fabricate coordinates to paper over it), MaxMind configured but
            nothing enriched for these specific IPs yet, and simply no
            public IPs observed at all. The table below is never hidden
            behind this banner — network intelligence (classification,
            reverse DNS, hop counts, related emails) is still fully useful
            without geolocation.
          */}
          {!data.geoEnrichmentAvailable && (
            <div className="lg:col-span-3 border p-4 rounded-xl flex items-center gap-3 bg-amber-950/20 border-amber-900/40">
              <MapPinOff className="w-6 h-6 text-amber-500 shrink-0" />
              <div className="text-sm">
                <p className="text-amber-200 font-medium">
                  {data.maxmindConfigured ? 'No geolocation enriched yet' : 'Geolocation unavailable — MaxMind is not configured'}
                </p>
                <p className="text-amber-200/70 text-xs mt-0.5">
                  {data.maxmindConfigured
                    ? 'MaxMind is configured for this deployment, but none of the IPs observed so far have been enriched. Network intelligence below (classification, reverse DNS, related emails) is still real and complete.'
                    : 'This deployment has no MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY configured, so relay-hop IPs cannot be mapped to a location. Network intelligence below (classification, reverse DNS, related emails) is still real and complete — add MaxMind credentials to enable mapping.'}
                </p>
              </div>
            </div>
          )}

          {located.length > 0 ? (
            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-x-auto">
              <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} className="w-full h-auto min-w-[500px]">
                <rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="#020617" />
                {Array.from({ length: 7 }).map((_, i) => (
                  <line key={`v${i}`} x1={(i * MAP_WIDTH) / 6} y1={0} x2={(i * MAP_WIDTH) / 6} y2={MAP_HEIGHT} stroke="#1e293b" strokeWidth={1} />
                ))}
                {Array.from({ length: 5 }).map((_, i) => (
                  <line key={`h${i}`} x1={0} y1={(i * MAP_HEIGHT) / 4} x2={MAP_WIDTH} y2={(i * MAP_HEIGHT) / 4} stroke="#1e293b" strokeWidth={1} />
                ))}
                <line x1={MAP_WIDTH / 2} y1={0} x2={MAP_WIDTH / 2} y2={MAP_HEIGHT} stroke="#334155" strokeWidth={1} />
                <line x1={0} y1={MAP_HEIGHT / 2} x2={MAP_WIDTH} y2={MAP_HEIGHT / 2} stroke="#334155" strokeWidth={1} />
                {located.map((item) => {
                  const { x, y } = project(item.geolocation!.latitude!, item.geolocation!.longitude!);
                  const isSelected = selectedIp === item.ip;
                  return (
                    <g key={item.ip} transform={`translate(${x}, ${y})`} onClick={() => setSelectedIp(item.ip)} className="cursor-pointer">
                      <circle r={isSelected ? 7 : 5} fill="#f43f5e" fillOpacity={0.25} />
                      <circle r={isSelected ? 4 : 3} fill="#f43f5e" stroke={isSelected ? '#fda4af' : 'transparent'} strokeWidth={2} />
                    </g>
                  );
                })}
              </svg>
              <p className="text-[11px] text-slate-600 mt-2">Equirectangular projection · {located.length} located IP{located.length === 1 ? '' : 's'} · click a point for details</p>
            </div>
          ) : (
            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-8 flex flex-col items-center justify-center text-center gap-2">
              <MapPinOff className="w-8 h-8 text-slate-700" />
              <p className="text-slate-500 text-sm">
                {data.maxmindConfigured ? 'No located IPs yet.' : 'No map — MaxMind is not configured in this deployment.'}
              </p>
            </div>
          )}

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-sm">
            {!selected ? (
              <p className="text-slate-500">Click a point on the map, or a row below, to inspect that IP.</p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-200">{selected.ip}</span>
                  <span className="text-xs text-slate-500">{selected.classification}</span>
                </div>
                <dl className="text-xs space-y-1.5 pt-2 border-t border-slate-800">
                  <div className="flex justify-between"><dt className="text-slate-500">Country</dt><dd className="text-slate-300">{selected.geolocation?.country ?? 'Unknown'}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">Region</dt><dd className="text-slate-300">{selected.geolocation?.region ?? 'Unknown'}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">City</dt><dd className="text-slate-300">{selected.geolocation?.city ?? 'Unknown'}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">ASN</dt><dd className="text-slate-300">{selected.geolocation?.asn ?? 'Unknown'}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">ISP</dt><dd className="text-slate-300 truncate max-w-[140px]" title={selected.geolocation?.isp ?? undefined}>{selected.geolocation?.isp ?? 'Unknown'}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">Hops observed</dt><dd className="text-slate-300">{selected.hopCount}</dd></div>
                  <div className="flex justify-between"><dt className="text-slate-500">Related emails</dt><dd className="text-slate-300">{selected.relatedEmailCount}</dd></div>
                </dl>
                {selected.relatedEmailIds.length > 0 && (
                  <div className="pt-2 border-t border-slate-800 space-y-1">
                    <p className="text-slate-500 text-xs">Related emails</p>
                    {selected.relatedEmailIds.map((id) => (
                      <Link key={id} to={`/email-analysis/${id}`} className="block text-blue-400 hover:text-blue-300 text-xs font-mono truncate">
                        {id}
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-6 py-4 font-medium">IP</th>
                    <th className="px-6 py-4 font-medium">Classification</th>
                    <th className="px-6 py-4 font-medium">Location</th>
                    <th className="px-6 py-4 font-medium">ISP / ASN</th>
                    <th className="px-6 py-4 font-medium">Reverse DNS</th>
                    <th className="px-6 py-4 font-medium">Hops</th>
                    <th className="px-6 py-4 font-medium">First Seen</th>
                    <th className="px-6 py-4 font-medium">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {data.items.map((item: NetworkIntelligenceItem) => {
                    // Three honestly distinct reasons "Location" can be
                    // empty — never collapsed into one ambiguous dash.
                    const locationLabel = !item.isRoutablePublic
                      ? 'Private/Reserved'
                      : item.geolocation
                        ? [item.geolocation.city, item.geolocation.country].filter(Boolean).join(', ') || 'Unknown'
                        : data.geoEnrichmentAvailable
                          ? 'Not yet enriched'
                          : 'Unavailable (MaxMind not configured)';
                    return (
                    <tr
                      key={item.ip}
                      onClick={() => setSelectedIp(item.ip)}
                      className={`cursor-pointer hover:bg-slate-800/30 transition-colors ${selectedIp === item.ip ? 'bg-slate-800/40' : ''}`}
                    >
                      <td className="px-6 py-3 font-mono text-xs text-slate-200">{item.ip}</td>
                      <td className="px-6 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium border ${item.isRoutablePublic ? 'bg-indigo-950/30 text-indigo-400 border-indigo-900/50' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                          {item.classification}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-slate-400">{locationLabel}</td>
                      <td className="px-6 py-3 text-slate-400 truncate max-w-[180px]">{item.geolocation?.isp ?? '—'}</td>
                      <td className="px-6 py-3 text-slate-400 truncate max-w-[160px]" title={item.reverseDns?.join(', ') ?? undefined}>
                        {item.reverseDns && item.reverseDns.length > 0 ? item.reverseDns.join(', ') : 'Not resolved'}
                      </td>
                      <td className="px-6 py-3 text-slate-400">{item.hopCount}</td>
                      <td className="px-6 py-3 text-slate-400">{new Date(item.firstSeen).toLocaleDateString()}</td>
                      <td className="px-6 py-3 text-slate-400">{new Date(item.lastSeen).toLocaleDateString()}</td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {data.truncated && (
              <div className="p-3 text-xs text-amber-400/80 border-t border-slate-800 text-center">
                Showing a bounded sample of relay hops — some older observations may not be reflected.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
