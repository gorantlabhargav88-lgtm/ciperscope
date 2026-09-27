import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Loader2, AlertTriangle, Globe2, ShieldOff, MapPinOff, Crosshair } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { GeoMap } from '../components/geo/GeoMap';
import { IpIntelligencePanel } from '../components/geo/IpIntelligencePanel';
import { filterPublicLocatedIps } from '../components/geo/geoUtils';
import type { NetworkIntelligenceItem } from '@ciperscope/types';

/**
 * Org-wide Geo Intelligence — GET /intelligence/network
 * (services/api/src/modules/intelligence/intelligence.routes.ts).
 * Aggregates every relay-hop source IP observed across this org's emails
 * with the already-persisted GeoLocation/classification/reverse-DNS data.
 * Displays real world map with OpenStreetMap tiles, markers, and accuracy radius.
 */
export const GeoIntelligence = () => {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['network-intelligence'],
    queryFn: () => apiClient.getNetworkIntelligence(),
  });

  const classified = error ? classifyApiError(error, 'geo intelligence') : null;

  // Filter public routable IPs with strictly valid coordinates
  const locatedPublicIps = useMemo(() => filterPublicLocatedIps(data?.items), [data?.items]);

  // Selected item synchronized between Map, Panel, and Table
  const selectedGeoItem = useMemo(
    () => locatedPublicIps.find((i) => i.ip === selectedIp) ?? null,
    [locatedPublicIps, selectedIp]
  );
  const selectedRawItem = useMemo(
    () => data?.items.find((i) => i.ip === selectedIp) ?? null,
    [data?.items, selectedIp]
  );

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Globe2 className="w-8 h-8 text-blue-500" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Geo Intelligence</h1>
          </div>
          <p className="text-slate-400 mt-2">
            Approximate network geolocation for every relay-hop IP observed across your organization's emails.
          </p>
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
        <div
          className={`border p-6 rounded-xl flex items-center gap-4 ${
            classified.kind === 'unauthorized' || classified.kind === 'forbidden'
              ? 'bg-amber-950/30 border-amber-900/50'
              : 'bg-red-950/30 border-red-900/50'
          }`}
        >
          {classified.kind === 'forbidden' ? (
            <ShieldOff className="w-8 h-8 text-amber-500" />
          ) : (
            <AlertTriangle className="w-8 h-8 text-red-500" />
          )}
          <div>
            <h3 className="font-medium text-slate-100">
              {classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load geo intelligence'}
            </h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : !data || data.items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No relay-hop IP addresses have been observed for this organization's emails yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* MaxMind unconfigured warning banner */}
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

          {/* Real Interactive Leaflet World Map (2 columns on large screen) */}
          <div className="lg:col-span-2">
            <GeoMap
              items={locatedPublicIps}
              selectedIp={selectedIp}
              onSelectIp={(ip) => setSelectedIp(ip)}
            />
            <div className="flex items-center justify-between text-[11px] text-slate-500 px-2 mt-2">
              <span>
                Interactive OpenStreetMap · {locatedPublicIps.length} public located IP{locatedPublicIps.length === 1 ? '' : 's'} · click a marker to inspect
              </span>
              <span>Coordinates provided by MaxMind GeoIP2</span>
            </div>
          </div>

          {/* Professional Right-Side IP Intelligence Panel (1 column on large screen) */}
          <div className="lg:col-span-1">
            <IpIntelligencePanel
              selectedItem={selectedGeoItem}
              rawItem={selectedRawItem}
              onSelectIp={(ip) => setSelectedIp(ip)}
            />
          </div>

          {/* Relay Hop Observations Table */}
          <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg mt-2">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
              <div>
                <h3 className="text-base font-semibold text-white">Observed Relay Hops ({data.items.length})</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  All relay-hop IP addresses extracted from email headers. Select any row to pinpoint it on the world map.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-6 py-4 font-medium">IP Address</th>
                    <th className="px-6 py-4 font-medium">Classification</th>
                    <th className="px-6 py-4 font-medium">Location</th>
                    <th className="px-6 py-4 font-medium">ISP / Organization</th>
                    <th className="px-6 py-4 font-medium">Reverse DNS</th>
                    <th className="px-6 py-4 font-medium">Hops</th>
                    <th className="px-6 py-4 font-medium">First Seen</th>
                    <th className="px-6 py-4 font-medium">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {data.items.map((item: NetworkIntelligenceItem) => {
                    const locationLabel = !item.isRoutablePublic
                      ? 'Private / Reserved'
                      : item.geolocation
                        ? [item.geolocation.city, item.geolocation.country].filter(Boolean).join(', ') || 'Unknown'
                        : data.geoEnrichmentAvailable
                          ? 'Not yet enriched'
                          : 'Unavailable (MaxMind not configured)';

                    const isLocated = item.isRoutablePublic && item.geolocation?.latitude != null && item.geolocation?.longitude != null;
                    const isSelected = selectedIp === item.ip;

                    return (
                      <tr
                        key={item.ip}
                        onClick={() => setSelectedIp(item.ip)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-sky-950/40 border-l-4 border-sky-400'
                            : 'hover:bg-slate-800/30'
                        }`}
                      >
                        <td className="px-6 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-slate-200">{item.ip}</span>
                            {isLocated && (
                              <span title="Geolocated on world map">
                                <Crosshair className="w-3.5 h-3.5 text-sky-400" />
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-medium border ${
                              item.isRoutablePublic
                                ? 'bg-indigo-950/30 text-indigo-400 border-indigo-900/50'
                                : 'bg-slate-800 text-slate-500 border-slate-700'
                            }`}
                          >
                            {item.classification}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-slate-300 font-medium">{locationLabel}</td>
                        <td className="px-6 py-3 text-slate-400 truncate max-w-[180px]">
                          {item.geolocation?.isp ?? '—'}
                        </td>
                        <td
                          className="px-6 py-3 text-slate-400 truncate max-w-[160px]"
                          title={item.reverseDns?.join(', ') ?? undefined}
                        >
                          {item.reverseDns && item.reverseDns.length > 0 ? item.reverseDns.join(', ') : 'Not resolved'}
                        </td>
                        <td className="px-6 py-3 text-slate-400 font-mono">{item.hopCount}</td>
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
