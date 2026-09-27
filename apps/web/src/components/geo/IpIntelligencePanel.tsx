import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Radio,
  Server,
  Clock,
  Mail,
  Copy,
  Check,
  Compass,
  Building,
  Info,
  ExternalLink,
} from 'lucide-react';
import type { ValidatedGeoItem } from './geoUtils';
import { formatCoordinates, formatAccuracyRadius } from './geoUtils';
import type { NetworkIntelligenceItem } from '@ciperscope/types';

interface IpIntelligencePanelProps {
  selectedItem: ValidatedGeoItem | null;
  rawItem: NetworkIntelligenceItem | null;
  onSelectIp?: (ip: string) => void;
}

export const IpIntelligencePanel = ({ selectedItem, rawItem }: IpIntelligencePanelProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopyIp = () => {
    if (!rawItem && !selectedItem) return;
    const ip = selectedItem?.ip || rawItem?.ip;
    if (!ip) return;
    navigator.clipboard.writeText(ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!rawItem && !selectedItem) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-sm flex flex-col items-center justify-center text-center h-[520px] text-slate-500 gap-3">
        <Compass className="w-10 h-10 text-slate-700 animate-spin-slow" />
        <h4 className="text-slate-300 font-medium">Select an IP for Intelligence</h4>
        <p className="text-xs text-slate-500 max-w-[240px]">
          Click on any marker on the interactive world map or select a row from the relay table below to inspect its geographic forensic profile.
        </p>
      </div>
    );
  }

  const ip = selectedItem?.ip || rawItem!.ip;
  const classification = selectedItem?.classification || rawItem!.classification;
  const isRoutable = selectedItem?.isRoutablePublic ?? rawItem!.isRoutablePublic;
  const country = selectedItem?.country || rawItem?.geolocation?.country || 'Unknown';
  const region = selectedItem?.region || rawItem?.geolocation?.region || 'Unknown';
  const city = selectedItem?.city || rawItem?.geolocation?.city || 'Unknown';
  const locationLabel = [city !== 'Unknown' ? city : null, region !== 'Unknown' ? region : null, country !== 'Unknown' ? country : null]
    .filter(Boolean)
    .join(', ') || 'Unknown Location';
  const asn = selectedItem?.asn || rawItem?.geolocation?.asn || '—';
  const isp = selectedItem?.isp || rawItem?.geolocation?.isp || '—';
  const provider = selectedItem?.provider || rawItem?.geolocation?.provider || 'MaxMind';
  const timeZone = selectedItem?.timeZone || rawItem?.geolocation?.timeZone || '—';
  const lastSeen = selectedItem?.lastSeen || rawItem?.lastSeen;
  const firstSeen = selectedItem?.firstSeen || rawItem?.firstSeen;
  const hopCount = selectedItem?.hopCount ?? rawItem?.hopCount ?? 0;
  const relatedEmailIds = selectedItem?.relatedEmailIds || rawItem?.relatedEmailIds || [];
  const reverseDns = selectedItem?.reverseDns || rawItem?.reverseDns || [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 text-sm flex flex-col h-[520px] overflow-y-auto shadow-xl">
      {/* Header with IP and copy button */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-lg font-bold text-white tracking-tight">{ip}</span>
            <button
              onClick={handleCopyIp}
              title="Copy IP address"
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-[11px] px-2 py-0.5 rounded font-medium border ${isRoutable ? 'bg-indigo-950/40 text-indigo-300 border-indigo-900/60' : 'bg-slate-800 text-slate-400 border-slate-700'}`}>
              {classification}
            </span>
            <span className="text-[11px] text-slate-500">
              {isRoutable ? 'Public Internet' : 'Non-routable'}
            </span>
          </div>
        </div>

        <div className="text-right">
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-1 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-900/50">
            {provider}
          </span>
        </div>
      </div>

      {/* Approximate Location Notice */}
      <div className="mt-3 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-start gap-2 text-xs">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-[11px] text-slate-300 leading-relaxed">
          <span className="font-semibold text-cyan-300">Approximate Location</span>
          <p className="text-slate-400 mt-0.5">
            IP geolocation identifies relay/carrier point-of-presence, not user physical coordinates.
          </p>
        </div>
      </div>

      {/* Key Attribute List */}
      <div className="mt-4 space-y-2.5 flex-1 overflow-y-auto pr-1">
        {/* Geographic Information */}
        <div className="space-y-1.5 text-xs">
          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-blue-400" /> Location
            </span>
            <span className="font-medium text-slate-200 text-right truncate max-w-[180px]" title={locationLabel}>
              {locationLabel}
            </span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400">Country</span>
            <span className="text-slate-200 font-medium">{country}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400">Region / State</span>
            <span className="text-slate-300">{region}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400">City</span>
            <span className="text-slate-300">{city}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Compass className="w-3.5 h-3.5 text-purple-400" /> Coordinates
            </span>
            <span className="font-mono text-slate-200 text-[11px]">
              {selectedItem ? formatCoordinates(selectedItem.latitude, selectedItem.longitude) : 'Unavailable'}
            </span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-cyan-400" /> Accuracy Radius
            </span>
            <span className="text-slate-300 text-[11px] font-medium">
              {selectedItem ? formatAccuracyRadius(selectedItem.accuracyRadiusKm) : '—'}
            </span>
          </div>
        </div>

        {/* Network & Infrastructure */}
        <div className="pt-2 space-y-1.5 text-xs">
          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-emerald-400" /> ASN
            </span>
            <span className="font-mono text-slate-200">{asn}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Building className="w-3.5 h-3.5 text-amber-400" /> ISP / Organization
            </span>
            <span className="text-slate-300 truncate max-w-[170px]" title={isp}>
              {isp}
            </span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400">Time Zone</span>
            <span className="text-slate-300 font-mono text-[11px]">{timeZone}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400">Total Relay Hops</span>
            <span className="text-slate-200 font-mono">{hopCount}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" /> First Observed
            </span>
            <span className="text-slate-300 text-[11px]">
              {firstSeen ? new Date(firstSeen).toLocaleString() : '—'}
            </span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/50">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" /> Last Observed
            </span>
            <span className="text-slate-300 text-[11px]">
              {lastSeen ? new Date(lastSeen).toLocaleString() : '—'}
            </span>
          </div>
        </div>

        {/* Reverse DNS */}
        {reverseDns && reverseDns.length > 0 && (
          <div className="pt-2 text-xs">
            <span className="text-slate-400 block mb-1">Reverse DNS (PTR):</span>
            <div className="space-y-1">
              {reverseDns.map((ptr, idx) => (
                <div key={idx} className="font-mono text-[11px] text-slate-300 bg-slate-950/40 p-1 rounded border border-slate-800/60 truncate" title={ptr}>
                  {ptr}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Related Emails */}
        {relatedEmailIds.length > 0 && (
          <div className="pt-2 text-xs">
            <span className="text-slate-400 flex items-center gap-1.5 mb-1.5">
              <Mail className="w-3.5 h-3.5 text-blue-400" /> Associated Evidence ({relatedEmailIds.length})
            </span>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {relatedEmailIds.map((id) => (
                <Link
                  key={id}
                  to={`/email-analysis/${id}`}
                  className="flex items-center justify-between text-blue-400 hover:text-blue-300 text-xs font-mono bg-slate-950/40 hover:bg-slate-800/40 p-1.5 rounded border border-slate-800/60 transition-colors"
                >
                  <span className="truncate">{id}</span>
                  <ExternalLink className="w-3 h-3 shrink-0 ml-1 opacity-70" />
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
