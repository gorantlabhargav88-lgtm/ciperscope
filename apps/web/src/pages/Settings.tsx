import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Loader2, AlertTriangle, ShieldOff, Settings as SettingsIcon, Check, Plug } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import type { AutoCaseRiskThreshold } from '@ciperscope/types';

const RISK_OPTIONS: { value: AutoCaseRiskThreshold; label: string }[] = [
  { value: 'NEVER', label: 'Never auto-create a case' },
  { value: 'CRITICAL', label: 'CRITICAL risk only' },
  { value: 'HIGH', label: 'HIGH risk and above' },
  { value: 'MEDIUM', label: 'MEDIUM risk and above' },
  { value: 'LOW', label: 'LOW risk and above' },
];

/**
 * Organization Settings — GET/PATCH /settings
 * (services/api/src/modules/settings/settings.routes.ts). Every field here
 * is backed by a real column (Organization.name) or a real, previously
 * unused SystemSetting row — nothing is shown that the backend doesn't
 * actually persist and enforce/consume.
 */
export const Settings = () => {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ['org-settings'],
    queryFn: () => apiClient.getOrgSettings(),
  });

  const [displayName, setDisplayName] = useState('');
  const [notifyOnCriticalCase, setNotifyOnCriticalCase] = useState(true);
  const [notifyOnThreatDetected, setNotifyOnThreatDetected] = useState(true);
  const [autoCaseRiskThreshold, setAutoCaseRiskThreshold] = useState<AutoCaseRiskThreshold>('NEVER');
  const [evidenceRetentionDays, setEvidenceRetentionDays] = useState(365);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!data) return;
    setDisplayName(data.organization.name);
    setNotifyOnCriticalCase(data.preferences.notifyOnCriticalCase);
    setNotifyOnThreatDetected(data.preferences.notifyOnThreatDetected);
    setAutoCaseRiskThreshold(data.preferences.autoCaseRiskThreshold);
    setEvidenceRetentionDays(data.preferences.evidenceRetentionDays);
  }, [data]);

  const isDirty = data
    ? displayName !== data.organization.name
      || notifyOnCriticalCase !== data.preferences.notifyOnCriticalCase
      || notifyOnThreatDetected !== data.preferences.notifyOnThreatDetected
      || autoCaseRiskThreshold !== data.preferences.autoCaseRiskThreshold
      || evidenceRetentionDays !== data.preferences.evidenceRetentionDays
    : false;

  const mutation = useMutation({
    mutationFn: () => apiClient.updateOrgSettings({
      ...(data && displayName !== data.organization.name ? { displayName } : {}),
      ...(data && notifyOnCriticalCase !== data.preferences.notifyOnCriticalCase ? { notifyOnCriticalCase } : {}),
      ...(data && notifyOnThreatDetected !== data.preferences.notifyOnThreatDetected ? { notifyOnThreatDetected } : {}),
      ...(data && autoCaseRiskThreshold !== data.preferences.autoCaseRiskThreshold ? { autoCaseRiskThreshold } : {}),
      ...(data && evidenceRetentionDays !== data.preferences.evidenceRetentionDays ? { evidenceRetentionDays } : {}),
    }),
    onSuccess: (res) => {
      queryClient.setQueryData(['org-settings'], res);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    },
  });

  const handleReset = () => {
    if (!data) return;
    setDisplayName(data.organization.name);
    setNotifyOnCriticalCase(data.preferences.notifyOnCriticalCase);
    setNotifyOnThreatDetected(data.preferences.notifyOnThreatDetected);
    setAutoCaseRiskThreshold(data.preferences.autoCaseRiskThreshold);
    setEvidenceRetentionDays(data.preferences.evidenceRetentionDays);
  };

  const classified = error ? classifyApiError(error, 'organization settings') : null;

  return (
    <div className="space-y-6 pb-20 max-w-3xl">
      <header className="mb-2 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <SettingsIcon className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Settings</h1>
        </div>
        <p className="text-slate-400 mt-2">Organization profile and platform preferences.</p>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load settings'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : data ? (
        <div className="space-y-6">
          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="font-medium text-slate-200">Organization Profile</h2>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Organization name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-600"
              />
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div><span className="text-slate-500 block mb-0.5">Domain</span><span className="text-slate-300">{data.organization.domain ?? 'Not set'}</span></div>
              <div><span className="text-slate-500 block mb-0.5">Created</span><span className="text-slate-300">{new Date(data.organization.createdAt).toLocaleDateString()}</span></div>
            </div>
          </section>

          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="font-medium text-slate-200">Notification Preferences</h2>
            <ToggleRow
              label="Notify on critical case"
              description="Governs whether critical-case webhook events are considered enabled at the org level."
              checked={notifyOnCriticalCase}
              onChange={setNotifyOnCriticalCase}
            />
            <ToggleRow
              label="Notify on threat detected"
              description="Governs whether threat-detection webhook events are considered enabled at the org level."
              checked={notifyOnThreatDetected}
              onChange={setNotifyOnThreatDetected}
            />
            <p className="text-xs text-slate-500 flex items-center gap-1.5">
              <Plug className="w-3.5 h-3.5" />
              Actual delivery still requires a configured webhook subscribed to these events — see{' '}
              <Link to="/webhooks" className="text-blue-400 hover:text-blue-300">Webhooks</Link>.
            </p>
          </section>

          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="font-medium text-slate-200">Threat Analysis Preferences</h2>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Auto-create a case when risk reaches</label>
              <select
                value={autoCaseRiskThreshold}
                onChange={(e) => setAutoCaseRiskThreshold(e.target.value as AutoCaseRiskThreshold)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-600"
              >
                {RISK_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </section>

          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="font-medium text-slate-200">Retention</h2>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Evidence retention (days)</label>
              <input
                type="number"
                min={30}
                max={3650}
                value={evidenceRetentionDays}
                onChange={(e) => setEvidenceRetentionDays(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-600"
              />
              <p className="text-xs text-slate-500 mt-1">
                Stored as a preference. No automated purge job exists in this deployment yet — this does not enforce deletion.
              </p>
            </div>
          </section>

          {mutation.isError && (
            <div className="text-sm text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-3">
              {classifyApiError(mutation.error, 'organization settings').message}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 sticky bottom-4 bg-slate-950/80 backdrop-blur border border-slate-800 rounded-lg p-3">
            {saved && <span className="text-xs text-emerald-400 flex items-center gap-1"><Check className="w-3.5 h-3.5" /> Saved</span>}
            <button
              onClick={handleReset}
              disabled={!isDirty || mutation.isPending}
              className="text-sm px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 disabled:opacity-40"
            >
              Reset
            </button>
            <button
              onClick={() => mutation.mutate()}
              disabled={!isDirty || mutation.isPending}
              className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 flex items-center gap-1.5"
            >
              {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Save Changes
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
};

function ToggleRow({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <div className="text-sm text-slate-200">{label}</div>
        <div className="text-xs text-slate-500">{description}</div>
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`w-10 h-6 rounded-full transition-colors relative shrink-0 ${checked ? 'bg-emerald-600' : 'bg-slate-700'}`}
      >
        <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-5' : 'translate-x-1'}`} />
      </button>
    </div>
  );
}
