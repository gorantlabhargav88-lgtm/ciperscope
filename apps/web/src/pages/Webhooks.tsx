import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Loader2, AlertTriangle, Webhook as WebhookIcon, ShieldOff, Plus, Trash2, Send, Copy, Check } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { WEBHOOK_EVENT_TYPES, type WebhookEventType } from '@ciperscope/types';

/**
 * Webhook management — full CRUD against services/api/src/modules/webhook/
 * webhook.routes.ts (INTEGRATION_MANAGE-gated, tenant-isolated, already
 * covered by webhook.integration.test.ts on the backend). Previously had
 * zero frontend surface despite the backend supporting create/list/update/
 * delete/test-delivery.
 */
export const Webhooks = () => {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<WebhookEventType[]>([WEBHOOK_EVENT_TYPES[0]]);
  const [createError, setCreateError] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);
  const [testResult, setTestResult] = useState<{ id: string; message: string } | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => apiClient.getWebhooks(),
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.createWebhook({ url, events }),
    onSuccess: (res) => {
      setNewSecret(res.secret);
      setUrl('');
      setCreateError(null);
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
    },
    onError: (err) => setCreateError(err instanceof Error ? err.message : 'Failed to create webhook'),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => apiClient.updateWebhook(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteWebhook(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => apiClient.testWebhook(id),
    onSuccess: (res, id) => setTestResult({ id, message: res.message }),
  });

  const classified = error ? classifyApiError(error, 'webhooks') : null;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <WebhookIcon className="w-8 h-8 text-blue-500" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Webhooks</h1>
          </div>
          <p className="text-slate-400 mt-2">Deliver real-time event notifications to external systems.</p>
        </div>
        <button
          onClick={() => { setShowCreate((v) => !v); setNewSecret(null); setCreateError(null); }}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> New Webhook
        </button>
      </header>

      {showCreate && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          {newSecret ? (
            <div className="space-y-3">
              <p className="text-sm text-amber-300">Webhook created. This secret is shown once — copy it now; it cannot be retrieved again.</p>
              <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2">
                <code className="text-xs text-slate-300 font-mono break-all flex-1">{newSecret}</code>
                <button
                  onClick={() => { navigator.clipboard.writeText(newSecret); setSecretCopied(true); setTimeout(() => setSecretCopied(false), 2000); }}
                  className="text-slate-400 hover:text-slate-200 flex-shrink-0"
                  aria-label="Copy secret"
                >
                  {secretCopied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <button onClick={() => { setShowCreate(false); setNewSecret(null); }} className="text-sm text-slate-400 hover:text-slate-200">Done</button>
            </div>
          ) : (
            <>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Endpoint URL</label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-system.example.com/webhooks/ciperscope"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-600"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Events</label>
                <div className="space-y-1.5">
                  {WEBHOOK_EVENT_TYPES.map((evt) => (
                    <label key={evt} className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={events.includes(evt)}
                        onChange={(e) => setEvents((prev) => (e.target.checked ? [...prev, evt] : prev.filter((x) => x !== evt)))}
                        className="rounded border-slate-700"
                      />
                      {evt}
                    </label>
                  ))}
                </div>
              </div>
              {createError && <p className="text-sm text-red-400">{createError}</p>}
              <button
                onClick={() => createMutation.mutate()}
                disabled={!url || events.length === 0 || createMutation.isPending}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
              >
                {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />} Create Webhook
              </button>
            </>
          )}
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load webhooks'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 font-medium">URL</th>
                <th className="px-6 py-4 font-medium">Events</th>
                <th className="px-6 py-4 font-medium">Status</th>
                <th className="px-6 py-4 font-medium">Created</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {data?.webhooks?.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-slate-500 italic">
                    No webhooks configured.
                  </td>
                </tr>
              ) : (
                data?.webhooks?.map((w) => (
                  <tr key={w.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 font-mono text-xs text-slate-300 max-w-xs truncate" title={w.url}>{w.url}</td>
                    <td className="px-6 py-4 text-slate-400 text-xs">{w.events.join(', ')}</td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => toggleMutation.mutate({ id: w.id, enabled: !w.enabled })}
                        className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${w.enabled ? 'bg-emerald-950/30 text-emerald-400 border-emerald-900/50 hover:bg-emerald-950/50' : 'bg-slate-800 text-slate-500 border-slate-700 hover:bg-slate-700'}`}
                      >
                        {w.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </td>
                    <td className="px-6 py-4 text-slate-400">{new Date(w.createdAt).toLocaleDateString()}</td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-3">
                        <button
                          onClick={() => testMutation.mutate(w.id)}
                          disabled={testMutation.isPending}
                          className="text-blue-400 hover:text-blue-300 inline-flex items-center text-xs font-medium transition-colors"
                          title="Send a test delivery"
                        >
                          <Send className="w-3.5 h-3.5 mr-1" /> Test
                        </button>
                        <button
                          onClick={() => { if (confirm('Delete this webhook? This cannot be undone.')) deleteMutation.mutate(w.id); }}
                          className="text-red-400 hover:text-red-300 inline-flex items-center text-xs font-medium transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5 mr-1" /> Delete
                        </button>
                      </div>
                      {testResult?.id === w.id && (
                        <p className="text-[11px] text-emerald-400 mt-1">{testResult.message}</p>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>
        </div>
      )}
    </div>
  );
};
