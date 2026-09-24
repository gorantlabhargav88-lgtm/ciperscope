import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Loader2, AlertTriangle, Archive, ChevronRight, ShieldOff } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';

const TYPE_STYLES: Record<string, string> = {
  RAW_EMAIL: 'bg-indigo-950/30 text-indigo-400 border-indigo-900/50',
  ATTACHMENT: 'bg-orange-950/30 text-orange-400 border-orange-900/50',
  SCREENSHOT: 'bg-cyan-950/30 text-cyan-400 border-cyan-900/50',
  REPORT: 'bg-emerald-950/30 text-emerald-400 border-emerald-900/50',
  LOG: 'bg-slate-800 text-slate-400 border-slate-700',
};

/**
 * Org-wide Evidence Vault — GET /evidence (services/api/src/modules/
 * evidence/evidence.routes.ts). Lists every evidence item across all cases
 * in the current organization, cursor-paginated by the backend. Links to
 * EvidenceDetail for the per-item integrity/verification view.
 */
export const EvidenceVault = () => {
  const [cursor, setCursor] = useState<string | undefined>();

  const { data, isLoading, error } = useQuery({
    queryKey: ['evidence-vault', cursor],
    queryFn: () => apiClient.getEvidenceList(20, cursor),
  });

  const classified = error ? classifyApiError(error, 'evidence vault') : null;

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Archive className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Evidence Vault</h1>
        </div>
        <p className="text-slate-400 mt-2">All collected forensic evidence across cases, with cryptographic integrity verification.</p>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className={classified.kind === 'forbidden' ? 'text-amber-200 font-medium' : 'text-red-200 font-medium'}>
              {classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load evidence vault'}
            </h3>
            <p className={classified.kind === 'forbidden' ? 'text-amber-400/80 text-sm' : 'text-red-400/80 text-sm'}>{classified.message}</p>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 font-medium">Filename</th>
                <th className="px-6 py-4 font-medium">Type</th>
                <th className="px-6 py-4 font-medium">SHA-256</th>
                <th className="px-6 py-4 font-medium">Size</th>
                <th className="px-6 py-4 font-medium">Collected</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {data?.items?.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-500 italic">
                    No evidence collected yet.
                  </td>
                </tr>
              ) : (
                data?.items?.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-4 font-medium text-slate-200 max-w-xs truncate" title={e.filename ?? undefined}>
                      {e.filename ?? <span className="text-slate-600 italic">Unnamed</span>}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded text-xs font-medium border ${TYPE_STYLES[e.type] ?? 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                        {e.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-slate-500 max-w-[160px] truncate" title={e.sha256}>{e.sha256}</td>
                    <td className="px-6 py-4 text-slate-400">{e.sizeBytes != null ? `${(e.sizeBytes / 1024).toFixed(1)} KB` : 'Unknown'}</td>
                    <td className="px-6 py-4 text-slate-400">{new Date(e.collectionTime).toLocaleDateString()}</td>
                    <td className="px-6 py-4 text-right">
                      <Link to={`/evidence/${e.id}`} className="text-blue-400 hover:text-blue-300 inline-flex items-center text-xs font-medium transition-colors">
                        Verify <ChevronRight className="w-4 h-4 ml-1" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>

          {data?.nextCursor && (
            <div className="p-4 border-t border-slate-800 flex justify-center">
              <button
                onClick={() => setCursor(data.nextCursor!)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm font-medium transition-colors border border-slate-700 hover:border-slate-600"
              >
                Load More
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
