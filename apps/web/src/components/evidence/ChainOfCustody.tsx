import { useState } from 'react';
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';
import { buildCustodyChain } from '../../features/evidence/transformCustody';
import type { Evidence } from '@ciperscope/types';

export interface ChainOfCustodyProps {
  caseId: string;
  evidence: Evidence;
}

type LoadState = 'collapsed' | 'loading' | 'loaded' | 'error' | 'unauthorized';

/**
 * Renders Evidence integrity fields plus its real chain-of-custody history
 * (GET /cases/:caseId/evidence/:evidenceId/custody). Fetches lazily on
 * first expand rather than eagerly for every evidence item in a list —
 * avoids an N+1 fan-out when several ChainOfCustody instances render at
 * once (e.g. one per evidence row).
 *
 * Blockchain anchoring is always shown as "Not configured" — no endpoint
 * exposes BlockchainAnchor data today, and CiperScope has no real
 * anchoring implementation (schema/demo data only). This is never
 * presented as verified.
 */
export function ChainOfCustody({ caseId, evidence }: ChainOfCustodyProps) {
  const [state, setState] = useState<LoadState>('collapsed');
  const [chain, setChain] = useState<ReturnType<typeof buildCustodyChain>>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const expand = async () => {
    if (state === 'loading' || state === 'loaded') {
      setState(state === 'loaded' ? 'collapsed' : state);
      return;
    }
    setState('loading');
    try {
      const res = await apiClient.getEvidenceCustody(caseId, evidence.id);
      setChain(buildCustodyChain(res.items));
      setState('loaded');
    } catch (err) {
      const classified = classifyApiError(err, "evidence's chain of custody");
      setState(classified.kind === 'error' ? 'error' : 'unauthorized');
      setErrorMessage(classified.message);
    }
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
      <div className="p-3 text-xs grid grid-cols-2 gap-2">
        <div className="flex justify-between"><span className="text-slate-500">Evidence ID</span><span className="text-slate-300 font-mono truncate max-w-[140px]" title={evidence.id}>{evidence.id}</span></div>
        <div className="flex justify-between"><span className="text-slate-500">Type</span><span className="text-slate-300">{evidence.type}</span></div>
        <div className="flex justify-between"><span className="text-slate-500">SHA-256 Integrity</span><span className="text-slate-300 font-mono truncate max-w-[140px]" title={evidence.sha256}>{evidence.sha256 || 'Not available'}</span></div>
        <div className="flex justify-between"><span className="text-slate-500">Status</span><span className="text-slate-300">{evidence.status}</span></div>
        <div className="flex justify-between"><span className="text-slate-500">Collected</span><span className="text-slate-300">{new Date(evidence.collectionTime).toLocaleString()}</span></div>
        <div className="flex justify-between"><span className="text-slate-500">Blockchain Anchoring</span><span className="text-slate-500 italic">Not configured</span></div>
      </div>

      <button
        onClick={expand}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-slate-400 hover:text-slate-200 border-t border-slate-800 transition-colors"
      >
        <span>Chain of Custody</span>
        {state === 'loading' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : state === 'loaded' ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
      </button>

      {(state === 'error' || state === 'unauthorized') && (
        <div className="px-3 pb-3 text-xs text-rose-400">{errorMessage}</div>
      )}

      {state === 'loaded' && (
        chain.length === 0 ? (
          <div className="px-3 pb-3 text-xs text-slate-600">No custody events recorded.</div>
        ) : (
          <div className="px-3 pb-3 space-y-2">
            {chain.map((node) => (
              <div key={node.id} className="bg-slate-900 border border-slate-800 rounded p-2 text-[11px] flex flex-col gap-1">
                <div className="flex justify-between items-center">
                  <span className="font-semibold text-slate-200">{node.action}</span>
                  <span className="text-slate-500">{node.timestamp ? new Date(node.timestamp).toLocaleString() : 'Not available'}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Actor: <span className="text-slate-300">{node.actorLabel}</span></span>
                  <span>Previous state: <span className="text-slate-300">{node.previousAction ?? 'Not available'}</span></span>
                </div>
                {node.description && <div className="text-slate-500 italic">{node.description}</div>}
              </div>
            ))}
          </div>
        )
      )}
    </div>
  );
}
