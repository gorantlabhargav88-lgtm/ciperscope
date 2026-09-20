import { useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, Clock, Loader2 } from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';
import { prepareCaseTimeline, type DisplayTimelineEvent } from '../../features/case-timeline/transformCaseTimeline';

export interface CaseForensicTimelineProps {
  caseId: string;
}

type LoadState = 'loading' | 'loaded' | 'empty' | 'error' | 'unauthorized';

/**
 * Renders the case's real, backend-sourced activity trail
 * (GET /cases/:caseId/timeline — AuditLog rows scoped to this case).
 *
 * This is CiperScope's actual case-level forensic timeline, not a
 * synthesized cross-system one: email-level events (ingestion,
 * authentication, ML classification, CTI enrichment) are logged against
 * the email, not the case, so they will not appear here (see
 * packages/types/src/caseTimeline.ts). Nothing is fabricated to fill that
 * gap — only real events the backend returns are rendered.
 */
export function CaseForensicTimeline({ caseId }: CaseForensicTimelineProps) {
  const [state, setState] = useState<LoadState>('loading');
  const [events, setEvents] = useState<DisplayTimelineEvent[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    // Re-entering 'loading' on a caseId change (rather than only relying on
    // the initial state) needs a synchronous reset here since this effect
    // itself is what reacts to that change; deriving it during render isn't
    // possible without also caching the previous caseId.
    setState('loading');

    apiClient
      .getCaseTimeline(caseId)
      .then((res) => {
        if (cancelled) return;
        const prepared = prepareCaseTimeline(res.items);
        setEvents(prepared);
        setState(prepared.length === 0 ? 'empty' : 'loaded');
      })
      .catch((err) => {
        if (cancelled) return;
        const classified = classifyApiError(err, 'case timeline');
        setState(classified.kind === 'error' ? 'error' : 'unauthorized');
        setErrorMessage(classified.message);
      });

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  if (state === 'loading') {
    return (
      <div className="flex items-center justify-center py-8 text-slate-500 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading case timeline…
      </div>
    );
  }

  if (state === 'error' || state === 'unauthorized') {
    return <div className="p-4 text-sm text-rose-400 border border-rose-900/50 bg-rose-950/20 rounded-lg">{errorMessage}</div>;
  }

  if (state === 'empty') {
    return <div className="text-sm text-slate-500 text-center py-4">No case activity recorded yet.</div>;
  }

  return (
    <div className="space-y-2">
      {events.map((event) => {
        const isExpanded = expandedId === event.id;
        const hasDetails = event.metadata && Object.keys(event.metadata).length > 0;
        return (
          <div key={event.id} className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
            <button
              onClick={() => hasDetails && setExpandedId(isExpanded ? null : event.id)}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left ${hasDetails ? 'cursor-pointer hover:bg-slate-900/50' : 'cursor-default'}`}
            >
              <div className="flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="text-slate-200 font-medium">{event.title}</span>
                {event.actorId && <span className="text-slate-600 font-mono text-[10px]">by {event.actorId}</span>}
              </div>
              <div className="flex items-center gap-2 text-slate-500">
                <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Not available'}</span>
                {hasDetails && (isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />)}
              </div>
            </button>
            {isExpanded && hasDetails && (
              <pre className="px-3 pb-3 text-[10px] text-slate-500 overflow-x-auto">{JSON.stringify(event.metadata, null, 2)}</pre>
            )}
          </div>
        );
      })}
    </div>
  );
}
