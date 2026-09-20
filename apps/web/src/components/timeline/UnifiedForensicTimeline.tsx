import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';
import { prepareForensicTimeline, filterByCategory } from '../../features/forensic-timeline/prepareForensicTimeline';
import { isActionableEvent } from '../../features/forensic-timeline/actionableEvents';
import { buildDecisionIndex, findDecisionForTarget } from '../../features/forensic-timeline/matchDecisions';
import { EventDetailPanel } from './EventDetailPanel';
import { AnalystActionDialog } from './AnalystActionDialog';
import type { AnalystDecision, AnalystDecisionType, ForensicTimelineCategory, ForensicTimelineEvent, InvestigationSummary, ThreatPriority } from '@ciperscope/types';

export interface UnifiedForensicTimelineProps {
  caseId: string;
}

type LoadState = 'loading' | 'loaded' | 'empty' | 'error' | 'unauthorized';

const PRIORITY_STYLES: Record<ThreatPriority, string> = {
  P1: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  P2: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  P3: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
};

const CATEGORY_LABELS: Record<ForensicTimelineCategory, string> = {
  EMAIL: 'Email',
  AUTHENTICATION: 'Authentication',
  THREAT_INTELLIGENCE: 'Threat Intelligence',
  ML: 'ML',
  INVESTIGATION: 'Investigation',
  EVIDENCE: 'Evidence',
  ANALYST: 'Analyst',
  SYSTEM: 'System',
};

const DECISION_ACTIONS: { decision: AnalystDecisionType; label: string }[] = [
  { decision: 'REVIEWED', label: 'Review' },
  { decision: 'CONFIRMED', label: 'Confirm' },
  { decision: 'ESCALATED', label: 'Escalate' },
  { decision: 'DISMISSED', label: 'Dismiss' },
];

function EventLink({ event }: { event: ForensicTimelineEvent }) {
  // Only link to routes that actually render real content for the target
  // entity — /evidence/:id and a standalone case workspace route don't
  // exist as real pages today (see CIPERSCOPE_NEXT_PHASE_AUDIT.md), so
  // this deliberately does not link there.
  if (event.emailId) {
    return (
      <Link to={`/email-analysis/${event.emailId}`} className="text-indigo-400 hover:text-indigo-300 underline decoration-dotted">
        View email
      </Link>
    );
  }
  if (event.investigationId) {
    return (
      <Link to={`/cases/${event.caseId}/investigations/${event.investigationId}/workspace`} className="text-indigo-400 hover:text-indigo-300 underline decoration-dotted">
        View investigation
      </Link>
    );
  }
  return null;
}

/**
 * The real, correlated unified forensic timeline (Phase 5), now upgraded
 * (Phase 6) into a genuine analyst action surface: actionable events
 * (EMAIL/AUTHENTICATION/THREAT_INTELLIGENCE/ML) expose real
 * Review/Confirm/Escalate/Dismiss controls backed by the existing
 * POST .../decisions endpoint — never a frontend-only authorization
 * decision, and P1/P2/P3 is never auto-converted into a decision.
 */
export function UnifiedForensicTimeline({ caseId }: UnifiedForensicTimelineProps) {
  const [state, setState] = useState<LoadState>('loading');
  const [rawEvents, setRawEvents] = useState<ForensicTimelineEvent[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [decisionIndex, setDecisionIndex] = useState<Map<string, AnalystDecision>>(new Map());
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<ForensicTimelineCategory | 'ALL'>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<{ event: ForensicTimelineEvent; action: AnalystDecisionType } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    setActiveCategory('ALL');

    // One aggregated timeline request + one investigations request + one
    // decisions request per investigation (typically just one) — bounded
    // by investigation count, never by timeline event count.
    Promise.all([apiClient.getCaseForensicTimeline(caseId), apiClient.getCaseInvestigations(caseId)])
      .then(async ([timelineRes, investigationsRes]) => {
        if (cancelled) return;
        setRawEvents(timelineRes.items);
        setInvestigations(investigationsRes.items);
        setState(timelineRes.items.length === 0 ? 'empty' : 'loaded');

        if (investigationsRes.items.length > 0) {
          const decisionLists = await Promise.all(
            investigationsRes.items.map((inv) =>
              apiClient
                .getInvestigationDecisions(caseId, inv.id)
                .then((r) => r.items)
                .catch(() => [] as AnalystDecision[])
            )
          );
          if (!cancelled) setDecisionIndex(buildDecisionIndex(decisionLists));
        }
      })
      .catch((err) => {
        if (cancelled) return;
        const classified = classifyApiError(err, 'forensic timeline');
        setState(classified.kind === 'error' ? 'error' : 'unauthorized');
        setErrorMessage(classified.message);
      });

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  const prepared = useMemo(() => prepareForensicTimeline(rawEvents), [rawEvents]);
  const visibleEvents = useMemo(() => filterByCategory(prepared.events, activeCategory), [prepared.events, activeCategory]);

  const refreshDecisionsFor = async (investigationId: string) => {
    try {
      const res = await apiClient.getInvestigationDecisions(caseId, investigationId);
      setDecisionIndex((prev) => buildDecisionIndex([Array.from(prev.values()), res.items]));
    } catch {
      // Non-fatal — the dialog already recorded an optimistic entry via onRecorded.
    }
  };

  if (state === 'loading') {
    return (
      <div className="flex items-center justify-center py-8 text-slate-500 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading forensic timeline…
      </div>
    );
  }

  if (state === 'error' || state === 'unauthorized') {
    return <div className="p-4 text-sm text-rose-400 border border-rose-900/50 bg-rose-950/20 rounded-lg">{errorMessage}</div>;
  }

  if (state === 'empty') {
    return <div className="text-sm text-slate-500 text-center py-4">No forensic events recorded for this case yet.</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setActiveCategory('ALL')}
          className={`text-xs px-2.5 py-1 rounded border transition-colors ${activeCategory === 'ALL' ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'}`}
        >
          All ({prepared.events.length})
        </button>
        {prepared.availableCategories.map((cat) => {
          const count = prepared.events.filter((e) => e.category === cat).length;
          return (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`text-xs px-2.5 py-1 rounded border transition-colors ${activeCategory === cat ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'}`}
            >
              {CATEGORY_LABELS[cat]} ({count})
            </button>
          );
        })}
      </div>

      <div className="space-y-2">
        {visibleEvents.map((event) => {
          const isExpanded = expandedId === event.id;
          const actionable = isActionableEvent(event);
          const decision = findDecisionForTarget(decisionIndex, event.resourceId);

          return (
            <div key={event.id} className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
              <div className="flex items-start justify-between px-3 py-2 gap-3">
                <button
                  onClick={() => setExpandedId(isExpanded ? null : event.id)}
                  className="flex-1 text-left flex items-start gap-2 cursor-pointer"
                >
                  {isExpanded ? <ChevronDown className="w-3.5 h-3.5 mt-0.5 text-slate-500 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 mt-0.5 text-slate-500 shrink-0" />}
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] uppercase tracking-wide text-slate-600 bg-slate-900 px-1.5 py-0.5 rounded">{CATEGORY_LABELS[event.category]}</span>
                      <span className="text-xs font-medium text-slate-200">{event.title}</span>
                      {event.priority && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${PRIORITY_STYLES[event.priority.priority]}`} title={event.priority.reasons.join('; ')}>
                          {event.priority.priority}
                        </span>
                      )}
                      {decision && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300">
                          Decision: {decision.decision}
                        </span>
                      )}
                    </div>
                    {event.description && <div className="text-xs text-slate-500 mt-1">{event.description}</div>}
                    {event.source && <div className="text-[10px] text-slate-600 mt-1">Source: {event.source}</div>}
                  </div>
                </button>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span className="text-[10px] text-slate-500">{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Not available'}</span>
                  <EventLink event={event} />
                </div>
              </div>

              {actionable && (
                <div className="px-3 pb-2 flex flex-wrap gap-1.5">
                  {DECISION_ACTIONS.map((a) => (
                    <button
                      key={a.decision}
                      onClick={() => setPendingAction({ event, action: a.decision })}
                      className="text-[10px] px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
                    >
                      {a.label}
                    </button>
                  ))}
                </div>
              )}

              {isExpanded && <EventDetailPanel event={event} decision={decision} />}
            </div>
          );
        })}
        {visibleEvents.length === 0 && (
          <div className="text-xs text-slate-600 text-center py-3">No events in this category.</div>
        )}
      </div>

      {pendingAction && (
        <AnalystActionDialog
          event={pendingAction.event}
          action={pendingAction.action}
          caseId={caseId}
          investigations={investigations}
          onClose={() => setPendingAction(null)}
          onRecorded={(decision, investigationId) => {
            setDecisionIndex((prev) => buildDecisionIndex([Array.from(prev.values()), [decision]]));
            void refreshDecisionsFor(investigationId);
          }}
        />
      )}
    </div>
  );
}
