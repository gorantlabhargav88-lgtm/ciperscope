import type { CaseTimelineEvent } from '@ciperscope/types';

const ACTION_LABELS: Record<string, string> = {
  CASE_CREATED: 'Case created',
  CASE_VIEWED: 'Case viewed',
  CASE_UPDATED: 'Case updated',
  CASE_ASSIGNED: 'Case assigned',
  CASE_HISTORY_VIEWED: 'Case history viewed',
  CASE_EMAIL_LINKED: 'Email linked to case',
  CASE_EMAIL_UNLINKED: 'Email unlinked from case',
  CASE_NOTE_ADDED: 'Note added',
  CASE_NOTE_UPDATED: 'Note updated',
  CASE_NOTE_DELETED: 'Note deleted',
  CASE_EVIDENCE_ADDED: 'Evidence added',
  CASE_EVIDENCE_VIEWED: 'Evidence viewed',
  CASE_EVIDENCE_DELETED: 'Evidence deleted',
  CASE_CUSTODY_VIEWED: 'Chain of custody viewed',
  CASE_REPORT_CREATED: 'Report created',
  CASE_REPORT_DELETED: 'Report deleted',
  CASE_ALERT_VIEWED: 'Alert viewed',
  CASE_ALERT_UPDATED: 'Alert updated',
  CASE_INVESTIGATION_CREATED: 'Investigation opened',
  CASE_INVESTIGATION_VIEWED: 'Investigation viewed',
  CASE_INVESTIGATION_UPDATED: 'Investigation updated',
  CASE_INVESTIGATION_INTELLIGENCE_VIEWED: 'Investigation intelligence reviewed',
  CASE_INVESTIGATION_DECISION_RECORDED: 'Analyst decision recorded',
};

export interface DisplayTimelineEvent {
  id: string;
  title: string;
  actorId: string | null;
  timestamp: string | null;
  metadata: Record<string, unknown> | null;
}

/** Falls back to the raw action code when there's no friendlier label — never invents a description. */
export function describeTimelineAction(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

/**
 * Prepares raw CaseTimelineEvent rows (from GET /cases/:caseId/timeline)
 * for display: drops malformed entries (missing id/action), de-duplicates
 * by id, and sorts newest-first, treating a missing/invalid timestamp as
 * "unknown" (sorted last, never guessed at or defaulted to "now").
 */
export function prepareCaseTimeline(events: CaseTimelineEvent[]): DisplayTimelineEvent[] {
  const seen = new Set<string>();
  const prepared: DisplayTimelineEvent[] = [];

  for (const event of events) {
    if (!event || !event.id || !event.action) continue;
    if (seen.has(event.id)) continue;
    seen.add(event.id);

    const timestamp = event.createdAt && !Number.isNaN(Date.parse(event.createdAt)) ? event.createdAt : null;

    prepared.push({
      id: event.id,
      title: describeTimelineAction(event.action),
      actorId: event.actorId,
      timestamp,
      metadata: event.metadata,
    });
  }

  return prepared.sort((a, b) => {
    if (a.timestamp === null && b.timestamp === null) return 0;
    if (a.timestamp === null) return 1;
    if (b.timestamp === null) return -1;
    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
  });
}
