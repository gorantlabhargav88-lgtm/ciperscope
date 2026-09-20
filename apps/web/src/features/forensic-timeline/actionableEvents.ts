import type { ForensicTimelineCategory, ForensicTimelineEvent } from '@ciperscope/types';

/**
 * Which timeline categories represent a "finding" an analyst can judge
 * (Review/Confirm/Escalate/Dismiss), vs. categories that are already a
 * record of something that happened (a custody transition, an audit
 * entry, an investigation's own lifecycle, or a prior analyst decision)
 * and are not themselves actionable.
 *
 * This is a UI/UX curation decision, not a backend capability gap — the
 * backend's POST .../decisions endpoint could technically target any
 * resourceId/resourceType pair, but presenting "Confirm" on an
 * already-recorded ANALYST_DECISION or a SYSTEM audit row would be
 * meaningless.
 */
export const ACTIONABLE_CATEGORIES: ForensicTimelineCategory[] = ['EMAIL', 'AUTHENTICATION', 'THREAT_INTELLIGENCE', 'ML'];

export function isActionableEvent(event: Pick<ForensicTimelineEvent, 'category' | 'resourceId' | 'resourceType'>): boolean {
  if (!event.resourceId || !event.resourceType) return false;
  return ACTIONABLE_CATEGORIES.includes(event.category);
}

/**
 * The (targetId, targetType) pair sent to POST .../decisions is derived
 * directly from the event's own real resourceId/resourceType — never a
 * synthesized identifier.
 */
export function getDecisionTarget(event: Pick<ForensicTimelineEvent, 'resourceId' | 'resourceType'>): {
  targetId: string;
  targetType: string;
} {
  return { targetId: event.resourceId, targetType: event.resourceType };
}
