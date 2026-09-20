import type { Severity } from './threat';

/**
 * TimelineEvent is a supporting type for the Email Forensics aggregator.
 * There is no dedicated timeline API endpoint for a single email today —
 * the existing `apps/web/src/components/ForensicTimeline.tsx` builds its
 * timeline client-side from already-fetched email/auth/url/ML data. This
 * type gives that client-side construction a stable shape rather than the
 * previous ad-hoc `any[]`, without inventing a new backend endpoint.
 *
 * (`/cases/:caseId/timeline` is a separate, real, case-level backend
 * endpoint — see investigation.ts's InvestigationTimelineEvent for that.)
 */
export type TimelineEventType =
  | 'EMAIL_INGESTED'
  | 'AUTHENTICATION_CHECKED'
  | 'THREAT_ANALYZED'
  | 'ML_CLASSIFIED'
  | 'CTI_ENRICHED'
  | 'EVIDENCE_COLLECTED'
  | 'ANALYST_DECISION'
  | 'OTHER';

export interface TimelineEvent {
  id: string;
  type: TimelineEventType;
  timestamp: string;
  title: string;
  description?: string;
  severity?: Severity;
}
