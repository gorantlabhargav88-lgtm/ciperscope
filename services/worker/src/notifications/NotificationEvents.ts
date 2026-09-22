/**
 * Outbound webhook event registry (Phase 2). Adding a new event type means
 * adding one entry here and one `notifyX(...)` method on NotificationService
 * — nothing about delivery, retry, signing, or idempotency changes.
 */
export const WEBHOOK_EVENT_TYPES = ['THREAT_ANALYSIS_COMPLETED'] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export function isSupportedWebhookEvent(value: string): value is WebhookEventType {
  return (WEBHOOK_EVENT_TYPES as readonly string[]).includes(value);
}

export interface ThreatAnalysisCompletedPayload {
  eventType: 'THREAT_ANALYSIS_COMPLETED';
  eventId: string;
  organizationId: string;
  emailId: string;
  threatScore: number | null;
  priority: string | null;
  threatCategory: string | null;
  analysisStatus: string;
  timestamp: string;
}

export interface ThreatAnalysisCompletedInput {
  eventId: string;
  organizationId: string;
  emailId: string;
  threatScore: number | null;
  priority: string | null;
  threatCategory: string | null;
  analysisStatus: string;
}

/**
 * Builds the minimal outbound payload for THREAT_ANALYSIS_COMPLETED.
 * Deliberately excludes: OAuth tokens, API keys, raw email content/headers,
 * attachment bytes, and any other field not explicitly listed — this is the
 * one place that shape is decided, so it can't drift per call site.
 */
export function buildThreatAnalysisCompletedPayload(input: ThreatAnalysisCompletedInput): ThreatAnalysisCompletedPayload {
  return {
    eventType: 'THREAT_ANALYSIS_COMPLETED',
    eventId: input.eventId,
    organizationId: input.organizationId,
    emailId: input.emailId,
    threatScore: input.threatScore,
    priority: input.priority,
    threatCategory: input.threatCategory,
    analysisStatus: input.analysisStatus,
    timestamp: new Date().toISOString(),
  };
}
