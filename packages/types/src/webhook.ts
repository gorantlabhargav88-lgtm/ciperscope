/**
 * Outbound webhook management — services/api/src/modules/webhook/webhook.routes.ts.
 * Only one event type is currently emitted by the backend
 * (services/api/src/utils/validation.ts's WEBHOOK_EVENT_TYPES); this is not
 * an arbitrary/extensible list invented by the frontend.
 */
export const WEBHOOK_EVENT_TYPES = ['THREAT_ANALYSIS_COMPLETED'] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface Webhook {
  id: string;
  organizationId: string;
  url: string;
  events: WebhookEventType[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Only returned once, from POST /webhooks — never persisted or returned again in plaintext. */
export interface WebhookWithSecret extends Webhook {
  secret: string;
}
