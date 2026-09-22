import crypto from 'crypto';
import { PrismaClient } from '@ciperscope/database';
import { QueueManager, WebhookDeliveryJobPayload } from '@ciperscope/queue';
import { logger } from '@ciperscope/logger';
import { buildThreatAnalysisCompletedPayload, isSupportedWebhookEvent } from './NotificationEvents';

export const WEBHOOK_DELIVERY_QUEUE = 'webhook-delivery';

export interface ThreatAnalysisCompletedParams {
  emailId: string;
  organizationId: string;
  threatScore: number | null;
  priority: string | null;
  threatCategory: string | null;
  analysisStatus: string;
}

/** What FusionEngine depends on — kept minimal and BullMQ-agnostic so the
 *  risk-scoring pipeline's tests never need to mock a queue. */
export interface ThreatAnalysisNotifier {
  notifyThreatAnalysisCompleted(params: ThreatAnalysisCompletedParams): Promise<void>;
}

/**
 * Enqueue side of the outbound notification pipeline. Never makes an HTTP
 * call itself — it only looks up this tenant's enabled webhooks and pushes
 * one bounded, fast Redis job per webhook onto the existing BullMQ
 * infrastructure. Actual delivery happens in WebhookDeliveryWorker, on a
 * separate queue consumer, so a slow/unreachable receiver can never delay
 * or block email analysis.
 */
export class WebhookNotificationService implements ThreatAnalysisNotifier {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly queueManager: QueueManager
  ) {}

  async notifyThreatAnalysisCompleted(params: ThreatAnalysisCompletedParams): Promise<void> {
    const webhooks = await this.prisma.webhook.findMany({
      where: { organizationId: params.organizationId, enabled: true },
    });

    const subscribed = webhooks.filter((w) => {
      const events = Array.isArray(w.events) ? (w.events as unknown[]) : [];
      return events.some((e) => typeof e === 'string' && isSupportedWebhookEvent(e) && e === 'THREAT_ANALYSIS_COMPLETED');
    });

    if (subscribed.length === 0) return;

    // One event, potentially delivered to several webhooks — each webhook
    // gets its own delivery-tracking row (webhookId+eventId is the
    // idempotency key), but they all share one eventId since it's the same
    // underlying occurrence.
    const eventId = crypto.randomUUID();
    const payload = buildThreatAnalysisCompletedPayload({ ...params, eventId });

    const queue = this.queueManager.getQueue(WEBHOOK_DELIVERY_QUEUE);

    for (const webhook of subscribed) {
      // BullMQ rejects ':' in custom job IDs (it's BullMQ's own Redis-key
      // delimiter), so this joins with '_' instead.
      const jobId = `${eventId}_${webhook.id}`;
      const jobPayload: WebhookDeliveryJobPayload = {
        organizationId: params.organizationId,
        resourceId: webhook.id,
        jobId,
        operation: 'webhook_delivery',
        webhookId: webhook.id,
        eventId,
        eventType: 'THREAT_ANALYSIS_COMPLETED',
        payload,
      };

      try {
        // Deterministic jobId = queue-level dedupe: if this exact event was
        // already enqueued for this webhook, BullMQ silently no-ops instead
        // of creating a second job.
        await queue.add('deliver', jobPayload, { jobId });
      } catch (err) {
        logger.error({ err, webhookId: webhook.id, eventId }, 'Failed to enqueue webhook delivery job');
      }
    }
  }
}
