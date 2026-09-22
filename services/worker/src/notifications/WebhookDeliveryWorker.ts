import { PrismaClient, Prisma, WebhookDeliveryStatus } from '@ciperscope/database';
import { env, decryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { WebhookDeliveryJobPayload } from '@ciperscope/queue';
import { logger } from '@ciperscope/logger';
import { signWebhookPayload } from './webhookSigning';

const DELIVERY_TIMEOUT_MS = 10_000;
const PRISMA_UNIQUE_CONSTRAINT_ERROR = 'P2002';

export class WebhookDeliveryPermanentError extends Error {}

/**
 * Delivery side of the outbound notification pipeline — runs as a BullMQ
 * job processor (registered in services/worker/src/index.ts), never inline
 * with email analysis. Retries are handled by BullMQ's own `attempts` +
 * `backoff` job options (bounded, exponential, finite) — this function
 * itself either succeeds, or throws so BullMQ retries, or throws a
 * WebhookDeliveryPermanentError for failures retrying can't fix (disabled
 * webhook, non-HTTPS URL in production, already-delivered event).
 */
export async function processWebhookDelivery(
  prisma: PrismaClient,
  job: { data: WebhookDeliveryJobPayload; attemptsMade: number; opts: { attempts?: number } }
): Promise<void> {
  const { organizationId, webhookId, eventId, eventType, payload } = job.data;

  const webhook = await prisma.webhook.findUnique({
    where: { id_organizationId: { id: webhookId, organizationId } },
  });

  if (!webhook) {
    // Deleted since the job was enqueued — nothing to deliver to, not a
    // transient failure, so don't retry.
    logger.warn({ webhookId, eventId }, 'Webhook delivery skipped: webhook no longer exists');
    return;
  }

  if (!webhook.enabled) {
    logger.info({ webhookId, eventId }, 'Webhook delivery skipped: webhook is disabled');
    return;
  }

  const isProduction = env.NODE_ENV === 'production';
  if (isProduction && !webhook.url.startsWith('https://')) {
    await recordOutcome(prisma, webhookId, organizationId, eventId, eventType, payload, {
      status: WebhookDeliveryStatus.EXHAUSTED,
      lastError: 'Refused: production webhook URLs must use HTTPS',
    });
    throw new WebhookDeliveryPermanentError('Non-HTTPS webhook URL refused in production');
  }

  // Idempotency: durable at the database level via the (webhookId, eventId)
  // unique constraint, so this holds even if BullMQ redelivers the same job
  // (stalled-job requeue) or two workers race on it.
  const existing = await prisma.webhookDelivery.findUnique({
    where: { webhookId_eventId: { webhookId, eventId } },
  });

  if (existing?.status === WebhookDeliveryStatus.SUCCESS) {
    logger.info({ webhookId, eventId }, 'Webhook delivery skipped: event already delivered successfully');
    return;
  }

  if (existing) {
    await prisma.webhookDelivery.update({
      where: { webhookId_eventId: { webhookId, eventId } },
      data: { attemptCount: { increment: 1 }, status: WebhookDeliveryStatus.PENDING },
    });
  } else {
    try {
      await prisma.webhookDelivery.create({
        data: {
          webhookId,
          organizationId,
          eventId,
          eventType,
          payload,
          status: WebhookDeliveryStatus.PENDING,
          attemptCount: 1,
        },
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === PRISMA_UNIQUE_CONSTRAINT_ERROR) {
        // Lost a race with another worker creating the same row first —
        // that attempt owns this delivery now, not an error on our part.
        logger.info({ webhookId, eventId }, 'Webhook delivery row already created by a concurrent attempt');
        return;
      }
      throw err;
    }
  }

  const secret = decryptToken(webhook.secretEncrypted, requireGmailTokenEncryptionKey());
  const payloadJson = JSON.stringify(payload);
  const signature = signWebhookPayload(payloadJson, secret);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

  try {
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CipherScope-Event': eventType,
        'X-CipherScope-Delivery': eventId,
        'X-CipherScope-Signature': signature,
      },
      body: payloadJson,
      signal: controller.signal,
    });

    if (response.ok) {
      await recordOutcome(prisma, webhookId, organizationId, eventId, eventType, payload, {
        status: WebhookDeliveryStatus.SUCCESS,
        lastStatusCode: response.status,
      });
      return;
    }

    await recordOutcome(prisma, webhookId, organizationId, eventId, eventType, payload, {
      status: WebhookDeliveryStatus.FAILED,
      lastStatusCode: response.status,
      lastError: `Receiver returned non-2xx status ${response.status}`,
    });
    throw new Error(`Webhook delivery failed with status ${response.status}`);
  } catch (err) {
    if (!(err instanceof Error) || !err.message.startsWith('Webhook delivery failed with status')) {
      // Network error / timeout — never include the secret or raw error
      // object (which could carry request internals) in the persisted or
      // logged message.
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      const safeMessage = isTimeout ? 'Request timed out' : 'Network error while delivering webhook';
      await recordOutcome(prisma, webhookId, organizationId, eventId, eventType, payload, {
        status: WebhookDeliveryStatus.FAILED,
        lastError: safeMessage,
      });
    }

    const isLastAttempt = job.attemptsMade + 1 >= (job.opts.attempts ?? 1);
    if (isLastAttempt) {
      await prisma.webhookDelivery.update({
        where: { webhookId_eventId: { webhookId, eventId } },
        data: { status: WebhookDeliveryStatus.EXHAUSTED },
      });
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

async function recordOutcome(
  prisma: PrismaClient,
  webhookId: string,
  organizationId: string,
  eventId: string,
  eventType: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: any,
  outcome: { status: WebhookDeliveryStatus; lastStatusCode?: number; lastError?: string }
): Promise<void> {
  await prisma.webhookDelivery.update({
    where: { webhookId_eventId: { webhookId, eventId } },
    data: outcome,
  }).catch(async () => {
    // Row genuinely doesn't exist yet in an unexpected code path — recreate
    // rather than silently drop the outcome.
    await prisma.webhookDelivery.upsert({
      where: { webhookId_eventId: { webhookId, eventId } },
      create: { webhookId, organizationId, eventId, eventType, payload, attemptCount: 1, ...outcome },
      update: outcome,
    });
  });
}
