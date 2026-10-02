import { randomUUID } from 'crypto';
import { Prisma, PrismaClient } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import type { QueueManager } from './index';

export const EmailProcessingStage = {
  PROCESSING: 'PROCESSING',
  AUTHENTICATION: 'AUTHENTICATION',
  THREAT_ANALYSIS: 'THREAT_ANALYSIS',
  CTI_ENRICHMENT: 'CTI_ENRICHMENT',
  ML_CLASSIFICATION: 'ML_CLASSIFICATION',
} as const;

export type EmailProcessingStage =
  (typeof EmailProcessingStage)[keyof typeof EmailProcessingStage];

export interface EmailOutboxEventInput {
  organizationId: string;
  emailId: string;
  stage: EmailProcessingStage;
  queueName: string;
  jobName: string;
  priority?: number;
  payload: Prisma.InputJsonObject;
}

export async function ensureEmailOutboxEvent(
  tx: Prisma.TransactionClient,
  input: EmailOutboxEventInput
) {
  const eventKey = `email:${input.organizationId}:${input.emailId}:${input.stage}`;
  const id = randomUUID();
  const payload: Prisma.InputJsonObject = {
    ...input.payload,
    outboxEventId: id,
  };

  return tx.emailDispatchOutbox.upsert({
    where: { eventKey },
    create: { id, ...input, eventKey, payload },
    update: {},
  });
}

export async function completeEmailOutboxEvent(
  tx: Prisma.TransactionClient,
  outboxEventId: string | undefined
): Promise<void> {
  if (!outboxEventId) return;
  await tx.emailDispatchOutbox.updateMany({
    where: { id: outboxEventId },
    data: {
      state: 'COMPLETED',
      claimToken: null,
      claimedAt: null,
      lockedUntil: null,
      lastError: null,
    },
  });
}

export async function isEmailOutboxEventCompleted(
  prisma: PrismaClient,
  eventId: string | undefined,
  organizationId: string,
  emailId: string
): Promise<boolean> {
  if (!eventId) return false;
  const event = await prisma.emailDispatchOutbox.findFirst({
    where: {
      id: eventId,
      organizationId,
      emailId,
      state: 'COMPLETED',
    },
    select: { id: true },
  });
  return event !== null;
}

interface ClaimedEmailOutboxEvent {
  id: string;
  organizationId: string;
  emailId: string;
  stage: string;
  queueName: string;
  jobName: string;
  priority: number | null;
  payload: Prisma.JsonValue;
  claimToken: string;
  attemptCount: number;
}

export interface EmailOutboxRelayOptions {
  batchSize?: number;
  leaseSeconds?: number;
  dispatchTimeoutMs?: number;
  retryBaseDelayMs?: number;
  completedRetentionDays?: number;
  cleanupBatchSize?: number;
}

export class EmailOutboxRelay {
  private readonly batchSize: number;
  private readonly leaseSeconds: number;
  private readonly dispatchTimeoutMs: number;
  private readonly retryBaseDelayMs: number;
  private readonly completedRetentionDays: number;
  private readonly cleanupBatchSize: number;
  private timer?: NodeJS.Timeout;
  private running = false;
  private draining?: Promise<number>;
  private lastCleanupAt = 0;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly queueManager: QueueManager,
    options: EmailOutboxRelayOptions = {}
  ) {
    this.batchSize = options.batchSize ?? 25;
    this.leaseSeconds = options.leaseSeconds ?? 60;
    this.dispatchTimeoutMs = options.dispatchTimeoutMs ?? 10_000;
    this.retryBaseDelayMs = options.retryBaseDelayMs ?? 1_000;
    this.completedRetentionDays = options.completedRetentionDays ?? 90;
    this.cleanupBatchSize = options.cleanupBatchSize ?? 500;
  }

  start(intervalMs = 1_000): void {
    if (this.timer) return;
    this.running = true;
    this.timer = setInterval(() => {
      void this.dispatchPending().catch((err: unknown) => {
        logger.error({ err }, 'Email outbox polling failed');
      });
    }, intervalMs);
    this.timer.unref();
    void this.dispatchPending().catch((err: unknown) => {
      logger.error({ err }, 'Initial email outbox dispatch failed');
    });
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.draining;
  }

  async dispatchPending(): Promise<number> {
    if (this.draining) return this.draining;
    this.draining = this.dispatchBatch();
    try {
      return await this.draining;
    } finally {
      this.draining = undefined;
    }
  }

  private async dispatchBatch(): Promise<number> {
    await this.cleanupCompletedEvents();
    const events = await this.claimBatch();
    let dispatched = 0;
    for (const event of events) {
      if (!this.running && this.timer) break;
      try {
        const payload = {
          ...(event.payload as Prisma.JsonObject),
          outboxEventId: event.id,
        };
        const dispatch = this.queueManager
          .getQueue(event.queueName)
          .add(event.jobName, payload, {
            jobId: this.jobId(event.id),
            ...(event.priority === null ? {} : { priority: event.priority }),
          });
        await this.withTimeout(dispatch);

        const marked = await this.prisma.emailDispatchOutbox.updateMany({
          where: { id: event.id, state: 'DISPATCHING', claimToken: event.claimToken },
          data: {
            state: 'DISPATCHED',
            dispatchedAt: new Date(),
            claimToken: null,
            claimedAt: null,
            lockedUntil: null,
            lastError: null,
          },
        });
        if (marked.count) dispatched++;
        logger.info({
          outboxEventId: event.id,
          emailId: event.emailId,
          organizationId: event.organizationId,
          stage: event.stage,
          attempt: event.attemptCount,
          dispatchState: marked.count ? 'DISPATCHED' : 'CLAIM_LOST',
        }, 'Email outbox event handled');
      } catch (error) {
        const safeMessage = this.safeErrorMessage(error);
        const delay = Math.min(
          this.retryBaseDelayMs * 2 ** Math.min(event.attemptCount - 1, 8),
          5 * 60_000
        );
        await this.prisma.emailDispatchOutbox.updateMany({
          where: { id: event.id, state: 'DISPATCHING', claimToken: event.claimToken },
          data: {
            state: 'PENDING',
            nextAttemptAt: new Date(Date.now() + delay),
            claimToken: null,
            claimedAt: null,
            lockedUntil: null,
            lastError: safeMessage,
          },
        });
        logger.error({
          outboxEventId: event.id,
          emailId: event.emailId,
          organizationId: event.organizationId,
          stage: event.stage,
          attempt: event.attemptCount,
          dispatchState: 'PENDING',
          reason: safeMessage,
        }, 'Email outbox dispatch failed');
      }

    }
    return dispatched;
  }

  private async cleanupCompletedEvents(): Promise<void> {
    const now = Date.now();
    if (now - this.lastCleanupAt < 60 * 60_000) return;
    this.lastCleanupAt = now;

    try {
      const deleted = await this.prisma.$executeRaw`
        WITH stale AS (
          SELECT event."id"
          FROM "EmailDispatchOutbox" AS event
          INNER JOIN "Email" AS email
            ON email."id" = event."emailId"
            AND email."organizationId" = event."organizationId"
          WHERE event."state" = 'COMPLETED'::"EmailDispatchState"
            AND email."analysisStatus" = 'COMPLETED'::"AnalysisState"
            AND event."updatedAt" < NOW() - (${this.completedRetentionDays} * INTERVAL '1 day')
          ORDER BY event."updatedAt"
          LIMIT ${this.cleanupBatchSize}
          FOR UPDATE OF event SKIP LOCKED
        )
        DELETE FROM "EmailDispatchOutbox" AS event
        USING stale
        WHERE event."id" = stale."id"
      `;
      if (deleted > 0) logger.info({ deleted }, 'Pruned completed email outbox events');
    } catch (err) {
      logger.error({ err }, 'Failed to prune completed email outbox events');
    }
  }

  private async claimBatch(): Promise<ClaimedEmailOutboxEvent[]> {
    const claimToken = randomUUID();
    return this.prisma.$transaction(async (tx) => tx.$queryRaw<ClaimedEmailOutboxEvent[]>`
      WITH candidates AS (
        SELECT "id"
        FROM "EmailDispatchOutbox"
        WHERE (
          "state" = 'PENDING'::"EmailDispatchState"
          AND "nextAttemptAt" <= NOW()
        ) OR (
          "state" = 'DISPATCHING'::"EmailDispatchState"
          AND ("lockedUntil" IS NULL OR "lockedUntil" <= NOW())
        )
        ORDER BY "nextAttemptAt", "createdAt"
        FOR UPDATE SKIP LOCKED
        LIMIT ${this.batchSize}
      )
      UPDATE "EmailDispatchOutbox" AS event
      SET
        "state" = 'DISPATCHING'::"EmailDispatchState",
        "attemptCount" = event."attemptCount" + 1,
        "claimedAt" = NOW(),
        "claimToken" = ${claimToken},
        "lockedUntil" = NOW() + (${this.leaseSeconds} * INTERVAL '1 second'),
        "updatedAt" = NOW()
      FROM candidates
      WHERE event."id" = candidates."id"
      RETURNING
        event."id",
        event."organizationId",
        event."emailId",
        event."stage",
        event."queueName",
        event."jobName",
        event."priority",
        event."payload",
        event."claimToken",
        event."attemptCount"
    `);
  }

  private jobId(eventId: string): string {
    return `email-outbox-${eventId}`;
  }

  private async withTimeout<T>(promise: Promise<T>): Promise<T> {
    let timeout: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => reject(new Error('Queue dispatch timed out')), this.dispatchTimeoutMs);
          timeout.unref();
        }),
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  private safeErrorMessage(error: unknown): string {
    const message = error instanceof Error ? error.message : 'Unknown queue dispatch error';
    return message
      .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+:[^/@\s]+@/gi, '$1[redacted]@')
      .slice(0, 1000);
  }
}
