import { Queue, Worker, QueueEvents, Job, DefaultJobOptions, DelayedError } from 'bullmq';
import IORedis from 'ioredis';
import { logger } from '@ciperscope/logger';
import { PrismaClient, IdempotencyOperationStatus } from '@ciperscope/database';

export * from './cti-job';
export * from './notificationChannel';
export * from './emailOutbox';

// Standard connection options
export const createRedisConnection = (url: string) => {
  return new IORedis(url, {
    maxRetriesPerRequest: null,
  });
};

// Base queue options
export const defaultJobOptions: DefaultJobOptions = {
  attempts: 3,
  backoff: {
    type: 'exponential',
    delay: 1000,
  },
  removeOnComplete: {
    age: 3600, // keep for 1 hour
    count: 1000, // keep up to 1000 jobs
  },
  removeOnFail: {
    age: 24 * 3600, // keep failed for 24 hours
  },
};

export class QueueManager {
  private connection: IORedis;
  private queues: Map<string, Queue> = new Map();
  private workers: Map<string, Worker> = new Map();
  private events: Map<string, QueueEvents> = new Map();

  constructor(redisUrl: string) {
    this.connection = createRedisConnection(redisUrl);
    this.connection.on('error', (err) => {
      logger.error({ err }, 'Queue Redis connection error');
    });
  }

  public getQueue(name: string): Queue {
    if (!this.queues.has(name)) {
      const queue = new Queue(name, {
        connection: this.connection,
        defaultJobOptions,
      });
      this.queues.set(name, queue);
    }
    return this.queues.get(name)!;
  }

  public createWorker<T = any, R = any>(
    name: string,
    processor: (job: Job<T, R>) => Promise<R>,
    concurrency: number = 1
  ): Worker {
    if (this.workers.has(name)) {
      throw new Error(`Worker for queue ${name} already exists`);
    }

    const worker = new Worker<T, R>(name, processor, {
      connection: this.connection,
      concurrency,
    });

    worker.on('completed', (job) => {
      logger.info({ jobId: job.id, queue: name }, 'Job completed successfully');
    });

    worker.on('failed', (job, err) => {
      // Logic for DLQ can be added here or inherently managed by removeOnFail
      logger.error({ jobId: job?.id, queue: name, err }, 'Job failed');
    });

    this.workers.set(name, worker);
    return worker;
  }

  public async closeAll() {
    for (const worker of this.workers.values()) {
      await worker.close();
    }
    for (const queue of this.queues.values()) {
      await queue.close();
    }
    for (const event of this.events.values()) {
      await event.close();
    }
    await this.connection.quit();
  }
}

// Idempotency Utility
export const generateIdempotencyKey = (
  organizationId: string,
  resourceType: string,
  resourceId: string,
  operation: string,
  version: string = 'v1'
) => {
  return `idempotency:${organizationId}:${resourceType}:${resourceId}:${operation}:${version}`;
};

export class IdempotencyManager {
  private redis: IORedis;
  private prisma: PrismaClient;

  constructor(redis: IORedis, prisma: PrismaClient) {
    this.redis = redis;
    this.prisma = prisma;
  }

  public async acquireLock(
    organizationId: string,
    operationKey: string,
    resourceId: string,
    operationType: string,
    ttlSeconds: number = 300
  ): Promise<boolean> {
    const redisKey = `idempotency_lock:${organizationId}:${operationKey}:${resourceId}`;

    const lockAcquired = await this.redis.set(redisKey, 'locked', 'EX', ttlSeconds, 'NX');
    if (!lockAcquired) {
      const retryAfterMs = await this.redis.pttl(redisKey);
      throw new IdempotencyLockBusyError(
        organizationId,
        operationKey,
        resourceId,
        Math.max(1_000, retryAfterMs)
      );
    }

    try {
      let op = await this.prisma.idempotencyOperation.findUnique({
        where: {
          organizationId_operationKey_resourceId: {
            organizationId,
            operationKey,
            resourceId,
          }
        }
      });

      if (!op) {
        op = await this.prisma.idempotencyOperation.create({
          data: {
            organizationId,
            operationKey,
            resourceId,
            operationType,
            status: IdempotencyOperationStatus.PROCESSING,
            attemptCount: 1,
            lockedUntil: new Date(Date.now() + ttlSeconds * 1000)
          }
        });
        return true;
      }

      if (op.status === IdempotencyOperationStatus.SUCCEEDED) {
        await this.redis.del(redisKey);
        return false;
      }

      if (op.status === IdempotencyOperationStatus.RECONCILIATION_REQUIRED) {
        await this.redis.del(redisKey);
        throw new Error('Operation requires external reconciliation before retry.');
      }

      await this.prisma.idempotencyOperation.update({
        where: { id: op.id },
        data: {
          status: IdempotencyOperationStatus.PROCESSING,
          attemptCount: op.attemptCount + 1,
          lockedUntil: new Date(Date.now() + ttlSeconds * 1000)
        }
      });
      return true;

    } catch (error) {
      await this.redis.del(redisKey);
      throw error;
    }
  }

  public async markCompleted(
    organizationId: string,
    operationKey: string,
    resourceId: string,
    resultReference?: string
  ): Promise<void> {
    await this.prisma.idempotencyOperation.update({
      where: {
        organizationId_operationKey_resourceId: {
          organizationId,
          operationKey,
          resourceId,
        }
      },
      data: {
        status: IdempotencyOperationStatus.SUCCEEDED,
        resultReference,
        completedAt: new Date(),
        lockedUntil: null
      }
    });
    const redisKey = `idempotency_lock:${organizationId}:${operationKey}:${resourceId}`;
    await this.redis.del(redisKey);
  }

  public async markFailed(
    organizationId: string,
    operationKey: string,
    resourceId: string,
    errorMessage: string
  ): Promise<void> {
    await this.prisma.idempotencyOperation.update({
      where: {
        organizationId_operationKey_resourceId: {
          organizationId,
          operationKey,
          resourceId,
        }
      },
      data: {
        status: IdempotencyOperationStatus.FAILED,
        errorMessage,
        lockedUntil: null
      }
    });
    const redisKey = `idempotency_lock:${organizationId}:${operationKey}:${resourceId}`;
    await this.redis.del(redisKey);
  }

  public async markReconciliationRequired(
    organizationId: string,
    operationKey: string,
    resourceId: string,
    errorMessage: string
  ): Promise<void> {
    await this.prisma.idempotencyOperation.update({
      where: {
        organizationId_operationKey_resourceId: {
          organizationId,
          operationKey,
          resourceId,
        }
      },
      data: {
        status: IdempotencyOperationStatus.RECONCILIATION_REQUIRED,
        errorMessage,
        lockedUntil: null
      }
    });
    const redisKey = `idempotency_lock:${organizationId}:${operationKey}:${resourceId}`;
    await this.redis.del(redisKey);
  }

  public async clearLock(organizationId: string, operationKey: string, resourceId: string): Promise<void> {
    const redisKey = `idempotency_lock:${organizationId}:${operationKey}:${resourceId}`;
    await this.redis.del(redisKey);
  }
}

export class IdempotencyLockBusyError extends Error {
  constructor(
    organizationId: string,
    operationKey: string,
    resourceId: string,
    public readonly retryAfterMs: number
  ) {
    super(`Operation is already in progress: ${organizationId}/${operationKey}/${resourceId}`);
    this.name = 'IdempotencyLockBusyError';
  }
}

export interface TenantAwareJobPayload {
  organizationId: string;
  resourceId: string;
  jobId: string;
  operation: string;
  outboxEventId?: string;
  actorId?: string;
  requestId?: string;
  traceId?: string;
}

export interface EmailIngestionJobPayload extends TenantAwareJobPayload {
  emailId: string;           // Maps to resourceId in TenantAwareJobPayload
  storageReference: string;
  rawSha256: string;
  source: string;
}

export interface EmailAuthenticationVerificationJobPayload extends TenantAwareJobPayload {
  emailId: string;
}

export interface EmailThreatAnalysisJobPayload extends TenantAwareJobPayload {
  emailId: string;
}

export interface EmailCtiEnrichmentJobPayload extends TenantAwareJobPayload {
  emailId: string;
}

export interface EmailMlClassificationJobPayload extends TenantAwareJobPayload {
  emailId: string;
}

// Phase 2: outbound webhook notification foundation.
export interface WebhookDeliveryJobPayload extends TenantAwareJobPayload {
  webhookId: string; // resourceId in TenantAwareJobPayload
  eventId: string;
  eventType: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: Record<string, any>;
}

// Phase J: forensic PDF report generation.
export interface ReportGenerationJobPayload extends TenantAwareJobPayload {
  reportId: string; // resourceId in TenantAwareJobPayload
  emailId: string;
}

export type ResourceValidator = (resourceId: string, organizationId: string) => Promise<boolean>;

export const wrapTenantScopedProcessor = <T extends TenantAwareJobPayload, R>(
  processor: (job: Job<T, R>) => Promise<R>,
  resourceValidator?: ResourceValidator
) => {
  return async (job: Job<T, R>): Promise<R> => {
    const { organizationId, resourceId } = job.data;
    if (!organizationId) {
      throw new Error('Tenant isolation failed: Missing organizationId in job payload.');
    }
    if (!resourceId) {
      throw new Error('Tenant isolation failed: Missing resourceId in job payload.');
    }

    if (resourceValidator) {
      const isAuthorized = await resourceValidator(resourceId, organizationId);
      if (!isAuthorized) {
        throw new Error(`Tenant isolation failed: Resource ${resourceId} does not belong to organization ${organizationId}`);
      }
    }

    return processor(job);
  };
};

export const createTenantScopedWorker = <T extends TenantAwareJobPayload, R>(
  name: string,
  connection: IORedis,
  processor: (job: Job<T, R>) => Promise<R>,
  concurrency: number = 1,
  resourceValidator?: ResourceValidator
): Worker => {
  const wrappedProcessor = wrapTenantScopedProcessor(processor, resourceValidator);

  return new Worker<T, R>(name, async (job) => {
    try {
      return await wrappedProcessor(job);
    } catch (error) {
      if (error instanceof IdempotencyLockBusyError && job.token) {
        await job.moveToDelayed(Date.now() + error.retryAfterMs, job.token);
        throw new DelayedError();
      }
      throw error;
    }
  }, {
    connection,
    concurrency,
  });
}
