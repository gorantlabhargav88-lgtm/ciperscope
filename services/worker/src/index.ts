import { logger, runWithContext, generateRequestId } from '@ciperscope/logger';
import { QueueManager, createTenantScopedWorker, IdempotencyManager, TenantAwareJobPayload } from '@ciperscope/queue';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import IORedis from 'ioredis';

const redisUrl = env.REDIS_URL;

const queueManager = new QueueManager(redisUrl);
const idempotencyRedis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const idempotencyManager = new IdempotencyManager(idempotencyRedis, prisma);

const emailResourceValidator = async (resourceId: string, organizationId: string) => {
  const email = await prisma.email.findUnique({
    where: { id: resourceId },
    include: { case: true }
  });
  return email?.case?.organizationId === organizationId;
};

export async function start() {
  logger.info('Starting CiperScope Worker Service...');

  // Setup Email Processing Worker using the tenant-scoped wrapper
  const worker = createTenantScopedWorker<TenantAwareJobPayload, unknown>(
    'email-processing',
    idempotencyRedis,
    async (job) => {
      // Run worker logic in a context for logging, preserving requestId
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          traceId: job.data.traceId,
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ data: job.data }, 'Processing email job');
          
          const operationKey = `email:${job.data.operation}`;

          try {
            const acquired = await idempotencyManager.acquireLock(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              job.data.operation
            );
            if (!acquired) {
              logger.info({ operationKey }, 'Skipping job: idempotency lock not acquired (already processed or processing)');
              return { skipped: true, reason: 'idempotency' };
            }
          } catch (error) {
             logger.warn({ err: error }, 'Failed to acquire idempotency lock');
             throw error;
          }

          try {
            // Actual Domain Logic here
            // e.g. EmailPipelineProvider
            
            await idempotencyManager.markCompleted(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              'result-ref-success'
            );
            return { success: true, processedAt: new Date().toISOString() };
          } catch (error: unknown) {
            await idempotencyManager.markFailed(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              error instanceof Error ? error.message : 'Unknown error'
            );
            throw error;
          }
        }
      );
    },
    1,
    emailResourceValidator
  );

  worker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'email-processing' }, 'Job completed successfully');
  });

  worker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'email-processing', err }, 'Job failed');
  });

  logger.info('Workers registered and listening for jobs.');
}

// Graceful shutdown
async function shutdown(signal: string) {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  try {
    await queueManager.closeAll();
    await prisma.$disconnect();
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (err) {
    logger.error({ err }, 'Error during shutdown');
    process.exit(1);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

start().catch((err) => {
  logger.error({ err }, 'Failed to start worker service');
  process.exit(1);
});
