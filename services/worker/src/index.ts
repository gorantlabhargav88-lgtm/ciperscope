import { logger, runWithContext, generateRequestId } from '@ciperscope/logger';
import { QueueManager, createTenantScopedWorker, IdempotencyManager, EmailIngestionJobPayload } from '@ciperscope/queue';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import IORedis from 'ioredis';
import { LocalRawEmailStore } from '@ciperscope/storage';

const redisUrl = env.REDIS_URL;

const queueManager = new QueueManager(redisUrl);
const idempotencyRedis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const idempotencyManager = new IdempotencyManager(idempotencyRedis, prisma);
const rawEmailStore = new LocalRawEmailStore();

const emailResourceValidator = async (resourceId: string, organizationId: string) => {
  const email = await prisma.email.findUnique({
    where: { id: resourceId }
  });
  return email?.organizationId === organizationId;
};

export async function start() {
  logger.info('Starting CiperScope Worker Service...');

  // Setup Email Processing Worker using the tenant-scoped wrapper
  const worker = createTenantScopedWorker<EmailIngestionJobPayload, unknown>(
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
            // Worker Logic for Phase 7
            // 1. Retrieve the email record
            const emailRecord = await prisma.email.findUnique({
              where: { id: job.data.resourceId }
            });

            if (!emailRecord) {
              throw new Error(`Email record ${job.data.resourceId} not found`);
            }

            // 2. Verify raw SHA-256 matches what was sent in the job payload
            if (emailRecord.sha256 !== job.data.rawSha256) {
              throw new Error(`Integrity mismatch: Database SHA-256 does not match job payload`);
            }

            // 3. Verify raw email exists in storage
            const storageExists = await rawEmailStore.exists(job.data.storageReference);
            if (!storageExists) {
               throw new Error(`Raw email object missing in storage: ${job.data.storageReference}`);
            }

            // At this point in Phase 7, the ingestion pipeline has successfully stored the raw bytes,
            // verified tenant ownership (via createTenantScopedWorker wrapper), and verified integrity.
            // Further MIME parsing, threat analysis, and extraction are part of Phase 8.

            // 4. Update ingestion state to READY_FOR_ANALYSIS
            await prisma.email.update({
              where: { id: job.data.resourceId },
              data: {
                // In Phase 7 we just mark it as successfully ingested
                // (Assuming we had an ingestionStatus enum, but currently it's just classification=UNKNOWN)
              }
            });

            logger.info({ emailId: job.data.resourceId }, 'Email successfully ingested and validated');
            
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
