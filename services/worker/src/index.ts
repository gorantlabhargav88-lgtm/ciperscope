import { logger, runWithContext, generateRequestId } from '@ciperscope/logger';
import { QueueManager, createTenantScopedWorker, IdempotencyManager, EmailIngestionJobPayload, EmailAuthenticationVerificationJobPayload } from '@ciperscope/queue';
import { prisma } from '@ciperscope/database';
import { env, defaultRawEmailStoragePath } from '@ciperscope/config';
import IORedis from 'ioredis';
import { LocalRawEmailStore, S3RawEmailStore, RawEmailStore } from '@ciperscope/storage';
import { EmailForensicParser } from './parser/EmailForensicParser';
import { AuthenticationVerifier } from './verifier/AuthenticationVerifier';
import { ThreatAnalyzer } from './analyzer/ThreatAnalyzer';
import { MLClassifier } from './classifier/MLClassifier';
import { FusionEngine } from './analyzer/FusionEngine';
import { EmailThreatAnalysisJobPayload, EmailCtiEnrichmentJobPayload, EmailMlClassificationJobPayload } from '@ciperscope/queue';
import { createMetricsServer } from './metricsServer';
import { CtiEnrichmentWorker } from './cti/CtiEnrichmentWorker';
import { CtiReevaluationCoordinator } from './cti/CtiReevaluationCoordinator';
import { scheduleCtiReevaluationIfComplete, isTerminalIocFailure } from './cti/scheduleCtiReevaluation';
import { runMlEvaluationStage } from './analyzer/mlEvaluationStage';
import { processCTIJob } from './cti-worker';
import { CTIEnrichmentJob } from '@ciperscope/queue';
import { GmailSyncWorker, GmailSyncJobPayload } from './integration/gmail-sync';
import { GmailWatchRenewalWorker } from './integration/gmail-watch-renewal';
import { WebhookDeliveryJobPayload } from '@ciperscope/queue';
import { WebhookNotificationService } from './notifications/NotificationService';
import { processWebhookDelivery } from './notifications/WebhookDeliveryWorker';
import { ReportGenerationJobPayload } from '@ciperscope/queue';
import { ReportGenerationWorker } from './reports/ReportGenerationWorker';
import { runNotarizationSweep } from './integrity/NotarizationSweep';

const redisUrl = env.REDIS_URL;

const queueManager = new QueueManager(redisUrl);
const idempotencyRedis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const idempotencyManager = new IdempotencyManager(idempotencyRedis, prisma);
let rawEmailStore: RawEmailStore;
if (env.S3_BUCKET) {
  rawEmailStore = new S3RawEmailStore(env.S3_BUCKET, env.S3_REGION || 'us-east-1', env.S3_ENDPOINT);
} else {
  rawEmailStore = new LocalRawEmailStore(defaultRawEmailStoragePath);
}

const emailResourceValidator = async (resourceId: string, organizationId: string) => {
  const email = await prisma.email.findUnique({
    where: { id: resourceId }
  });
  return email?.organizationId === organizationId;
};

const webhookResourceValidator = async (resourceId: string, organizationId: string) => {
  const webhook = await prisma.webhook.findUnique({
    where: { id_organizationId: { id: resourceId, organizationId } },
  });
  return !!webhook;
};

const reportResourceValidator = async (resourceId: string, organizationId: string) => {
  const report = await prisma.forensicReport.findUnique({ where: { id: resourceId } });
  return report?.organizationId === organizationId;
};

const notificationService = new WebhookNotificationService(prisma, queueManager);

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

            // 4. Stream and parse the email
            const rawStream = await rawEmailStore.get(job.data.storageReference);
            const parsed = await EmailForensicParser.parse(rawStream);

            // 5. Transactionally insert all forensic data
            await prisma.$transaction(async (tx) => {
              // Create headers
              if (parsed.headers.length > 0) {
                await tx.emailHeader.createMany({
                  data: parsed.headers.map(h => ({
                    emailId: job.data.resourceId,
                    name: h.name,
                    value: h.value,
                    index: h.index
                  }))
                });
              }

              // Create addresses
              if (parsed.addresses.length > 0) {
                await tx.emailAddress.createMany({
                  data: parsed.addresses.map(a => ({
                    emailId: job.data.resourceId,
                    headerName: a.headerName,
                    displayName: a.displayName,
                    address: a.address,
                    localPart: a.localPart,
                    domain: a.domain,
                    raw: a.raw
                  }))
                });
              }

              // Create relay hops
              if (parsed.relayHops.length > 0) {
                await tx.relayHop.createMany({
                  data: parsed.relayHops.map(r => ({
                    emailId: job.data.resourceId,
                    hopOrder: r.hopOrder,
                    receivingHost: r.receivingHost,
                    sendingHost: r.sendingHost,
                    fromHost: r.fromHost,
                    byHost: r.byHost,
                    protocol: r.protocol,
                    parsedConfidence: r.parsedConfidence,
                    sourceIp: r.sourceIp,
                    hostname: r.hostname,
                    timestamp: r.timestamp,
                    receivedHeader: r.receivedHeader
                  }))
                });
              }

              // Create Mime Parts
              if (parsed.mimeParts.length > 0) {
                await tx.mimePart.createMany({
                  data: parsed.mimeParts.map(m => ({
                    emailId: job.data.resourceId,
                    partIndex: m.partIndex,
                    contentType: m.contentType,
                    contentDisposition: m.contentDisposition,
                    filename: m.filename,
                    contentId: m.contentId,
                    contentLocation: m.contentLocation,
                    transferEncoding: m.transferEncoding,
                    sizeBytes: m.sizeBytes,
                    isAttachment: m.isAttachment
                  }))
                });
              }

              // Update Analysis Status — 'PROCESSING', NOT 'COMPLETED' (Phase
              // 10G.2). Raw MIME parsing succeeding does not mean the
              // security-analysis pipeline (SPF/DKIM/DMARC -> CTI -> ML ->
              // FusionEngine) has run. 'COMPLETED' is set exactly once, by
              // FusionEngine.evaluate() (services/worker/src/analyzer/
              // FusionEngine.ts), in the same transaction that persists the
              // final RiskAssessment — that is the only place in the
              // pipeline where 'COMPLETED' can legitimately be declared.
              // Setting it here previously let the frontend treat a
              // freshly-parsed, not-yet-analyzed email as fully analyzed and
              // display it as P3/apparently-safe with riskAssessment still
              // null.
              await tx.email.update({
                where: { id: job.data.resourceId },
                data: {
                  analysisStatus: 'PROCESSING'
                }
              });
            });

            logger.info({ emailId: job.data.resourceId }, 'Email successfully ingested and validated');

            // Dispatch Authentication Verification Phase 9
            const authQueue = queueManager.getQueue('email-authentication');
            await authQueue.add(
              'verify-authentication',
              {
                organizationId: job.data.organizationId,
                resourceId: job.data.resourceId,
                jobId: job.id as string,
                operation: 'verify-authentication',
                emailId: job.data.resourceId,
                requestId: job.data.requestId,
                traceId: job.data.traceId
              },
              { jobId: `auth-${job.data.resourceId}` }
            );

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

            // Mark analysis as failed
            try {
              await prisma.email.update({
                where: { id: job.data.resourceId },
                data: { analysisStatus: 'FAILED' }
              });
            } catch (updateErr) {
              logger.error({ err: updateErr }, 'Failed to update analysis status to FAILED');
            }

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

  // Setup Authentication Verification Worker
  const authVerifier = new AuthenticationVerifier(prisma, rawEmailStore);
  const authWorker = createTenantScopedWorker<EmailAuthenticationVerificationJobPayload, unknown>(
    'email-authentication',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          traceId: job.data.traceId,
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ data: job.data }, 'Processing email authentication verification job');

          const operationKey = `auth:${job.data.operation}`;

          try {
            const acquired = await idempotencyManager.acquireLock(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              job.data.operation
            );
            if (!acquired) {
              logger.info({ operationKey }, 'Skipping job: idempotency lock not acquired');
              return { skipped: true, reason: 'idempotency' };
            }
          } catch (error) {
             logger.warn({ err: error }, 'Failed to acquire idempotency lock');
             throw error;
          }

          try {
            await authVerifier.verifyEmail(job.data.resourceId);

            await idempotencyManager.markCompleted(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              'result-ref-success'
            );

            // Dispatch Threat Analysis Phase 10
            const threatQueue = queueManager.getQueue('email-threat-analysis');
            await threatQueue.add(
              'threat-analysis',
              {
                organizationId: job.data.organizationId,
                resourceId: job.data.resourceId,
                jobId: job.id as string,
                operation: 'threat-analysis',
                emailId: job.data.resourceId,
                requestId: job.data.requestId,
                traceId: job.data.traceId
              },
              { jobId: `threat-${job.data.resourceId}` }
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

  authWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'email-authentication' }, 'Auth Job completed successfully');
  });

  authWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'email-authentication', err }, 'Auth Job failed');
  });

  // Setup Threat Analysis Worker
  const threatAnalyzer = new ThreatAnalyzer(prisma, rawEmailStore);
  const threatWorker = createTenantScopedWorker<EmailThreatAnalysisJobPayload, unknown>(
    'email-threat-analysis',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          traceId: job.data.traceId,
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ data: job.data }, 'Processing email threat analysis job');

          const operationKey = `threat:${job.data.operation}`;

          try {
            const acquired = await idempotencyManager.acquireLock(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              job.data.operation
            );
            if (!acquired) {
              logger.info({ operationKey }, 'Skipping job: idempotency lock not acquired');
              return { skipped: true, reason: 'idempotency' };
            }
          } catch (error) {
             logger.warn({ err: error }, 'Failed to acquire idempotency lock');
             throw error;
          }

          try {
            await threatAnalyzer.analyzeEmail(job.data.resourceId);

            await idempotencyManager.markCompleted(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              'result-ref-success'
            );

            // Dispatch CTI Enrichment Phase 14.3
            const ctiQueue = queueManager.getQueue('email-cti-enrichment');
            await ctiQueue.add(
              'cti-enrichment',
              {
                organizationId: job.data.organizationId,
                resourceId: job.data.resourceId,
                jobId: job.id as string,
                operation: 'cti-enrichment',
                emailId: job.data.resourceId,
                requestId: job.data.requestId,
                traceId: job.data.traceId
              },
              { jobId: `cti-${job.data.resourceId}` }
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

  threatWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'email-threat-analysis' }, 'Threat Analysis Job completed successfully');
  });

  threatWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'email-threat-analysis', err }, 'Threat Analysis Job failed');
  });

  // Setup CTI Enrichment Fan-out Worker Phase 14.3
  const iocQueue = queueManager.getQueue('ioc-cti-enrichment');
  const ctiReevalCoordinator = new CtiReevaluationCoordinator(idempotencyRedis);
  const ctiWorkerLogic = new CtiEnrichmentWorker(
    prisma,
    async (ioc, emailId, organizationId) => {
      await iocQueue.add('enrich-ioc', {
        indicator: ioc.value,
        indicatorType: ioc.type,
        emailId,
        organizationId
      } as CTIEnrichmentJob);
    },
    ctiReevalCoordinator
  );

  const ctiWorker = createTenantScopedWorker<EmailCtiEnrichmentJobPayload, unknown>(
    'email-cti-enrichment',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          traceId: job.data.traceId,
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ data: job.data }, 'Processing email CTI enrichment job');

          const operationKey = `cti:${job.data.operation}`;

          try {
            const acquired = await idempotencyManager.acquireLock(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              job.data.operation
            );
            if (!acquired) {
              logger.info({ operationKey }, 'Skipping job: idempotency lock not acquired');
              return { skipped: true, reason: 'idempotency' };
            }
          } catch (error) {
             logger.warn({ err: error }, 'Failed to acquire idempotency lock');
             throw error;
          }

          try {
            await ctiWorkerLogic.processEmail(job.data.resourceId, job.data.organizationId);

            await idempotencyManager.markCompleted(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              'result-ref-success'
            );

            // Dispatch ML Classification Phase 11
            const mlQueue = queueManager.getQueue('email-ml-classification');
            await mlQueue.add(
              'ml-classification',
              {
                organizationId: job.data.organizationId,
                resourceId: job.data.resourceId,
                jobId: job.id as string,
                operation: 'ml-classification',
                emailId: job.data.resourceId,
                requestId: job.data.requestId,
                traceId: job.data.traceId
              },
              { jobId: `ml-${job.data.resourceId}` }
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

  ctiWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'email-cti-enrichment' }, 'CTI Enrichment Job completed successfully');
  });

  ctiWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'email-cti-enrichment', err }, 'CTI Enrichment Job failed');
  });

  // Setup decoupled IOC CTI Worker Phase 17.3-AG
  const iocWorker = queueManager.createWorker<CTIEnrichmentJob, unknown>(
    'ioc-cti-enrichment',
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.correlationId || generateRequestId(),
          jobId: job.id as string,
          traceId: job.data.correlationId,
        },
        async () => {
          logger.info({ indicator: job.data.indicator }, 'Processing decoupled IOC CTI job');
          await processCTIJob(job.data);
          return { success: true };
        }
      );
    },
    5 // Higher concurrency for IOC lookups
  );

  // Phase 7D: once every IOC job fanned out for an email has reached a
  // terminal state (succeeded, or exhausted its retries), schedule exactly
  // one CTI re-evaluation of that email so real observations can still reach
  // its risk score even though ML/Fusion may have already run once before
  // CTI enrichment finished. This never re-enqueues CTI work, so it cannot loop.
  const triggerCtiReevaluation = (job: { data: CTIEnrichmentJob; id?: string }) =>
    scheduleCtiReevaluationIfComplete(
      job.data.emailId,
      job.data.organizationId,
      job.id as string,
      ctiReevalCoordinator,
      queueManager.getQueue('email-ml-classification')
    );

  iocWorker.on('completed', (job) => {
    void triggerCtiReevaluation(job);
  });

  iocWorker.on('failed', (job, err) => {
    if (!job) return;
    if (!isTerminalIocFailure(job.attemptsMade, job.opts.attempts ?? 1)) {
      // More retries remain for this IOC job; not a terminal outcome yet.
      return;
    }
    logger.warn({ jobId: job.id, indicator: job.data.indicator, err }, 'IOC CTI job permanently failed');
    void triggerCtiReevaluation(job);
  });

  // Setup ML Classification Worker
  const mlClassifier = new MLClassifier(prisma, rawEmailStore);
  const mlWorker = createTenantScopedWorker<EmailMlClassificationJobPayload, unknown>(
    'email-ml-classification',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          traceId: job.data.traceId,
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ data: job.data }, 'Processing email ML classification job');

          const operationKey = `ml:${job.data.operation}`;

          try {
            const acquired = await idempotencyManager.acquireLock(
              job.data.organizationId,
              operationKey,
              job.data.resourceId,
              job.data.operation
            );
            if (!acquired) {
              logger.info({ operationKey }, 'Skipping job: idempotency lock not acquired');
              return { skipped: true, reason: 'idempotency' };
            }
          } catch (error) {
             logger.warn({ err: error }, 'Failed to acquire idempotency lock');
             throw error;
          }

          try {
            // Phase 13: ML classification, then Fusion Engine to create Risk
            // Assessment. Phase 7D: a CTI-triggered re-evaluation skips
            // re-classification (see runMlEvaluationStage) since only the CTI
            // observations available to FusionEngine have changed.
            const fusionEngine = new FusionEngine(prisma, notificationService, idempotencyRedis);
            await runMlEvaluationStage(job.data.resourceId, job.data.operation, {
              classifyEmail: (emailId) => mlClassifier.classifyEmail(emailId),
              evaluateFusion: (emailId) => fusionEngine.evaluate(emailId)
            });

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

  mlWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'email-ml-classification' }, 'ML Classification Job completed successfully');
  });

  mlWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'email-ml-classification', err }, 'ML Classification Job failed');
  });

  // Phase 2: Outbound webhook delivery worker. Runs on its own queue, so a
  // slow or unreachable receiver never delays email analysis — FusionEngine
  // only enqueues here, never waits for delivery.
  const webhookDeliveryWorker = createTenantScopedWorker<WebhookDeliveryJobPayload, unknown>(
    'webhook-delivery',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          jobId: job.id as string,
          tenantId: job.data.organizationId,
        },
        async () => {
          await processWebhookDelivery(prisma, job);
          return { success: true };
        }
      );
    },
    2,
    webhookResourceValidator
  );

  webhookDeliveryWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'webhook-delivery' }, 'Webhook delivery job completed successfully');
  });

  webhookDeliveryWorker.on('failed', (job, err) => {
    // err is a generic Error from processWebhookDelivery's own safe-message
    // handling — never the raw fetch/network error object, and never
    // includes the webhook secret.
    logger.error({ jobId: job?.id, queue: 'webhook-delivery', err: err.message }, 'Webhook delivery job failed');
  });

  // Phase J: forensic PDF report generation. Runs on its own queue so a
  // report request never delays or is delayed by email analysis; the
  // resourceValidator enforces that a job can only ever act on a
  // ForensicReport row belonging to the requesting organization.
  const reportGenerationWorkerLogic = new ReportGenerationWorker(prisma, rawEmailStore);
  const reportGenerationWorker = createTenantScopedWorker<ReportGenerationJobPayload, unknown>(
    'report-generation',
    idempotencyRedis,
    async (job) => {
      return runWithContext(
        {
          requestId: job.data.requestId || generateRequestId(),
          jobId: job.id as string,
          tenantId: job.data.organizationId,
          actorId: job.data.actorId,
        },
        async () => {
          logger.info({ reportId: job.data.reportId, emailId: job.data.emailId }, 'Processing forensic report generation job');
          await reportGenerationWorkerLogic.generate(job.data.reportId, job.data.organizationId);
          return { success: true };
        }
      );
    },
    1,
    reportResourceValidator
  );

  reportGenerationWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'report-generation' }, 'Report generation job completed successfully');
  });

  reportGenerationWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'report-generation', err: err.message }, 'Report generation job failed');
  });

  // Setup Gmail Sync Worker
  const gmailSyncWorkerLogic = new GmailSyncWorker(rawEmailStore);
  const gmailSyncWorker = queueManager.createWorker<GmailSyncJobPayload, unknown>(
    'gmail-sync',
    async (job) => {
      return runWithContext(
        {
          requestId: generateRequestId(),
          jobId: job.id as string,
          tenantId: job.data.organizationId,
        },
        async () => {
          logger.info({ emailAddress: job.data.emailAddress }, 'Processing Gmail sync job');
          await gmailSyncWorkerLogic.process(job.data);
          return { success: true };
        }
      );
    },
    2 // Concurrency
  );

  gmailSyncWorker.on('completed', (job) => {
    logger.info({ jobId: job.id, queue: 'gmail-sync' }, 'Gmail Sync Job completed successfully');
  });

  gmailSyncWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'gmail-sync', err }, 'Gmail Sync Job failed');
  });

  // Gmail Watch Renewal — Phase 10G.1. Google's push-notification watch
  // subscriptions expire after a maximum of 7 days and are otherwise never
  // renewed anywhere in this codebase (see gmail-watch-renewal.ts's doc
  // comment for the full rationale). A BullMQ repeatable job is the
  // smallest addition that reuses existing infrastructure: BullMQ
  // deduplicates a repeatable job registration by its repeat key, so
  // calling `.add()` with the same options from multiple worker instances
  // does not create duplicate scheduled firings, and only one worker
  // instance actually claims each firing when it occurs — no new locking
  // or scheduling mechanism is introduced.
  const gmailWatchRenewalWorkerLogic = new GmailWatchRenewalWorker();
  const gmailWatchRenewalQueue = queueManager.getQueue('gmail-watch-renewal');
  await gmailWatchRenewalQueue.add(
    'renew-watches',
    {},
    {
      repeat: { every: 24 * 60 * 60 * 1000 }, // daily — safely under Gmail's 7-day watch expiration
      jobId: 'gmail-watch-renewal-repeat'
    }
  );
  const gmailWatchRenewalWorker = queueManager.createWorker<Record<string, never>, unknown>(
    'gmail-watch-renewal',
    async () => {
      return runWithContext(
        { requestId: generateRequestId(), jobId: 'gmail-watch-renewal', tenantId: 'system' },
        async () => {
          await gmailWatchRenewalWorkerLogic.renewAll();
          return { success: true };
        }
      );
    },
    1
  );

  gmailWatchRenewalWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'gmail-watch-renewal', err }, 'Gmail Watch Renewal Job failed');
  });

  // Phase M: evidence notarization sweep. Batching is inherently
  // cross-evidence (it accumulates multiple items before acting), so — like
  // gmail-watch-renewal above — this is a periodic repeatable job rather
  // than a per-event trigger. Never blocks or fails the primary email
  // ingestion/analysis pipeline; every failure inside the sweep is caught
  // and logged per-organization (see NotarizationSweep.ts).
  const notarizationQueue = queueManager.getQueue('evidence-notarization');
  await notarizationQueue.add(
    'sweep',
    {},
    {
      repeat: { every: 5 * 60 * 1000 }, // every 5 minutes
      jobId: 'evidence-notarization-sweep-repeat'
    }
  );
  const notarizationWorker = queueManager.createWorker<Record<string, never>, unknown>(
    'evidence-notarization',
    async () => {
      return runWithContext(
        { requestId: generateRequestId(), jobId: 'evidence-notarization-sweep', tenantId: 'system' },
        async () => {
          const result = await runNotarizationSweep(prisma);
          return { success: true, ...result };
        }
      );
    },
    1
  );

  notarizationWorker.on('completed', (job, result) => {
    logger.info({ jobId: job.id, queue: 'evidence-notarization', result }, 'Evidence notarization sweep completed');
  });

  notarizationWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, queue: 'evidence-notarization', err }, 'Evidence notarization sweep failed');
  });

  logger.info('Workers registered and listening for jobs.');

  // Start Metrics Server
  const server = createMetricsServer();

  const port = env.WORKER_PORT;
  await server.listen({ port, host: '0.0.0.0' });
  logger.info(`Worker metrics server listening on port ${port}`);
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
