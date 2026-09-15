import { FastifyInstance } from 'fastify';
import { EmailIngestionService } from './ingestion.service';
import { prisma } from '@ciperscope/database';
import { LocalRawEmailStore, S3RawEmailStore, RawEmailStore } from '@ciperscope/storage';
import { QueueManager, IdempotencyManager, createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import { getRequestContext } from '@ciperscope/logger';

export default async function emailRoutes(server: FastifyInstance) {
  // Setup dependencies for the route
  let storage: RawEmailStore;
  if (env.S3_BUCKET) {
    storage = new S3RawEmailStore(env.S3_BUCKET, env.S3_REGION || 'us-east-1', env.S3_ENDPOINT);
  } else {
    storage = new LocalRawEmailStore();
  }
  const redisConnection = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');
  const queueManager = new QueueManager(env.REDIS_URL || 'redis://127.0.0.1:6379');
  const idempotencyManager = new IdempotencyManager(redisConnection, prisma);

  const ingestionService = new EmailIngestionService(prisma, storage, idempotencyManager, queueManager);

  // Close connections when Fastify closes
  server.addHook('onClose', async () => {
    await queueManager.closeAll();
    redisConnection.disconnect();
  });

  server.post('/ingest', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_INGEST')],
    config: {
      rateLimit: {
        max: 1000,
        timeWindow: '1 minute'
      }
    }
  }, async (request, reply) => {
    // 1. Verify organization context (tenant isolation)
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // 2. Validate Multipart
    const data = await request.file({
      limits: {
        fileSize: 30 * 1024 * 1024, // 30 MB limit
      }
    });

    if (!data) {
      return reply.status(400).send({ error: 'Bad Request', message: 'No file uploaded' });
    }

    data.file.on('limit', () => {
      data.file.destroy(new Error('File size limit reached'));
    });

    // 3. Process ingestion securely
    try {
      const context = getRequestContext();
      const result = await ingestionService.ingestFromStream(data.file, {
        organizationId,
        source: 'UPLOAD',
        traceId: context?.traceId,
        requestId: request.id as string,
        userId: userId,
      });

      if (result.duplicate) {
        return reply.status(200).send({
          message: 'Duplicate email detected',
          ...result
        });
      }

      return reply.status(202).send({
        message: 'Email ingested and queued for processing',
        ...result
      });
    } catch (err: unknown) {
      const error = err as Error;
      if (error.message.includes('Empty file')) {
         return reply.status(400).send({ error: 'Bad Request', message: 'Empty file uploaded' });
      }
      if (error.message.includes('Concurrent ingestion detected')) {
         return reply.status(409).send({ error: 'Conflict', message: error.message });
      }
      if (error.message === 'File size limit reached' ||
          err instanceof server.multipartErrors.FilesLimitError ||
          err instanceof server.multipartErrors.FieldsLimitError ||
          err instanceof server.multipartErrors.PartsLimitError ||
          err instanceof server.multipartErrors.RequestFileTooLargeError) {
          return reply.status(413).send({ error: 'Payload Too Large', message: 'Upload limits exceeded' });
      }
      throw err;
    }
  });

  // ==========================================
  // Phase 8 Forensics Endpoints
  // ==========================================

  server.get('/:emailId/analysis', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({
      where: { id: emailId, organizationId },
      include: {
        riskAssessments: {
          include: { factors: true },
          orderBy: { createdAt: 'desc' },
          take: 1
        }
      }
    });

    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    return reply.send({
      id: email.id,
      analysisStatus: email.analysisStatus || 'UNKNOWN',
      classification: email.classification,
      riskScore: email.riskScore,
      createdAt: email.createdAt,
      riskAssessment: email.riskAssessments[0] || null
    });
  });

  server.get('/:emailId/headers', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // Verify ownership
    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const headers = await prisma.emailHeader.findMany({
      where: { emailId },
      orderBy: { index: 'asc' }
    });

    return reply.send({ headers });
  });

  server.get('/:emailId/received-hops', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // Verify ownership
    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const hops = await prisma.relayHop.findMany({
      where: { emailId },
      orderBy: { hopOrder: 'asc' }
    });

    return reply.send({ hops });
  });

  server.get('/:emailId/mime-parts', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // Verify ownership
    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    // Fetch all parts, they are usually minimal so flat array is fine, UI can reconstruct tree
    const parts = await prisma.mimePart.findMany({
      where: { emailId },
      orderBy: { partIndex: 'asc' }
    });

    return reply.send({ mimeParts: parts });
  });

  // ==========================================
  // Phase 9 Authentication Verification
  // ==========================================

  server.get('/:emailId/authentication', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const analysis = await prisma.emailAuthenticationAnalysis.findUnique({
      where: { emailId }
    });

    return reply.send({ analysis });
  });

  server.get('/:emailId/spf', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const verifications = await prisma.spfVerification.findMany({
      where: { emailId },
      orderBy: { createdAt: 'desc' }
    });

    return reply.send({ spfVerifications: verifications });
  });

  server.get('/:emailId/dkim', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const verifications = await prisma.dkimVerification.findMany({
      where: { emailId },
      orderBy: { createdAt: 'desc' }
    });

    return reply.send({ dkimVerifications: verifications });
  });

  server.get('/:emailId/dmarc', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const verification = await prisma.dmarcVerification.findUnique({
      where: { emailId }
    });

    return reply.send({ dmarcVerification: verification });
  });

  // ==========================================
  // Phase 10 Threat Analysis Endpoints
  // ==========================================

  server.get('/:emailId/urls', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const urls = await prisma.emailUrl.findMany({
      where: { emailId },
      orderBy: { createdAt: 'desc' }
    });

    return reply.send({ urls });
  });

  server.get('/:emailId/attachments', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const attachments = await prisma.emailAttachment.findMany({
      where: { emailId },
      orderBy: { createdAt: 'desc' }
    });

    return reply.send({ attachments });
  });

  server.get('/:emailId/attachments/:attachmentId', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId, attachmentId } = request.params as { emailId: string, attachmentId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const attachment = await prisma.emailAttachment.findUnique({
      where: { id: attachmentId, emailId }
    });

    if (!attachment) {
      return reply.status(404).send({ error: 'Not Found', message: 'Attachment not found' });
    }

    return reply.send({ attachment });
  });

  server.get('/:emailId/ai-analysis', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const prediction = await prisma.mLInference.findFirst({
      where: { emailId, organizationId },
      orderBy: { createdAt: 'desc' }
    });

    if (!prediction) {
      return reply.send({
        status: 'NOT_AVAILABLE',
        prediction: { status: 'NOT_AVAILABLE', message: 'No verified CiperScope ML model artifact is currently configured.' }
      });
    }

    return reply.send({ prediction });
  });

  // ==========================================
  // Phase 14.5 Forensic Intelligence Endpoints
  // ==========================================

  server.get('/:emailId/threat-indicators', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const indicators = await prisma.threatIndicator.findMany({
      where: { emailId },
      select: {
        id: true,
        iocType: true,
        iocValue: true,
        provider: true,
        status: true,
        confidence: true
      }
    });

    return reply.send({ threatIndicators: indicators });
  });

  server.get('/:emailId/geolocation', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { emailId } = request.params as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const email = await prisma.email.findUnique({ where: { id: emailId, organizationId } });
    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const geolocation = await prisma.geolocationInfo.findMany({
      where: { emailId },
      select: {
        id: true,
        ipAddress: true,
        country: true,
        city: true,
        asn: true,
        isp: true
      }
    });

    return reply.send({ geolocation });
  });
}
