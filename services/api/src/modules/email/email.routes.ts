import { FastifyInstance } from 'fastify';
import { EmailIngestionService } from './ingestion.service';
import { prisma } from '@ciperscope/database';
import { LocalRawEmailStore, S3RawEmailStore, RawEmailStore } from '@ciperscope/storage';
import { QueueManager, IdempotencyManager, createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import { getRequestContext } from '@ciperscope/logger';
import { multiRateLimit } from '../../middleware/rateLimiter';
import { logAuditEvent } from '../../utils/audit';
import { fastifyEmailParamsSchema, fastifyAttachmentParamsSchema } from '../../utils/validation';

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
    preHandler: multiRateLimit([
      // IP limit: 100/minute to prevent generic DDoS (Fail open if Redis is down because core business logic depends on it)
      (req) => ({ key: `rl:ingest:ip:${req.ip}`, max: 100, windowSec: 60, failOpen: true, errorMessage: 'Too many ingestions from this IP' }),
      // User limit: 50/minute (Fail open)
      (req) => ({ key: `rl:ingest:user:${req.user?.sub}`, max: 50, windowSec: 60, failOpen: true, errorMessage: 'Too many ingestions for this user' }),
      // Org limit: 200/minute (Fail open). We must extract org ID safely.
      (req) => {
        const orgId = req.headers['x-organization-id'] as string;
        if (!orgId) return null; // We'll reject missing orgId inside the route handler
        return { key: `rl:ingest:org:${orgId}`, max: 200, windowSec: 60, failOpen: true, errorMessage: 'Organization ingestion limit reached' };
      }
    ]),
  }, async (request, reply) => {
    // 1. Verify organization context (tenant isolation) securely from authenticated claims
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // Ensure the user actually belongs to this organization (RBAC/Spoofing protection)
    const allowedOrgs = request.user?.orgs || [];
    if (!allowedOrgs.includes(organizationId)) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User not authorized for this organization' });
    }

    // 2. Validate Multipart
    const data = await request.file({
      limits: {
        fileSize: 30 * 1024 * 1024, // 30 MB limit
        files: 1,
        fields: 0, // No extra metadata fields expected
      }
    });

    if (!data) {
      return reply.status(400).send({ error: 'Bad Request', message: 'No file uploaded' });
    }

    if (data.file.destroyed) {
      return reply.status(413).send({ error: 'Payload Too Large', message: 'Upload limits exceeded' });
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
        await logAuditEvent({
          action: 'EMAIL_INGESTED',
          resource: 'Email',
          resourceId: result.emailId,
          status: 'SUCCESS',
          req: request,
          metadata: { duplicate: true }
        });
        return reply.status(200).send({
          message: 'Duplicate email detected',
          ...result
        });
      }

      await logAuditEvent({
        action: 'EMAIL_INGESTED',
        resource: 'Email',
        resourceId: result.emailId,
        status: 'SUCCESS',
        req: request,
        metadata: { duplicate: false }
      });

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
      const errCode = (error as any).code;
      if (error.message === 'File size limit reached' ||
        errCode === 'FST_FILES_LIMIT' ||
        errCode === 'FST_FIELDS_LIMIT' ||
        errCode === 'FST_PARTS_LIMIT' ||
        errCode === 'FST_REQ_FILE_TOO_LARGE') {
        return reply.status(413).send({ error: 'Payload Too Large', message: 'Upload limits exceeded' });
      }
      throw err;
    }
  });

  // ==========================================
  // Phase 8 Forensics Endpoints
  // ==========================================

  server.get('/:emailId/analysis', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_ANALYSIS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

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
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_HEADERS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ headers });
  });

  server.get('/:emailId/received-hops', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_RECEIVED_HOPS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ hops });
  });

  server.get('/:emailId/mime-parts', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_MIME_PARTS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ mimeParts: parts });
  });

  // ==========================================
  // Phase 9 Authentication Verification
  // ==========================================

  server.get('/:emailId/authentication', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_AUTH_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ analysis });
  });

  server.get('/:emailId/spf', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_SPF_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ spfVerifications: verifications });
  });

  server.get('/:emailId/dkim', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_DKIM_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ dkimVerifications: verifications });
  });

  server.get('/:emailId/dmarc', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_DMARC_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ dmarcVerification: verification });
  });

  // ==========================================
  // Phase 10 Threat Analysis Endpoints
  // ==========================================

  server.get('/:emailId/urls', {
    schema: { params: fastifyEmailParamsSchema },
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
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_ATTACHMENT_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ attachments });
  });

  server.get('/:emailId/attachments/:attachmentId', {
    schema: { params: fastifyAttachmentParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_ATTACHMENT_VIEWED',
      resource: 'Attachment',
      resourceId: attachment.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ attachment });
  });

  server.get('/:emailId/ai-analysis', {
    schema: { params: fastifyEmailParamsSchema },
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

    await logAuditEvent({
      action: 'EMAIL_AI_ANALYSIS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ prediction });
  });

  // ==========================================
  // Phase 14.5 Forensic Intelligence Endpoints
  // ==========================================

  server.get('/:emailId/threat-indicators', {
    schema: { params: fastifyEmailParamsSchema },
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
        urls: true,
        attachments: true,
        relayHops: true
      }
    });

    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const possibleIocs = [
      ...email.urls.map(u => {
        try {
          return new URL(u.url).hostname;
        } catch {
          return u.url;
        }
      }),
      ...email.attachments.map(a => a.sha256).filter(Boolean),
      ...email.relayHops.map(h => h.sourceIp).filter(Boolean)
    ] as string[];

    const observations = await prisma.threatIntelObservation.findMany({
      where: {
        indicator: {
          value: { in: possibleIocs }
        }
      },
      include: {
        indicator: true
      }
    });

    const indicators = observations.map(obs => ({
      id: obs.id,
      iocType: obs.indicator.type,
      iocValue: obs.indicator.value,
      provider: obs.provider,
      status: obs.verdict,
      confidence: obs.confidence
    }));

    await logAuditEvent({
      action: 'EMAIL_THREAT_INDICATORS_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ threatIndicators: indicators });
  });

  server.get('/:emailId/geolocation', {
    schema: { params: fastifyEmailParamsSchema },
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
        relayHops: true
      }
    });

    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const ips = email.relayHops.map(h => h.sourceIp).filter(Boolean) as string[];

    const geolocation = await prisma.geoLocation.findMany({
      where: {
        ipAddress: { in: ips }
      },
      select: {
        id: true,
        ipAddress: true,
        country: true,
        city: true,
        asn: true,
        isp: true
      }
    });

    await logAuditEvent({
      action: 'EMAIL_GEOLOCATION_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ geolocation });
  });
}
