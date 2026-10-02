import { FastifyInstance } from 'fastify';
import psl from 'psl';
import { EmailIngestionService } from './ingestion.service';
import { prisma, Prisma } from '@ciperscope/database';
import { LocalRawEmailStore, S3RawEmailStore, RawEmailStore } from '@ciperscope/storage';
import { QueueManager } from '@ciperscope/queue';
import { env, defaultRawEmailStoragePath } from '@ciperscope/config';
import { getRequestContext } from '@ciperscope/logger';
import { classifyIp } from '@ciperscope/http-client';
import { buildEvidenceGraph } from './evidenceGraph';
import { multiRateLimit } from '../../middleware/rateLimiter';
import { logAuditEvent } from '../../utils/audit';
import { fastifyEmailParamsSchema, fastifyAttachmentParamsSchema } from '../../utils/validation';
import { toPublicForensicReport } from '../report/reportSerializer';

// Phase N: builds a most-recent-per-IP map from raw PTR DnsObservation rows
// (response is a JSON-encoded string[] of hostnames, or null on failure/no
// record). Shared by /:emailId/intelligence, /:emailId/evidence-graph, and
// the org-wide network-intelligence module (services/api/src/modules/
// intelligence/intelligence.routes.ts).
export function buildReverseDnsByIp(ptrRows: Array<{ queryName: string; response: string | null }>): Map<string, string[] | null> {
  const reverseDnsByIp = new Map<string, string[] | null>();
  for (const row of ptrRows) {
    if (reverseDnsByIp.has(row.queryName)) continue;
    let hostnames: string[] | null = null;
    if (row.response) {
      try {
        const parsed = JSON.parse(row.response);
        if (Array.isArray(parsed)) hostnames = parsed;
      } catch {
        hostnames = null;
      }
    }
    reverseDnsByIp.set(row.queryName, hostnames);
  }
  return reverseDnsByIp;
}

export default async function emailRoutes(server: FastifyInstance) {
  // Setup dependencies for the route
  let storage: RawEmailStore;
  if (env.S3_BUCKET) {
    storage = new S3RawEmailStore(env.S3_BUCKET, env.S3_REGION || 'us-east-1', env.S3_ENDPOINT);
  } else {
    storage = new LocalRawEmailStore(defaultRawEmailStoragePath);
  }
  const queueManager = new QueueManager(env.REDIS_URL || 'redis://127.0.0.1:6379');

  const ingestionService = new EmailIngestionService(prisma, storage);

  // Close connections when Fastify closes
  server.addHook('onClose', async () => {
    await queueManager.closeAll();
  });

  // GET / — List ingested emails for authenticated tenant with search, filtering, and pagination
  server.get('/', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (request.user?.orgs && Array.isArray(request.user.orgs) && !request.user.orgs.includes(organizationId)) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User not authorized for this organization' });
    }

    const query = request.query as {
      page?: string;
      limit?: string;
      search?: string;
      status?: string;
      classification?: string;
      source?: string;
    };

    const page = Math.max(1, parseInt(query.page || '1', 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10) || 20));
    const skip = (page - 1) * limit;

    const andConditions: Prisma.EmailWhereInput[] = [{ organizationId }];

    if (query.status && query.status !== 'ALL') {
      andConditions.push({ analysisStatus: query.status as any });
    }

    if (query.classification && query.classification !== 'ALL') {
      andConditions.push({ classification: query.classification as any });
    }

    if (query.source && query.source !== 'ALL') {
      if (query.source === 'GMAIL') {
        andConditions.push({
          OR: [
            { ingestionSrc: 'GMAIL' },
            { headers: { some: { name: 'delivered-to' } } }
          ]
        });
      } else if (query.source === 'UPLOAD') {
        andConditions.push({
          AND: [
            { ingestionSrc: 'UPLOAD' },
            { headers: { none: { name: 'delivered-to' } } }
          ]
        });
      } else {
        andConditions.push({ ingestionSrc: query.source });
      }
    }

    if (query.search && query.search.trim().length > 0) {
      const term = query.search.trim();
      andConditions.push({
        OR: [
          { subject: { contains: term, mode: 'insensitive' } },
          { senderAddress: { contains: term, mode: 'insensitive' } },
          {
            headers: {
              some: {
                name: { in: ['subject', 'from', 'to'] },
                value: { contains: term, mode: 'insensitive' }
              }
            }
          },
          {
            addresses: {
              some: {
                OR: [
                  { address: { contains: term, mode: 'insensitive' } },
                  { displayName: { contains: term, mode: 'insensitive' } },
                  { raw: { contains: term, mode: 'insensitive' } }
                ]
              }
            }
          }
        ]
      });
    }

    const where: Prisma.EmailWhereInput = { AND: andConditions };

    const [total, emails] = await Promise.all([
      prisma.email.count({ where }),
      prisma.email.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          headers: {
            where: {
              name: { in: ['subject', 'from', 'to', 'date', 'delivered-to'] }
            }
          },
          addresses: {
            where: {
              headerName: { in: ['from', 'to', 'cc'] }
            }
          },
          attachments: {
            select: {
              id: true,
              filename: true,
              mimeType: true,
              sizeBytes: true,
              threatIndicators: true,
            }
          },
          riskAssessments: {
            orderBy: { createdAt: 'desc' },
            take: 1,
            select: {
              overallScore: true,
              riskLevel: true,
            }
          }
        }
      })
    ]);

    const items = emails.map(email => {
      const subjectHeader = email.headers.find(h => h.name.toLowerCase() === 'subject')?.value;
      const fromHeader = email.headers.find(h => h.name.toLowerCase() === 'from')?.value;
      const toHeader = email.headers.find(h => h.name.toLowerCase() === 'to')?.value;
      const dateHeader = email.headers.find(h => h.name.toLowerCase() === 'date')?.value;

      const fromAddress = email.addresses.find(a => a.headerName.toLowerCase() === 'from');
      const toAddress = email.addresses.find(a => a.headerName.toLowerCase() === 'to');

      const sender = email.senderAddress || fromAddress?.address || fromAddress?.raw || fromHeader || 'Unknown Sender';
      const recipient = toAddress?.address || toAddress?.raw || toHeader || 'Unknown Recipient';
      const subject = email.subject || subjectHeader || '(No Subject)';

      let date: string;
      if (email.date) {
        date = email.date.toISOString();
      } else if (dateHeader) {
        try {
          const d = new Date(dateHeader);
          date = isNaN(d.getTime()) ? email.createdAt.toISOString() : d.toISOString();
        } catch {
          date = email.createdAt.toISOString();
        }
      } else {
        date = email.createdAt.toISOString();
      }

      const latestAssessment = email.riskAssessments[0];
      const riskScore = email.riskScore ?? latestAssessment?.overallScore ?? null;
      let priority: 'P1' | 'P2' | 'P3' | null = null;
      if (latestAssessment?.riskLevel) {
        if (latestAssessment.riskLevel === 'CRITICAL' || latestAssessment.riskLevel === 'HIGH') {
          priority = 'P1';
        } else if (latestAssessment.riskLevel === 'MEDIUM') {
          priority = 'P2';
        } else {
          priority = 'P3';
        }
      } else if (riskScore != null) {
        if (riskScore >= 70) priority = 'P1';
        else if (riskScore >= 40) priority = 'P2';
        else priority = 'P3';
      }

      const hasMaliciousAttachment = email.attachments.some(a => Array.isArray(a.threatIndicators) && a.threatIndicators.length > 0);
      const isSuspiciousOrMalicious =
        email.classification === 'PHISHING' ||
        email.classification === 'MALWARE' ||
        email.classification === 'BEC' ||
        email.classification === 'IMPERSONATION' ||
        email.classification === 'FRAUD' ||
        email.classification === 'SUSPICIOUS' ||
        (riskScore != null && riskScore >= 70) ||
        priority === 'P1' ||
        hasMaliciousAttachment;

      const isGmail = email.ingestionSrc === 'GMAIL' || email.headers.some(h => h.name.toLowerCase() === 'delivered-to');
      const resolvedIngestionSrc = isGmail ? 'GMAIL' : email.ingestionSrc;

      return {
        id: email.id,
        messageId: email.messageId,
        subject,
        sender,
        recipient,
        date,
        createdAt: email.createdAt.toISOString(),
        ingestionSrc: resolvedIngestionSrc,
        classification: email.classification,
        riskScore,
        priority,
        analysisStatus: email.analysisStatus,
        attachmentCount: email.attachments.length,
        attachments: email.attachments.map(a => ({
          id: a.id,
          filename: a.filename,
          mimeType: a.mimeType,
          sizeBytes: a.sizeBytes,
        })),
        isSuspiciousOrMalicious,
        caseId: email.caseId,
      };
    });

    await logAuditEvent({
      action: 'EMAIL_LIST_VIEWED',
      resource: 'Email',
      organizationId,
      actorId: request.user?.sub,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(200).send({
      items,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    });
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
    // fileSize is the authoritative HTTP-ingress limit — before
    // AttachmentAnalyzer's internal 50MB in-memory buffer cap ever applies
    // to a raw .eml's zip/archive attachments, and before the upload is
    // ever written to raw-email storage. On @fastify/multipart 10 /
    // Fastify 5, THIS per-call value is what actually governs (confirmed
    // via live testing: it fully replaces the plugin-level registration's
    // limits in services/api/src/index.ts rather than being bounded by
    // them, unlike the prior major version) — kept at the original
    // intended 25MB rather than the pre-migration route-level 30MB, which
    // was never actually binding before (the smaller global limit always
    // won).
    const data = await request.file({
      limits: {
        fileSize: 25 * 1024 * 1024,
        files: 1,
        fields: 0, // No extra metadata fields expected — no longer enforced by @fastify/multipart 10 (see multipartValidation.test.ts), kept for documentation/future-proofing
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
      caseId: email.caseId,
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
        region: true,
        city: true,
        latitude: true,
        longitude: true,
        asn: true,
        isp: true,
        provider: true,
        updatedAt: true
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

  // Phase H: a single, narrowly-scoped view combining relay-hop IP
  // classification, GeoIP/ASN enrichment, and CTI reputation — everything
  // already persisted by the existing pipeline, joined for the forensic
  // investigation UI. Never queries an external provider itself; this is a
  // read of already-collected evidence, tenant-scoped like every other
  // route in this file.
  server.get('/:emailId/intelligence', {
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
        relayHops: true,
        urls: true,
      }
    });

    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const uniqueIps = Array.from(new Set(email.relayHops.map(h => h.sourceIp).filter(Boolean) as string[]));

    const [geoRows, indicatorRows, ptrRows] = await Promise.all([
      prisma.geoLocation.findMany({
        where: { ipAddress: { in: uniqueIps } },
        select: {
          ipAddress: true, country: true, region: true, city: true,
          latitude: true, longitude: true, asn: true, isp: true, provider: true, updatedAt: true
        }
      }),
      uniqueIps.length > 0
        ? prisma.indicator.findMany({
          where: { value: { in: uniqueIps } },
          include: { observations: { orderBy: { observationTime: 'desc' }, take: 1 } }
        })
        : Promise.resolve([]),
      // Phase N: reverse-DNS (PTR), scoped to THIS email — enriched
      // asynchronously by the worker's CTI pipeline (cti-worker.ts). This
      // route never performs a live DNS call itself.
      uniqueIps.length > 0
        ? prisma.dnsObservation.findMany({
          where: { emailId: email.id, recordType: 'PTR', queryName: { in: uniqueIps } },
          orderBy: { createdAt: 'desc' },
        })
        : Promise.resolve([]),
    ]);

    const geoByIp = new Map(geoRows.map(g => [g.ipAddress, g]));
    const observationByIp = new Map(
      indicatorRows
        .filter(i => i.observations.length > 0)
        .map(i => [i.value, i.observations[0]])
    );
    // Most-recent PTR observation per IP. The value is attacker-influenceable
    // (see DnsResolver.resolvePtr) and is surfaced as raw forensic context,
    // never as a verified hostname.
    const reverseDnsByIp = buildReverseDnsByIp(ptrRows);

    // Each classification is deterministic and computed here, never stored
    // separately — RelayHop.sourceIp remains the single source of truth.
    const ipIntelligence = uniqueIps.map((ip) => {
      const classification = classifyIp(ip);
      const geo = geoByIp.get(ip) ?? null;
      const observation = observationByIp.get(ip) ?? null;

      return {
        ip,
        source: 'RECEIVED_HEADER' as const,
        version: classification.version,
        classification: classification.category,
        isRoutablePublic: classification.isRoutablePublic,
        geolocation: geo ? {
          country: geo.country, region: geo.region, city: geo.city,
          latitude: geo.latitude, longitude: geo.longitude,
          asn: geo.asn, isp: geo.isp, provider: geo.provider, updatedAt: geo.updatedAt,
        } : null,
        reputation: observation ? {
          verdict: observation.verdict, confidence: observation.confidence,
          provider: observation.provider, observedAt: observation.observationTime,
        } : null,
        reverseDns: reverseDnsByIp.has(ip) ? reverseDnsByIp.get(ip) : null,
      };
    });

    // Domain summary — reuses EmailUrl.domain (Phase H population fix),
    // never a second extraction pass.
    const domainCounts = new Map<string, number>();
    for (const u of email.urls) {
      if (!u.domain) continue;
      domainCounts.set(u.domain, (domainCounts.get(u.domain) ?? 0) + 1);
    }

    // Phase L: RDAP domain intelligence — read-only, already-persisted
    // (enriched asynchronously by the worker's CTI pipeline, see
    // services/worker/src/cti-worker.ts). This route never performs a live
    // RDAP/network call itself. Keyed by registrable domain, since that's
    // what RDAP resolves and what DomainIntelligence is stored against.
    const registrableByDomain = new Map(Array.from(domainCounts.keys()).map((d) => [d, psl.get(d)]));
    const registrableDomains = Array.from(new Set(Array.from(registrableByDomain.values()).filter((d): d is string => !!d)));
    const domainIntelRows = registrableDomains.length > 0
      ? await prisma.domainIntelligence.findMany({ where: { registrableDomain: { in: registrableDomains } } })
      : [];
    const domainIntelByRegistrable = new Map(domainIntelRows.map((d) => [d.registrableDomain, d]));

    const domains = Array.from(domainCounts.entries()).map(([domain, urlCount]) => {
      const registrable = registrableByDomain.get(domain) ?? null;
      const intel = registrable ? domainIntelByRegistrable.get(registrable) : undefined;
      return {
        domain,
        urlCount,
        domainIntelligence: intel
          ? {
            registrableDomain: intel.registrableDomain,
            status: intel.status,
            registrar: intel.registrar,
            registrationDate: intel.registrationDate,
            expirationDate: intel.expirationDate,
            nameservers: intel.nameservers,
            domainStatus: intel.domainStatus,
            rdapSource: intel.rdapSource,
            fetchedAt: intel.fetchedAt,
          }
          : null,
      };
    });

    await logAuditEvent({
      action: 'EMAIL_INTELLIGENCE_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send({ ipIntelligence, domains });
  });

  // Phase I: deterministic Evidence Graph — a read-only correlation of
  // already-persisted evidence (relay IPs, URLs/domains, attachments/
  // hashes/APK/QR, CTI observations, GeoIP). Never queries an external
  // provider and never returns raw email body/attachment bytes/credentials
  // — see evidenceGraph.ts's buildEvidenceGraph() for the actual logic,
  // kept as a pure, independently-testable function.
  server.get('/:emailId/evidence-graph', {
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
        relayHops: true,
        urls: true,
        attachments: true,
        addresses: true,
      }
    });

    if (!email) {
      return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
    }

    const uniqueIps = Array.from(new Set(email.relayHops.map(h => h.sourceIp).filter(Boolean) as string[]));
    const uniqueDomains = Array.from(new Set(email.urls.map(u => u.domain).filter(Boolean) as string[]));
    const uniqueHashes = Array.from(new Set(email.attachments.map(a => a.sha256).filter(Boolean) as string[]));
    const ctiLookupValues = [...uniqueIps, ...uniqueDomains, ...uniqueHashes];

    const registrableDomains = Array.from(new Set(uniqueDomains.map((d) => psl.get(d.toLowerCase())).filter((d): d is string => !!d)));

    const [geoRows, indicatorRows, caseRecord, domainIntelRows, ptrRows] = await Promise.all([
      uniqueIps.length > 0
        ? prisma.geoLocation.findMany({
          where: { ipAddress: { in: uniqueIps } },
          select: { ipAddress: true, country: true, city: true, asn: true, isp: true, provider: true }
        })
        : Promise.resolve([]),
      ctiLookupValues.length > 0
        ? prisma.indicator.findMany({
          where: { value: { in: ctiLookupValues } },
          include: { observations: { orderBy: { observationTime: 'desc' }, take: 1 } }
        })
        : Promise.resolve([]),
      // Only fetched when this email is actually linked to a case — never
      // fabricated for an unlinked email (see evidenceGraph.ts's doc comment).
      email.caseId
        ? prisma.case.findUnique({
          where: { id: email.caseId, organizationId },
          include: {
            evidence: {
              where: { organizationId },
              select: { id: true, type: true, sha256: true, filename: true, collectionTime: true, anchor: { select: { status: true, merkleRoot: true } } },
            },
            alerts: { where: { organizationId }, select: { id: true, title: true, severity: true, createdAt: true } },
          },
        })
        : Promise.resolve(null),
      registrableDomains.length > 0
        ? prisma.domainIntelligence.findMany({ where: { registrableDomain: { in: registrableDomains } } })
        : Promise.resolve([]),
      uniqueIps.length > 0
        ? prisma.dnsObservation.findMany({
          where: { emailId: email.id, recordType: 'PTR', queryName: { in: uniqueIps } },
          orderBy: { createdAt: 'desc' },
        })
        : Promise.resolve([]),
    ]);

    const reverseDnsByIp = buildReverseDnsByIp(ptrRows);

    const indicatorObservations = indicatorRows
      .filter(i => i.observations.length > 0)
      .map(i => ({
        value: i.value,
        type: i.type,
        verdict: i.observations[0].verdict,
        confidence: i.observations[0].confidence,
        provider: i.observations[0].provider,
        observationTime: i.observations[0].observationTime,
      }));

    const graph = buildEvidenceGraph({
      emailId: email.id,
      organizationId,
      senderAddress: email.senderAddress,
      relayHops: email.relayHops.map(h => ({ sourceIp: h.sourceIp, hopOrder: h.hopOrder, receivedHeader: h.receivedHeader })),
      urls: email.urls.map(u => ({
        id: u.id, url: u.url, normalizedUrl: u.normalizedUrl, domain: u.domain, source: u.source, indicators: u.indicators,
      })),
      attachments: email.attachments.map(a => ({
        id: a.id, filename: a.filename, sha256: a.sha256, apkMetadata: a.apkMetadata, qrFindings: a.qrFindings, threatIndicators: a.threatIndicators,
      })),
      geoLocations: geoRows,
      reverseDnsObservations: Array.from(reverseDnsByIp.entries()).map(([ipAddress, hostnames]) => ({ ipAddress, hostnames })),
      indicatorObservations,
      domainIntelligence: domainIntelRows.map((d) => ({
        registrableDomain: d.registrableDomain,
        status: d.status,
        registrar: d.registrar,
        registrationDate: d.registrationDate,
        expirationDate: d.expirationDate,
        nameservers: d.nameservers,
        domainStatus: d.domainStatus,
      })),
      recipients: email.addresses
        .filter(a => ['to', 'cc', 'bcc'].includes(a.headerName.toLowerCase()))
        .map(a => ({ headerName: a.headerName, address: a.address })),
      caseContext: caseRecord
        ? {
          caseId: caseRecord.id,
          title: caseRecord.title,
          status: caseRecord.status,
          priority: caseRecord.priority,
          evidence: caseRecord.evidence.map((e) => ({
            id: e.id, type: e.type, sha256: e.sha256, filename: e.filename, collectionTime: e.collectionTime,
            anchorStatus: e.anchor?.status ?? null,
            merkleRoot: e.anchor?.merkleRoot ?? null,
          })),
          alerts: caseRecord.alerts,
        }
        : null,
    });

    await logAuditEvent({
      action: 'EMAIL_EVIDENCE_GRAPH_VIEWED',
      resource: 'Email',
      resourceId: email.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.send(graph);
  });

  // Phase J: forensic PDF report generation. The route only creates the
  // ForensicReport row and enqueues the worker job — it never generates the
  // PDF synchronously, per the phase's architecture requirement. Idempotent
  // under concurrent requests via the partial unique index on
  // ForensicReport(emailId) WHERE status IN (QUEUED, GENERATING) — see
  // migration 20260922130000_phase_j_report_inflight_unique.
  server.post('/:emailId/reports', {
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

    const priorReportCount = await prisma.forensicReport.count({ where: { emailId } });
    const reportVersion = `${priorReportCount + 1}.0`;

    let report;
    let created = true;
    try {
      report = await prisma.forensicReport.create({
        data: {
          organizationId,
          emailId,
          reportVersion,
          requestedById: request.user?.sub,
        },
      });
    } catch (err: any) {
      // Unique-violation on the partial in-flight index: another request
      // already queued/is generating a report for this email — return that
      // one instead of creating a duplicate. Deliberately not filtered to
      // QUEUED/GENERATING here: by the time this fallback query runs, the
      // winning report may have already finished (or failed) generation —
      // the P2002 alone proves a report existed for this email at INSERT
      // time, so the most recent row is still the correct idempotent
      // response, not a 500.
      if (err.code === 'P2002') {
        created = false;
        report = await prisma.forensicReport.findFirst({
          where: { emailId, organizationId },
          orderBy: { createdAt: 'desc' },
        });
        if (!report) {
          throw err;
        }
      } else {
        throw err;
      }
    }

    if (created) {
      const queue = queueManager.getQueue('report-generation');
      await queue.add(
        'generate-report',
        {
          organizationId,
          resourceId: report.id,
          jobId: report.id,
          operation: 'report-generation',
          reportId: report.id,
          emailId,
        },
        { jobId: `report-${report.id}` }
      );
    }

    await logAuditEvent({
      action: 'EMAIL_REPORT_GENERATION_REQUESTED',
      resource: 'ForensicReport',
      resourceId: report.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      metadata: { emailId, deduplicated: !created },
      req: request,
    });

    return reply.status(created ? 202 : 200).send(toPublicForensicReport(report));
  });

  server.get('/:emailId/reports', {
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

    const reports = await prisma.forensicReport.findMany({
      where: { emailId, organizationId },
      orderBy: { createdAt: 'desc' },
    });

    await logAuditEvent({
      action: 'EMAIL_REPORT_VIEWED',
      resource: 'Email',
      resourceId: emailId,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    return reply.send({ reports: reports.map(toPublicForensicReport) });
  });
}
