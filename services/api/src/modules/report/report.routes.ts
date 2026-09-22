import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { LocalRawEmailStore, S3RawEmailStore, RawEmailStore } from '@ciperscope/storage';
import { env, defaultRawEmailStoragePath } from '@ciperscope/config';
import { fastifyGlobalForensicReportParamsSchema } from '../../utils/validation';
import { logAuditEvent } from '../../utils/audit';
import { toPublicForensicReport } from './reportSerializer';

export default async function reportRoutes(server: FastifyInstance) {
  let storage: RawEmailStore;
  if (env.S3_BUCKET) {
    storage = new S3RawEmailStore(env.S3_BUCKET, env.S3_REGION || 'us-east-1', env.S3_ENDPOINT);
  } else {
    storage = new LocalRawEmailStore(defaultRawEmailStoragePath);
  }

  // GET /api/v1/reports/:reportId — report metadata (status, version,
  // timestamps, SHA-256). Never returns the artifact bytes or the internal
  // storage key — see reportSerializer.ts.
  server.get('/:reportId', {
    schema: { params: fastifyGlobalForensicReportParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { reportId } = request.params as { reportId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // organizationId is enforced directly in the WHERE clause (ForensicReport
    // stores it denormalized precisely so tenant isolation never depends on
    // a join) — a report belonging to another organization returns 404, the
    // same as a nonexistent one, never a 403 that would confirm its existence.
    const report = await prisma.forensicReport.findFirst({ where: { id: reportId, organizationId } });
    if (!report) {
      return reply.status(404).send({ error: 'Not Found', message: 'Report not found' });
    }

    await logAuditEvent({
      action: 'EMAIL_REPORT_VIEWED',
      resource: 'ForensicReport',
      resourceId: report.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    return reply.send(toPublicForensicReport(report));
  });

  // GET /api/v1/reports/:reportId/download — streams the generated PDF
  // artifact. Only ever reads the key persisted on the ForensicReport row
  // itself (never a caller-supplied path), so there is no path-traversal or
  // arbitrary-file-read surface here.
  server.get('/:reportId/download', {
    schema: { params: fastifyGlobalForensicReportParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { reportId } = request.params as { reportId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const report = await prisma.forensicReport.findFirst({ where: { id: reportId, organizationId } });
    if (!report) {
      return reply.status(404).send({ error: 'Not Found', message: 'Report not found' });
    }

    if (report.status !== 'COMPLETED' || !report.artifactLocation) {
      return reply.status(409).send({ error: 'Conflict', message: `Report is not ready for download (status: ${report.status})` });
    }

    const exists = await storage.exists(report.artifactLocation);
    if (!exists) {
      return reply.status(404).send({ error: 'Not Found', message: 'Report artifact is missing from storage' });
    }

    const stream = await storage.get(report.artifactLocation);

    await logAuditEvent({
      action: 'EMAIL_REPORT_DOWNLOADED',
      resource: 'ForensicReport',
      resourceId: report.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    reply.header('Content-Type', 'application/pdf');
    reply.header('Content-Disposition', `attachment; filename="ciperscope-report-${report.id}.pdf"`);
    if (report.sha256) {
      reply.header('X-Report-SHA256', report.sha256);
    }
    return reply.send(stream);
  });
}
