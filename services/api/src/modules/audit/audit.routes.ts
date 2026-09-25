import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';
import { fastifyAuditLogQuerySchema, uuidSchema } from '../../utils/validation';

/**
 * Organization-wide Audit Log — the same AuditLog table backing the
 * case-scoped Change History (case.routes.ts's GET /:caseId/history), just
 * without the `resource: 'Case', resourceId: caseId` narrowing. Read-only,
 * safe-field-only projection: never returns ipAddress/userAgent or raw
 * metadata beyond what logAuditEvent() already scrubbed at write time.
 */
export default async function auditRoutes(server: FastifyInstance) {
  server.get('/', {
    schema: { querystring: fastifyAuditLogQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('AUDIT_LOG_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
      action?: string;
      actorId?: string;
      resource?: string;
      resourceId?: string;
      dateFrom?: string;
      dateTo?: string;
      q?: string;
    };

    let cursorOpt: { id: string } | undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);
        const cursorSchema = z.tuple([z.string().datetime(), uuidSchema]);
        const validated = cursorSchema.parse(decoded);
        cursorOpt = { id: validated[1] };
      } catch {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    const createdAtFilter: { gte?: Date; lte?: Date } = {};
    if (query.dateFrom) createdAtFilter.gte = new Date(query.dateFrom);
    if (query.dateTo) createdAtFilter.lte = new Date(query.dateTo);

    const where = {
      organizationId,
      ...(query.action ? { action: query.action } : {}),
      ...(query.actorId ? { actorId: query.actorId } : {}),
      ...(query.resource ? { resource: query.resource } : {}),
      ...(query.resourceId ? { resourceId: query.resourceId } : {}),
      ...(Object.keys(createdAtFilter).length > 0 ? { createdAt: createdAtFilter } : {}),
      ...(query.q
        ? {
            OR: [
              { action: { contains: query.q, mode: 'insensitive' as const } },
              { resource: { contains: query.q, mode: 'insensitive' as const } },
              { resourceId: { contains: query.q, mode: 'insensitive' as const } },
            ],
          }
        : {}),
    };

    const limit = query.limit;
    const logs = await prisma.auditLog.findMany({
      where,
      take: limit + 1,
      skip: cursorOpt ? 1 : 0,
      cursor: cursorOpt,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: {
        id: true,
        action: true,
        resource: true,
        resourceId: true,
        actorId: true,
        status: true,
        metadata: true,
        createdAt: true,
      },
    });

    let nextCursor: string | null = null;
    if (logs.length > limit) {
      logs.pop();
      const lastItem = logs[logs.length - 1];
      if (lastItem) {
        nextCursor = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
      }
    }

    // Batched actor enrichment (tenant-scoped) — same pattern as
    // case.routes.ts's history endpoint.
    const actorIds = Array.from(new Set(logs.map((l) => l.actorId).filter((id): id is string => Boolean(id))));
    const actors = actorIds.length > 0
      ? await prisma.user.findMany({
          where: { id: { in: actorIds }, memberships: { some: { organizationId } } },
          select: { id: true, email: true, firstName: true, lastName: true },
        })
      : [];
    const actorById = new Map(actors.map((a) => [a.id, a]));

    const items = logs.map((log) => ({
      id: log.id,
      action: log.action,
      resource: log.resource,
      resourceId: log.resourceId,
      status: log.status,
      createdAt: log.createdAt,
      actorId: log.actorId,
      actor: log.actorId ? actorById.get(log.actorId) ?? null : null,
      metadata: log.metadata,
    }));

    await logAuditEvent({
      action: 'AUDIT_LOG_VIEWED',
      resource: 'Organization',
      resourceId: organizationId,
      organizationId,
      actorId: request.user?.sub,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(200).send({ items, nextCursor });
  });
}
