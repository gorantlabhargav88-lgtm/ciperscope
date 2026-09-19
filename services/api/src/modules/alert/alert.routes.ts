import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { fastifyAlertListQuerySchema, fastifyGlobalAlertParamsSchema, fastifyUpdateAlertBodySchema } from '../../utils/validation';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';

export default async function alertRoutes(server: FastifyInstance) {
  server.get('/', {
    schema: { querystring: fastifyAlertListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('ALERT_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as any;
    const limit = query.limit;

    let cursorOpt: any = undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);
        cursorOpt = { id: decoded[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    const where: any = { organizationId };
    if (query.severity) where.severity = query.severity;
    if (query.isRead !== undefined) where.isRead = query.isRead;

    try {
      const items = await prisma.alert.findMany({
        where,
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy: [
          { createdAt: query.direction || 'desc' },
          { id: query.direction || 'desc' }
        ],
      });

      let nextCursor: string | null = null;
      if (items.length > limit) {
        items.pop();
        const lastItem = items[items.length - 1];
        if (lastItem) {
          nextCursor = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
        }
      }

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.patch('/:alertId', {
    schema: {
      params: fastifyGlobalAlertParamsSchema,
      body: fastifyUpdateAlertBodySchema
    },
    preValidation: [server.authenticate, server.requirePermission('ALERT_UPDATE')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { alertId } = request.params as { alertId: string };
    const { isRead } = request.body as { isRead: boolean };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      const alert = await prisma.alert.update({
        where: { id: alertId, organizationId },
        data: { isRead }
      });

      await logAuditEvent({
        action: 'CASE_ALERT_UPDATED',
        resource: 'Alert',
        resourceId: alert.id,
        actorId: request.user?.sub,
        status: 'SUCCESS',
        metadata: { isRead },
        req: request
      });

      return reply.status(200).send(alert);
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(404).send({ error: 'Not Found', message: 'Alert not found' });
      }
      throw err;
    }
  });
}
