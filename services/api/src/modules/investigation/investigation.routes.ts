import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { fastifyInvestigationListQuerySchema, fastifyGlobalInvestigationParamsSchema } from '../../utils/validation';

export default async function investigationRoutes(server: FastifyInstance) {
  server.get('/', {
    schema: { querystring: fastifyInvestigationListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('INVESTIGATION_READ')]
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

    try {
      const items = await prisma.investigation.findMany({
        where: { case: { organizationId } },
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy: [
          { createdAt: 'desc' },
          { id: 'desc' }
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

  server.get('/:investigationId', {
    schema: { params: fastifyGlobalInvestigationParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('INVESTIGATION_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { investigationId } = request.params as { investigationId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const investigation = await prisma.investigation.findFirst({
      where: { id: investigationId, case: { organizationId } },
    });

    if (!investigation) {
      return reply.status(404).send({ error: 'Not Found', message: 'Investigation not found' });
    }

    return reply.status(200).send(investigation);
  });
}
