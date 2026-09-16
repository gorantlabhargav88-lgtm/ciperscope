import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { fastifyCreateCaseBodySchema, fastifyCaseListQuerySchema, fastifyCaseParamsSchema, uuidSchema } from '../../utils/validation';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';

export default async function caseRoutes(server: FastifyInstance) {
  server.post('/', {
    schema: { body: fastifyCreateCaseBodySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_CREATE')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (!userId) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'User ID missing from token' });
    }

    const { title, description, priority } = request.body as {
      title: string;
      description?: string;
      priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    };

    try {
      const newCase = await prisma.case.create({
        data: {
          title,
          description: description || null,
          priority: priority || 'LOW',
          organizationId,
          creatorId: userId,
        }
      });

      await logAuditEvent({
        action: 'CASE_CREATED',
        resource: 'Case',
        resourceId: newCase.id,
        status: 'SUCCESS',
        req: request
      });

      return reply.status(201).send({
        id: newCase.id,
        title: newCase.title,
        description: newCase.description,
        status: newCase.status,
        priority: newCase.priority,
        organizationId: newCase.organizationId,
        creatorId: newCase.creatorId,
        createdAt: newCase.createdAt,
        updatedAt: newCase.updatedAt,
      });
    } catch (err: unknown) {
      // Fastify's centralized error handler will pick this up
      throw err;
    }
  });

  server.get('/', {
    schema: { querystring: fastifyCaseListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
      status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
      priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    };

    const limit = query.limit;

    const where: any = { organizationId };
    if (query.status) where.status = query.status;
    if (query.priority) where.priority = query.priority;

    let cursorOpt: any = undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);
        
        const cursorSchema = z.tuple([
          z.string().datetime(),
          uuidSchema
        ]);
        
        const validated = cursorSchema.parse(decoded);
        cursorOpt = { id: validated[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    let items;
    try {
      items = await prisma.case.findMany({
        where,
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy: [
          { createdAt: 'desc' },
          { id: 'desc' }
        ],
        select: {
          id: true,
          title: true,
          description: true,
          status: true,
          priority: true,
          organizationId: true,
          creatorId: true,
          assignedUserId: true,
          resolvedAt: true,
          createdAt: true,
          updatedAt: true,
        }
      });
    } catch (err: any) {
      // P2025: Record to skip not found. This legitimately occurs if the cursor UUID is valid 
      // but no longer matches the where clause (e.g. status filter changed) or belongs to another tenant.
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }

    let nextCursor: string | null = null;
    if (items.length > limit) {
      const nextItem = items.pop();
      if (nextItem) {
        nextCursor = Buffer.from(JSON.stringify([nextItem.createdAt.toISOString(), nextItem.id])).toString('base64');
      }
    }

    return reply.status(200).send({ items, nextCursor });
  });

  server.get('/:caseId', {
    schema: { params: fastifyCaseParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { caseId } = request.params as { caseId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const c = await prisma.case.findUnique({
      where: { id_organizationId: { id: caseId, organizationId } },
      select: {
        id: true,
        title: true,
        description: true,
        status: true,
        priority: true,
        organizationId: true,
        creatorId: true,
        assignedUserId: true,
        resolvedAt: true,
        createdAt: true,
        updatedAt: true,
      }
    });

    if (!c) {
      return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
    }

    await logAuditEvent({
      action: 'CASE_VIEWED',
      resource: 'Case',
      resourceId: c.id,
      status: 'SUCCESS',
      req: request
    });

    return reply.status(200).send(c);
  });
}
