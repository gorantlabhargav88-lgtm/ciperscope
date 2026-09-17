import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { fastifyCreateCaseBodySchema, fastifyCaseListQuerySchema, fastifyCaseParamsSchema, uuidSchema, fastifyUpdateCaseBodySchema, fastifyAssignCaseBodySchema, fastifyLinkCaseEmailBodySchema, fastifyCreateCaseNoteBodySchema, fastifyCaseNoteListQuerySchema, fastifyCaseEmailParamsSchema, fastifyCaseNoteParamsSchema, fastifyUpdateCaseNoteBodySchema, fastifyCaseTimelineQuerySchema, fastifyCaseEmailListQuerySchema, fastifyCaseHistoryQuerySchema, fastifyCreateEvidenceBodySchema, fastifyEvidenceListQuerySchema, fastifyEvidenceParamsSchema } from '../../utils/validation';
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
      q?: string;
      status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
      priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      assigneeId?: string;
      createdFrom?: string;
      createdTo?: string;
      sort: 'createdAt' | 'updatedAt' | 'priority' | 'status';
      direction: 'asc' | 'desc';
    };

    if (query.createdFrom && query.createdTo) {
      if (new Date(query.createdFrom) > new Date(query.createdTo)) {
        return reply.status(400).send({ error: 'Bad Request', message: 'createdFrom cannot be after createdTo' });
      }
    }

    const limit = query.limit;

    const where: any = { organizationId };

    if (query.q) {
      where.OR = [
        { title: { contains: query.q, mode: 'insensitive' } },
        { description: { contains: query.q, mode: 'insensitive' } }
      ];
    }

    if (query.status) where.status = query.status;
    if (query.priority) where.priority = query.priority;
    if (query.assigneeId) where.assignedUserId = query.assigneeId;

    if (query.createdFrom || query.createdTo) {
      where.createdAt = {};
      if (query.createdFrom) where.createdAt.gte = new Date(query.createdFrom);
      if (query.createdTo) where.createdAt.lte = new Date(query.createdTo);
    }

    let cursorOpt: any = undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);

        const sortValSchema = (query.sort === 'createdAt' || query.sort === 'updatedAt') ? z.string().datetime() : z.string();
        const cursorSchema = z.tuple([sortValSchema, uuidSchema]);

        const validated = cursorSchema.parse(decoded);
        cursorOpt = { id: validated[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    const orderBy = [
      { [query.sort]: query.direction },
      { id: query.direction }
    ];

    let items;
    try {
      items = await prisma.case.findMany({
        where,
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy,
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
      items.pop(); // remove the n+1 item
      const lastItem = items[items.length - 1];
      if (lastItem) {
        const sortValue = (lastItem as any)[query.sort];
        const cursorVal = (sortValue instanceof Date) ? sortValue.toISOString() : sortValue;
        nextCursor = Buffer.from(JSON.stringify([cursorVal, lastItem.id])).toString('base64');
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

  // State machine transition helper
  const isValidTransition = (fromStatus: string, toStatus: string): boolean => {
    if (fromStatus === toStatus) return true;
    const transitions: Record<string, string[]> = {
      'OPEN': ['INVESTIGATING'],
      'INVESTIGATING': ['CONTAINED'],
      'CONTAINED': ['RESOLVED'],
      'RESOLVED': ['CLOSED'],
      'CLOSED': []
    };
    return transitions[fromStatus]?.includes(toStatus) ?? false;
  };

  server.patch('/:caseId', {
    schema: {
      params: fastifyCaseParamsSchema,
      body: fastifyUpdateCaseBodySchema
    },
    preValidation: [server.authenticate, server.requirePermission('CASE_UPDATE')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { caseId } = request.params as { caseId: string };
    const userId = request.user?.sub;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (!userId) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'User ID missing from token' });
    }

    const bodyKeys = Object.keys(request.body || {});
    if (bodyKeys.length === 0) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Update body cannot be empty' });
    }

    const { title, description, priority, status } = request.body as {
      title?: string;
      description?: string;
      priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
    };

    const data: any = {};
    if (title !== undefined) data.title = title;
    if (description !== undefined) data.description = description;
    if (priority !== undefined) data.priority = priority;

    const currentCase = await prisma.case.findUnique({
      where: { id_organizationId: { id: caseId, organizationId } },
      select: { id: true, status: true }
    });

    if (!currentCase) {
      return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
    }

    if (status !== undefined) {
      if (!isValidTransition(currentCase.status, status)) {
        return reply.status(400).send({ error: 'Bad Request', message: `Invalid state transition from ${currentCase.status} to ${status}` });
      }
      data.status = status;
      if (status === 'RESOLVED' || status === 'CLOSED') {
        data.resolvedAt = new Date();
      }
      // Re-opening is strictly forbidden by the state machine, so we no longer clear resolvedAt
    }

    try {
      let c;
      if (status !== undefined && status !== currentCase.status) {
        c = await prisma.$transaction(async (tx) => {
          const result = await tx.case.updateMany({
            where: { id: caseId, organizationId, status: currentCase.status },
            data
          });
          if (result.count === 0) {
            throw new Error('CONCURRENCY_CONFLICT');
          }
          return await tx.case.findUnique({
            where: { id_organizationId: { id: caseId, organizationId } },
            select: {
              id: true, title: true, description: true, status: true, priority: true,
              organizationId: true, creatorId: true, assignedUserId: true, resolvedAt: true,
              createdAt: true, updatedAt: true,
            }
          });
        });
      } else {
        c = await prisma.case.update({
          where: { id_organizationId: { id: caseId, organizationId } },
          data,
          select: {
            id: true, title: true, description: true, status: true, priority: true,
            organizationId: true, creatorId: true, assignedUserId: true, resolvedAt: true,
            createdAt: true, updatedAt: true,
          }
        });
      }

      const auditMetadata: any = {};
      if (status !== undefined && status !== currentCase.status) {
        auditMetadata.previousStatus = currentCase.status;
        auditMetadata.newStatus = status;
      }

      await logAuditEvent({
        action: 'CASE_UPDATED',
        resource: 'Case',
        resourceId: c!.id,
        actorId: userId,
        status: 'SUCCESS',
        metadata: Object.keys(auditMetadata).length > 0 ? auditMetadata : undefined,
        req: request
      });

      return reply.status(200).send(c);
    } catch (err: any) {
      if (err.message === 'CONCURRENCY_CONFLICT') {
        return reply.status(409).send({ error: 'Conflict', message: 'The case status was modified concurrently' });
      }
      if (err.code === 'P2025') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      throw err;
    }
  });

  server.post('/:caseId/assignment', {
    schema: {
      params: fastifyCaseParamsSchema,
      body: fastifyAssignCaseBodySchema
    },
    preValidation: [server.authenticate, server.requirePermission('CASE_ASSIGN')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { caseId } = request.params as { caseId: string };
    const userId = request.user?.sub;
    const { assignedUserId } = request.body as { assignedUserId: string | null };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (!userId) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'User ID missing from token' });
    }

    try {
      const updatedCase = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. If assigning to a user, verify active membership in the same organization
        if (assignedUserId !== null) {
          const membership = await tx.organizationMember.findUnique({
            where: {
              userId_organizationId: {
                userId: assignedUserId,
                organizationId
              }
            },
            include: { user: true }
          });

          if (!membership || !membership.user.isActive) {
            throw new Error('INVALID_TARGET_USER');
          }
        }

        // 3. Atomically update the case assignment, ensuring tenant isolation is maintained
        return await tx.case.update({
          where: { id_organizationId: { id: caseId, organizationId } },
          data: { assignedUserId },
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
      });

      await logAuditEvent({
        action: 'CASE_ASSIGNED',
        resource: 'Case',
        resourceId: updatedCase.id,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { assignedUserId },
        req: request
      });

      return reply.status(200).send(updatedCase);
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.message === 'INVALID_TARGET_USER') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Target user is not a valid active member of the organization' });
      }
      throw err;
    }
  });

  server.get('/:caseId/history', {
    schema: { params: fastifyCaseParamsSchema, querystring: fastifyCaseHistoryQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
      action?: string;
    };

    const limit = query.limit;

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

    try {
      const { items, nextCursor } = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Fetch the history (AuditLog entries) with pagination
        const logs = await tx.auditLog.findMany({
          where: {
            organizationId,
            resource: 'Case',
            resourceId: caseId,
            ...(query.action ? { action: query.action } : {})
          },
          take: limit + 1,
          skip: cursorOpt ? 1 : 0,
          cursor: cursorOpt,
          orderBy: [
            { createdAt: 'desc' },
            { id: 'desc' }
          ],
          select: {
            id: true,
            action: true,
            actorId: true,
            createdAt: true,
            metadata: true
          }
        });

        let nextCursorValue: string | null = null;
        if (logs.length > limit) {
          logs.pop();
          const lastItem = logs[logs.length - 1];
          if (lastItem) {
            nextCursorValue = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
          }
        }

        // 3. Batched Actor / Assignee Enrichment (Tenant Scoped)
        const uniqueUserIds = new Set<string>();
        for (const log of logs) {
          if (log.actorId) {
            uniqueUserIds.add(log.actorId);
          }
          if (log.action === 'CASE_ASSIGNED' && log.metadata && typeof log.metadata === 'object' && 'assignedUserId' in log.metadata) {
            const assignedUserId = (log.metadata as any).assignedUserId;
            if (assignedUserId) {
              uniqueUserIds.add(assignedUserId);
            }
          }
        }

        const userMap = new Map<string, any>();
        if (uniqueUserIds.size > 0) {
          const users = await tx.user.findMany({
            where: {
              id: { in: Array.from(uniqueUserIds) },
              memberships: {
                some: { organizationId }
              }
            },
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true
            }
          });
          for (const u of users) {
            userMap.set(u.id, u);
          }
        }

        const enrichedLogs = logs.map(log => {
          const result: any = { ...log };
          if (log.actorId) {
            result.actor = userMap.get(log.actorId) || null;
          }
          if (log.action === 'CASE_ASSIGNED' && log.metadata && typeof log.metadata === 'object' && 'assignedUserId' in log.metadata) {
            const assignedUserId = (log.metadata as any).assignedUserId;
            if (assignedUserId) {
              result.assignedUser = userMap.get(assignedUserId) || null;
            } else {
              result.assignedUser = null;
            }
          }
          return result;
        });

        return { items: enrichedLogs, nextCursor: nextCursorValue };
      });

      // Audit the history access
      await logAuditEvent({
        action: 'CASE_HISTORY_VIEWED',
        resource: 'Case',
        resourceId: caseId,
        actorId: request.user?.sub,
        status: 'SUCCESS',
        req: request
      });

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        // Safe 404 response to avoid leaking cross-tenant existence
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found or unauthorized' });
      }
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.post('/:caseId/emails', {
    schema: {
      params: fastifyCaseParamsSchema,
      body: fastifyLinkCaseEmailBodySchema
    },
    preValidation: [server.authenticate, server.requirePermission('CASE_LINK_EMAIL')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { caseId } = request.params as { caseId: string };
    const userId = request.user?.sub;
    const { emailId } = request.body as { emailId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (!userId) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'User ID missing from token' });
    }

    try {
      const updatedEmail = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Verify Email exists in the tenant securely
        const existingEmail = await tx.email.findUnique({
          where: { id: emailId }
        });

        if (!existingEmail || existingEmail.organizationId !== organizationId) {
          throw new Error('EMAIL_NOT_FOUND');
        }

        // 3. Check if already linked
        if (existingEmail.caseId !== null) {
          throw new Error('EMAIL_ALREADY_LINKED');
        }

        // 4. Atomically link Email to Case, isolating mutation to caseId
        const updateResult = await tx.email.updateMany({
          where: {
            id: emailId,
            organizationId,
            caseId: null
          },
          data: { caseId }
        });

        if (updateResult.count === 0) {
          throw new Error('EMAIL_ALREADY_LINKED');
        }

        return await tx.email.findUnique({
          where: { id: emailId },
          select: {
            id: true,
            organizationId: true,
            caseId: true,
            subject: true,
            date: true,
            classification: true,
            analysisStatus: true
          }
        });
      });

      await logAuditEvent({
        action: 'CASE_EMAIL_LINKED',
        resource: 'Case',
        resourceId: caseId,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { emailId },
        req: request
      });

      return reply.status(200).send(updatedEmail);
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.message === 'EMAIL_NOT_FOUND') {
        // Use 404 to avoid leaking existence of cross-tenant emails
        return reply.status(404).send({ error: 'Not Found', message: 'Email not found' });
      }
      if (err.message === 'EMAIL_ALREADY_LINKED') {
        return reply.status(409).send({ error: 'Conflict', message: 'Email is already linked to a case' });
      }
      throw err;
    }
  });

  server.get('/:caseId/emails', {
    schema: { params: fastifyCaseParamsSchema, querystring: fastifyCaseEmailListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
    };

    const limit = query.limit;

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

    try {
      const { items, nextCursor } = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists securely in the tenant
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Fetch linked emails with pagination
        const emails = await tx.email.findMany({
          where: { organizationId, caseId },
          take: limit + 1,
          skip: cursorOpt ? 1 : 0,
          cursor: cursorOpt,
          orderBy: [
            { createdAt: 'desc' },
            { id: 'desc' }
          ],
          select: {
            id: true,
            organizationId: true,
            caseId: true,
            subject: true,
            senderAddress: true,
            date: true,
            classification: true,
            analysisStatus: true,
            riskScore: true,
            createdAt: true,
            updatedAt: true
          }
        });

        let nextCursorValue: string | null = null;
        if (emails.length > limit) {
          emails.pop();
          const lastItem = emails[emails.length - 1];
          if (lastItem) {
            nextCursorValue = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
          }
        }

        return { items: emails, nextCursor: nextCursorValue };
      });

      // Log read access according to Case read conventions
      await logAuditEvent({
        action: 'CASE_VIEWED',
        resource: 'Case',
        resourceId: caseId,
        status: 'SUCCESS',
        metadata: { subresource: 'emails' },
        req: request
      });

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.post('/:caseId/notes', {
    schema: { params: fastifyCaseParamsSchema, body: fastifyCreateCaseNoteBodySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_ADD_NOTE')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    if (!userId) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'User ID missing from token' });
    }

    const { content } = request.body as { content: string };

    try {
      const newNote = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Create the CaseNote
        return await tx.caseNote.create({
          data: {
            organizationId,
            caseId,
            authorId: userId,
            content
          },
          select: {
            id: true,
            caseId: true,
            authorId: true,
            content: true,
            createdAt: true,
            updatedAt: true
          }
        });
      });

      await logAuditEvent({
        action: 'CASE_NOTE_ADDED',
        resource: 'Case',
        resourceId: caseId,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { noteId: newNote.id },
        req: request
      });

      return reply.status(201).send(newNote);
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      throw err;
    }
  });

  server.get('/:caseId/notes', {
    schema: { params: fastifyCaseParamsSchema, querystring: fastifyCaseNoteListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
    };

    const limit = query.limit;

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

    try {
      const { items, nextCursor } = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Fetch the notes with pagination
        const notes = await tx.caseNote.findMany({
          where: { organizationId, caseId },
          take: limit + 1,
          skip: cursorOpt ? 1 : 0,
          cursor: cursorOpt,
          orderBy: [
            { createdAt: 'desc' },
            { id: 'desc' }
          ],
          select: {
            id: true,
            caseId: true,
            authorId: true,
            content: true,
            createdAt: true,
            updatedAt: true
          }
        });

        let nextCursorValue: string | null = null;
        if (notes.length > limit) {
          notes.pop();
          const lastItem = notes[notes.length - 1];
          if (lastItem) {
            nextCursorValue = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
          }
        }

        return { items: notes, nextCursor: nextCursorValue };
      });

      // Log read access according to Case read conventions
      await logAuditEvent({
        action: 'CASE_VIEWED',
        resource: 'Case',
        resourceId: caseId,
        status: 'SUCCESS',
        metadata: { subresource: 'notes' },
        req: request
      });

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.delete('/:caseId/emails/:emailId', {
    schema: { params: fastifyCaseEmailParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_LINK_EMAIL')]
  }, async (request, reply) => {
    const { caseId, emailId } = request.params as { caseId: string, emailId: string };
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists securely in the tenant
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Perform conditional, tenant-scoped atomic update to clear the caseId
        const result = await tx.email.updateMany({
          where: {
            id: emailId,
            organizationId,
            caseId
          },
          data: {
            caseId: null
          }
        });

        // 3. ToCToU / Record presence check
        if (result.count === 0) {
          throw new Error('EMAIL_NOT_LINKED');
        }
      });

      // 4. Log the audit event on absolute success
      await logAuditEvent({
        action: 'CASE_EMAIL_UNLINKED',
        resource: 'Case',
        resourceId: caseId,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { emailId },
        req: request
      });

      return reply.status(200).send({ success: true });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.message === 'EMAIL_NOT_LINKED') {
        // For security against enumeration of cross-tenant emails, if count=0 we pretend it's 404
        return reply.status(404).send({ error: 'Not Found', message: 'Email not found or not linked to this case' });
      }
      throw err;
    }
  });
  server.patch('/:caseId/notes/:noteId', {
    schema: { params: fastifyCaseNoteParamsSchema, body: fastifyUpdateCaseNoteBodySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_ADD_NOTE')]
  }, async (request, reply) => {
    const { caseId, noteId } = request.params as { caseId: string, noteId: string };
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub as string;
    const { content } = request.body as { content: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists securely in the tenant
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Perform conditional, tenant-scoped and author-scoped atomic update
        const result = await tx.caseNote.updateMany({
          where: {
            id: noteId,
            caseId,
            organizationId,
            authorId: userId
          },
          data: {
            content
          }
        });

        if (result.count === 0) {
          throw new Error('NOTE_NOT_FOUND_OR_UNAUTHORIZED');
        }
      });

      // 3. Log the audit event on absolute success
      await logAuditEvent({
        action: 'CASE_NOTE_UPDATED',
        resource: 'Case',
        resourceId: caseId,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { noteId },
        req: request
      });

      return reply.status(200).send({ success: true });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.message === 'NOTE_NOT_FOUND_OR_UNAUTHORIZED') {
        // Safe 404 response to avoid leaking cross-tenant or cross-author note existence
        return reply.status(404).send({ error: 'Not Found', message: 'Note not found or unauthorized' });
      }
      throw err;
    }
  });

  server.delete('/:caseId/notes/:noteId', {
    schema: { params: fastifyCaseNoteParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_ADD_NOTE')]
  }, async (request, reply) => {
    const { caseId, noteId } = request.params as { caseId: string, noteId: string };
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists securely in the tenant
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Perform conditional, tenant-scoped and author-scoped atomic delete
        const result = await tx.caseNote.deleteMany({
          where: {
            id: noteId,
            caseId,
            organizationId,
            authorId: userId
          }
        });

        if (result.count === 0) {
          throw new Error('NOTE_NOT_FOUND_OR_UNAUTHORIZED');
        }
      });

      // 3. Log the audit event on absolute success
      await logAuditEvent({
        action: 'CASE_NOTE_DELETED',
        resource: 'Case',
        resourceId: caseId,
        actorId: userId,
        status: 'SUCCESS',
        metadata: { noteId },
        req: request
      });

      return reply.status(200).send({ success: true });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.message === 'NOTE_NOT_FOUND_OR_UNAUTHORIZED') {
        // Safe 404 response to avoid leaking cross-tenant or cross-author note existence
        return reply.status(404).send({ error: 'Not Found', message: 'Note not found or unauthorized' });
      }
      throw err;
    }
  });

  server.get('/:caseId/timeline', {
    schema: { params: fastifyCaseParamsSchema, querystring: fastifyCaseTimelineQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      limit: number;
      cursor?: string;
    };

    const limit = query.limit;

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

    try {
      const { items, nextCursor } = await prisma.$transaction(async (tx) => {
        // 1. Verify Case exists in the tenant securely
        const existingCase = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });

        if (!existingCase) {
          throw new Error('CASE_NOT_FOUND');
        }

        // 2. Fetch the timeline (AuditLog entries for this Case) with pagination
        const logs = await tx.auditLog.findMany({
          where: { organizationId, resource: 'Case', resourceId: caseId },
          take: limit + 1,
          skip: cursorOpt ? 1 : 0,
          cursor: cursorOpt,
          orderBy: [
            { createdAt: 'desc' },
            { id: 'desc' }
          ],
          select: {
            id: true,
            action: true,
            actorId: true,
            createdAt: true,
            metadata: true
          }
        });

        let nextCursorValue: string | null = null;
        if (logs.length > limit) {
          logs.pop();
          const lastItem = logs[logs.length - 1];
          if (lastItem) {
            nextCursorValue = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
          }
        }

        return { items: logs, nextCursor: nextCursorValue };
      });

      // Log read access according to Case read conventions
      await logAuditEvent({
        action: 'CASE_VIEWED',
        resource: 'Case',
        resourceId: caseId,
        status: 'SUCCESS',
        metadata: { subresource: 'timeline' },
        req: request
      });

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  // ==========================================================================
  // CASE EVIDENCE
  // ==========================================================================

  server.post('/:caseId/evidence', {
    schema: { params: fastifyCaseParamsSchema, body: fastifyCreateEvidenceBodySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_MANAGE_EVIDENCE')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const organizationId = request.headers['x-organization-id'] as string;
    const body = request.body as any; // Verified by fastifyCreateEvidenceBodySchema

    try {
      const evidence = await prisma.$transaction(async (tx) => {
        const c = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } }
        });
        if (!c) throw new Error('CASE_NOT_FOUND');

        const e = await tx.evidence.create({
          data: {
            caseId,
            type: body.type,
            storageKey: body.storageKey,
            filename: body.filename || null,
            mimeType: body.mimeType || null,
            sizeBytes: body.sizeBytes || null,
            sha256: body.sha256,
            status: 'ACTIVE',
            collectionTime: body.collectionTime ? new Date(body.collectionTime) : new Date(),
            collectedById: body.collectedById || null,
            custodyEvents: {
              create: {
                action: 'UPLOADED',
                actorId: request.user?.sub
              }
            }
          }
        });
        return e;
      });

      await logAuditEvent({
        action: 'CASE_EVIDENCE_ADDED',
        resource: 'Evidence',
        resourceId: evidence.id,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        metadata: { caseId, sha256: evidence.sha256 },
        req: request
      });

      return reply.status(201).send(evidence);
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.code === 'P2002' && err.meta?.target?.includes('sha256')) {
         // Evidence with this SHA-256 already exists in the system (unique constraint)
         return reply.status(409).send({ error: 'Conflict', message: 'Evidence with this SHA-256 already exists' });
      }
      throw err;
    }
  });

  server.get('/:caseId/evidence', {
    schema: { params: fastifyCaseParamsSchema, querystring: fastifyEvidenceListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId } = request.params as { caseId: string };
    const query = request.query as any;
    const organizationId = request.headers['x-organization-id'] as string;
    const limit = parseInt(query.limit) || 20;

    let cursorOpt = undefined;
    if (query.cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(query.cursor, 'base64').toString('utf-8'));
        if (!Array.isArray(decoded) || decoded.length !== 2) throw new Error();
        cursorOpt = { id: decoded[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor format' });
      }
    }

    try {
      const items = await prisma.$transaction(async (tx) => {
        const c = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } },
          select: { id: true }
        });
        if (!c) throw new Error('CASE_NOT_FOUND');

        const items = await tx.evidence.findMany({
          where: { caseId, status: { not: 'DELETED' } },
          take: limit + 1,
          skip: cursorOpt ? 1 : 0,
          cursor: cursorOpt,
          orderBy: [
            { collectionTime: 'desc' },
            { id: 'desc' }
          ]
        });
        return items;
      });

      let nextCursorValue: string | null = null;
      if (items.length > limit) {
        items.pop();
        const lastItem = items[items.length - 1];
        if (lastItem) {
          nextCursorValue = Buffer.from(JSON.stringify([lastItem.collectionTime.toISOString(), lastItem.id])).toString('base64');
        }
      }

      await logAuditEvent({
        action: 'CASE_EVIDENCE_VIEWED',
        resource: 'Case',
        resourceId: caseId,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        metadata: { list: true },
        req: request
      });

      return reply.status(200).send({ items, nextCursor: nextCursorValue });
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case not found' });
      }
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.get('/:caseId/evidence/:evidenceId', {
    schema: { params: fastifyEvidenceParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')]
  }, async (request, reply) => {
    const { caseId, evidenceId } = request.params as { caseId: string, evidenceId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    try {
      const evidence = await prisma.$transaction(async (tx) => {
        const c = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } },
          select: { id: true }
        });
        if (!c) throw new Error('CASE_NOT_FOUND');

        const e = await tx.evidence.findUnique({
          where: { id: evidenceId }
        });
        if (!e || e.caseId !== caseId || e.status === 'DELETED') {
          throw new Error('EVIDENCE_NOT_FOUND');
        }
        return e;
      });

      await logAuditEvent({
        action: 'CASE_EVIDENCE_VIEWED',
        resource: 'Evidence',
        resourceId: evidence.id,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        metadata: { caseId },
        req: request
      });

      return reply.status(200).send(evidence);
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND' || err.message === 'EVIDENCE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case or Evidence not found' });
      }
      throw err;
    }
  });

  server.delete('/:caseId/evidence/:evidenceId', {
    schema: { params: fastifyEvidenceParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_MANAGE_EVIDENCE')]
  }, async (request, reply) => {
    const { caseId, evidenceId } = request.params as { caseId: string, evidenceId: string };
    const organizationId = request.headers['x-organization-id'] as string;

    try {
      await prisma.$transaction(async (tx) => {
        const c = await tx.case.findUnique({
          where: { id_organizationId: { id: caseId, organizationId } },
          select: { id: true }
        });
        if (!c) throw new Error('CASE_NOT_FOUND');

        const e = await tx.evidence.findUnique({
          where: { id: evidenceId }
        });
        if (!e || e.caseId !== caseId || e.status === 'DELETED') {
          throw new Error('EVIDENCE_NOT_FOUND');
        }

        // Soft delete the evidence (hard delete is restricted by custodyEvents)
        await tx.evidence.update({
          where: { id: evidenceId },
          data: { status: 'DELETED' }
        });
      });

      await logAuditEvent({
        action: 'CASE_EVIDENCE_DELETED',
        resource: 'Evidence',
        resourceId: evidenceId,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        metadata: { caseId },
        req: request
      });

      return reply.status(204).send();
    } catch (err: any) {
      if (err.message === 'CASE_NOT_FOUND' || err.message === 'EVIDENCE_NOT_FOUND') {
        return reply.status(404).send({ error: 'Not Found', message: 'Case or Evidence not found' });
      }
      throw err;
    }
  });
}
