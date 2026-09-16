import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { fastifyCreateCaseBodySchema, fastifyCaseListQuerySchema, fastifyCaseParamsSchema, uuidSchema, fastifyUpdateCaseBodySchema, fastifyAssignCaseBodySchema, fastifyLinkCaseEmailBodySchema, fastifyCreateCaseNoteBodySchema, fastifyCaseNoteListQuerySchema } from '../../utils/validation';
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

    // Construct update data explicitly to prevent mass-assignment
    const data: any = {};
    if (title !== undefined) data.title = title;
    if (description !== undefined) data.description = description;
    if (priority !== undefined) data.priority = priority;

    // Status and resolvedAt handling
    if (status !== undefined) {
      data.status = status;
      if (status === 'RESOLVED' || status === 'CLOSED') {
        data.resolvedAt = new Date();
      } else {
        data.resolvedAt = null; // Re-opening clears resolvedAt
      }
    }

    try {
      // Find first to verify existence and tenant isolation
      // Prisma's composite update using id_organizationId provides atomic isolation
      const c = await prisma.case.update({
        where: { id_organizationId: { id: caseId, organizationId } },
        data,
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

      await logAuditEvent({
        action: 'CASE_UPDATED',
        resource: 'Case',
        resourceId: c.id,
        actorId: userId,
        status: 'SUCCESS',
        req: request
      });

      return reply.status(200).send(c);
    } catch (err: any) {
      // P2025: Record to update not found (either doesn't exist, or belongs to another tenant)
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
}
