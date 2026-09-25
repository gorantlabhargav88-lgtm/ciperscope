import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';
import { hashPassword } from '../../utils/crypto';
import { roleVisibleToOrgWhere } from '../../utils/orgRoles';
import {
  fastifyMemberListQuerySchema,
  fastifyMemberParamsSchema,
  fastifyCreateMemberBodySchema,
  fastifyUpdateMemberBodySchema,
  uuidSchema,
} from '../../utils/validation';

const ADMIN_PERMISSION_ACTION = 'USER_MANAGE';

const memberSelect = {
  id: true,
  organizationId: true,
  roleId: true,
  createdAt: true,
  updatedAt: true,
  user: {
    select: { id: true, email: true, firstName: true, lastName: true, isActive: true, lastLoginAt: true, createdAt: true },
  },
  role: { select: { id: true, name: true, description: true } },
} as const;

function serializeMember(m: {
  id: string; organizationId: string; roleId: string; createdAt: Date; updatedAt: Date;
  user: { id: string; email: string; firstName: string | null; lastName: string | null; isActive: boolean; lastLoginAt: Date | null; createdAt: Date };
  role: { id: string; name: string; description: string | null };
}) {
  return {
    id: m.id,
    userId: m.user.id,
    email: m.user.email,
    firstName: m.user.firstName,
    lastName: m.user.lastName,
    isActive: m.user.isActive,
    lastLoginAt: m.user.lastLoginAt,
    joinedAt: m.createdAt,
    role: m.role,
  };
}

/** Whether a role grants USER_MANAGE — computed dynamically, never hardcoded to a role name (e.g. "System Admin"). */
async function roleGrantsUserManage(roleId: string): Promise<boolean> {
  const count = await prisma.rolePermission.count({
    where: { roleId, permission: { action: ADMIN_PERMISSION_ACTION } },
  });
  return count > 0;
}

/** Active members (excluding one, e.g. the one being changed) whose role currently grants USER_MANAGE. */
async function countOtherActiveAdmins(organizationId: string, excludeMembershipId: string): Promise<number> {
  return prisma.organizationMember.count({
    where: {
      organizationId,
      id: { not: excludeMembershipId },
      user: { isActive: true },
      role: { permissions: { some: { permission: { action: ADMIN_PERMISSION_ACTION } } } },
    },
  });
}

export default async function membersRoutes(server: FastifyInstance) {
  server.get('/roles', {
    preValidation: [server.authenticate, server.requirePermission('USER_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const roles = await prisma.role.findMany({
      where: roleVisibleToOrgWhere(organizationId),
      select: { id: true, name: true, description: true },
      orderBy: { name: 'asc' },
    });
    return reply.status(200).send({ roles });
  });

  server.get('/', {
    schema: { querystring: fastifyMemberListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as { limit: number; cursor?: string; q?: string; roleId?: string; isActive?: 'true' | 'false' };

    let cursorOpt: { id: string } | undefined;
    if (query.cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(query.cursor, 'base64').toString('utf-8'));
        const validated = z.tuple([z.string().datetime(), uuidSchema]).parse(decoded);
        cursorOpt = { id: validated[1] };
      } catch {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    const where = {
      organizationId,
      ...(query.roleId ? { roleId: query.roleId } : {}),
      ...(query.isActive !== undefined ? { user: { isActive: query.isActive === 'true' } } : {}),
      ...(query.q
        ? {
            user: {
              ...(query.isActive !== undefined ? { isActive: query.isActive === 'true' } : {}),
              OR: [
                { email: { contains: query.q, mode: 'insensitive' as const } },
                { firstName: { contains: query.q, mode: 'insensitive' as const } },
                { lastName: { contains: query.q, mode: 'insensitive' as const } },
              ],
            },
          }
        : {}),
    };

    const limit = query.limit;
    const rows = await prisma.organizationMember.findMany({
      where,
      take: limit + 1,
      skip: cursorOpt ? 1 : 0,
      cursor: cursorOpt,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: memberSelect,
    });

    let nextCursor: string | null = null;
    if (rows.length > limit) {
      rows.pop();
      const last = rows[rows.length - 1];
      if (last) nextCursor = Buffer.from(JSON.stringify([last.createdAt.toISOString(), last.id])).toString('base64');
    }

    return reply.status(200).send({ items: rows.map(serializeMember), nextCursor });
  });

  server.get('/:memberId', {
    schema: { params: fastifyMemberParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('USER_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { memberId } = request.params as { memberId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const member = await prisma.organizationMember.findFirst({ where: { id: memberId, organizationId }, select: memberSelect });
    if (!member) {
      return reply.status(404).send({ error: 'Not Found', message: 'Member not found' });
    }

    await logAuditEvent({
      action: 'MEMBER_VIEWED', resource: 'OrganizationMember', resourceId: member.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
    });

    return reply.status(200).send(serializeMember(member));
  });

  server.post('/', {
    schema: { body: fastifyCreateMemberBodySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const { email, firstName, lastName, roleId } = request.body as { email: string; firstName?: string; lastName?: string; roleId: string };

    // Never trust a client-supplied roleId without confirming it belongs to
    // THIS organization — otherwise a caller could assign a role (and thus
    // permission set) from an organization they don't administer.
    const role = await prisma.role.findFirst({ where: { id: roleId, ...roleVisibleToOrgWhere(organizationId) } });
    if (!role) {
      return reply.status(400).send({ error: 'Bad Request', message: 'roleId does not belong to this organization' });
    }

    const normalizedEmail = email.toLowerCase();
    const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (existingUser) {
      const existingMembership = await prisma.organizationMember.findUnique({
        where: { userId_organizationId: { userId: existingUser.id, organizationId } },
      });
      if (existingMembership) {
        return reply.status(409).send({ error: 'Conflict', message: 'This user is already a member of the organization' });
      }
      const created = await prisma.organizationMember.create({
        data: { userId: existingUser.id, organizationId, roleId },
        select: memberSelect,
      });
      await logAuditEvent({
        action: 'MEMBER_ADDED', resource: 'OrganizationMember', resourceId: created.id,
        organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
        metadata: { targetUserId: existingUser.id, roleId, newAccount: false },
      });
      return reply.status(201).send(serializeMember(created));
    }

    // No existing platform user with this email — create one. There is no
    // invite-email system in this deployment, so (mirroring the existing
    // Webhook-secret convention: services/api/src/modules/webhook/
    // webhook.routes.ts, "the plaintext secret is only ever returned once,
    // at creation time") a securely random temporary password is generated
    // server-side, hashed with the same argon2id policy real logins use,
    // and returned to the caller exactly once — never logged, never
    // persisted in plaintext, never retrievable again.
    const tempPassword = crypto.randomBytes(18).toString('base64url');
    const passwordHash = await hashPassword(tempPassword);

    const created = await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { email: normalizedEmail, passwordHash, firstName: firstName ?? null, lastName: lastName ?? null },
      });
      return tx.organizationMember.create({
        data: { userId: user.id, organizationId, roleId },
        select: memberSelect,
      });
    });

    await logAuditEvent({
      action: 'MEMBER_ADDED', resource: 'OrganizationMember', resourceId: created.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { targetUserId: created.user.id, roleId, newAccount: true },
    });

    return reply.status(201).send({ ...serializeMember(created), temporaryPassword: tempPassword });
  });

  server.patch('/:memberId', {
    schema: { params: fastifyMemberParamsSchema, body: fastifyUpdateMemberBodySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { memberId } = request.params as { memberId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const body = request.body as { roleId?: string; isActive?: boolean };

    const member = await prisma.organizationMember.findFirst({ where: { id: memberId, organizationId }, select: memberSelect });
    if (!member) {
      return reply.status(404).send({ error: 'Not Found', message: 'Member not found' });
    }

    if (body.roleId) {
      const newRole = await prisma.role.findFirst({ where: { id: body.roleId, ...roleVisibleToOrgWhere(organizationId) } });
      if (!newRole) {
        return reply.status(400).send({ error: 'Bad Request', message: 'roleId does not belong to this organization' });
      }
    }

    const oldRoleHasManage = await roleGrantsUserManage(member.roleId);
    const newRoleHasManage = body.roleId ? await roleGrantsUserManage(body.roleId) : oldRoleHasManage;
    const oldActive = member.user.isActive;
    const newActive = body.isActive ?? oldActive;

    const wasAdmin = oldActive && oldRoleHasManage;
    const willBeAdmin = newActive && newRoleHasManage;

    if (wasAdmin && !willBeAdmin) {
      const remaining = await countOtherActiveAdmins(organizationId, member.id);
      if (remaining === 0) {
        return reply.status(409).send({
          error: 'Conflict',
          message: 'This change would leave the organization without an active administrator (a member whose role grants USER_MANAGE).',
        });
      }
    }

    const roleChanged = body.roleId !== undefined && body.roleId !== member.roleId;
    const statusChanged = body.isActive !== undefined && body.isActive !== oldActive;

    const updated = await prisma.$transaction(async (tx) => {
      if (roleChanged) {
        await tx.organizationMember.update({ where: { id: member.id }, data: { roleId: body.roleId! } });
      }
      if (statusChanged) {
        // User.isActive is a GLOBAL account flag (see schema — there is no
        // per-membership status field), not per-organization. Toggling it
        // here deactivates the user's account everywhere, not just this
        // organization; the frontend surfaces this honestly rather than
        // implying a scoped "remove from this org only" effect.
        await tx.user.update({ where: { id: member.user.id }, data: { isActive: body.isActive! } });
      }
      return tx.organizationMember.findUniqueOrThrow({ where: { id: member.id }, select: memberSelect });
    });

    if (roleChanged) {
      await logAuditEvent({
        action: 'MEMBER_ROLE_CHANGED', resource: 'OrganizationMember', resourceId: member.id,
        organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
        metadata: { targetUserId: member.user.id, fromRoleId: member.roleId, toRoleId: body.roleId },
      });
    }
    if (statusChanged) {
      await logAuditEvent({
        action: 'MEMBER_STATUS_CHANGED', resource: 'OrganizationMember', resourceId: member.id,
        organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
        metadata: { targetUserId: member.user.id, isActive: body.isActive },
      });
    }

    return reply.status(200).send(serializeMember(updated));
  });

  server.delete('/:memberId', {
    schema: { params: fastifyMemberParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { memberId } = request.params as { memberId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const member = await prisma.organizationMember.findFirst({ where: { id: memberId, organizationId }, select: memberSelect });
    if (!member) {
      return reply.status(404).send({ error: 'Not Found', message: 'Member not found' });
    }

    const wasAdmin = member.user.isActive && (await roleGrantsUserManage(member.roleId));
    if (wasAdmin) {
      const remaining = await countOtherActiveAdmins(organizationId, member.id);
      if (remaining === 0) {
        return reply.status(409).send({
          error: 'Conflict',
          message: 'Cannot remove the last active administrator from the organization.',
        });
      }
    }

    await prisma.organizationMember.delete({ where: { id: member.id } });

    await logAuditEvent({
      action: 'MEMBER_REMOVED', resource: 'OrganizationMember', resourceId: member.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { targetUserId: member.user.id },
    });

    return reply.status(204).send();
  });
}
