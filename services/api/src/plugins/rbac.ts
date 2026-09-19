import fp from 'fastify-plugin';
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '@ciperscope/database';
import { logAuditEvent } from '../utils/audit';
import { uuidSchema } from '../utils/validation';

import '@fastify/jwt';

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requirePermission: (action: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifySchema {
    tags?: string[];
    summary?: string;
  }
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { sub: string; orgs: string[]; sid: string }; // payload type is used for sign and verify
    user: {
      sub: string;
      orgs: string[];
      sid: string;
    }; // user type is return type of `request.user` object
  }
}

export default fp(async (fastify: FastifyInstance) => {
  // 1. Authenticate hook
  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      await request.jwtVerify();
      // Check if session is revoked
      if (request.user && request.user.sid) {
         const session = await prisma.session.findUnique({ where: { id: request.user.sid }});
         if (!session || !session.isValid) {
            throw new Error('Session is invalid or revoked');
         }
      }
    } catch (err) {
      reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
    }
  });

  // 2. RBAC check hook builder
  fastify.decorate('requirePermission', (action: string) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      // Must be authenticated first
      if (!request.user) {
        reply.code(401).send({ error: 'Unauthorized', message: 'Not authenticated' });
        return;
      }

      const userId = request.user.sub;
      const orgId = request.headers['x-organization-id'] as string; // Target organization context

      if (!orgId) {
        reply.code(400).send({ error: 'Bad Request', message: 'Missing x-organization-id header context' });
        return;
      }

      const orgIdValidation = uuidSchema.safeParse(orgId);
      if (!orgIdValidation.success) {
        reply.code(400).send({ error: 'Bad Request', message: 'Malformed x-organization-id header' });
        return;
      }

      if (!request.user.orgs.includes(orgId)) {
        reply.code(403).send({ error: 'Forbidden', message: 'Tenant isolation violation' });
        return;
      }

      // Check DB for exact permission
      const membership = await prisma.organizationMember.findUnique({
        where: {
          userId_organizationId: {
            userId,
            organizationId: orgId,
          },
        },
        include: {
          role: {
            include: {
              permissions: {
                include: { permission: true },
              },
            },
          },
        },
      });

      if (!membership) {
        reply.code(403).send({ error: 'Forbidden', message: 'No membership found' });
        return;
      }

      // If System Admin (isSystem role with high privileges), bypass or verify
      // For this phase, we check if the permission exists in the role
      const hasPermission = membership.role.permissions.some(rp => rp.permission.action === action);

      if (!hasPermission) {
        // Create audit log for denied action
        await logAuditEvent({
          action: 'AUTHZ_DENIED',
          resource: action,
          status: 'DENIED',
          organizationId: orgId,
          actorId: userId,
          req: request
        });
        reply.code(403).send({ error: 'Forbidden', message: `Missing required permission: ${action}` });
        return;
      }
    };
  });
});
