import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';
import { env } from '@ciperscope/config';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';
import { hashPassword } from '../../utils/crypto';
import { roleVisibleToOrgWhere } from '../../utils/orgRoles';
import { getEmailProvider } from './emailProviderConfig';
import { buildInvitationEmail } from './invitationEmailTemplate';
import { notificationHub } from '../alert/notificationHub';
import {
  fastifyCreateInvitationBodySchema,
  fastifyInvitationListQuerySchema,
  fastifyInvitationParamsSchema,
  fastifyInvitationTokenParamsSchema,
  fastifyAcceptInvitationBodySchema,
  uuidSchema,
} from '../../utils/validation';

// 7 days — long enough that a Friday invite is still valid Monday, short
// enough that a stale invite doesn't linger indefinitely as a standing
// access grant.
const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// SHA-256, not argon2 (see the Invitation model's doc comment in
// schema.prisma) — this token is a 256-bit random value the invitee never
// chooses, so a slow password-hash function buys no security here and
// would force enumerating every pending invitation per lookup instead of
// one indexed query.
function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

const invitationSelect = {
  id: true,
  organizationId: true,
  email: true,
  roleId: true,
  status: true,
  invitedById: true,
  expiresAt: true,
  acceptedAt: true,
  createdAt: true,
  emailStatus: true,
  emailError: true,
  supersedesId: true,
  role: { select: { id: true, name: true } },
} as const;

function buildAcceptUrl(rawToken: string): string {
  const origin = env.CORS_ORIGIN[0] ?? 'http://localhost:5173';
  return `${origin}/accept-invite/${rawToken}`;
}

/**
 * The raw token is returned directly in the API response ONLY outside
 * production (NODE_ENV !== 'production') — a development convenience for
 * when no SMTP provider is configured locally. In production this is
 * always absent; the token has already been emailed (or, if delivery
 * failed, `emailStatus`/`emailError` on the invitation record tell the
 * admin exactly that — they resend rather than being handed the live
 * secret token over HTTP).
 */
function devOnlyInviteUrl(rawToken: string): string | undefined {
  if (env.NODE_ENV === 'production') return undefined;
  return buildAcceptUrl(rawToken);
}

interface IssueInvitationParams {
  organizationId: string;
  organizationName: string;
  email: string;
  roleId: string;
  roleName: string;
  invitedById?: string;
  supersedesId?: string;
}

/**
 * Shared by POST / (create) and POST /:id/resend — generates a fresh
 * token (a resend NEVER reuses the old one), persists the invitation row,
 * then attempts delivery. Email delivery is attempted AFTER the database
 * write commits, never inside the same transaction: the invitation is a
 * real, valid, acceptable grant the moment it's created regardless of
 * whether the email send that follows succeeds, so a flaky SMTP call can
 * never roll back or block the invitation's own existence — only
 * `emailStatus`/`emailError` on the row (safely re-queryable, safely
 * retryable via resend) reflect the outcome.
 */
async function issueInvitation(params: IssueInvitationParams) {
  const rawToken = crypto.randomBytes(32).toString('base64url');
  const invitation = await prisma.invitation.create({
    data: {
      organizationId: params.organizationId,
      email: params.email,
      roleId: params.roleId,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() + INVITATION_TTL_MS),
      invitedById: params.invitedById,
      supersedesId: params.supersedesId,
    },
    select: invitationSelect,
  });

  const provider = getEmailProvider();
  let emailStatus: 'NOT_CONFIGURED' | 'SENT' | 'FAILED' = 'NOT_CONFIGURED';
  let emailError: string | null = null;

  if (provider.isConfigured()) {
    const { subject, html, text } = buildInvitationEmail({
      organizationName: params.organizationName,
      invitedEmail: params.email,
      roleName: params.roleName,
      expiresAt: invitation.expiresAt,
      acceptUrl: buildAcceptUrl(rawToken),
    });
    const result = await provider.send({ to: params.email, subject, html, text });
    if (result.status === 'sent') {
      emailStatus = 'SENT';
    } else if (result.status === 'failed') {
      emailStatus = 'FAILED';
      emailError = result.error;
    }
  }

  const updated = await prisma.invitation.update({
    where: { id: invitation.id },
    data: { emailStatus, emailError },
    select: invitationSelect,
  });

  return { invitation: updated, rawToken };
}

export default async function invitationRoutes(server: FastifyInstance) {
  server.post('/', {
    schema: { body: fastifyCreateInvitationBodySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const { email, roleId } = request.body as { email: string; roleId: string };
    const normalizedEmail = email.toLowerCase();

    // Never trust a client-supplied roleId without confirming it belongs to
    // THIS organization (or is a genuine global system role) — an
    // invitation's role is fixed at creation and the invitee can never
    // change it, so this is the one place privilege escalation could be
    // smuggled in.
    const role = await prisma.role.findFirst({ where: { id: roleId, ...roleVisibleToOrgWhere(organizationId) } });
    if (!role) {
      return reply.status(400).send({ error: 'Bad Request', message: 'roleId does not belong to this organization' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existingUser) {
      const existingMembership = await prisma.organizationMember.findUnique({
        where: { userId_organizationId: { userId: existingUser.id, organizationId } },
      });
      if (existingMembership) {
        return reply.status(409).send({ error: 'Conflict', message: 'This user is already a member of the organization' });
      }
    }

    // Superseding: an org can only ever have one live pending invitation
    // per email — creating a new one revokes any prior pending token
    // rather than leaving two valid tokens for the same grant alive at
    // once.
    await prisma.invitation.updateMany({
      where: { organizationId, email: normalizedEmail, status: 'PENDING' },
      data: { status: 'REVOKED' },
    });

    const organization = await prisma.organization.findUniqueOrThrow({ where: { id: organizationId }, select: { name: true } });
    const { invitation, rawToken } = await issueInvitation({
      organizationId,
      organizationName: organization.name,
      email: normalizedEmail,
      roleId,
      roleName: role.name,
      invitedById: request.user?.sub,
    });

    // Never the raw token — only safe, already-public-facing fields.
    await logAuditEvent({
      action: 'INVITATION_CREATED', resource: 'Invitation', resourceId: invitation.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { email: normalizedEmail, roleId, emailStatus: invitation.emailStatus },
    });

    return reply.status(201).send({ ...invitation, devOnlyInviteUrl: devOnlyInviteUrl(rawToken) });
  });

  server.post('/:invitationId/resend', {
    schema: { params: fastifyInvitationParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { invitationId } = request.params as { invitationId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const existing = await prisma.invitation.findFirst({
      where: { id: invitationId, organizationId },
      include: { role: { select: { id: true, name: true } }, organization: { select: { name: true } } },
    });
    if (!existing) {
      return reply.status(404).send({ error: 'Not Found', message: 'Invitation not found' });
    }
    if (existing.status !== 'PENDING') {
      return reply.status(409).send({ error: 'Conflict', message: `Cannot resend an invitation with status ${existing.status}` });
    }

    // Supersede: the old token is revoked and NEVER reused — resending
    // always mints a brand-new token, same as re-inviting the same email
    // from scratch does above.
    await prisma.invitation.update({ where: { id: existing.id }, data: { status: 'REVOKED' } });

    const { invitation, rawToken } = await issueInvitation({
      organizationId,
      organizationName: existing.organization.name,
      email: existing.email,
      roleId: existing.roleId,
      roleName: existing.role.name,
      invitedById: request.user?.sub,
      supersedesId: existing.id,
    });

    await logAuditEvent({
      action: 'INVITATION_CREATED', resource: 'Invitation', resourceId: invitation.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { email: existing.email, roleId: existing.roleId, emailStatus: invitation.emailStatus, resendOf: existing.id },
    });

    return reply.status(201).send({ ...invitation, devOnlyInviteUrl: devOnlyInviteUrl(rawToken) });
  });

  server.get('/', {
    schema: { querystring: fastifyInvitationListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const query = request.query as { limit: number; cursor?: string; status?: string };

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

    const rows = await prisma.invitation.findMany({
      where: { organizationId, ...(query.status ? { status: query.status as any } : {}) },
      take: query.limit + 1,
      skip: cursorOpt ? 1 : 0,
      cursor: cursorOpt,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: invitationSelect,
    });

    let nextCursor: string | null = null;
    if (rows.length > query.limit) {
      rows.pop();
      const last = rows[rows.length - 1];
      if (last) nextCursor = Buffer.from(JSON.stringify([last.createdAt.toISOString(), last.id])).toString('base64');
    }

    return reply.status(200).send({ items: rows, nextCursor });
  });

  server.delete('/:invitationId', {
    schema: { params: fastifyInvitationParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { invitationId } = request.params as { invitationId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const invitation = await prisma.invitation.findFirst({ where: { id: invitationId, organizationId } });
    if (!invitation) {
      return reply.status(404).send({ error: 'Not Found', message: 'Invitation not found' });
    }
    if (invitation.status !== 'PENDING') {
      return reply.status(409).send({ error: 'Conflict', message: `Cannot revoke an invitation with status ${invitation.status}` });
    }

    await prisma.invitation.update({ where: { id: invitation.id }, data: { status: 'REVOKED' } });

    await logAuditEvent({
      action: 'INVITATION_REVOKED', resource: 'Invitation', resourceId: invitation.id,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
    });

    return reply.status(204).send();
  });

  // ------------------------------------------------------------------
  // Public routes below — no server.authenticate preValidation, since the
  // invitee usually has no session yet. /accept optionally authenticates
  // manually (see inside) only to support the "email already has an
  // account" path.
  // ------------------------------------------------------------------

  server.get('/:token', {
    schema: { params: fastifyInvitationTokenParamsSchema },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const invitation = await prisma.invitation.findUnique({
      where: { tokenHash: hashToken(token) },
      select: {
        id: true, email: true, status: true, expiresAt: true,
        organization: { select: { name: true } },
        role: { select: { name: true } },
      },
    });

    // Invalid and expired-but-still-PENDING both return the same generic
    // 404 shape — never distinguish "token doesn't exist" from "token
    // exists but is wrong" to an unauthenticated caller (enumeration
    // protection).
    if (!invitation || invitation.status !== 'PENDING' || invitation.expiresAt < new Date()) {
      return reply.status(404).send({ error: 'Not Found', message: 'This invitation link is invalid or has expired' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email: invitation.email }, select: { id: true } });

    return reply.status(200).send({
      email: invitation.email,
      organizationName: invitation.organization.name,
      roleName: invitation.role.name,
      expiresAt: invitation.expiresAt,
      requiresPassword: !existingUser,
    });
  });

  server.post('/:token/accept', {
    schema: { params: fastifyInvitationTokenParamsSchema, body: fastifyAcceptInvitationBodySchema },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { password?: string; firstName?: string; lastName?: string };

    const invitation = await prisma.invitation.findUnique({ where: { tokenHash: hashToken(token) } });
    if (!invitation || invitation.status !== 'PENDING' || invitation.expiresAt < new Date()) {
      return reply.status(404).send({ error: 'Not Found', message: 'This invitation link is invalid or has expired' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email: invitation.email } });

    let targetUserId: string;

    if (existingUser) {
      // An account already exists for this email — accepting must prove
      // ownership of that account via a real session, never merely
      // knowledge of the invite link (which could have been forwarded or
      // leaked). This is the one place this route requires auth, and only
      // conditionally.
      try {
        await request.jwtVerify();
      } catch {
        return reply.status(401).send({
          error: 'Unauthorized',
          message: `An account already exists for ${invitation.email}. Log in as that user, then open this invitation link again.`,
        });
      }
      if (request.user.sub !== existingUser.id) {
        return reply.status(403).send({
          error: 'Forbidden',
          message: `This invitation is for ${invitation.email}. Log in as that user to accept it.`,
        });
      }
      targetUserId = existingUser.id;
    } else {
      if (!body.password) {
        return reply.status(400).send({ error: 'Bad Request', message: 'password is required to create a new account' });
      }
      const passwordHash = await hashPassword(body.password);
      const created = await prisma.user.create({
        data: { email: invitation.email, passwordHash, firstName: body.firstName ?? null, lastName: body.lastName ?? null },
      });
      targetUserId = created.id;
    }

    const alreadyMember = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: targetUserId, organizationId: invitation.organizationId } },
    });

    await prisma.$transaction(async (tx) => {
      if (!alreadyMember) {
        // The role is exactly the one fixed at invitation-creation time —
        // never anything from this request body, so an invitee can never
        // grant themselves a different role than the admin who invited
        // them chose.
        await tx.organizationMember.create({
          data: { userId: targetUserId, organizationId: invitation.organizationId, roleId: invitation.roleId },
        });
      }
      await tx.invitation.update({ where: { id: invitation.id }, data: { status: 'ACCEPTED', acceptedAt: new Date() } });
    });

    await logAuditEvent({
      action: 'INVITATION_ACCEPTED', resource: 'Invitation', resourceId: invitation.id,
      organizationId: invitation.organizationId, actorId: targetUserId, status: 'SUCCESS', req: request,
      metadata: { email: invitation.email },
    });

    // Real-time push — a genuine, real domain event (this invitation truly
    // was just accepted), not backed by a new Alert row: the admin who
    // invited them doesn't need an actionable "unread alert" for this, but
    // a connected Users & Roles page benefits from updating the moment it
    // happens rather than only on its next poll.
    await notificationHub.publish({
      type: 'INVITATION_ACCEPTED',
      organizationId: invitation.organizationId,
      userId: targetUserId,
      timestamp: new Date().toISOString(),
    });

    return reply.status(200).send({ status: 'accepted', organizationId: invitation.organizationId });
  });
}
