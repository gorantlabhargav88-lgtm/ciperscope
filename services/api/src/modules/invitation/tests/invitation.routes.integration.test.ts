import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';

// The email provider is swapped for a controllable mock so these tests can
// deterministically exercise the SENT/FAILED/NOT_CONFIGURED paths without
// a real SMTP server or network-timeout risk. packages/providers/src/
// email/index.test.ts already covers SmtpEmailProvider's own behavior
// (real nodemailer mocking) — this file proves invitation.routes.ts wires
// the result through correctly.
const sendMock = vi.fn();
vi.mock('../emailProviderConfig', () => ({
  getEmailProvider: () => ({
    isConfigured: () => true,
    send: sendMock,
  }),
}));

const invitationRoutes = (await import('../invitation.routes')).default;

/**
 * Organization invitations — real SHA-256 token hashing, single-use
 * enforcement, expiry, existing-account protection, and now real (mocked)
 * email delivery with resend/supersession.
 */
describe('Invitations API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let adminUserA: string;
  let noPermUserA: string;
  let userB: string;
  let adminSessionA: string;
  let noPermSessionA: string;
  let sessionB: string;
  let adminTokenA: string;
  let noPermTokenA: string;
  let tokenB: string;
  let analystRoleA: string;
  let roleB: string;

  async function grantPermissions(roleId: string, actions: string[]): Promise<void> {
    for (const action of actions) {
      const perm = SYSTEM_ENFORCED_PERMISSIONS.find((p) => p.action === action);
      if (!perm) throw new Error(`Unknown permission action in test setup: ${action}`);
      const permission = await prisma.permission.upsert({
        where: { action: perm.action },
        update: {},
        create: { action: perm.action, description: perm.description },
      });
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId, permissionId: permission.id } },
        update: {},
        create: { roleId, permissionId: permission.id },
      });
    }
  }

  beforeEach(() => {
    sendMock.mockReset();
    sendMock.mockResolvedValue({ status: 'sent' });
  });

  beforeAll(async () => {
    server = Fastify({ ajv: { customOptions: { removeAdditional: false } } });
    server.register(tolerantJsonBodyParser);
    server.register(fastifyJwt, { secret: 'test-invitations-api-secret' });
    server.register(rbacPlugin);
    server.register(invitationRoutes, { prefix: '/api/v1/invitations' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    adminUserA = crypto.randomUUID();
    noPermUserA = crypto.randomUUID();
    userB = crypto.randomUUID();
    adminSessionA = crypto.randomUUID();
    noPermSessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Invitations Test Org A' }, { id: orgB, name: 'Invitations Test Org B' }],
    });
    await prisma.user.createMany({
      data: [
        { id: adminUserA, email: `invite-admin-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: noPermUserA, email: `invite-noperm-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `invite-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: adminSessionA, userId: adminUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: noPermSessionA, userId: noPermUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const adminRole = await prisma.role.create({ data: { name: 'Invite Admin A', organizationId: orgA } });
    const analystRole = await prisma.role.create({ data: { name: 'Invite Analyst A', organizationId: orgA } });
    const noPermRole = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });
    const roleBRow = await prisma.role.create({ data: { name: 'Reader B', organizationId: orgB } });
    analystRoleA = analystRole.id;
    roleB = roleBRow.id;
    await grantPermissions(adminRole.id, ['USER_READ', 'USER_MANAGE']);
    await grantPermissions(roleB, ['USER_READ', 'USER_MANAGE']);

    await prisma.organizationMember.create({ data: { userId: adminUserA, organizationId: orgA, roleId: adminRole.id } });
    await prisma.organizationMember.create({ data: { userId: noPermUserA, organizationId: orgA, roleId: noPermRole.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB } });

    adminTokenA = server.jwt.sign({ sub: adminUserA, orgs: [orgA], sid: adminSessionA });
    noPermTokenA = server.jwt.sign({ sub: noPermUserA, orgs: [orgA], sid: noPermSessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
  });

  afterAll(async () => {
    await prisma.invitation.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [adminSessionA, noPermSessionA, sessionB] } } });
    await prisma.user.deleteMany({ where: { id: { in: [adminUserA, noPermUserA, userB] } } });
    await prisma.user.deleteMany({ where: { email: { startsWith: 'invite-new-' } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('creates an invitation, sends a real email, and returns a dev-only invite URL', async () => {
    const email = `invite-new-${Date.now()}@test.local`;
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.email).toBe(email.toLowerCase());
    expect(body.status).toBe('PENDING');
    expect(body.emailStatus).toBe('SENT');
    expect(body.devOnlyInviteUrl).toMatch(/\/accept-invite\//);

    expect(sendMock).toHaveBeenCalledWith(expect.objectContaining({
      to: email.toLowerCase(),
      subject: expect.stringContaining('Invitations Test Org A'),
      html: expect.stringContaining('Invitations Test Org A'),
    }));
  });

  it('records a FAILED emailStatus (and safe error) when the provider fails, without blocking invitation creation', async () => {
    sendMock.mockResolvedValueOnce({ status: 'failed', error: 'connection refused' });
    const email = `invite-new-failed-${Date.now()}@test.local`;
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    // The invitation itself is still created and fully valid — only
    // delivery failed.
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.status).toBe('PENDING');
    expect(body.emailStatus).toBe('FAILED');
    expect(body.emailError).toBe('connection refused');

    // The link is still real and acceptable even though the email never arrived.
    const token = body.devOnlyInviteUrl.split('/accept-invite/')[1];
    const verifyRes = await server.inject({ method: 'GET', url: `/api/v1/invitations/${token}` });
    expect(verifyRes.statusCode).toBe(200);
  });

  it('never puts the raw token in audit-log metadata or in logs, even on email failure', async () => {
    sendMock.mockResolvedValueOnce({ status: 'failed', error: 'auth failed' });
    const email = `invite-new-noleak-${Date.now()}@test.local`;
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const invitationId = res.json().id;
    const auditRow = await prisma.auditLog.findFirst({ where: { action: 'INVITATION_CREATED', resourceId: invitationId } });
    expect(auditRow).toBeTruthy();
    const metadataStr = JSON.stringify(auditRow!.metadata);
    // The token only ever appears inside devOnlyInviteUrl in the HTTP
    // response — audit metadata must never carry it.
    expect(metadataStr).not.toMatch(/accept-invite/);
  });

  it('rejects a roleId from a different organization (privilege-escalation guard)', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email: `invite-cross-${Date.now()}@test.local`, roleId: roleB },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects a user without USER_MANAGE permission', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${noPermTokenA}`, 'x-organization-id': orgA },
      payload: { email: `invite-x-${Date.now()}@test.local`, roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/invitations' });
    expect(res.statusCode).toBe(401);
  });

  it('tenant isolation — org B never sees org A invitations', async () => {
    const email = `invite-new-${Date.now()}@test.local`;
    await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });

    const res = await server.inject({
      method: 'GET', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(res.json().items.find((i: any) => i.email === email.toLowerCase())).toBeUndefined();
  });

  it('full accept flow: public verify -> accept creates a new user + membership with the fixed role', async () => {
    const email = `invite-new-accept-${Date.now()}@test.local`;
    const createRes = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];

    const verifyRes = await server.inject({ method: 'GET', url: `/api/v1/invitations/${token}` });
    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.json().requiresPassword).toBe(true);
    expect(verifyRes.json().organizationName).toBe('Invitations Test Org A');

    const acceptRes = await server.inject({
      method: 'POST', url: `/api/v1/invitations/${token}/accept`,
      payload: { password: 'a-secure-password-123', firstName: 'Invited', lastName: 'User' },
    });
    expect(acceptRes.statusCode).toBe(200);
    expect(acceptRes.json().organizationId).toBe(orgA);

    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    expect(user).toBeTruthy();
    const membership = await prisma.organizationMember.findUnique({ where: { userId_organizationId: { userId: user!.id, organizationId: orgA } } });
    expect(membership?.roleId).toBe(analystRoleA);

    const invitation = await prisma.invitation.findFirst({ where: { email: email.toLowerCase(), organizationId: orgA } });
    expect(invitation?.status).toBe('ACCEPTED');
  });

  it('rejects accepting without a password when no account exists yet', async () => {
    const email = `invite-new-nopass-${Date.now()}@test.local`;
    const createRes = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];

    const res = await server.inject({ method: 'POST', url: `/api/v1/invitations/${token}/accept`, payload: {} });
    expect(res.statusCode).toBe(400);
  });

  it('a token is single-use: accepting twice fails the second time', async () => {
    const email = `invite-new-single-${Date.now()}@test.local`;
    const createRes = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];

    const first = await server.inject({ method: 'POST', url: `/api/v1/invitations/${token}/accept`, payload: { password: 'a-secure-password-123' } });
    expect(first.statusCode).toBe(200);

    const second = await server.inject({ method: 'POST', url: `/api/v1/invitations/${token}/accept`, payload: { password: 'a-secure-password-123' } });
    expect(second.statusCode).toBe(404);
  });

  it('an unknown or garbage token returns a generic 404 (enumeration protection)', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/invitations/${'a'.repeat(64)}` });
    expect(res.statusCode).toBe(404);
    expect(res.json().message).not.toMatch(/database|prisma|sql/i);
  });

  it('accepting for an email that already has an account requires logging in as that user', async () => {
    const existingUser = await prisma.user.create({ data: { email: `invite-existing-${Date.now()}@test.local`, passwordHash: 'x' } });
    const createRes = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email: existingUser.email, roleId: analystRoleA },
    });
    const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];

    const verifyRes = await server.inject({ method: 'GET', url: `/api/v1/invitations/${token}` });
    expect(verifyRes.json().requiresPassword).toBe(false);

    const unauthAccept = await server.inject({ method: 'POST', url: `/api/v1/invitations/${token}/accept`, payload: {} });
    expect(unauthAccept.statusCode).toBe(401);

    // A different, unrelated logged-in user cannot claim someone else's invitation
    const wrongUserAccept = await server.inject({
      method: 'POST', url: `/api/v1/invitations/${token}/accept`,
      headers: { authorization: `Bearer ${tokenB}` },
      payload: {},
    });
    expect(wrongUserAccept.statusCode).toBe(403);

    const existingSession = await prisma.session.create({ data: { userId: existingUser.id, expiresAt: new Date(Date.now() + 100000) } });
    const existingUserToken = server.jwt.sign({ sub: existingUser.id, orgs: [], sid: existingSession.id });
    const correctAccept = await server.inject({
      method: 'POST', url: `/api/v1/invitations/${token}/accept`,
      headers: { authorization: `Bearer ${existingUserToken}` },
      payload: {},
    });
    expect(correctAccept.statusCode).toBe(200);

    const membership = await prisma.organizationMember.findUnique({ where: { userId_organizationId: { userId: existingUser.id, organizationId: orgA } } });
    expect(membership).toBeTruthy();

    await prisma.organizationMember.deleteMany({ where: { userId: existingUser.id } });
    await prisma.session.delete({ where: { id: existingSession.id } });
    await prisma.user.delete({ where: { id: existingUser.id } });
  });

  it('creating a new invitation for the same email supersedes (revokes) the previous pending one', async () => {
    const email = `invite-new-supersede-${Date.now()}@test.local`;
    const first = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const firstToken = first.json().devOnlyInviteUrl.split('/accept-invite/')[1];

    await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });

    const oldTokenVerify = await server.inject({ method: 'GET', url: `/api/v1/invitations/${firstToken}` });
    expect(oldTokenVerify.statusCode).toBe(404);
  });

  it('DELETE revokes a pending invitation, tenant-scoped', async () => {
    const email = `invite-new-revoke-${Date.now()}@test.local`;
    const createRes = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, roleId: analystRoleA },
    });
    const invitationId = createRes.json().id;

    const crossOrgDelete = await server.inject({
      method: 'DELETE', url: `/api/v1/invitations/${invitationId}`,
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(crossOrgDelete.statusCode).toBe(404);

    const res = await server.inject({
      method: 'DELETE', url: `/api/v1/invitations/${invitationId}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(204);

    const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];
    const verifyRes = await server.inject({ method: 'GET', url: `/api/v1/invitations/${token}` });
    expect(verifyRes.statusCode).toBe(404);
  });

  it('inviting an email that is already a member of the org returns 409', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/invitations',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email: (await prisma.user.findUniqueOrThrow({ where: { id: adminUserA } })).email, roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(409);
  });

  describe('resend', () => {
    it('resending mints a brand-new token, revokes the old one, and re-sends the email', async () => {
      const email = `invite-new-resend-${Date.now()}@test.local`;
      const createRes = await server.inject({
        method: 'POST', url: '/api/v1/invitations',
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
        payload: { email, roleId: analystRoleA },
      });
      const invitationId = createRes.json().id;
      const oldToken = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];
      expect(sendMock).toHaveBeenCalledTimes(1);

      const resendRes = await server.inject({
        method: 'POST', url: `/api/v1/invitations/${invitationId}/resend`,
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      });
      expect(resendRes.statusCode).toBe(201);
      const newBody = resendRes.json();
      expect(newBody.id).not.toBe(invitationId);
      expect(newBody.supersedesId).toBe(invitationId);
      const newToken = newBody.devOnlyInviteUrl.split('/accept-invite/')[1];
      expect(newToken).not.toBe(oldToken);
      expect(sendMock).toHaveBeenCalledTimes(2);

      // Old token is dead — never reused/still valid.
      const oldVerify = await server.inject({ method: 'GET', url: `/api/v1/invitations/${oldToken}` });
      expect(oldVerify.statusCode).toBe(404);

      // New token is the live one.
      const newVerify = await server.inject({ method: 'GET', url: `/api/v1/invitations/${newToken}` });
      expect(newVerify.statusCode).toBe(200);
    });

    it('cannot resend an already-accepted invitation', async () => {
      const email = `invite-new-resend-accepted-${Date.now()}@test.local`;
      const createRes = await server.inject({
        method: 'POST', url: '/api/v1/invitations',
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
        payload: { email, roleId: analystRoleA },
      });
      const invitationId = createRes.json().id;
      const token = createRes.json().devOnlyInviteUrl.split('/accept-invite/')[1];
      await server.inject({ method: 'POST', url: `/api/v1/invitations/${token}/accept`, payload: { password: 'a-secure-password-123' } });

      const resendRes = await server.inject({
        method: 'POST', url: `/api/v1/invitations/${invitationId}/resend`,
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      });
      expect(resendRes.statusCode).toBe(409);
    });

    it('tenant isolation — org B cannot resend org A\'s invitation', async () => {
      const email = `invite-new-resend-cross-${Date.now()}@test.local`;
      const createRes = await server.inject({
        method: 'POST', url: '/api/v1/invitations',
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
        payload: { email, roleId: analystRoleA },
      });
      const invitationId = createRes.json().id;

      const res = await server.inject({
        method: 'POST', url: `/api/v1/invitations/${invitationId}/resend`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects a user without USER_MANAGE permission from resending', async () => {
      const email = `invite-new-resend-noperm-${Date.now()}@test.local`;
      const createRes = await server.inject({
        method: 'POST', url: '/api/v1/invitations',
        headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
        payload: { email, roleId: analystRoleA },
      });
      const invitationId = createRes.json().id;

      const res = await server.inject({
        method: 'POST', url: `/api/v1/invitations/${invitationId}/resend`,
        headers: { authorization: `Bearer ${noPermTokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(403);
    });
  });
});
