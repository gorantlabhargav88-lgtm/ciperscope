import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma } from '@ciperscope/database';
import { env, encryptToken, decryptToken } from '@ciperscope/config';
import { QueueManager } from '@ciperscope/queue';
import rbacPlugin from '../../../plugins/rbac';
import integrationRoutes from '../integration.routes';

const ENCRYPTION_KEY = env.GMAIL_TOKEN_ENCRYPTION_KEY!;

describe('Gmail Integration — token encryption, disconnect, webhook isolation (Integration)', () => {
  let server: FastifyInstance;
  let orgId: string;
  let otherOrgId: string;
  let userIdWithPerm: string;
  let userIdWithoutPerm: string;
  let sessionIdWithPerm: string;
  let sessionIdWithoutPerm: string;
  let tokenWithPerm: string;
  let tokenWithoutPerm: string;
  const createdIntegrationIds: string[] = [];

  beforeAll(async () => {
    if (!ENCRYPTION_KEY) {
      throw new Error('GMAIL_TOKEN_ENCRYPTION_KEY must be set to run this test suite (see .env.example)');
    }

    server = Fastify();
    server.register(fastifyJwt, { secret: 'test-gmail-integration-secret' });
    server.register(rbacPlugin);
    server.register(integrationRoutes, { prefix: '/api/v1/integrations' });
    await server.ready();

    orgId = crypto.randomUUID();
    otherOrgId = crypto.randomUUID();
    userIdWithPerm = crypto.randomUUID();
    userIdWithoutPerm = crypto.randomUUID();
    sessionIdWithPerm = crypto.randomUUID();
    sessionIdWithoutPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgId, name: 'Gmail Integration Test Org' },
        { id: otherOrgId, name: 'Other Org' }
      ]
    });

    await prisma.user.createMany({
      data: [
        { id: userIdWithPerm, email: `gmail-with-perm-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userIdWithoutPerm, email: `gmail-no-perm-${Date.now()}@test.local`, passwordHash: 'dummy' }
      ]
    });

    await prisma.session.createMany({
      data: [
        { id: sessionIdWithPerm, userId: userIdWithPerm, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionIdWithoutPerm, userId: userIdWithoutPerm, expiresAt: new Date(Date.now() + 100000) }
      ]
    });

    const roleWithPerm = await prisma.role.create({ data: { name: 'Integration Manager', organizationId: orgId } });
    const roleWithoutPerm = await prisma.role.create({ data: { name: 'No Integration Access', organizationId: orgId } });

    const integrationManagePerm = await prisma.permission.upsert({
      where: { action: 'INTEGRATION_MANAGE' },
      update: {},
      create: { action: 'INTEGRATION_MANAGE', description: 'Connect, view, and disconnect third-party integrations' }
    });
    await prisma.rolePermission.create({ data: { roleId: roleWithPerm.id, permissionId: integrationManagePerm.id } });

    await prisma.organizationMember.create({ data: { userId: userIdWithPerm, organizationId: orgId, roleId: roleWithPerm.id } });
    await prisma.organizationMember.create({ data: { userId: userIdWithoutPerm, organizationId: orgId, roleId: roleWithoutPerm.id } });

    tokenWithPerm = server.jwt.sign({ sub: userIdWithPerm, orgs: [orgId], sid: sessionIdWithPerm });
    tokenWithoutPerm = server.jwt.sign({ sub: userIdWithoutPerm, orgs: [orgId], sid: sessionIdWithoutPerm });
  });

  afterAll(async () => {
    await prisma.integration.deleteMany({ where: { id: { in: createdIntegrationIds } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: orgId } } });
    await prisma.role.deleteMany({ where: { organizationId: orgId } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionIdWithPerm, sessionIdWithoutPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgId, otherOrgId] } } });
    await server.close();
  });

  async function createIntegration(orgIdToUse: string, emailAddress: string, status = 'ACTIVE') {
    const integration = await prisma.integration.create({
      data: {
        organizationId: orgIdToUse,
        provider: 'GMAIL',
        emailAddress,
        accessToken: encryptToken('fake-access-token-value', ENCRYPTION_KEY),
        refreshToken: encryptToken('fake-refresh-token-value', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        status
      }
    });
    createdIntegrationIds.push(integration.id);
    return integration;
  }

  async function setupIsolatedOrgWithAccess() {
    const isolatedOrgId = crypto.randomUUID();
    await prisma.organization.create({ data: { id: isolatedOrgId, name: 'Gmail Status Isolated Org' } });
    const permission = await prisma.permission.upsert({
      where: { action: 'INTEGRATION_MANAGE' },
      update: {},
      create: { action: 'INTEGRATION_MANAGE', description: 'Connect, view, and disconnect third-party integrations' }
    });
    const role = await prisma.role.create({ data: { name: 'Integration Manager', organizationId: isolatedOrgId } });
    await prisma.rolePermission.create({ data: { roleId: role.id, permissionId: permission.id } });
    await prisma.organizationMember.create({ data: { userId: userIdWithPerm, organizationId: isolatedOrgId, roleId: role.id } });
    const token = server.jwt.sign({ sub: userIdWithPerm, orgs: [isolatedOrgId], sid: sessionIdWithPerm });
    return {
      isolatedOrgId,
      token,
      cleanup: async () => {
        await prisma.integration.deleteMany({ where: { organizationId: isolatedOrgId } });
        await prisma.organizationMember.deleteMany({ where: { organizationId: isolatedOrgId } });
        await prisma.rolePermission.deleteMany({ where: { roleId: role.id } });
        await prisma.role.deleteMany({ where: { id: role.id } });
        await prisma.organization.deleteMany({ where: { id: isolatedOrgId } });
      }
    };
  }


  describe('Token encryption at rest', () => {
    it('stored accessToken/refreshToken are never the plaintext value', async () => {
      const integration = await createIntegration(orgId, `plaintext-check-${crypto.randomUUID()}@example.com`);
      expect(integration.accessToken).not.toBe('fake-access-token-value');
      expect(integration.refreshToken).not.toBe('fake-refresh-token-value');
      expect(integration.accessToken).toMatch(/^v1:/);
    });

    it('the stored envelope decrypts back to the original token value', async () => {
      const integration = await createIntegration(orgId, `roundtrip-check-${crypto.randomUUID()}@example.com`);
      expect(decryptToken(integration.accessToken, ENCRYPTION_KEY)).toBe('fake-access-token-value');
      expect(decryptToken(integration.refreshToken, ENCRYPTION_KEY)).toBe('fake-refresh-token-value');
    });
  });

  describe('Database-level tenant isolation (provider, emailAddress) uniqueness', () => {
    it('a given mailbox cannot be connected to two different organizations at once', async () => {
      const sharedEmail = `shared-mailbox-${crypto.randomUUID()}@example.com`;
      await createIntegration(orgId, sharedEmail);

      await expect(createIntegration(otherOrgId, sharedEmail)).rejects.toMatchObject({ code: 'P2002' });
    });
  });

  describe('GET /gmail/connection — status', () => {
    it('rejects an unauthenticated request (401)', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': orgId }
      });
      expect(response.statusCode).toBe(401);
    });

    it('rejects a user without INTEGRATION_MANAGE (403)', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithoutPerm}` }
      });
      expect(response.statusCode).toBe(403);
    });

    it('rejects a token not claiming the target organization (tenant isolation)', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': otherOrgId, authorization: `Bearer ${tokenWithPerm}` }
      });
      expect(response.statusCode).toBe(403);
    });

    // Each test below uses its own freshly-created organization (rather than
    // the shared `orgId`) — GET /gmail/connection has no per-test-run
    // isolation of its own (by design: it reports the real, current,
    // possibly-multi-row ACTIVE state for an org), so reusing `orgId`
    // across these specific tests would let one test's created integration
    // leak into another's assertions.
    it('returns not_connected when no ACTIVE integration exists for the org', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const response = await server.inject({
          method: 'GET',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });
        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ status: 'not_connected' });
      } finally {
        await cleanup();
      }
    });

    it('returns connected with the real emailAddress, and never a token, for an ACTIVE integration', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const emailAddress = `status-check-${crypto.randomUUID()}@example.com`;
        await createIntegration(isolatedOrgId, emailAddress);

        const response = await server.inject({
          method: 'GET',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });

        expect(response.statusCode).toBe(200);
        const body = response.json();
        expect(body.status).toBe('connected');
        expect(body.emailAddress).toBe(emailAddress);
        expect(JSON.stringify(body)).not.toContain('fake-access-token-value');
        expect(JSON.stringify(body)).not.toContain('fake-refresh-token-value');
        expect(body).not.toHaveProperty('accessToken');
        expect(body).not.toHaveProperty('refreshToken');
      } finally {
        await cleanup();
      }
    });

    it('does not report a DISCONNECTED integration as connected', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const emailAddress = `status-disconnected-${crypto.randomUUID()}@example.com`;
        await createIntegration(isolatedOrgId, emailAddress, 'DISCONNECTED');

        const response = await server.inject({
          method: 'GET',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ status: 'not_connected' });
      } finally {
        await cleanup();
      }
    });
  });

  describe('DELETE /gmail/connection — authorization', () => {
    it('rejects an unauthenticated request (401)', async () => {
      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': orgId }
      });
      expect(response.statusCode).toBe(401);
    });

    it('rejects a user without INTEGRATION_MANAGE (403)', async () => {
      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithoutPerm}` }
      });
      expect(response.statusCode).toBe(403);
    });

    it('rejects a token not claiming the target organization (tenant isolation)', async () => {
      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/integrations/gmail/connection',
        headers: { 'x-organization-id': otherOrgId, authorization: `Bearer ${tokenWithPerm}` }
      });
      expect(response.statusCode).toBe(403);
    });
  });

  describe('DELETE /gmail/connection — disconnect behavior', () => {
    it('disconnects an active connection: marks it DISCONNECTED, clears tokens, never returns a token', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const emailAddress = `disconnect-me-${crypto.randomUUID()}@example.com`;
        await createIntegration(isolatedOrgId, emailAddress);

        const response = await server.inject({
          method: 'DELETE',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });

        expect(response.statusCode).toBe(200);
        const body = response.json();
        expect(body.status).toBe('disconnected');
        expect(JSON.stringify(body)).not.toContain('fake-access-token-value');
        expect(JSON.stringify(body)).not.toContain('fake-refresh-token-value');

        const updated = await prisma.integration.findUnique({ where: { organizationId_provider_emailAddress: { organizationId: isolatedOrgId, provider: 'GMAIL', emailAddress } } });
        expect(updated?.status).toBe('DISCONNECTED');
        expect(decryptToken(updated!.accessToken, ENCRYPTION_KEY)).toBe('');
        expect(decryptToken(updated!.refreshToken, ENCRYPTION_KEY)).toBe('');
      } finally {
        await cleanup();
      }
    });

    it('is idempotent: disconnecting again when nothing is active returns not_connected, not an error', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const response = await server.inject({
          method: 'DELETE',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });
        expect(response.statusCode).toBe(200);
        expect(response.json().status).toBe('not_connected');
      } finally {
        await cleanup();
      }
    });

    it('does not delete historical Email records or Case data associated with the organization', async () => {
      const { isolatedOrgId, token, cleanup } = await setupIsolatedOrgWithAccess();
      try {
        const testCase = await prisma.case.create({ data: { organizationId: isolatedOrgId, title: 'Gmail disconnect retention test case' } });
        const email = await prisma.email.create({
          data: { organizationId: isolatedOrgId, caseId: testCase.id, sha256: crypto.randomUUID().replace(/-/g, ''), subject: 'Retained after disconnect' }
        });

        await createIntegration(isolatedOrgId, `retention-check-${crypto.randomUUID()}@example.com`);
        await server.inject({
          method: 'DELETE',
          url: '/api/v1/integrations/gmail/connection',
          headers: { 'x-organization-id': isolatedOrgId, authorization: `Bearer ${token}` }
        });

        const stillExists = await prisma.email.findUnique({ where: { id: email.id } });
        expect(stillExists).not.toBeNull();

        await prisma.email.deleteMany({ where: { id: email.id } });
        await prisma.case.deleteMany({ where: { id: testCase.id } });
      } finally {
        await cleanup();
      }
    });
  });

  describe('Webhook lookup isolation', () => {
    it('an ACTIVE integration enqueues a real sync job', async () => {
      const emailAddress = `webhook-active-${crypto.randomUUID()}@example.com`;
      await createIntegration(orgId, emailAddress);
      const historyId = `hist-${crypto.randomUUID()}`;

      const pubsubData = Buffer.from(JSON.stringify({ emailAddress, historyId })).toString('base64');
      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/integrations/gmail/webhook',
        payload: { message: { data: pubsubData, messageId: 'm1', publishTime: new Date().toISOString() }, subscription: 'projects/x/subscriptions/y' }
      });
      expect(response.statusCode).toBe(200);

      await new Promise((resolve) => setTimeout(resolve, 100)); // let the fire-and-forget handler finish enqueueing

      const queueManager = new QueueManager(env.REDIS_URL);
      const queue = queueManager.getQueue('gmail-sync');
      const integration = await prisma.integration.findFirst({ where: { emailAddress } });
      const job = await queue.getJob(`sync-${integration!.id}-${historyId}`);
      expect(job).toBeDefined();
      if (job) await job.remove().catch(() => {});
      await queueManager.closeAll();
    });

    it('a DISCONNECTED integration does NOT enqueue a sync job, even if it still receives a stale webhook', async () => {
      const emailAddress = `webhook-disconnected-${crypto.randomUUID()}@example.com`;
      const integration = await createIntegration(orgId, emailAddress, 'DISCONNECTED');
      const historyId = `hist-${crypto.randomUUID()}`;

      const pubsubData = Buffer.from(JSON.stringify({ emailAddress, historyId })).toString('base64');
      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/integrations/gmail/webhook',
        payload: { message: { data: pubsubData, messageId: 'm2', publishTime: new Date().toISOString() }, subscription: 'projects/x/subscriptions/y' }
      });
      expect(response.statusCode).toBe(200);

      await new Promise((resolve) => setTimeout(resolve, 100));

      const queueManager = new QueueManager(env.REDIS_URL);
      const queue = queueManager.getQueue('gmail-sync');
      const job = await queue.getJob(`sync-${integration.id}-${historyId}`);
      expect(job).toBeUndefined();
      await queueManager.closeAll();
    });

    it('an unknown emailAddress does not throw and does not enqueue anything', async () => {
      const pubsubData = Buffer.from(JSON.stringify({ emailAddress: `never-connected-${crypto.randomUUID()}@example.com`, historyId: 'h' })).toString('base64');
      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/integrations/gmail/webhook',
        payload: { message: { data: pubsubData, messageId: 'm3', publishTime: new Date().toISOString() }, subscription: 'projects/x/subscriptions/y' }
      });
      expect(response.statusCode).toBe(200);
    });

    it('a malformed webhook payload does not crash the server (200 returned immediately regardless)', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/integrations/gmail/webhook',
        payload: { not: 'a valid pubsub envelope' }
      });
      expect(response.statusCode).toBe(200);
    });
  });
});
