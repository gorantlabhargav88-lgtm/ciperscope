import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import { decryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import rbacPlugin from '../../../plugins/rbac';
import webhookRoutes from '../webhook.routes';

/**
 * Phase 2 — webhook management API: tenant isolation, permission
 * enforcement, and the "secret shown exactly once" contract, against a
 * real Postgres (same fixture pattern as resourceOwnershipIsolation.
 * integration.test.ts). Delivery behavior itself (HMAC, retries, timeouts)
 * is covered by services/worker's WebhookDeliveryWorker unit tests — this
 * file only proves the API surface and its authorization boundary.
 */
describe('Webhook management API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userB: string;
  let userANoPerm: string;
  let sessionA: string;
  let sessionB: string;
  let sessionANoPerm: string;
  let tokenA: string;
  let tokenB: string;
  let tokenANoPerm: string;
  let webhookAId: string;

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

  beforeAll(async () => {
    server = Fastify({ ajv: { customOptions: { removeAdditional: false } } });
    server.register(fastifyJwt, { secret: 'test-webhook-api-secret' });
    server.register(rbacPlugin);
    server.register(webhookRoutes, { prefix: '/api/v1/webhooks' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userB = crypto.randomUUID();
    userANoPerm = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();
    sessionANoPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Webhook Test Org A' },
        { id: orgB, name: 'Webhook Test Org B' },
      ],
    });

    await prisma.user.createMany({
      data: [
        { id: userA, email: `webhook-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `webhook-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `webhook-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });

    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Webhook Manager A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Webhook Manager B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });

    await grantPermissions(roleA.id, ['INTEGRATION_MANAGE']);
    await grantPermissions(roleB.id, ['INTEGRATION_MANAGE']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });
  });

  afterAll(async () => {
    await prisma.webhookDelivery.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.webhook.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  describe('POST /api/v1/webhooks', () => {
    it('creates a webhook and returns the plaintext secret exactly once', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { url: 'https://receiver.example.com/hook', events: ['THREAT_ANALYSIS_COMPLETED'] },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.secret).toMatch(/^[0-9a-f]{64}$/);
      expect(body.id).toBeTruthy();
      webhookAId = body.id;

      // The persisted row must never store the plaintext.
      const row = await prisma.webhook.findUnique({ where: { id: webhookAId } });
      expect(row!.secretEncrypted).not.toBe(body.secret);
      expect(decryptToken(row!.secretEncrypted, requireGmailTokenEncryptionKey())).toBe(body.secret);
    });

    it('rejects a request with no organization context', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenA}` },
        payload: { url: 'https://receiver.example.com/hook', events: ['THREAT_ANALYSIS_COMPLETED'] },
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects a user without INTEGRATION_MANAGE permission', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
        payload: { url: 'https://receiver.example.com/hook', events: ['THREAT_ANALYSIS_COMPLETED'] },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects an invalid event type', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { url: 'https://receiver.example.com/hook', events: ['NOT_A_REAL_EVENT'] },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/v1/webhooks', () => {
    it('never includes the secret in the list response', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.webhooks.length).toBeGreaterThan(0);
      for (const w of body.webhooks) {
        expect(w.secret).toBeUndefined();
        expect(w.secretEncrypted).toBeUndefined();
      }
    });

    it('tenant isolation — org B never sees org A webhooks in its list', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/webhooks',
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.webhooks.find((w: any) => w.id === webhookAId)).toBeUndefined();
    });
  });

  describe('PATCH /api/v1/webhooks/:webhookId', () => {
    it('updates a field owned by the requesting org', async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/webhooks/${webhookAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { enabled: false },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().enabled).toBe(false);

      // restore for later tests
      await server.inject({
        method: 'PATCH',
        url: `/api/v1/webhooks/${webhookAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { enabled: true },
      });
    });

    it('tenant isolation — org B cannot update org A webhook (404, not leaked as 403)', async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/webhooks/${webhookAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
        payload: { enabled: false },
      });
      expect(res.statusCode).toBe(404);

      // Confirm org A's webhook was genuinely untouched.
      const row = await prisma.webhook.findUnique({ where: { id: webhookAId } });
      expect(row!.enabled).toBe(true);
    });
  });

  describe('POST /api/v1/webhooks/:webhookId/test', () => {
    it('enqueues a test delivery for a webhook owned by the requesting org', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/api/v1/webhooks/${webhookAId}/test`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(202);
      expect(res.json().eventId).toBeTruthy();
    });

    it('tenant isolation — org B cannot trigger a test delivery for org A webhook', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/api/v1/webhooks/${webhookAId}/test`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('DELETE /api/v1/webhooks/:webhookId', () => {
    it('tenant isolation — org B cannot delete org A webhook', async () => {
      const res = await server.inject({
        method: 'DELETE',
        url: `/api/v1/webhooks/${webhookAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('deletes a webhook owned by the requesting org', async () => {
      const res = await server.inject({
        method: 'DELETE',
        url: `/api/v1/webhooks/${webhookAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(204);

      const row = await prisma.webhook.findUnique({ where: { id: webhookAId } });
      expect(row).toBeNull();
    });
  });
});
