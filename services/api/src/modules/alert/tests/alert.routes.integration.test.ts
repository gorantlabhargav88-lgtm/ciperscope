import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import alertRoutes from '../alert.routes';

/**
 * Alerts / notification-bell backend (GET /alerts, GET /alerts/unread-count,
 * POST /alerts/mark-all-read, PATCH /alerts/:id). No prior test file
 * existed for this module — this covers it end to end, including the two
 * new endpoints added to back the header notification bell.
 */
describe('Alerts API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userANoPerm: string;
  let userB: string;
  let sessionA: string;
  let sessionANoPerm: string;
  let sessionB: string;
  let tokenA: string;
  let tokenANoPerm: string;
  let tokenB: string;
  let alertAId: string;
  let alertA2Id: string;
  let alertBId: string;

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
    server.register(tolerantJsonBodyParser);
    server.register(fastifyJwt, { secret: 'test-alerts-api-secret' });
    server.register(rbacPlugin);
    server.register(alertRoutes, { prefix: '/api/v1/alerts' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userANoPerm = crypto.randomUUID();
    userB = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionANoPerm = crypto.randomUUID();
    sessionB = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Alerts Test Org A' }, { id: orgB, name: 'Alerts Test Org B' }],
    });
    await prisma.user.createMany({
      data: [
        { id: userA, email: `alerts-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `alerts-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `alerts-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Alerts Reader A', organizationId: orgA } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Alerts Reader B', organizationId: orgB } });
    await grantPermissions(roleA.id, ['ALERT_READ', 'ALERT_UPDATE']);
    await grantPermissions(roleB.id, ['ALERT_READ', 'ALERT_UPDATE']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });

    const alertA = await prisma.alert.create({ data: { organizationId: orgA, title: 'Critical threat detected', message: 'Real fixture alert A1', severity: 'CRITICAL' } });
    const alertA2 = await prisma.alert.create({ data: { organizationId: orgA, title: 'High risk email', message: 'Real fixture alert A2', severity: 'HIGH' } });
    const alertB = await prisma.alert.create({ data: { organizationId: orgB, title: 'Org B alert', message: 'Real fixture alert B1', severity: 'CRITICAL' } });
    alertAId = alertA.id;
    alertA2Id = alertA2.id;
    alertBId = alertB.id;
  });

  afterAll(async () => {
    await prisma.alert.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userANoPerm, userB] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionANoPerm, sessionB] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userANoPerm, userB] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('lists org-scoped alerts', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/alerts',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.some((a: any) => a.id === alertAId)).toBe(true);
    expect(body.items.some((a: any) => a.id === alertBId)).toBe(false);
  });

  it('tenant isolation — org B never sees org A alerts', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/alerts',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    const body = res.json();
    expect(body.items.some((a: any) => a.id === alertAId)).toBe(false);
    expect(body.items.some((a: any) => a.id === alertBId)).toBe(true);
  });

  it('GET /alerts/unread-count returns the real org-scoped unread count', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/alerts/unread-count',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().count).toBe(2);
  });

  it('unread-count never leaks another org\'s count', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/alerts/unread-count',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(res.json().count).toBe(1);
  });

  it('PATCH /alerts/:id marks a single alert read, tenant-scoped', async () => {
    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/alerts/${alertAId}`,
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      payload: { isRead: true },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().isRead).toBe(true);

    const countRes = await server.inject({
      method: 'GET', url: '/api/v1/alerts/unread-count',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(countRes.json().count).toBe(1);
  });

  it('org B cannot mark org A\'s alert as read (IDOR guard)', async () => {
    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/alerts/${alertA2Id}`,
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      payload: { isRead: true },
    });
    expect(res.statusCode).toBe(404);

    const stillUnread = await prisma.alert.findUnique({ where: { id: alertA2Id } });
    expect(stillUnread?.isRead).toBe(false);
  });

  it('POST /alerts/mark-all-read marks every unread org alert read and is audited', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/alerts/mark-all-read',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().count).toBe(1); // only alertA2Id was still unread

    const countRes = await server.inject({
      method: 'GET', url: '/api/v1/alerts/unread-count',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(countRes.json().count).toBe(0);

    // org B's alert must be untouched
    const orgBAlert = await prisma.alert.findUnique({ where: { id: alertBId } });
    expect(orgBAlert?.isRead).toBe(false);

    const auditRow = await prisma.auditLog.findFirst({ where: { action: 'ALERTS_MARKED_ALL_READ', organizationId: orgA } });
    expect(auditRow).toBeTruthy();
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/alerts' });
    expect(res.statusCode).toBe(401);
    const res2 = await server.inject({ method: 'GET', url: '/api/v1/alerts/unread-count' });
    expect(res2.statusCode).toBe(401);
  });

  it('rejects a user without ALERT_READ permission', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/alerts',
      headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a user without ALERT_UPDATE permission from mark-all-read', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/alerts/mark-all-read',
      headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/alerts', headers: { authorization: `Bearer ${tokenA}` } });
    expect(res.statusCode).toBe(400);
  });

  it('never leaks another organization\'s alert content in error responses', async () => {
    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/alerts/${alertBId}`,
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      payload: { isRead: true },
    });
    expect(res.statusCode).toBe(404);
    expect(JSON.stringify(res.json())).not.toContain('Org B alert');
  });

  describe('GET /alerts/stream (SSE) — authorization guards', () => {
    // These only exercise the pre-stream guard path (every one of these
    // cases returns before reply.hijack()/writeHead() ever runs), so
    // server.inject() resolves normally. The actual open-connection +
    // event-delivery behavior is covered by notificationHub.test.ts (the
    // real pub/sub mechanics this route's handler writes to the response)
    // and by live browser E2E — a real long-lived stream deliberately
    // never completes, which server.inject() cannot represent.

    it('rejects a request with no auth cookie/token at all', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/alerts/stream?organizationId=${orgA}` });
      expect(res.statusCode).toBe(401);
    });

    it('rejects a malformed organizationId', async () => {
      const res = await server.inject({
        method: 'GET', url: '/api/v1/alerts/stream?organizationId=not-a-uuid',
        headers: { authorization: `Bearer ${tokenA}` },
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects an organizationId the authenticated user is not a member of (tenant isolation — never trusts the query param alone)', async () => {
      const res = await server.inject({
        method: 'GET', url: `/api/v1/alerts/stream?organizationId=${orgB}`,
        headers: { authorization: `Bearer ${tokenA}` },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects a user without ALERT_READ permission in that org, and audits the denial', async () => {
      const res = await server.inject({
        method: 'GET', url: `/api/v1/alerts/stream?organizationId=${orgA}`,
        headers: { authorization: `Bearer ${tokenANoPerm}` },
      });
      expect(res.statusCode).toBe(403);
      const denied = await prisma.auditLog.findFirst({
        where: { action: 'AUTHZ_DENIED', organizationId: orgA, actorId: userANoPerm },
        orderBy: { createdAt: 'desc' },
      });
      expect(denied).toBeTruthy();
    });
  });
});
