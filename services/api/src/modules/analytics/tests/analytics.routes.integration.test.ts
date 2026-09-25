import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import analyticsRoutes from '../analytics.routes';

/**
 * Security Analytics (GET /analytics/overview) — same fixture pattern as
 * intelligence.routes.integration.test.ts. Every stat is computed from
 * real persisted rows for the requesting org within the selected range.
 */
describe('Analytics API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userANoPerm: string;
  let sessionA: string;
  let sessionANoPerm: string;
  let tokenA: string;
  let tokenANoPerm: string;
  let emailAId: string;
  let emailBId: string;

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
    server.register(fastifyJwt, { secret: 'test-analytics-api-secret' });
    server.register(rbacPlugin);
    server.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userANoPerm = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionANoPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Analytics Test Org A' },
        { id: orgB, name: 'Analytics Test Org B' },
      ],
    });
    await prisma.user.createMany({
      data: [
        { id: userA, email: `analytics-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `analytics-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Analytics Reader A', organizationId: orgA } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });
    await grantPermissions(roleA.id, ['CASE_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });

    const emailA = await prisma.email.create({
      data: {
        organizationId: orgA,
        sha256: crypto.createHash('sha256').update('analytics-test-email-a').digest('hex'),
        senderAddress: 'attacker@example.com',
        subject: 'Analytics test fixture A',
        classification: 'PHISHING',
      },
    });
    emailAId = emailA.id;

    const emailB = await prisma.email.create({
      data: {
        organizationId: orgB,
        sha256: crypto.createHash('sha256').update('analytics-test-email-b').digest('hex'),
        senderAddress: 'other@example.com',
        subject: 'Analytics test fixture B (org B — must never appear in org A stats)',
        classification: 'PHISHING',
      },
    });
    emailBId = emailB.id;

    await prisma.riskAssessment.create({
      data: { emailId: emailAId, overallScore: 95, riskLevel: 'CRITICAL', version: '1.0' },
    });
    await prisma.case.create({ data: { organizationId: orgA, title: 'Open critical case', priority: 'CRITICAL', status: 'OPEN' } });
  });

  afterAll(async () => {
    await prisma.riskAssessment.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.case.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('computes real, org-scoped aggregate metrics', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/analytics/overview?range=30d',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.emailsAnalyzed).toBe(1);
    expect(body.threatsDetected).toBe(1);
    expect(body.criticalThreats).toBe(1);
    expect(body.openCriticalCases).toBe(1);
    expect(body.range).toBe('30d');
    expect(Array.isArray(body.threatActivity)).toBe(true);
    expect(Array.isArray(body.severityDistribution)).toBe(true);
    // never fabricated cross-tenant data
    expect(JSON.stringify(body)).not.toContain(emailBId);
  });

  it('defaults to a sensible range and only accepts supported ranges', async () => {
    const badRange = await server.inject({
      method: 'GET',
      url: '/api/v1/analytics/overview?range=1y',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(badRange.statusCode).toBe(400);
  });

  it('works for an organization with no data (empty state)', async () => {
    const emptyOrg = crypto.randomUUID();
    const emptyUser = crypto.randomUUID();
    const emptySession = crypto.randomUUID();
    await prisma.organization.create({ data: { id: emptyOrg, name: 'Empty Analytics Org' } });
    await prisma.user.create({ data: { id: emptyUser, email: `empty-${Date.now()}@test.local`, passwordHash: 'dummy' } });
    await prisma.session.create({ data: { id: emptySession, userId: emptyUser, expiresAt: new Date(Date.now() + 100000) } });
    const roleEmpty = await prisma.role.create({ data: { name: 'Empty Reader', organizationId: emptyOrg } });
    await grantPermissions(roleEmpty.id, ['CASE_READ']);
    await prisma.organizationMember.create({ data: { userId: emptyUser, organizationId: emptyOrg, roleId: roleEmpty.id } });
    const emptyToken = server.jwt.sign({ sub: emptyUser, orgs: [emptyOrg], sid: emptySession });

    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/analytics/overview',
      headers: { authorization: `Bearer ${emptyToken}`, 'x-organization-id': emptyOrg },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.emailsAnalyzed).toBe(0);
    expect(body.threatsDetected).toBe(0);
    expect(body.threatActivity).toEqual([]);

    await prisma.organizationMember.deleteMany({ where: { userId: emptyUser } });
    await prisma.rolePermission.deleteMany({ where: { roleId: roleEmpty.id } });
    await prisma.role.deleteMany({ where: { id: roleEmpty.id } });
    await prisma.session.deleteMany({ where: { id: emptySession } });
    await prisma.user.deleteMany({ where: { id: emptyUser } });
    await prisma.organization.deleteMany({ where: { id: emptyOrg } });
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/analytics/overview' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a user without CASE_READ permission', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/analytics/overview',
      headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/analytics/overview',
      headers: { authorization: `Bearer ${tokenA}` },
    });
    expect(res.statusCode).toBe(400);
  });
});
