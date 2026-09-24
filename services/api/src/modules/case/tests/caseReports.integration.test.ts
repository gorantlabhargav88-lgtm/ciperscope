import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import caseRoutes from '../case.routes';

/**
 * Case-scoped narrative reports (GET/POST/DELETE /cases/:caseId/reports*)
 * — this surface had zero integration test coverage before (only the
 * generated-PDF ForensicReport / email-scoped report paths were tested).
 * Same fixture pattern as webhook.integration.test.ts /
 * evidence.routes.integration.test.ts.
 */
describe('Case Reports API (Integration)', () => {
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
  let caseAId: string;
  let reportAId: string;

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
    server.register(fastifyJwt, { secret: 'test-case-reports-api-secret' });
    server.register(rbacPlugin);
    server.register(caseRoutes, { prefix: '/api/v1/cases' });
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
        { id: orgA, name: 'Case Reports Test Org A' },
        { id: orgB, name: 'Case Reports Test Org B' },
      ],
    });

    await prisma.user.createMany({
      data: [
        { id: userA, email: `case-reports-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `case-reports-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `case-reports-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });

    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Case Reports A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Case Reports B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });

    await grantPermissions(roleA.id, ['CASE_CREATE', 'CASE_READ']);
    await grantPermissions(roleB.id, ['CASE_CREATE', 'CASE_READ']);
    await grantPermissions(roleANoPerm.id, ['CASE_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });

    const caseA = await prisma.case.create({
      data: { organizationId: orgA, title: 'Case Reports Test Case', priority: 'MEDIUM', status: 'OPEN' },
    });
    caseAId = caseA.id;
  });

  afterAll(async () => {
    await prisma.report.deleteMany({ where: { caseId: caseAId } });
    await prisma.case.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  describe('POST /api/v1/cases/:caseId/reports', () => {
    it('creates a report for a case owned by the requesting org', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/api/v1/cases/${caseAId}/reports`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { title: 'Initial Findings', contentHtml: 'Analyst notes here.' },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.id).toBeTruthy();
      expect(body.title).toBe('Initial Findings');
      reportAId = body.id;
    });

    it('rejects a user without CASE_CREATE permission', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/api/v1/cases/${caseAId}/reports`,
        headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
        payload: { title: 'Should be blocked' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('IDOR — org B cannot create a report on org A case', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/api/v1/cases/${caseAId}/reports`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
        payload: { title: 'Should not attach' },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /api/v1/cases/:caseId/reports', () => {
    it('lists reports for the owning org', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/cases/${caseAId}/reports`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().items.find((r: any) => r.id === reportAId)).toBeTruthy();
    });

    it('tenant isolation — org B cannot list org A case reports', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/cases/${caseAId}/reports`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects an unauthenticated request', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/cases/${caseAId}/reports` });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /api/v1/cases/:caseId/reports/:reportId', () => {
    it('returns the report for the owning org', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/cases/${caseAId}/reports/${reportAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().id).toBe(reportAId);
    });

    it('IDOR — org B requesting org A report by id gets 404', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/cases/${caseAId}/reports/${reportAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('DELETE /api/v1/cases/:caseId/reports/:reportId', () => {
    it('IDOR — org B cannot delete org A report', async () => {
      const res = await server.inject({
        method: 'DELETE',
        url: `/api/v1/cases/${caseAId}/reports/${reportAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);

      const row = await prisma.report.findUnique({ where: { id: reportAId } });
      expect(row).not.toBeNull();
    });

    it('deletes a report owned by the requesting org', async () => {
      const res = await server.inject({
        method: 'DELETE',
        url: `/api/v1/cases/${caseAId}/reports/${reportAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(204);

      const row = await prisma.report.findUnique({ where: { id: reportAId } });
      expect(row).toBeNull();
    });
  });
});
